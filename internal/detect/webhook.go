package detect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/netguard"
)

// WebhookSink POSTs each finding to an address the operator chose.
//
// # What it is, and what it is not
//
// A copy. The finding is already in the database and, if configured, in the
// NDJSON file before this sink is offered it — those are the record, this is a
// notification. Everything here is allowed to fail; none of it is allowed to
// delay anything.
//
// It is not a SIEM integration. The NDJSON file plus a log shipper remains the
// way to get findings into a log platform, because that path survives this
// process being restarted and this one does not. What a webhook is for is a
// human seeing an alert in Slack or Teams within a few seconds.
//
// # Why it cannot stall detection
//
// Emit is a non-blocking send to a bounded queue. A full queue drops and
// counts. The queue is drained by one goroutine that does the HTTP work, so an
// endpoint that has gone away, hangs, or 500s for an hour costs a growing drop
// counter and nothing else — not a detector, not an observation, and certainly
// not a DNS answer.
//
// # Why it is not an SSRF gadget
//
// The URL comes from configuration, which means it comes from whoever can edit
// the config file. That is an operator, but an operator of this dashboard is
// not necessarily an administrator of the host, and pointing this process at
// 169.254.169.254 would turn the first into the second. So: HTTPS only,
// netguard.PublicOnly on every connection after DNS resolution, IP literals
// checked before any lookup for the proxied case, and no redirects followed at
// all — a redirect is the standard way to turn an allowed destination into a
// refused one after the check has passed.
type WebhookSink struct {
	url        string
	headerName string
	headerVal  string
	client     *http.Client
	maxBody    int64
	attempts   int
	log        *slog.Logger

	queue chan Finding
	wg    sync.WaitGroup

	enqueued atomic.Uint64
	sent     atomic.Uint64
	dropped  sync.Map // reason -> *atomic.Uint64
	lastErr  atomic.Pointer[string]
	lastSend atomic.Int64 // unix milli; 0 = never
}

// Drop reasons. A small closed set, safe as a metric label.
//
// Closed because these are labels on a counter, and a label whose values come
// from an error string is a cardinality explosion waiting for the first
// unusual failure. Anything that does not fit is counted as rejected.
const (
	// WebhookDropFull: the queue was full. Findings are arriving faster than
	// the endpoint accepts them.
	WebhookDropFull = "full"
	// WebhookDropInvalidURL: the address could not be used at all.
	WebhookDropInvalidURL = "invalid_url"
	// WebhookDropSSRF: the address resolved somewhere this process refuses to
	// connect.
	WebhookDropSSRF = "ssrf"
	// WebhookDropTimeout: the endpoint did not answer in time, on every
	// attempt.
	WebhookDropTimeout = "timeout"
	// WebhookDropRejected: the endpoint answered, and kept refusing.
	WebhookDropRejected = "rejected"
)

// WebhookDropReasons is every reason, for emitting a metric series per reason
// whether or not it has happened. A series that appears only once something
// has gone wrong is one an operator cannot alert on in advance.
func WebhookDropReasons() []string {
	return []string{
		WebhookDropFull, WebhookDropInvalidURL, WebhookDropSSRF,
		WebhookDropTimeout, WebhookDropRejected,
	}
}

// WebhookOptions configures a WebhookSink.
type WebhookOptions struct {
	// URL is where to POST. Empty means the sink is not built at all.
	URL string
	// HeaderName and HeaderValue are one optional secret header, for endpoints
	// that authenticate. One header rather than a map: a free-form header map
	// is a way to smuggle a Host or an Authorization somewhere it was not
	// meant to go, and nothing has asked for more than one.
	HeaderName  string
	HeaderValue string

	Timeout      time.Duration
	MaxAttempts  int
	QueueSize    int
	MaxBodyBytes int64

	Log *slog.Logger
}

// Webhook defaults. Modest on purpose: this runs on a 1 GB box beside a
// resolver, and a notification path is not allowed to be the expensive thing
// in the process.
const (
	DefaultWebhookTimeout      = 5 * time.Second
	DefaultWebhookAttempts     = 3
	DefaultWebhookQueueSize    = 256
	DefaultWebhookMaxBodyBytes = 64 << 10
)

// NewWebhookSink builds a sink, or returns an error the operator can act on.
//
// The URL is validated here, at startup, rather than on first use. An address
// that can never work should stop the operator at the point they can still fix
// it, not produce a drop counter three days later when a finding they cared
// about failed to arrive.
func NewWebhookSink(o WebhookOptions) (*WebhookSink, error) {
	if strings.TrimSpace(o.URL) == "" {
		return nil, nil
	}
	if err := ValidateWebhookURL(o.URL); err != nil {
		return nil, err
	}

	timeout := o.Timeout
	if timeout <= 0 {
		timeout = DefaultWebhookTimeout
	}
	attempts := o.MaxAttempts
	if attempts <= 0 {
		attempts = DefaultWebhookAttempts
	}
	queueSize := o.QueueSize
	if queueSize <= 0 {
		queueSize = DefaultWebhookQueueSize
	}
	maxBody := o.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = DefaultWebhookMaxBodyBytes
	}
	logger := o.Log
	if logger == nil {
		logger = slog.Default()
	}

	s := &WebhookSink{
		url:        o.URL,
		headerName: strings.TrimSpace(o.HeaderName),
		headerVal:  o.HeaderValue,
		maxBody:    maxBody,
		attempts:   attempts,
		log:        logger,
		queue:      make(chan Finding, queueSize),
		client: &http.Client{
			Timeout: timeout,
			// Never follow a redirect. A 302 is the standard way to turn a
			// destination that passed the check into one that would not have:
			// the operator's URL is checked, the redirect target is whatever
			// the endpoint says, and by the time the second request is dialed
			// the decision has already been made.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   timeout,
					KeepAlive: 30 * time.Second,
					// After DNS resolution, on every attempt. A hostname that
					// resolves to 127.0.0.1 today and to metadata tomorrow is
					// caught on the attempt that would have reached it.
					Control: netguard.Control(netguard.PublicOnly),
				}).DialContext,
				MaxIdleConns:          2,
				MaxIdleConnsPerHost:   2,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   timeout,
				ExpectContinueTimeout: time.Second,
				ForceAttemptHTTP2:     true,
			},
		},
	}
	return s, nil
}

// ValidateWebhookURL reports whether an address can be used as a webhook.
//
// Called at startup and by dnsdaddy doctor. It never dials: the point is to
// refuse an address that is wrong on its face, before anything has been sent
// anywhere, and doing a DNS lookup here would make a diagnostic depend on the
// network it is diagnosing.
func ValidateWebhookURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("notification address: %q is not a URL", redactURL(raw))
	}
	if u.Scheme != "https" {
		// HTTPS only, with no opt-out. A finding names a client and a domain
		// somebody on the network looked up; sending that over plain HTTP puts
		// it in front of every hop between here and the endpoint. Slack, Teams
		// and every other target of this feature are HTTPS.
		return fmt.Errorf("notification address: must start with https:// — "+
			"a finding names a device and a domain, and plain HTTP would send "+
			"that in the clear (got %q)", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("notification address: no host in the URL")
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("notification address: no host in the URL")
	}
	if err := netguard.CheckURLHost(host, netguard.PublicOnly); err != nil {
		return fmt.Errorf("notification address: %w", err)
	}
	return nil
}

// Emit implements Sink. It never blocks and never fails.
//
// Returning nil on a drop is deliberate. MultiSink collects the first error
// and the engine logs it, and a webhook that could not be reached is not a
// reason to log an error against a finding that was stored perfectly well. The
// drop is counted, surfaced in /metrics and reported by doctor, which is where
// something that is nobody's emergency belongs.
func (s *WebhookSink) Emit(_ context.Context, f Finding) error {
	if s == nil {
		return nil
	}
	select {
	case s.queue <- f:
		s.enqueued.Add(1)
	default:
		s.drop(WebhookDropFull)
	}
	return nil
}

// Run drains the queue until ctx is cancelled. Start it once, in a goroutine.
func (s *WebhookSink) Run(ctx context.Context) {
	if s == nil {
		return
	}
	s.wg.Add(1)
	defer s.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case f := <-s.queue:
			s.deliver(ctx, f)
		}
	}
}

// Wait blocks until Run has returned.
func (s *WebhookSink) Wait() {
	if s == nil {
		return
	}
	s.wg.Wait()
}

// deliver sends one finding, retrying the failures that are worth retrying.
func (s *WebhookSink) deliver(ctx context.Context, f Finding) {
	body, err := json.Marshal(f)
	if err != nil {
		// Cannot happen for a Finding, and if it somehow did, retrying would
		// fail identically every time.
		s.drop(WebhookDropRejected)
		s.note("could not encode a finding for the notification address: " + err.Error())
		return
	}

	for attempt := 1; attempt <= s.attempts; attempt++ {
		retry, reason, err := s.attempt(ctx, body)
		if err == nil {
			s.sent.Add(1)
			s.lastSend.Store(time.Now().UnixMilli())
			s.lastErr.Store(nil)
			return
		}
		s.note(err.Error())
		if !retry || attempt == s.attempts {
			s.drop(reason)
			return
		}
		select {
		case <-ctx.Done():
			s.drop(reason)
			return
		case <-time.After(backoff(attempt)):
		}
	}
}

// attempt makes one request and says whether another is worth making.
func (s *WebhookSink) attempt(ctx context.Context, body []byte) (retry bool, reason string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return false, WebhookDropInvalidURL, fmt.Errorf("notification address is unusable: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "dnsdaddy")
	if s.headerName != "" {
		req.Header.Set(s.headerName, s.headerVal)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		// An address this process refuses to connect to is never worth
		// retrying: the answer will be the same every time, and counting it as
		// a timeout would hide an SSRF attempt among ordinary network noise.
		if errors.Is(err, netguard.ErrBlocked) {
			return false, WebhookDropSSRF, fmt.Errorf("refused to connect: %w", scrub(err))
		}
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return true, WebhookDropTimeout, fmt.Errorf("notification timed out: %w", scrub(err))
		}
		return true, WebhookDropTimeout, fmt.Errorf("could not reach the notification address: %w", scrub(err))
	}
	defer resp.Body.Close()

	// Read a bounded amount and discard it. The response is not wanted — what
	// matters is the status — but a connection left with an unread body cannot
	// be reused, and an endpoint that answers with a gigabyte must not be able
	// to make this process hold it.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, s.maxBody))

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return false, "", nil
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		// Rate limited, or the endpoint is having a bad time. Both pass.
		return true, WebhookDropRejected,
			fmt.Errorf("the notification address answered %d", resp.StatusCode)
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		// A redirect, which is not followed. Reported as a rejection rather
		// than retried, because the next attempt would redirect identically.
		return false, WebhookDropRejected,
			fmt.Errorf("the notification address redirected (%d), which is not followed", resp.StatusCode)
	default:
		// Any other 4xx: wrong URL, wrong credential, malformed request.
		// Retrying a permanent refusal is how a misconfiguration becomes load
		// on somebody else's server.
		return false, WebhookDropRejected,
			fmt.Errorf("the notification address rejected this (%d)", resp.StatusCode)
	}
}

// backoff is the wait before attempt n+1: doubling, with jitter.
//
// Jitter from math/rand rather than crypto/rand, deliberately and in line with
// the rest of this project: the value only has to be unpredictable to a
// thundering herd, not to an adversary. Nothing about retry timing is a secret.
func backoff(attempt int) time.Duration {
	base := time.Duration(1<<uint(attempt-1)) * 250 * time.Millisecond
	const cap = 10 * time.Second
	if base > cap {
		base = cap
	}
	// Up to half the interval again, so N senders that failed together do not
	// return together.
	// #nosec G404 -- math/rand is the right choice, not a compromise. This
	// de-synchronises retries against an endpoint that has just failed; it
	// protects nothing and reveals nothing. Retry timing is not a secret, and
	// a cryptographic source would cost entropy on every failed delivery to
	// make a delay marginally harder to guess, which buys an attacker nothing.
	return base + time.Duration(rand.Int64N(int64(base/2)+1))
}

// drop counts one finding that did not arrive.
func (s *WebhookSink) drop(reason string) {
	v, _ := s.dropped.LoadOrStore(reason, new(atomic.Uint64))
	v.(*atomic.Uint64).Add(1)
}

// note records the most recent failure, for doctor.
//
// Scrubbed first: the URL can carry a token in its path or query — a Slack
// webhook is exactly that — and an error string ends up in the log, in
// /api/v1/diagnostics and in a doctor report somebody pastes into a ticket.
func (s *WebhookSink) note(msg string) {
	clean := redactURL(msg)
	s.lastErr.Store(&clean)
	s.log.Warn("finding notification failed", "error", clean)
}

// WebhookStats is what the sink has done, for metrics and diagnostics.
type WebhookStats struct {
	Configured bool
	Enqueued   uint64
	Sent       uint64
	Dropped    map[string]uint64
	QueueLen   int
	LastSendAt time.Time
	LastError  string
}

// Stats reports what has happened. Safe on a nil sink, which is what "no
// address configured" looks like everywhere else in the process.
func (s *WebhookSink) Stats() WebhookStats {
	st := WebhookStats{Dropped: map[string]uint64{}}
	for _, r := range WebhookDropReasons() {
		st.Dropped[r] = 0
	}
	if s == nil {
		return st
	}
	st.Configured = true
	st.Enqueued = s.enqueued.Load()
	st.Sent = s.sent.Load()
	st.QueueLen = len(s.queue)
	for _, r := range WebhookDropReasons() {
		if v, ok := s.dropped.Load(r); ok {
			st.Dropped[r] = v.(*atomic.Uint64).Load()
		}
	}
	if ms := s.lastSend.Load(); ms > 0 {
		st.LastSendAt = time.UnixMilli(ms).UTC()
	}
	if p := s.lastErr.Load(); p != nil {
		st.LastError = *p
	}
	return st
}

// RedactedURL is the configured address with anything secret removed, for
// showing an operator which endpoint is in use.
func (s *WebhookSink) RedactedURL() string {
	if s == nil {
		return ""
	}
	return redactURL(s.url)
}

// RedactWebhookURL removes the parts of an address that carry credentials, for
// showing an operator which endpoint is configured without handing them — or a
// ticket system — the token.
func RedactWebhookURL(raw string) string { return redactURL(raw) }

// redactURL removes the parts of a URL that carry credentials.
//
// A Slack webhook URL is a bearer token in path form: anyone holding
// hooks.slack.com/services/T000/B000/XXXX can post to that channel. The host
// is kept because "which endpoint is this going to" is the useful half, and
// the path and query are replaced wholesale rather than pattern-matched for
// things that look secret — a denylist of secret-looking shapes is a denylist
// somebody's token will not be on.
func redactURL(s string) string {
	var b strings.Builder
	// A cursor that only ever moves forward.
	//
	// The obvious version of this — find the first URL, replace it, search
	// again from the start — does not terminate: the replacement still begins
	// "https://", so the next search finds it at the same offset and the loop
	// spins for ever. That version hung the sender goroutine on the first
	// failed delivery, which is exactly the situation this function exists
	// for. Building the result forward makes the progress structural rather
	// than something to remember.
	for i := 0; i < len(s); {
		j := indexScheme(s[i:])
		if j < 0 {
			b.WriteString(s[i:])
			break
		}
		b.WriteString(s[i : i+j])
		start := i + j
		end := start
		for end < len(s) && !isURLTerminator(s[end]) {
			end++
		}
		b.WriteString(redactOne(s[start:end]))
		i = end
	}
	return b.String()
}

// indexScheme finds the first http:// or https:// in s, or -1.
func indexScheme(s string) int {
	https := strings.Index(s, "https://")
	http := strings.Index(s, "http://")
	switch {
	case https < 0:
		return http
	case http < 0:
		return https
	case http < https:
		return http
	default:
		return https
	}
}

// redactOne reduces a single URL to scheme, host, and a note that the rest was
// removed.
func redactOne(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		// URL-shaped but unparseable: remove the whole thing rather than leave
		// a token in a string nobody looked at closely.
		return "[address removed]"
	}
	clean := u.Scheme + "://" + u.Host
	if u.Path != "" && u.Path != "/" {
		clean += "/[redacted]"
	}
	if u.RawQuery != "" {
		clean += "?[redacted]"
	}
	return clean
}

// isURLTerminator reports the characters that end a URL inside a sentence.
func isURLTerminator(c byte) bool {
	return c == ' ' || c == '"' || c == '\'' || c == '\n' || c == '\t' || c == ','
}

// scrub removes a URL from an error before it is stored or logged.
func scrub(err error) error {
	if err == nil {
		return nil
	}
	return errors.New(redactURL(err.Error()))
}
