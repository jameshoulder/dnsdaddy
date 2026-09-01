package apiprovider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/version"
)

// MaxResponseBytes bounds what any provider may return.
//
// A provider is a third party. Without a cap, a service returning a
// multi-gigabyte body — through malice, a bug, or a captive portal serving an
// HTML error page from a CDN — would be an out-of-memory kill on a 1 GB VPS,
// delivered through the feature the operator switched on for safety.
//
// One megabyte is generous for a reputation answer and small enough that
// several providers failing this way at once still cannot exhaust the box.
const MaxResponseBytes = 1 << 20

// sharedTransport is one connection pool for every provider.
//
// One transport rather than one per provider: N providers must not mean N
// connection pools, N idle-connection budgets and N DNS caches on a machine
// with a gigabyte of memory. Bounded idle connections keep the footprint flat
// whether an operator has configured one provider or ten.
var sharedTransport = sync.OnceValue(func() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}
})

// Client is one provider's view of the outside world: the shared transport,
// wrapped in that provider's timeout, rate limiter and circuit breaker.
//
// Adapters are handed one of these and never construct an http.Client of their
// own. That is the whole enforcement mechanism for "no adapter can dial
// without a timeout, a limit and a breaker" — there is nothing else for them
// to call.
type Client struct {
	providerID string
	timeout    time.Duration
	limiter    *Limiter
	breaker    *Breaker
	http       *http.Client

	// Counters, read by the dashboard and the metrics endpoint.
	calls    atomic.Uint64
	failures atomic.Uint64
	totalNS  atomic.Uint64
	lastErr  atomic.Pointer[string]
	lastCall atomic.Int64 // unix milli
}

// ClientOptions configures a Client.
type ClientOptions struct {
	ProviderID    string
	Timeout       time.Duration
	RatePerMinute int
	Breaker       BreakerOptions
	// Transport overrides the shared one. For tests only.
	Transport http.RoundTripper
}

// NewClient builds a client for one provider.
func NewClient(o ClientOptions) *Client {
	if o.Timeout <= 0 {
		o.Timeout = 2 * time.Second
	}
	rt := o.Transport
	if rt == nil {
		rt = sharedTransport()
	}
	return &Client{
		providerID: o.ProviderID,
		timeout:    o.Timeout,
		limiter:    NewLimiter(o.RatePerMinute),
		breaker:    NewBreaker(o.Breaker),
		// No Timeout on the http.Client: the per-call context deadline set in
		// Do is the authority, and two competing deadlines produce errors that
		// name the wrong one.
		http: &http.Client{
			Transport: rt,
			// Providers are configured by URL. A redirect to somewhere else is
			// not something to follow silently — an operator who entered an
			// endpoint should have their credential sent there and nowhere
			// else.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Breaker exposes the breaker so the engine and the dashboard can read its
// state, and so a "test connection" can reset it.
func (c *Client) Breaker() *Breaker { return c.breaker }

// Limiter exposes the rate limiter, so an edit can change the rate in place.
func (c *Client) Limiter() *Limiter { return c.limiter }

// Response is a bounded, already-read provider answer.
//
// The body is read and closed inside Do rather than handed back open. An
// adapter holding an open body is an adapter that can leak a connection, and
// the limit is only a limit if nothing can read past it.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
	// Truncated is true when the provider sent more than MaxResponseBytes.
	// Surfaced rather than hidden: a truncated body that fails to parse should
	// say why.
	Truncated bool
}

// DecodeJSON unmarshals the body into v.
//
// Deliberately not a streaming decode: the body is already bounded and in
// memory, and a decoder over a network reader is how a slow provider holds a
// worker past its timeout.
func (r *Response) DecodeJSON(v any) error {
	if r.Truncated {
		return fmt.Errorf("%w: response exceeded %d bytes", ErrBadResponse, MaxResponseBytes)
	}
	if err := json.Unmarshal(r.Body, v); err != nil {
		// The provider's body is not included. It is untrusted input that
		// would end up in a log line and, for a misconfigured provider, may
		// be an error page containing the credential it was sent.
		return fmt.Errorf("%w: %v", ErrBadResponse, err)
	}
	return nil
}

// Excerpt returns a bounded, printable slice of the body for storing as
// evidence beside a verdict.
func (r *Response) Excerpt(limit int) string {
	if limit <= 0 || limit > 4096 {
		limit = 4096
	}
	b := r.Body
	if len(b) > limit {
		b = b[:limit]
	}
	return strings.ToValidUTF8(string(b), "")
}

// Do performs a request through the limiter, breaker, timeout and retry.
//
// The single choke point every adapter goes through. Everything that must be
// true of a provider call — that it is rate limited, that a failing provider
// stops being dialled, that it cannot run past its budget, that its body is
// bounded — is true because it is true here, rather than because ten adapters
// each remembered.
func (c *Client) Do(ctx context.Context, req *http.Request) (*Response, error) {
	if !c.breaker.Allow() {
		c.failures.Add(1)
		return nil, ErrCircuitOpen
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	if err := c.limiter.Wait(ctx); err != nil {
		// The provider was never called, so this is neither a success nor a
		// failure of it: Cancel releases the half-open probe slot without
		// recording either. Counting it as a failure would trip the breaker
		// because the operator set the rate too low, turning the mechanism
		// that prevents outages into one that causes them.
		c.breaker.Cancel()
		return nil, fmt.Errorf("rate limiter: %w", err)
	}

	started := time.Now()
	resp, err := c.attempt(ctx, req)
	c.calls.Add(1)
	c.totalNS.Add(uint64(time.Since(started)))
	c.lastCall.Store(time.Now().UnixMilli())

	if err != nil {
		c.failures.Add(1)
		c.breaker.Failure()
		c.recordErr(err)
		return nil, err
	}
	c.breaker.Success()
	return resp, nil
}

// attempt runs the request, retrying once on a transport error or a 5xx.
func (c *Client) attempt(ctx context.Context, req *http.Request) (*Response, error) {
	const maxAttempts = 2

	var lastErr error
	for i := 0; i < maxAttempts; i++ {
		if i > 0 {
			// Jittered, so a restart does not synchronise every provider's
			// retry into one burst at the same instant.
			delay := backoff(i)
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
		}

		resp, retryable, err := c.once(ctx, req)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if !retryable {
			return nil, err
		}
	}
	return nil, lastErr
}

// once performs a single request and classifies the outcome.
func (c *Client) once(ctx context.Context, req *http.Request) (*Response, bool, error) {
	r := req.Clone(ctx)
	if r.Header.Get("User-Agent") == "" {
		r.Header.Set("User-Agent", "dnsdaddy/"+version.String())
	}
	// A request body has to be re-readable for the retry. GetBody is what
	// http.NewRequest sets for the body types it understands; an adapter that
	// builds one another way gets one attempt, which is correct — replaying a
	// body we cannot rewind would send a truncated request.
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, false, fmt.Errorf("rewind request body: %w", err)
		}
		r.Body = body
	}

	resp, err := c.http.Do(r)
	if err != nil {
		// Transport errors are worth one retry: a connection reset on a reused
		// idle connection is the common case and succeeds immediately.
		// A context error is not — the budget is gone.
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		return nil, true, err
	}
	defer resp.Body.Close()

	body, truncated, readErr := readBounded(resp.Body)
	if readErr != nil {
		return nil, true, fmt.Errorf("read provider response: %w", readErr)
	}
	// Drain what is left so the connection can be reused rather than dropped.
	// Bounded, because draining an unbounded body is the same denial of
	// service the limit reader just prevented.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))

	out := &Response{
		Status:    resp.StatusCode,
		Header:    resp.Header,
		Body:      body,
		Truncated: truncated,
	}

	switch {
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
		// Never retried: the credential will be exactly as wrong next time,
		// and a second attempt on a metered API is a second billed call.
		return nil, false, ErrUnauthorised
	case resp.StatusCode == http.StatusTooManyRequests:
		// Never retried: retrying a rate limit is what makes it worse.
		return nil, false, ErrRateLimited
	case resp.StatusCode >= 500:
		return nil, true, fmt.Errorf("provider returned %d", resp.StatusCode)
	case resp.StatusCode >= 400:
		return nil, false, fmt.Errorf("provider returned %d", resp.StatusCode)
	}
	return out, false, nil
}

// readBounded reads at most MaxResponseBytes, reporting whether there was more.
//
// A function rather than three lines inline, because the property that matters
// is not what comes back — it is that nothing beyond the cap is ever read into
// memory. Reading a body in full and then slicing it produces an identical
// return value and none of the protection, which is exactly the mistake the
// first version of this code's test could not tell apart. Pulled out so a test
// can hand it a reader that counts what was consumed.
func readBounded(r io.Reader) (body []byte, truncated bool, err error) {
	// One byte past the cap: enough to know more was coming, and never more
	// than that.
	body, err = io.ReadAll(io.LimitReader(r, MaxResponseBytes+1))
	if err != nil {
		return nil, false, err
	}
	if len(body) > MaxResponseBytes {
		return body[:MaxResponseBytes], true, nil
	}
	return body, false, nil
}

// backoff returns a jittered delay for attempt n (1-based).
func backoff(n int) time.Duration {
	base := time.Duration(n) * 200 * time.Millisecond
	// Full jitter: uniform in [0, base). Cheaper than it looks and the only
	// form that actually de-synchronises callers, rather than merely blurring
	// them around a common centre.
	//nolint:gosec // not a security decision; a predictable retry delay leaks nothing
	return time.Duration(rand.Int63n(int64(base) + 1))
}

func (c *Client) recordErr(err error) {
	if err == nil {
		return
	}
	// Stored as a string rather than the error, so nothing downstream can
	// unwrap it and reach a request that may carry the credential.
	msg := err.Error()
	c.lastErr.Store(&msg)
}

// Stats is what the dashboard and metrics report about a provider's calls.
type Stats struct {
	Calls         uint64        `json:"calls"`
	Failures      uint64        `json:"failures"`
	MeanLatency   time.Duration `json:"-"`
	MeanLatencyMS int64         `json:"meanLatencyMs"`
	ErrorRate     float64       `json:"errorRate"`
	LastError     string        `json:"lastError,omitempty"`
	LastCallAt    *time.Time    `json:"lastCallAt,omitempty"`
	Breaker       BreakerState  `json:"breaker"`
	BreakerTrips  uint64        `json:"breakerTrips"`
	RateWaits     uint64        `json:"rateWaits"`
}

// Stats snapshots the counters.
func (c *Client) Stats() Stats {
	calls := c.calls.Load()
	failures := c.failures.Load()
	trips, _, _ := c.breaker.Stats()

	s := Stats{
		Calls:        calls,
		Failures:     failures,
		Breaker:      c.breaker.State(),
		BreakerTrips: trips,
		RateWaits:    c.limiter.Waited(),
	}
	if calls > 0 {
		s.MeanLatency = time.Duration(c.totalNS.Load() / calls)
		s.MeanLatencyMS = s.MeanLatency.Milliseconds()
		s.ErrorRate = float64(failures) / float64(calls)
	}
	if p := c.lastErr.Load(); p != nil {
		s.LastError = *p
	}
	if ms := c.lastCall.Load(); ms > 0 {
		t := time.UnixMilli(ms).UTC()
		s.LastCallAt = &t
	}
	return s
}
