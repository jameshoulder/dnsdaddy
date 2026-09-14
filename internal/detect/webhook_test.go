package detect

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testFinding() Finding {
	return Finding{
		SchemaVersion: SchemaVersion,
		ID:            "fnd_0123456789ab",
		Time:          time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC),
		EventType:     "dns_tunnelling",
		Severity:      SeverityHigh,
		Title:         "Possible DNS tunnelling",
		Summary:       "A client sent long encoded names to one domain.",
		Client:        Client{IP: "192.0.2.10", Name: "workstation-14"},
		Domain:        "tunnel.example",
	}
}

// sinkTo builds a sink pointed at a test server, bypassing the address rules
// so that delivery behaviour can be tested without a public endpoint.
//
// The rules themselves are tested separately and thoroughly — see
// TestTheAddressRulesRefuseEverythingThatIsNotTheInternet and the netguard
// package. Wiring a real httptest server through them is impossible by
// construction: httptest listens on 127.0.0.1, which is precisely what
// PublicOnly exists to refuse.
func sinkTo(t *testing.T, srv *httptest.Server, o WebhookOptions) *WebhookSink {
	t.Helper()
	o.URL = "https://notifications.example/hook"
	if o.Log == nil {
		o.Log = quietLogger()
	}
	s, err := NewWebhookSink(o)
	if err != nil {
		t.Fatalf("NewWebhookSink: %v", err)
	}
	// Point it at the test server, and use that server's own client so the
	// loopback address rule does not refuse it.
	s.url = srv.URL
	s.client.Transport = srv.Client().Transport
	return s
}

// drain runs the sink until it has settled, then stops it.
func drain(t *testing.T, s *WebhookSink, until func() bool) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if until() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	s.Wait()
}

// TestNoAddressMeansNoSinkAndNoDials.
//
// Off is the default and the normal state, especially on a small machine. An
// empty address must produce no sink at all rather than one that quietly does
// nothing — a sink that exists holds a queue, a goroutine and a connection
// pool for a feature nobody turned on.
func TestNoAddressMeansNoSinkAndNoDials(t *testing.T) {
	for _, raw := range []string{"", "   ", "\t\n"} {
		s, err := NewWebhookSink(WebhookOptions{URL: raw, Log: quietLogger()})
		if err != nil {
			t.Errorf("an empty address was an error: %v", err)
		}
		if s != nil {
			t.Errorf("an empty address built a sink: %+v", s)
		}
		// And every method is safe on the nil the caller now holds.
		if err := s.Emit(context.Background(), testFinding()); err != nil {
			t.Errorf("Emit on a nil sink: %v", err)
		}
		s.Run(context.Background())
		s.Wait()
		if st := s.Stats(); st.Configured {
			t.Error("a nil sink reports itself as configured")
		}
		if s.RedactedURL() != "" {
			t.Error("a nil sink has a URL")
		}
	}
}

// TestTheEndpointReceivesTheSameJSONTheFileGets.
//
// The body is the existing finding document, not a shape invented for this
// feature. Anything that consumes the NDJSON file can consume this, and a
// second format would be a second thing to version and keep in step.
func TestTheEndpointReceivesTheSameJSONTheFileGets(t *testing.T) {
	var (
		mu       sync.Mutex
		body     []byte
		headers  http.Header
		method   string
		received int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		body, headers, method = b, r.Header.Clone(), r.Method
		received++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := sinkTo(t, srv, WebhookOptions{HeaderName: "X-Token", HeaderValue: "s3cret"})
	f := testFinding()
	if err := s.Emit(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	drain(t, s, func() bool { return s.Stats().Sent > 0 })

	mu.Lock()
	defer mu.Unlock()
	if received != 1 {
		t.Fatalf("the endpoint received %d requests, want 1", received)
	}
	if method != http.MethodPost {
		t.Errorf("method = %s, want POST", method)
	}
	if got := headers.Get("Content-Type"); got != "application/json" {
		t.Errorf("content type = %q", got)
	}
	if got := headers.Get("X-Token"); got != "s3cret" {
		t.Errorf("the secret header was not sent: %q", got)
	}

	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("the body is not JSON: %v", err)
	}
	if decoded["schemaVersion"] != SchemaVersion {
		t.Errorf("schemaVersion = %v, want %q", decoded["schemaVersion"], SchemaVersion)
	}
	if decoded["id"] != f.ID {
		t.Errorf("id = %v, want %q — without it a consumer cannot de-duplicate", decoded["id"], f.ID)
	}
	if decoded["eventType"] != f.EventType {
		t.Errorf("eventType = %v", decoded["eventType"])
	}

	// Byte-identical to what the NDJSON sink writes, which is the property
	// that makes "the same shape" true rather than approximately true.
	fileBytes, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != string(fileBytes) {
		t.Errorf("the webhook body differs from the file's line:\nwebhook: %s\nfile:    %s",
			body, fileBytes)
	}
}

// TestAFullQueueDropsAndCounts, rather than blocking whatever is emitting.
//
// The queue is the whole protection. Detection runs on one goroutine that also
// evaluates windows and sweeps state; blocking it on an HTTP request to an
// endpoint that has gone away would stop findings being produced at all, and
// the queue behind it would grow without limit.
func TestAFullQueueDropsAndCounts(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	defer close(release)

	s := sinkTo(t, srv, WebhookOptions{QueueSize: 2})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	// Far more than the queue holds, while the endpoint is not answering.
	start := time.Now()
	for i := 0; i < 200; i++ {
		if err := s.Emit(ctx, testFinding()); err != nil {
			t.Fatalf("Emit returned an error: %v", err)
		}
	}
	elapsed := time.Since(start)

	// The point is that it did not wait for an endpoint that is not answering.
	if elapsed > time.Second {
		t.Errorf("200 emits took %s against a hung endpoint; they should not wait at all", elapsed)
	}
	st := s.Stats()
	if st.Dropped[WebhookDropFull] == 0 {
		t.Error("nothing was counted as dropped from a full queue")
	}
	if st.Enqueued+st.Dropped[WebhookDropFull] < 200 {
		t.Errorf("%d enqueued + %d dropped is fewer than the 200 offered",
			st.Enqueued, st.Dropped[WebhookDropFull])
	}
}

// TestAServerErrorIsRetriedAndThenSucceeds.
func TestAServerErrorIsRetriedAndThenSucceeds(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := sinkTo(t, srv, WebhookOptions{MaxAttempts: 3})
	if err := s.Emit(context.Background(), testFinding()); err != nil {
		t.Fatal(err)
	}
	drain(t, s, func() bool { return s.Stats().Sent > 0 })

	if got := calls.Load(); got != 2 {
		t.Errorf("the endpoint was called %d times, want 2 (one failure, one success)", got)
	}
	st := s.Stats()
	if st.Sent != 1 {
		t.Errorf("sent = %d, want 1", st.Sent)
	}
	if st.LastSendAt.IsZero() {
		t.Error("a successful send did not record when it happened")
	}
	for reason, n := range st.Dropped {
		if n != 0 {
			t.Errorf("a finding that was delivered was also counted as dropped (%s: %d)", reason, n)
		}
	}
}

// TestTooManyRequestsIsRetried, because a rate limit is temporary by
// definition and the endpoint has told us to come back.
func TestTooManyRequestsIsRetried(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	s := sinkTo(t, srv, WebhookOptions{MaxAttempts: 3})
	_ = s.Emit(context.Background(), testFinding())
	drain(t, s, func() bool { return s.Stats().Sent > 0 })

	if got := calls.Load(); got != 2 {
		t.Errorf("a 429 produced %d calls, want 2", got)
	}
}

// TestAClientErrorIsNotRetried.
//
// A 400 or a 404 means the request is wrong, and it will be exactly as wrong
// next time. Retrying a permanent refusal is how one operator's typo becomes
// sustained load on somebody else's server.
func TestAClientErrorIsNotRetried(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized,
		http.StatusForbidden, http.StatusNotFound, http.StatusGone} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(status)
			}))
			defer srv.Close()

			s := sinkTo(t, srv, WebhookOptions{MaxAttempts: 5})
			_ = s.Emit(context.Background(), testFinding())
			drain(t, s, func() bool { return s.Stats().Dropped[WebhookDropRejected] > 0 })

			if got := calls.Load(); got != 1 {
				t.Errorf("%d produced %d attempts, want exactly 1", status, got)
			}
			if s.Stats().Dropped[WebhookDropRejected] != 1 {
				t.Errorf("a permanent rejection was not counted: %+v", s.Stats().Dropped)
			}
		})
	}
}

// TestARedirectIsNotFollowed.
//
// A redirect is the standard way to turn a destination that passed the address
// check into one that would not have. The URL is checked; the redirect target
// is whatever the endpoint says.
func TestARedirectIsNotFollowed(t *testing.T) {
	var reached atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/followed" {
			reached.Store(true)
			w.WriteHeader(http.StatusOK)
			return
		}
		// Straight at link-local: the metadata service.
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer srv.Close()

	s := sinkTo(t, srv, WebhookOptions{MaxAttempts: 2})
	_ = s.Emit(context.Background(), testFinding())
	drain(t, s, func() bool { return s.Stats().Dropped[WebhookDropRejected] > 0 })

	if reached.Load() {
		t.Error("a redirect was followed")
	}
	if s.Stats().Sent != 0 {
		t.Error("a redirect was counted as a successful send")
	}
	if !strings.Contains(s.Stats().LastError, "redirect") {
		t.Errorf("the failure does not say it was a redirect: %q", s.Stats().LastError)
	}
}

// TestATimeoutIsCountedAndRetried.
func TestATimeoutIsCountedAndRetried(t *testing.T) {
	release := make(chan struct{})
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		<-release
	}))
	defer srv.Close()
	defer close(release)

	s := sinkTo(t, srv, WebhookOptions{MaxAttempts: 2, Timeout: 100 * time.Millisecond})
	// sinkTo swaps in the server's transport, so set the deadline on the
	// client itself.
	s.client.Timeout = 100 * time.Millisecond

	_ = s.Emit(context.Background(), testFinding())
	drain(t, s, func() bool { return s.Stats().Dropped[WebhookDropTimeout] > 0 })

	if s.Stats().Dropped[WebhookDropTimeout] == 0 {
		t.Errorf("a timeout was not counted: %+v", s.Stats().Dropped)
	}
	if got := calls.Load(); got < 2 {
		t.Errorf("a timeout produced %d attempts, want it retried", got)
	}
}

// TestTheAddressRulesRefuseEverythingThatIsNotTheInternet.
//
// The URL comes from whoever can edit the configuration. That is an operator
// of this dashboard, who is not necessarily an administrator of the host —
// and a webhook pointed at the metadata service would turn the first into the
// second.
func TestTheAddressRulesRefuseEverythingThatIsNotTheInternet(t *testing.T) {
	for _, tc := range []struct{ url, because string }{
		{"https://169.254.169.254/", "link-local"},
		{"https://[::ffff:169.254.169.254]/", "link-local"},
		{"https://[fd00:ec2::254]/", "metadata"},
		{"https://127.0.0.1/hook", "this machine"},
		{"https://127.0.0.1:8443/hook", "this machine"},
		{"https://[::1]/hook", "this machine"},
		{"https://10.0.0.1/hook", "private network"},
		{"https://192.168.1.10/hook", "private network"},
		{"https://172.16.0.1/hook", "private network"},
		{"https://[fd00::1]/hook", "unique-local"},
		{"https://0.0.0.0/hook", "not a destination"},
		{"http://example.com/hook", "https://"},
		{"ftp://example.com/hook", "https://"},
		{"https:///hook", "no host"},
	} {
		t.Run(tc.url, func(t *testing.T) {
			err := ValidateWebhookURL(tc.url)
			if err == nil {
				t.Fatalf("%s was accepted", tc.url)
			}
			if !strings.Contains(err.Error(), tc.because) {
				t.Errorf("refused with %q, which does not say %q", err, tc.because)
			}
			// And it refuses to build, rather than building something that
			// fails later.
			s, buildErr := NewWebhookSink(WebhookOptions{URL: tc.url, Log: quietLogger()})
			if buildErr == nil {
				t.Error("the sink was built anyway")
			}
			if s != nil {
				t.Error("a sink was returned alongside the error")
			}
		})
	}

	// A real endpoint is accepted, so this is a filter rather than a wall.
	for _, ok := range []string{
		"https://hooks.slack.com/services/T000/B000/XXXX",
		"https://example.webhook.office.com/webhookb2/abc",
		"https://1.1.1.1/hook",
	} {
		if err := ValidateWebhookURL(ok); err != nil {
			t.Errorf("%s was refused: %v", ok, err)
		}
	}
}

// TestAHostnameThatResolvesSomewhereRefusedIsCaughtAtDialTime.
//
// The literal check cannot see this: the URL is a name, and the name is
// resolved when the connection is made. localhost is the case somebody reaches
// for first, and it has to be caught after resolution rather than by a list of
// suspicious-looking names.
func TestAHostnameThatResolvesSomewhereRefusedIsCaughtAtDialTime(t *testing.T) {
	// The address is a hostname, so validation passes.
	if err := ValidateWebhookURL("https://localhost/hook"); err != nil {
		t.Fatalf("a hostname was refused before resolution: %v", err)
	}
	s, err := NewWebhookSink(WebhookOptions{
		URL: "https://localhost/hook", MaxAttempts: 1,
		Timeout: 2 * time.Second, Log: quietLogger(),
	})
	if err != nil {
		t.Fatalf("NewWebhookSink: %v", err)
	}

	_ = s.Emit(context.Background(), testFinding())
	drain(t, s, func() bool { return s.Stats().Dropped[WebhookDropSSRF] > 0 })

	if s.Stats().Dropped[WebhookDropSSRF] == 0 {
		t.Errorf("a name resolving to this machine was not refused at dial time: %+v",
			s.Stats().Dropped)
	}
	if s.Stats().Sent != 0 {
		t.Error("a refused address was counted as sent")
	}
}

// TestASecretNeverAppearsInWhatAnOperatorReads.
//
// A Slack webhook URL is a bearer token in path form. It ends up in an error
// string, which ends up in the log, in the diagnostics response, and in a
// doctor report somebody pastes into a ticket.
func TestASecretNeverAppearsInWhatAnOperatorReads(t *testing.T) {
	const secretPath = "/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"

	var logged strings.Builder
	logger := slog.New(slog.NewTextHandler(&logged, nil))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	s := sinkTo(t, srv, WebhookOptions{
		MaxAttempts: 1, Log: logger,
		HeaderName: "X-Token", HeaderValue: "super-secret-value",
	})
	s.url = srv.URL + secretPath

	_ = s.Emit(context.Background(), testFinding())
	drain(t, s, func() bool { return s.Stats().Dropped[WebhookDropRejected] > 0 })

	for name, text := range map[string]string{
		"the log":           logged.String(),
		"the last error":    s.Stats().LastError,
		"the displayed URL": s.RedactedURL(),
	} {
		if strings.Contains(text, "XXXXXXXXXXXXXXXXXXXXXXXX") {
			t.Errorf("%s contains the webhook token: %s", name, text)
		}
		if strings.Contains(text, "super-secret-value") {
			t.Errorf("%s contains the secret header value: %s", name, text)
		}
		if strings.Contains(text, secretPath) {
			t.Errorf("%s contains the secret path: %s", name, text)
		}
	}
	// The host is kept, because "which endpoint" is the useful half.
	if !strings.Contains(s.RedactedURL(), "127.0.0.1") {
		t.Errorf("the displayed URL does not say where it points: %q", s.RedactedURL())
	}
	if !strings.Contains(s.RedactedURL(), "[redacted]") {
		t.Errorf("the displayed URL does not show that something was removed: %q", s.RedactedURL())
	}
}

// TestRedactionHandlesTheShapesAnErrorStringPutsAURLIn.
func TestRedactionHandlesTheShapesAnErrorStringPutsAURLIn(t *testing.T) {
	for _, tc := range []struct{ in, wantAbsent, wantPresent string }{
		{"https://hooks.slack.com/services/T0/B0/SECRET", "SECRET", "hooks.slack.com"},
		{`Post "https://hooks.slack.com/services/T0/B0/SECRET": timeout`, "SECRET", "timeout"},
		{"https://example.com/hook?token=SECRET", "SECRET", "example.com"},
		{"two: https://a.example/SECRET and https://b.example/ALSO", "SECRET", "b.example"},
		{"no url here at all", "", "no url here at all"},
	} {
		got := redactURL(tc.in)
		if tc.wantAbsent != "" && strings.Contains(got, tc.wantAbsent) {
			t.Errorf("redactURL(%q) = %q, still contains %q", tc.in, got, tc.wantAbsent)
		}
		if !strings.Contains(got, tc.wantPresent) {
			t.Errorf("redactURL(%q) = %q, lost %q", tc.in, got, tc.wantPresent)
		}
	}
	// Both URLs in a two-URL string are redacted, not just the first.
	if got := redactURL("https://a.example/SECRET1 https://b.example/SECRET2"); strings.Contains(got, "SECRET2") {
		t.Errorf("the second URL was not redacted: %q", got)
	}
}

// TestTheSinkIsSafeUnderConcurrentProducersAndAFullQueue. Run with -race.
func TestTheSinkIsSafeUnderConcurrentProducersAndAFullQueue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := sinkTo(t, srv, WebhookOptions{QueueSize: 4})
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				_ = s.Emit(ctx, testFinding())
				_ = s.Stats()
			}
		}()
	}
	wg.Wait()
	cancel()
	s.Wait()

	st := s.Stats()
	if st.Enqueued+st.Dropped[WebhookDropFull] < 800 {
		t.Errorf("%d enqueued + %d dropped is fewer than the 800 offered",
			st.Enqueued, st.Dropped[WebhookDropFull])
	}
}

// TestEveryDropReasonHasASeriesBeforeItHappens, so an operator can alert on a
// counter that exists rather than one that appears the first time something
// goes wrong.
func TestEveryDropReasonHasASeriesBeforeItHappens(t *testing.T) {
	for _, st := range []WebhookStats{(*WebhookSink)(nil).Stats(), {Dropped: map[string]uint64{}}} {
		_ = st
	}
	fresh := (*WebhookSink)(nil).Stats()
	for _, reason := range WebhookDropReasons() {
		if _, ok := fresh.Dropped[reason]; !ok {
			t.Errorf("no series for the %q reason", reason)
		}
	}
	if len(fresh.Dropped) != len(WebhookDropReasons()) {
		t.Errorf("%d reasons reported, want exactly the %d declared",
			len(fresh.Dropped), len(WebhookDropReasons()))
	}
}

// TestDetectionKeepsWorkingWhileTheEndpointIsDown.
//
// The property the whole queue exists for, at the layer that matters: findings
// go on being produced and stored while the notification endpoint hangs.
//
// The engine runs detectors, evaluates windows and sweeps state on one
// goroutine, and MultiSink calls every sink on it in turn. A webhook that did
// its HTTP work there would stop that goroutine for the length of a timeout
// times the retry count — per finding — and the observation queue behind it
// would fill and start dropping. That is detection stopping because a chat
// tool is down.
func TestDetectionKeepsWorkingWhileTheEndpointIsDown(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	defer close(release)

	hook := sinkTo(t, srv, WebhookOptions{QueueSize: 1})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go hook.Run(ctx)

	// A recording sink standing in for the database, ahead of the webhook in
	// the same order the daemon builds them.
	var stored atomic.Int32
	sinks := MultiSink{
		sinkFunc(func(context.Context, Finding) error { stored.Add(1); return nil }),
		hook,
	}

	start := time.Now()
	for range 500 {
		if err := sinks.Emit(ctx, testFinding()); err != nil {
			t.Fatalf("the fan-out returned an error while the endpoint was down: %v", err)
		}
	}
	elapsed := time.Since(start)

	if got := stored.Load(); got != 500 {
		t.Errorf("%d findings were stored, want 500 — the record must not depend "+
			"on the notification", got)
	}
	if elapsed > 2*time.Second {
		t.Errorf("500 findings took %s while the endpoint hung; the fan-out waited "+
			"on it", elapsed)
	}
	if hook.Stats().Dropped[WebhookDropFull] == 0 {
		t.Error("nothing was dropped, so the endpoint was not actually blocked and " +
			"this test proves nothing")
	}
}

// sinkFunc adapts a function to Sink.
type sinkFunc func(context.Context, Finding) error

func (f sinkFunc) Emit(ctx context.Context, fi Finding) error { return f(ctx, fi) }

// TestAFailingWebhookDoesNotChangeWhatIsStored.
//
// Byte-for-byte: the findings written when no address is configured and when
// one is configured but broken must be identical. A notification path that
// altered the record would be the worst possible version of this feature.
func TestAFailingWebhookDoesNotChangeWhatIsStored(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	collect := func(withHook bool) []string {
		var mu sync.Mutex
		var lines []string
		record := sinkFunc(func(_ context.Context, f Finding) error {
			b, err := json.Marshal(f)
			if err != nil {
				t.Error(err)
				return err
			}
			mu.Lock()
			lines = append(lines, string(b))
			mu.Unlock()
			return nil
		})
		sinks := MultiSink{record}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if withHook {
			hook := sinkTo(t, srv, WebhookOptions{MaxAttempts: 2})
			go hook.Run(ctx)
			sinks = append(sinks, hook)
		}
		for i := range 5 {
			f := testFinding()
			f.ID = fmt.Sprintf("fnd_%012d", i)
			if err := sinks.Emit(ctx, f); err != nil {
				t.Fatalf("Emit: %v", err)
			}
		}
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), lines...)
	}

	without := collect(false)
	with := collect(true)

	if len(without) != len(with) {
		t.Fatalf("%d findings stored without a notification address, %d with one",
			len(without), len(with))
	}
	for i := range without {
		if without[i] != with[i] {
			t.Errorf("finding %d differs when a notification address is configured:\n"+
				"without: %s\nwith:    %s", i, without[i], with[i])
		}
	}
}
