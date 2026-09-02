package apiprovider

import (
	"context"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// clock is a hand-driven time source, so breaker and limiter tests assert on
// behaviour rather than on how long a sleep took. A test that waits out a
// 30-second cooldown is a test nobody runs.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Unix(1700000000, 0)} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// ---------------------------------------------------------------------------
// Circuit breaker
// ---------------------------------------------------------------------------

func TestBreakerOpensAfterThresholdAndShortCircuits(t *testing.T) {
	clk := newClock()
	b := NewBreaker(BreakerOptions{Threshold: 3, Cooldown: 30 * time.Second, Now: clk.Now})

	// Below the threshold the breaker stays closed: one bad response is not an
	// outage, and a breaker that opens on the first error is a breaker that
	// spends its life open.
	for i := 0; i < 2; i++ {
		if !b.Allow() {
			t.Fatalf("breaker refused call %d before the threshold", i)
		}
		b.Failure()
	}
	if got := b.State(); got != BreakerClosed {
		t.Errorf("state after 2 of 3 failures is %s, want closed", got)
	}

	if !b.Allow() {
		t.Fatal("breaker refused the call that should trip it")
	}
	b.Failure()

	if got := b.State(); got != BreakerOpen {
		t.Fatalf("state after the threshold is %s, want open", got)
	}
	// And now calls cost nothing: this is the whole point.
	for i := 0; i < 10; i++ {
		if b.Allow() {
			t.Fatalf("an open breaker admitted call %d", i)
		}
	}
	trips, shorts, _ := b.Stats()
	if trips != 1 {
		t.Errorf("trips = %d, want 1", trips)
	}
	if shorts != 10 {
		t.Errorf("short circuits = %d, want 10", shorts)
	}
}

func TestBreakerAdmitsOneProbeAfterCooldown(t *testing.T) {
	clk := newClock()
	b := NewBreaker(BreakerOptions{Threshold: 1, Cooldown: 30 * time.Second, Now: clk.Now})

	b.Allow()
	b.Failure()
	if b.Allow() {
		t.Fatal("a call was admitted before the cooldown elapsed")
	}

	clk.Advance(30 * time.Second)

	if !b.Allow() {
		t.Fatal("no probe was admitted after the cooldown")
	}
	// Exactly one. A recovering provider must not be hit by everything that
	// queued up while it was down.
	if b.Allow() {
		t.Error("a second probe was admitted while the first was in flight")
	}
}

func TestASuccessfulProbeClosesTheBreaker(t *testing.T) {
	clk := newClock()
	b := NewBreaker(BreakerOptions{Threshold: 1, Cooldown: time.Second, Now: clk.Now})

	b.Allow()
	b.Failure()
	clk.Advance(time.Second)

	if !b.Allow() {
		t.Fatal("no probe admitted")
	}
	b.Success()

	if got := b.State(); got != BreakerClosed {
		t.Errorf("state after a successful probe is %s, want closed", got)
	}
	if !b.Allow() {
		t.Error("a closed breaker refused a call")
	}
}

func TestAFailedProbeReopensImmediately(t *testing.T) {
	clk := newClock()
	b := NewBreaker(BreakerOptions{Threshold: 5, Cooldown: time.Second, Now: clk.Now})

	// Trip it.
	for i := 0; i < 5; i++ {
		b.Allow()
		b.Failure()
	}
	clk.Advance(time.Second)

	if !b.Allow() {
		t.Fatal("no probe admitted after the cooldown")
	}
	b.Failure()

	// Back to open, and the cooldown restarted — not five more failures
	// needed. The provider has already demonstrated it is down.
	if got := b.State(); got != BreakerOpen {
		t.Errorf("state after a failed probe is %s, want open", got)
	}
	if b.Allow() {
		t.Error("a call was admitted immediately after a failed probe")
	}
}

// State is read by a metrics scrape every fifteen seconds. If reading it
// consumed the probe slot, the next real call would be short-circuited and the
// breaker would never close.
func TestReadingStateDoesNotConsumeTheProbe(t *testing.T) {
	clk := newClock()
	b := NewBreaker(BreakerOptions{Threshold: 1, Cooldown: time.Second, Now: clk.Now})
	b.Allow()
	b.Failure()
	clk.Advance(time.Second)

	for i := 0; i < 5; i++ {
		if got := b.State(); got != BreakerHalfOpen {
			t.Fatalf("State() = %s on read %d, want half-open", got, i)
		}
	}
	// The probe is still there for a real caller.
	if !b.Allow() {
		t.Error("reading the state consumed the probe slot")
	}
}

// Cancel is the third outcome after Allow. Without it, a call that never
// reached the provider would either count as a failure — tripping the breaker
// because the operator set the rate too low — or leave the probe slot held
// forever.
func TestCancelReleasesTheProbeWithoutCountingIt(t *testing.T) {
	clk := newClock()
	b := NewBreaker(BreakerOptions{Threshold: 2, Cooldown: time.Second, Now: clk.Now})

	// A cancel in the closed state records nothing.
	for i := 0; i < 10; i++ {
		b.Allow()
		b.Cancel()
	}
	if got := b.State(); got != BreakerClosed {
		t.Errorf("ten cancelled calls moved the breaker to %s", got)
	}

	// And in half-open it frees the slot for a real call.
	b.Allow()
	b.Failure()
	b.Allow()
	b.Failure() // open
	clk.Advance(time.Second)

	if !b.Allow() {
		t.Fatal("no probe admitted")
	}
	b.Cancel()
	if !b.Allow() {
		t.Error("a cancelled probe left the slot held")
	}
}

func TestBreakerResetClosesIt(t *testing.T) {
	clk := newClock()
	b := NewBreaker(BreakerOptions{Threshold: 1, Cooldown: time.Hour, Now: clk.Now})
	b.Allow()
	b.Failure()
	if b.Allow() {
		t.Fatal("open breaker admitted a call")
	}

	b.Reset()

	if got := b.State(); got != BreakerClosed {
		t.Errorf("state after reset is %s, want closed", got)
	}
	if !b.Allow() {
		t.Error("a reset breaker refused a call")
	}
}

func TestBreakerIsSafeUnderConcurrency(t *testing.T) {
	b := NewBreaker(BreakerOptions{Threshold: 3, Cooldown: time.Millisecond})
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if b.Allow() {
					if (n+j)%3 == 0 {
						b.Failure()
					} else {
						b.Success()
					}
				}
				_ = b.State()
				_, _, _ = b.Stats()
			}
		}(i)
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// Rate limiter
// ---------------------------------------------------------------------------

func TestLimiterAllowsTheBurstThenRefills(t *testing.T) {
	clk := newClock()
	// 60/minute = 1/second, so the bucket holds one token.
	l := newLimiterWithClock(60, clk.Now)

	if !l.Allow() {
		t.Fatal("the first call was refused with a full bucket")
	}
	if l.Allow() {
		t.Fatal("a second call was allowed with an empty bucket")
	}

	clk.Advance(time.Second)
	if !l.Allow() {
		t.Error("a token did not refill after a second")
	}
}

// The burst must not be a whole minute's worth: a restart with a full queue
// would otherwise fire sixty requests at a metered API in the same instant,
// which is exactly what rate limits exist to prevent.
func TestLimiterBurstIsOneSecondNotOneMinute(t *testing.T) {
	clk := newClock()
	l := newLimiterWithClock(600, clk.Now) // 10/second

	allowed := 0
	for i := 0; i < 600; i++ {
		if l.Allow() {
			allowed++
		}
	}
	if allowed > 11 {
		t.Errorf("a cold limiter allowed %d immediate calls at 600/min; the burst is a whole minute", allowed)
	}
	if allowed < 10 {
		t.Errorf("a cold limiter allowed only %d immediate calls at 600/min, want ~10", allowed)
	}
}

func TestLimiterWaitRespectsTheContextDeadline(t *testing.T) {
	// A real clock here: the point is that Wait returns when the caller's
	// budget expires, and that is a wall-clock property.
	l := NewLimiter(1) // 1/minute — the next token is a minute away
	if !l.Allow() {
		t.Fatal("the first call was refused")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := l.Wait(ctx)
	elapsed := time.Since(start)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Wait returned %v, want DeadlineExceeded", err)
	}
	if elapsed > time.Second {
		t.Errorf("Wait blocked for %s past its 30ms budget", elapsed)
	}
	if l.Waited() == 0 {
		t.Error("a call that waited was not counted")
	}
}

func TestLimiterRateCanBeChangedInPlace(t *testing.T) {
	clk := newClock()
	l := newLimiterWithClock(60, clk.Now)
	l.Allow() // drain

	l.SetRate(6000) // 100/second
	clk.Advance(time.Second)

	allowed := 0
	for i := 0; i < 200; i++ {
		if l.Allow() {
			allowed++
		}
	}
	if allowed < 50 {
		t.Errorf("after raising the rate only %d calls were allowed", allowed)
	}
	// Raising the rate must not also hand out a burst larger than the new
	// bucket.
	if allowed > 101 {
		t.Errorf("raising the rate handed out %d immediate calls", allowed)
	}
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

func testClient(t *testing.T, srv *httptest.Server, o ClientOptions) *Client {
	t.Helper()
	if o.Timeout == 0 {
		o.Timeout = time.Second
	}
	if o.RatePerMinute == 0 {
		o.RatePerMinute = 6000
	}
	o.Transport = srv.Client().Transport
	return NewClient(o)
}

// countingReader reports how much of an endless stream was actually consumed.
//
// The property under test is a memory bound, and a body that is read in full
// and then sliced returns exactly what a bounded read returns. Only the
// consumed count tells the two apart, which is why the first version of this
// test passed against an unbounded read.
type countingReader struct {
	consumed int64
	limit    int64 // fail the test rather than allocate forever
	t        *testing.T
}

func (c *countingReader) Read(p []byte) (int, error) {
	if c.consumed > c.limit {
		c.t.Fatalf("read %d bytes, far past the %d-byte cap: the body is not bounded",
			c.consumed, MaxResponseBytes)
	}
	for i := range p {
		p[i] = 'A'
	}
	c.consumed += int64(len(p))
	return len(p), nil
}

func TestReadBoundedStopsAtTheCap(t *testing.T) {
	r := &countingReader{limit: 8 * MaxResponseBytes, t: t}

	body, truncated, err := readBounded(r)
	if err != nil {
		t.Fatalf("readBounded: %v", err)
	}
	if len(body) != MaxResponseBytes {
		t.Errorf("returned %d bytes, want exactly the cap %d", len(body), MaxResponseBytes)
	}
	if !truncated {
		t.Error("an endless body was not reported as truncated")
	}
	// The actual guarantee: nothing far beyond the cap was ever in memory.
	// io.ReadAll's buffer growth means a little over is expected; multiples
	// are not.
	if r.consumed > 2*MaxResponseBytes {
		t.Errorf("consumed %d bytes for a %d-byte cap — the read is not bounded",
			r.consumed, MaxResponseBytes)
	}
}

func TestReadBoundedPassesThroughASmallBody(t *testing.T) {
	body, truncated, err := readBounded(strings.NewReader(`{"ok":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if truncated {
		t.Error("a short body was reported as truncated")
	}
	if string(body) != `{"ok":true}` {
		t.Errorf("body = %q", body)
	}
}

func TestClientBoundsTheResponseBody(t *testing.T) {
	// A provider returning far more than the cap. Without the limit reader
	// this is an out-of-memory kill on a small VPS, delivered through the
	// feature the operator switched on for safety.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		chunk := strings.Repeat("A", 64<<10)
		for i := 0; i < 64; i++ { // 4 MiB, four times the cap
			_, _ = w.Write([]byte(chunk))
		}
	}))
	defer srv.Close()

	c := testClient(t, srv, ClientOptions{ProviderID: "apr_1"})
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)

	resp, err := c.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	if len(resp.Body) > MaxResponseBytes {
		t.Errorf("read %d bytes, want at most %d", len(resp.Body), MaxResponseBytes)
	}
	if !resp.Truncated {
		t.Error("an over-sized response was not reported as truncated")
	}
	// And a truncated body must not be decoded as though it were complete.
	var v map[string]any
	if err := resp.DecodeJSON(&v); !errors.Is(err, ErrBadResponse) {
		t.Errorf("decoding a truncated body returned %v, want ErrBadResponse", err)
	}
}

func TestClientRetriesOnceOnServerError(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c := testClient(t, srv, ClientOptions{ProviderID: "apr_1"})
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)

	resp, err := c.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("a retryable failure was not retried: %v", err)
	}
	if string(resp.Body) != `{"ok":true}` {
		t.Errorf("body = %q", resp.Body)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("provider was called %d times, want 2", got)
	}
}

// 401, 403 and 429 must never be retried. The first two will fail identically;
// the third is made worse by retrying, and on a metered API every attempt is
// billed.
func TestClientDoesNotRetryAuthOrRateLimitFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		want   error
	}{
		{"unauthorised", http.StatusUnauthorized, ErrUnauthorised},
		{"forbidden", http.StatusForbidden, ErrUnauthorised},
		{"rate limited", http.StatusTooManyRequests, ErrRateLimited},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()

			c := testClient(t, srv, ClientOptions{ProviderID: "apr_1"})
			req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)

			_, err := c.Do(context.Background(), req)
			if !errors.Is(err, tc.want) {
				t.Errorf("error is %v, want %v", err, tc.want)
			}
			if got := calls.Load(); got != 1 {
				t.Errorf("provider was called %d times, want exactly 1", got)
			}
		})
	}
}

// The breaker has to be wired into the client, not merely present in the
// package. Once open, a failing provider costs a mutex rather than a timeout.
func TestClientStopsCallingAFailingProvider(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := testClient(t, srv, ClientOptions{
		ProviderID: "apr_1",
		Breaker:    BreakerOptions{Threshold: 2, Cooldown: time.Hour},
	})
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)

	for i := 0; i < 2; i++ {
		if _, err := c.Do(context.Background(), req); err == nil {
			t.Fatal("a 500 was reported as success")
		}
	}
	before := calls.Load()

	// Every call from here is short-circuited.
	for i := 0; i < 20; i++ {
		if _, err := c.Do(context.Background(), req); !errors.Is(err, ErrCircuitOpen) {
			t.Fatalf("call %d after the breaker opened returned %v, want ErrCircuitOpen", i, err)
		}
	}
	if after := calls.Load(); after != before {
		t.Errorf("the provider was called %d more times after the breaker opened", after-before)
	}
	if got := c.Stats().Breaker; got != BreakerOpen {
		t.Errorf("reported breaker state is %s, want open", got)
	}
}

// A redirect must not carry the credential somewhere the operator did not
// configure.
func TestClientDoesNotFollowRedirects(t *testing.T) {
	var elsewhere atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		elsewhere.Add(1)
		_, _ = w.Write([]byte(`{"leaked":true}`))
	}))
	defer other.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusFound)
	}))
	defer srv.Close()

	c := testClient(t, srv, ClientOptions{ProviderID: "apr_1"})
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("Authorization", "Bearer a-real-credential")

	resp, err := c.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	if resp.Status != http.StatusFound {
		t.Errorf("status = %d, want the redirect to be returned unfollowed", resp.Status)
	}
	if n := elsewhere.Load(); n != 0 {
		t.Errorf("the credential was sent to a redirect target %d times", n)
	}
}

func TestClientHonoursItsTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
	}))
	defer func() { close(release); srv.Close() }()

	c := testClient(t, srv, ClientOptions{ProviderID: "apr_1", Timeout: 40 * time.Millisecond})
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)

	start := time.Now()
	_, err := c.Do(context.Background(), req)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a hung provider returned success")
	}
	// Generous, because the retry adds a jittered pause — but nowhere near the
	// forever the handler would otherwise take.
	if elapsed > 2*time.Second {
		t.Errorf("a 40ms budget took %s", elapsed)
	}
}

func TestClientStatsReportLatencyAndErrorRate(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Alternate success and a non-retryable client error, so the error
		// rate is a number the test can predict.
		if n.Add(1)%2 == 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := testClient(t, srv, ClientOptions{ProviderID: "apr_1"})
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	for i := 0; i < 10; i++ {
		_, _ = c.Do(context.Background(), req)
	}

	s := c.Stats()
	if s.Calls != 10 {
		t.Errorf("calls = %d, want 10", s.Calls)
	}
	if s.Failures != 5 {
		t.Errorf("failures = %d, want 5", s.Failures)
	}
	if s.ErrorRate < 0.49 || s.ErrorRate > 0.51 {
		t.Errorf("error rate = %v, want ~0.5", s.ErrorRate)
	}
	if s.LastCallAt == nil {
		t.Error("no last-call timestamp")
	}
	if s.LastError == "" {
		t.Error("no last error recorded despite five failures")
	}
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

func TestClampBoundsHostileScores(t *testing.T) {
	// A score outside [0,1] is the easiest way for a buggy or hostile provider
	// to clear every threshold downstream. NaN is the subtle one: it compares
	// false against everything, so an unclamped NaN reads as benign.
	nan := math.NaN()
	for _, tc := range []struct{ in, want float64 }{
		{-1, 0}, {0, 0}, {0.5, 0.5}, {1, 1}, {1e9, 1}, {nan, 0},
	} {
		if got := Clamp01(tc.in); got != tc.want {
			t.Errorf("Clamp01(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestParseCapabilitiesDropsWhatThisBuildCannotDo(t *testing.T) {
	got := ParseCapabilities([]string{"reputation", "ENRICHMENT", " feed ", "telepathy", "reputation"})
	want := []Capability{CapReputation, CapEnrichment, CapFeed}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got %v, want %v", got, want)
		}
	}
}

func TestNormaliseDomainMatchesWhatTheCacheIsKeyedOn(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Example.COM.", "example.com"},
		{"  example.com  ", "example.com"},
		{"example.com", "example.com"},
	} {
		if got := NormaliseDomain(tc.in); got != tc.want {
			t.Errorf("NormaliseDomain(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

/* ---------- link-local dial control -------------------------------------- */

// The one SSRF control in this package. It exists for a single escalation:
// somebody who can add a provider is already an administrator of this
// dashboard, but the cloud metadata service would make them an administrator
// of the account the machine runs in, which is strictly more.
func TestLinkLocalAddressesAreRefused(t *testing.T) {
	for _, tc := range []struct {
		name    string
		addr    string
		refused bool
	}{
		{"AWS, GCP and Azure metadata", "169.254.169.254", true},
		{"anywhere else in link-local", "169.254.1.1", true},
		{"IPv6 link-local", "fe80::1", true},
		{"IPv4-mapped metadata, the same endpoint spelled differently",
			"::ffff:169.254.169.254", true},
		{"another IPv6 link-local address", "fe80::a9fe:a9fe", true},
		{"AWS IPv6 metadata, which is unique-local rather than link-local",
			"fd00:ec2::254", true},

		// Everything an operator would legitimately point a provider at stays
		// reachable. Blocking these would break the stated use case — an
		// internal reputation service, or a self-hosted vendor appliance —
		// and would not protect anybody from an administrator who already has
		// the dashboard.
		{"a public address", "93.184.216.34", false},
		{"an RFC 1918 internal service", "10.1.2.3", false},
		{"a home network", "192.168.1.10", false},
		{"a carrier-grade NAT range", "100.64.0.1", false},
		{"loopback, which is where a test server lives", "127.0.0.1", false},
		{"IPv6 loopback", "::1", false},
		{"a public IPv6 address", "2606:2800:220:1:248:1893:25c8:1946", false},
		// The rest of unique-local space stays reachable: it is where an
		// operator's own internal services live, and taking fc00::/7 away
		// would break the use case this adapter exists for.
		{"an ordinary unique-local address", "fd00:1234::5", false},
		{"the neighbour of the AWS endpoint", "fd00:ec2::253", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, err := netip.ParseAddr(tc.addr)
			if err != nil {
				t.Fatalf("parse %s: %v", tc.addr, err)
			}
			err = checkAddr(addr)
			if tc.refused && err == nil {
				t.Errorf("%s was allowed", tc.addr)
			}
			if !tc.refused && err != nil {
				t.Errorf("%s was refused: %v", tc.addr, err)
			}
			if tc.refused && !errors.Is(err, ErrBlockedAddress) {
				t.Errorf("%s was refused with the wrong error: %v", tc.addr, err)
			}
		})
	}
}

// An unparseable address must be refused, not allowed. A check whose job is to
// say no has exactly one safe direction to fail in.
func TestTheDialControlFailsClosed(t *testing.T) {
	for _, tc := range []struct{ name, address string }{
		{"empty", ""},
		{"no port", "not-an-address"},
		{"a bare address with no port", "169.254.169.254"},
		{"a bracketed address with no port", "[::1]"},
		// This one reaches the second branch: SplitHostPort succeeds and
		// ParseAddr does not. Control is documented to receive a resolved
		// address, so a name arriving here means an assumption broke, and the
		// only safe response to that is to refuse.
		{"a hostname where an address was promised", "example.com:80"},
	} {
		if err := dialControl("tcp", tc.address, nil); err == nil {
			t.Errorf("dialControl allowed %q (%s), which it could not parse", tc.address, tc.name)
		}
	}
	// And a well-formed permitted address still gets through, so the test
	// above is not passing because everything is refused.
	if err := dialControl("tcp", "127.0.0.1:8080", nil); err != nil {
		t.Errorf("dialControl refused an ordinary address: %v", err)
	}
}

// The control has to be wired into the transport the clients actually use,
// not merely exist. A correct function nothing calls is the failure this
// catches.
//
// The transport's dialer is exercised directly rather than through a request,
// because Client.Do refuses a blocked literal before any dial happens — so a
// request-level test would pass with the transport's Control removed and would
// be proving the wrong thing. This is the layer that catches a hostname
// resolving to the metadata service, which the URL check cannot see.
func TestTheSharedTransportRefusesLinkLocal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := sharedTransport().DialContext(ctx, "tcp", "169.254.169.254:80")
	if err == nil {
		_ = conn.Close()
		t.Fatal("the shared transport dialled the cloud metadata service")
	}
	if !strings.Contains(err.Error(), "link-local") {
		t.Errorf("the dial failed for some other reason, so the control may not be wired in: %v", err)
	}

	// And an ordinary address still dials, so the check above is not passing
	// because the transport refuses everything.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	conn, err = sharedTransport().DialContext(ctx, "tcp", host)
	if err != nil {
		t.Fatalf("the shared transport refused an ordinary address: %v", err)
	}
	_ = conn.Close()
}

// The dialer's control is not enough on its own. With HTTP_PROXY set the
// transport dials the proxy, so Control sees the proxy's address and the
// request to the metadata service is forwarded by somebody else. A URL check
// that runs before any dial is what closes that.
func TestABlockedLiteralIsRefusedBeforeAnythingIsDialled(t *testing.T) {
	c := NewClient(ClientOptions{ProviderID: "p", Timeout: 2 * time.Second, RatePerMinute: 60})

	for _, raw := range []string{
		"http://169.254.169.254/latest/meta-data/",
		"https://[fd00:ec2::254]/latest/meta-data/",
		"http://[::ffff:169.254.169.254]/",
	} {
		req, err := http.NewRequest(http.MethodGet, raw, nil)
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if _, err := c.Do(context.Background(), req); !errors.Is(err, ErrBlockedAddress) {
			t.Errorf("%s was not refused as a blocked address: %v", raw, err)
		}
	}

	// And the refusal costs nothing: no breaker slot, no rate-limit token, no
	// call counted. Otherwise a misconfigured provider would trip its own
	// circuit and the operator would see "circuit open" rather than "that
	// address is refused".
	s := c.Stats()
	if s.Calls != 0 {
		t.Errorf("a refused request counted %d calls", s.Calls)
	}
	if s.Breaker != BreakerClosed {
		t.Errorf("a refused request moved the breaker to %s", s.Breaker)
	}

	// An ordinary host still gets through, so the check above is not simply
	// refusing everything.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do(context.Background(), req); err != nil {
		t.Errorf("an ordinary request was refused: %v", err)
	}
}
