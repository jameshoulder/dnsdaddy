package ratelimit

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// clock is a hand-wound time source. Rate limiting is arithmetic on
// timestamps, so testing it against the wall clock would test the scheduler
// instead and do it flakily.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock {
	return &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func addr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return a
}

func build(c *clock, cfg Config) *Limiter {
	cfg.now = c.now
	return New(cfg)
}

// TestAClientAtItsRateIsNeverRefused is the property an operator cares about
// most, because the failure it describes is an outage: a host doing exactly
// what it is allowed to do must not be turned away. Ten seconds of traffic at
// the limit, spaced evenly, with no allowance left over from a quiet period
// after the first interval.
func TestAClientAtItsRateIsNeverRefused(t *testing.T) {
	c := newClock()
	l := build(c, Config{Rate: 100, Burst: 10, MaxClients: 1024})
	a := addr(t, "192.0.2.10")

	for i := 0; i < 1000; i++ {
		if d := l.Allow(a); !d.Allowed {
			t.Fatalf("query %d refused at exactly the configured rate (retry after %v)", i, d.RetryAfter)
		}
		c.advance(10 * time.Millisecond) // 100/s
	}
	if l.Limited() != 0 {
		t.Errorf("Limited() = %d, want 0", l.Limited())
	}
}

// TestABurstIsAbsorbedThenRefused pins the shape of the allowance: burst is
// how far above the rate a client may go at once, so exactly burst queries
// arriving together are admitted and the next one is not.
func TestABurstIsAbsorbedThenRefused(t *testing.T) {
	c := newClock()
	l := build(c, Config{Rate: 100, Burst: 20, MaxClients: 1024})
	a := addr(t, "192.0.2.11")

	admitted := 0
	for i := 0; i < 100; i++ {
		if l.Allow(a).Allowed {
			admitted++
		}
	}
	if admitted != 20 {
		t.Errorf("admitted %d queries in an instantaneous burst, want the configured burst of 20", admitted)
	}
	d := l.Allow(a)
	if d.Allowed {
		t.Fatal("the query after the burst was admitted")
	}
	if d.RetryAfter <= 0 {
		t.Errorf("RetryAfter = %v on a refusal, want a positive wait", d.RetryAfter)
	}
	if d.Rate != 100 || d.Burst != 20 {
		t.Errorf("Decision reported rate=%v burst=%v, want the limits that were applied", d.Rate, d.Burst)
	}
}

// TestRetryAfterIsHonest checks that the wait a refusal reports is the wait
// that was actually imposed. A limiter that says "try again in 10ms" and then
// refuses at 10ms is worse than one that says nothing, because a client
// implementing backoff from it would loop.
func TestRetryAfterIsHonest(t *testing.T) {
	c := newClock()
	l := build(c, Config{Rate: 50, Burst: 5, MaxClients: 1024})
	a := addr(t, "192.0.2.12")

	for l.Allow(a).Allowed {
	}
	d := l.Allow(a)
	if d.Allowed {
		t.Fatal("expected a refusal to measure")
	}
	// A hair before the reported wait: still refused.
	c.advance(d.RetryAfter - time.Microsecond)
	if l.Allow(a).Allowed {
		t.Error("admitted before the wait it reported had elapsed")
	}
	c.advance(time.Microsecond)
	if !l.Allow(a).Allowed {
		t.Error("still refused after the wait it reported had elapsed")
	}
}

// TestRefusalsDoNotExtendTheLockout is the property that makes the limiter
// safe to put in front of a client that does not back off. A naive GCRA that
// advances the deadline on every arrival, refused or not, turns a client in a
// tight retry loop into a client that is locked out for as long as it keeps
// trying — a momentary overshoot becomes permanent, and the limiter has
// manufactured the outage it was meant to bound.
func TestRefusalsDoNotExtendTheLockout(t *testing.T) {
	c := newClock()
	l := build(c, Config{Rate: 100, Burst: 10, MaxClients: 1024})
	a := addr(t, "192.0.2.13")

	for l.Allow(a).Allowed {
	}
	// Hammer the closed door 10,000 times without the clock moving.
	for i := 0; i < 10000; i++ {
		if l.Allow(a).Allowed {
			t.Fatal("admitted while over the limit")
		}
	}
	// One emission interval later the client is owed exactly one query,
	// regardless of how hard it knocked.
	c.advance(10 * time.Millisecond)
	if !l.Allow(a).Allowed {
		t.Fatal("a client that retried while refused was locked out beyond its interval")
	}
}

// TestAQuietClientGetsItsBurstBack: the allowance is not a monthly quota.
func TestAQuietClientGetsItsBurstBack(t *testing.T) {
	c := newClock()
	l := build(c, Config{Rate: 100, Burst: 20, MaxClients: 1024})
	a := addr(t, "192.0.2.14")

	for l.Allow(a).Allowed {
	}
	c.advance(time.Hour)

	admitted := 0
	for i := 0; i < 100; i++ {
		if l.Allow(a).Allowed {
			admitted++
		}
	}
	if admitted != 20 {
		t.Errorf("after an hour idle the client got %d queries, want its full burst of 20", admitted)
	}
}

// TestOneClientCannotSpendAnother'sAllowance — the whole point of keying.
func TestOneClientCannotSpendAnothersAllowance(t *testing.T) {
	c := newClock()
	l := build(c, Config{Rate: 10, Burst: 5, MaxClients: 1024})
	noisy := addr(t, "192.0.2.20")
	quiet := addr(t, "192.0.2.21")

	for i := 0; i < 1000; i++ {
		l.Allow(noisy)
	}
	if !l.Allow(quiet).Allowed {
		t.Error("a quiet client was refused because a different client was noisy")
	}
}

// TestADualStackedClientHasOneAllowance. A listener bound to :: reports an
// IPv4 peer as ::ffff:a.b.c.d. Treating that as a different client from
// a.b.c.d would hand every IPv4 host two allowances on a dual-stack bind.
func TestADualStackedClientHasOneAllowance(t *testing.T) {
	c := newClock()
	l := build(c, Config{Rate: 10, Burst: 4, MaxClients: 1024})
	four := addr(t, "192.0.2.30")
	mapped := addr(t, "::ffff:192.0.2.30")

	admitted := 0
	for i := 0; i < 20; i++ {
		if l.Allow(four).Allowed {
			admitted++
		}
		if l.Allow(mapped).Allowed {
			admitted++
		}
	}
	if admitted != 4 {
		t.Errorf("admitted %d across both forms of one address, want the single burst of 4", admitted)
	}
}

// TestIPv6IsLimitedByPrefixNotByAddress. A host with privacy addressing holds
// several /128s at once and rotates them; per-address limiting would see a
// stream of strangers and never refuse any of them.
func TestIPv6IsLimitedByPrefixNotByAddress(t *testing.T) {
	c := newClock()
	l := build(c, Config{Rate: 10, Burst: 5, IPv6PrefixLength: 64, MaxClients: 1024})

	admitted := 0
	for i := 0; i < 50; i++ {
		// Every query from a different address inside one /64, which is what
		// RFC 8981 temporary addresses look like.
		a := netip.AddrFrom16([16]byte{
			0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
			byte(i), byte(i >> 8), 0xaa, 0xbb, 0xcc, 0xdd, 0xee, byte(i),
		})
		if l.Allow(a).Allowed {
			admitted++
		}
	}
	if admitted != 5 {
		t.Errorf("admitted %d queries from rotating addresses in one /64, want the single burst of 5", admitted)
	}

	// A genuinely different /64 is a different client and is unaffected.
	other := addr(t, "2001:db8:1::1")
	if !l.Allow(other).Allowed {
		t.Error("a different /64 was refused because another /64 was over its limit")
	}
}

// TestPerHostIPv6IsAvailableToAnOperatorWhoWantsIt: the aggregation is a
// default, not a law. Documented alongside the rotation caveat it reintroduces.
func TestPerHostIPv6IsAvailableToAnOperatorWhoWantsIt(t *testing.T) {
	c := newClock()
	l := build(c, Config{Rate: 10, Burst: 2, IPv6PrefixLength: 128, MaxClients: 1024})
	a := addr(t, "2001:db8::1")
	b := addr(t, "2001:db8::2")

	l.Allow(a)
	l.Allow(a)
	if l.Allow(a).Allowed {
		t.Fatal("expected the first address to be over its limit")
	}
	if !l.Allow(b).Allowed {
		t.Error("at /128 a neighbouring address shared an allowance")
	}
}

// TestTheMostSpecificOverrideWins. Overrides are read in configuration order
// by an operator and in longest-prefix order by the limiter; if those two
// disagree the operator's file does not mean what it looks like.
func TestTheMostSpecificOverrideWins(t *testing.T) {
	c := newClock()
	l := build(c, Config{
		Rate: 1000, Burst: 1000, MaxClients: 1024,
		Overrides: []Override{
			// Deliberately least-specific first, as someone would write it.
			{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Rate: 100, Burst: 100},
			{Prefix: netip.MustParsePrefix("10.1.0.0/16"), Rate: 5, Burst: 5},
		},
	})

	tight := addr(t, "10.1.2.3")
	admitted := 0
	for i := 0; i < 50; i++ {
		if l.Allow(tight).Allowed {
			admitted++
		}
	}
	if admitted != 5 {
		t.Errorf("the /16 override admitted %d, want 5 — the /8 appears to have won", admitted)
	}

	loose := addr(t, "10.9.9.9")
	if d := l.Allow(loose); d.Rate != 100 {
		t.Errorf("an address outside the /16 got rate %v, want the /8 override's 100", d.Rate)
	}
	outside := addr(t, "192.0.2.1")
	if d := l.Allow(outside); d.Rate != 1000 {
		t.Errorf("an address outside every override got rate %v, want the global 1000", d.Rate)
	}
}

// TestAZeroRateOverrideIsAnExemption, and costs no table space — an exempt
// monitoring host must not be able to evict the state of the client the
// limiter is actually there to refuse.
func TestAZeroRateOverrideIsAnExemption(t *testing.T) {
	c := newClock()
	l := build(c, Config{
		Rate: 10, Burst: 10, MaxClients: 1024,
		Overrides: []Override{{Prefix: netip.MustParsePrefix("127.0.0.0/8"), Rate: 0}},
	})
	a := addr(t, "127.0.0.1")

	for i := 0; i < 10000; i++ {
		if !l.Allow(a).Allowed {
			t.Fatalf("an exempt address was refused at query %d", i)
		}
	}
	if l.Tracked() != 0 {
		t.Errorf("an exempt address consumed %d tracking slots, want 0", l.Tracked())
	}
}

// TestTheTableStaysBounded. This is the memory promise on a 1 GB box, and it
// has to hold against the input designed to break it: a client emitting from a
// new source address every single query.
func TestTheTableStaysBounded(t *testing.T) {
	c := newClock()
	const max = 512
	l := build(c, Config{Rate: 10, Burst: 10, MaxClients: max, IPv4PrefixLength: 32})

	for i := 0; i < 200000; i++ {
		a := netip.AddrFrom4([4]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)})
		l.Allow(a)
		if i%1000 == 0 {
			c.advance(time.Millisecond)
		}
	}
	if got, cap := l.Tracked(), l.Capacity(); got > cap {
		t.Errorf("tracked %d clients, capacity is %d", got, cap)
	}
	if l.Evicted() == 0 {
		t.Error("200,000 distinct clients through a 512-entry table evicted nothing; the bound is not being enforced")
	}
}

// TestAnAddressFloodDoesNotRescueTheClientBeingLimited is the security
// property behind the eviction policy. If an attacker could flush the table by
// spraying source addresses, every limiter decision could be reset on demand
// and the control would be decorative. Eviction therefore prefers entries
// whose deadline has passed — which is what a spray produces — and otherwise
// takes the entry closest to expiring, never the one furthest over its limit.
func TestAnAddressFloodDoesNotRescueTheClientBeingLimited(t *testing.T) {
	c := newClock()
	const max = 256
	l := build(c, Config{Rate: 10, Burst: 10, MaxClients: max, IPv4PrefixLength: 32})

	hot := addr(t, "198.51.100.7")
	for l.Allow(hot).Allowed {
	}
	if l.Allow(hot).Allowed {
		t.Fatal("expected the hot client to be over its limit before the flood")
	}

	// Fifty times the table's capacity, from fresh addresses, without the
	// clock moving far enough for the hot client to earn anything back.
	for i := 0; i < max*50; i++ {
		l.Allow(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}))
	}

	if l.Allow(hot).Allowed {
		t.Error("the client being limited was admitted again after a source-address flood flushed the table")
	}
}

// TestNilLimiterAllowsEverything: "switched off" is a nil pointer, not a
// configured limiter with infinite limits, so there is no arithmetic to get
// wrong when the feature is off.
func TestNilLimiterAllowsEverything(t *testing.T) {
	var l *Limiter
	if !l.Allow(addr(t, "192.0.2.1")).Allowed {
		t.Error("a nil limiter refused a query")
	}
	if l.Limited() != 0 || l.Tracked() != 0 || l.Evicted() != 0 || l.Capacity() != 0 {
		t.Error("a nil limiter reported non-zero counters")
	}
}

// TestAnAddressWeCannotReadIsAllowed. The client ACL has already refused an
// unreadable address by the time this is reached; what is left is a DoH or DoT
// client identified by token, which has no address to key on. Refusing those
// would break roaming clients and protect nothing, since there is no state to
// accumulate either way.
func TestAnAddressWeCannotReadIsAllowed(t *testing.T) {
	c := newClock()
	l := build(c, Config{Rate: 1, Burst: 1, MaxClients: 16})
	for i := 0; i < 100; i++ {
		if !l.Allow(netip.Addr{}).Allowed {
			t.Fatal("a query with no readable source address was rate limited")
		}
	}
	if l.Tracked() != 0 {
		t.Error("an unreadable address consumed a tracking slot")
	}
}

// TestMisconfigurationIsNotAnOutage. A rate of zero, a negative burst, a
// nonsense prefix length: every one of those could be read as "refuse
// everything", and every one of them would take a network down on a typo.
func TestMisconfigurationIsNotAnOutage(t *testing.T) {
	c := newClock()
	for _, cfg := range []Config{
		{},
		{Rate: 0, Burst: 0},
		{Rate: -1, Burst: -1, IPv4PrefixLength: -5, IPv6PrefixLength: 999, MaxClients: -3},
	} {
		l := build(c, cfg)
		if !l.Allow(addr(t, "192.0.2.99")).Allowed {
			t.Errorf("config %+v produced a limiter that refuses a first query", cfg)
		}
		if l.Config().Rate != DefaultRate || l.Config().Burst != DefaultBurst {
			t.Errorf("config %+v did not fall back to the shipped defaults", cfg)
		}
	}
}

// TestConcurrentClientsGetTheirOwnAllowances runs under -race and also checks
// that the sharding has not lost or double-counted anything: each of the
// goroutines shares one address, so the total admitted is one burst.
func TestConcurrentClientsGetTheirOwnAllowances(t *testing.T) {
	c := newClock()
	const burst = 50
	l := build(c, Config{Rate: 1, Burst: burst, MaxClients: 4096})
	a := addr(t, "203.0.113.5")

	var admitted atomic.Int64
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				if l.Allow(a).Allowed {
					admitted.Add(1)
				}
			}
		}()
	}
	wg.Wait()

	if got := admitted.Load(); got != burst {
		t.Errorf("16 goroutines sharing one client address were admitted %d times, want exactly the burst of %d", got, burst)
	}
}

// TestAnOmittedPrefixLengthDoesNotCollapseTheNetwork guards the defect this
// package's own tests found: a prefix length is an int, an omitted YAML key
// leaves it zero, and zero is a syntactically valid prefix length meaning the
// default route. Honouring it would mask every client to 0.0.0.0/0 and turn a
// per-client limit into one shared allowance for the whole network — a
// network-wide outage the moment any single host got busy, produced by leaving
// a line out of a configuration file.
func TestAnOmittedPrefixLengthDoesNotCollapseTheNetwork(t *testing.T) {
	c := newClock()
	l := build(c, Config{Rate: 5, Burst: 5, MaxClients: 1024}) // both prefix lengths omitted

	if got := l.Config().IPv4PrefixLength; got != DefaultIPv4PrefixLength {
		t.Errorf("omitted IPv4 prefix length became /%d, want the default /%d", got, DefaultIPv4PrefixLength)
	}
	if got := l.Config().IPv6PrefixLength; got != DefaultIPv6PrefixLength {
		t.Errorf("omitted IPv6 prefix length became /%d, want the default /%d", got, DefaultIPv6PrefixLength)
	}

	// Behaviourally: exhausting one host must leave its neighbour untouched.
	exhausted := addr(t, "192.0.2.40")
	for l.Allow(exhausted).Allowed {
	}
	for i := 1; i <= 20; i++ {
		neighbour := netip.AddrFrom4([4]byte{192, 0, 2, byte(40 + i)})
		if !l.Allow(neighbour).Allowed {
			t.Fatalf("%v was refused because %v had used its allowance", neighbour, exhausted)
		}
	}
}

// TestOneSharedAllowanceIsStillExpressible, so that refusing to honour a zero
// prefix length has not removed a capability an operator might want — it has
// only moved it somewhere it cannot happen by accident.
func TestOneSharedAllowanceIsStillExpressible(t *testing.T) {
	c := newClock()
	l := build(c, Config{
		Rate: 1000, Burst: 1000, MaxClients: 1024,
		Overrides: []Override{{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Rate: 10, Burst: 5}},
	})

	admitted := 0
	for i := 0; i < 50; i++ {
		if l.Allow(netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})).Allowed {
			admitted++
		}
	}
	// Each address still keys separately, so each gets its own burst of 5 —
	// the override changes the limits, not the keying. Stated explicitly
	// because this is the part an operator is most likely to misread.
	if admitted != 50 {
		t.Errorf("admitted %d, want 50: an override sets limits, it does not merge clients", admitted)
	}
}
