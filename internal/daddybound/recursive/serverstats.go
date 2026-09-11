package recursive

import (
	"math"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// Choosing which authoritative server to ask.
//
// The problem this replaces: the resolver asked servers in a rotated order and
// discovered a dead one by waiting for it to time out. A zone with four
// nameservers, one of which is unreachable, therefore cost a full timeout on
// roughly one query in four — and the resolver learned nothing from it, so it
// did the same thing again on the next query, and the next. On a three-second
// timeout that is a user-visible stall recurring for as long as the server
// stays down.
//
// What is here instead: the resolver remembers how each address behaved and
// prefers the ones that have been answering. Two numbers per address, and both
// are deliberately crude.
//
// A smoothed round-trip time, so a server on the other side of the world is
// tried after a nearby one when both work. Smoothed rather than last-seen
// because a single slow answer is weather, not a property of the server.
//
// A penalty that decays with time, so a server that failed is tried later
// rather than never. Never would be wrong twice over: it would strand a zone
// whose servers all failed once during an outage of ours, and it would hand an
// attacker who can drop packets to one server the power to pin all this
// resolver's traffic onto another.
//
// # What this deliberately does not do
//
// It does not query several servers at once. Hedging a slow query against a
// second server is a real technique and it doubles this resolver's outbound
// traffic in exactly the conditions where the network is already struggling —
// and a bug in the hedging logic is a traffic multiplier aimed at somebody
// else's authoritative servers. Security and predictable resource usage come
// before latency here. The ordering below removes most of what hedging would
// buy, because the slow server stops being tried first.
//
// It does not prefer IPv6 or IPv4 by family. Whichever answers faster wins on
// its measured time, which is the honest version of a preference and needs no
// policy. A deployment with broken IPv6 will find its IPv6 addresses penalised
// within a few queries rather than by configuration.

const (
	// rttAlpha is the weight given to a new measurement, the standard
	// exponentially weighted moving average of RFC 6298 §2 in spirit though
	// not in its precise form — this is a server preference, not a
	// retransmission timer, and does not need the variance term.
	rttAlpha = 0.25

	// penaltyStep is added on a failure and decays at penaltyDecay per
	// second. A single failure therefore keeps a server out of first place
	// for a few seconds; a server that fails repeatedly accumulates and stays
	// behind. The cap stops an address that has been down for a week from
	// carrying a penalty that would take a week to work off.
	penaltyStep  = 4 * time.Second
	penaltyDecay = time.Second
	penaltyCap   = 30 * time.Second

	// unknownRTT is where an address with no history sorts.
	//
	// Optimistic on purpose: a new address is tried ahead of one known to be
	// slow, so a zone that adds a nameserver gets it used rather than having
	// to earn its way past servers that already have measurements. It is
	// behind anything that has answered quickly, so a working fast server is
	// not displaced by an untried one on every query.
	unknownRTT = 50 * time.Millisecond

	// maxServerStats bounds the table. Addresses arrive from delegations,
	// which arrive from the network, so this is a budget rather than an
	// expectation.
	maxServerStats = 4096
)

type serverStat struct {
	// srtt is the smoothed round-trip time, zero when never measured.
	srtt time.Duration
	// penalty is the accumulated failure penalty at penaltyAt.
	penalty   time.Duration
	penaltyAt time.Time
	// lastUsed drives eviction.
	lastUsed time.Time
}

// serverTable remembers how authoritative servers have behaved.
//
// Keyed by address rather than by zone. A nameserver serving fifty zones is one
// machine with one network path, and measuring it fifty times separately would
// take fifty times as long to notice it had gone down.
type serverTable struct {
	now func() time.Time

	mu sync.Mutex
	by map[netip.AddrPort]*serverStat
}

func newServerTable(now func() time.Time) *serverTable {
	if now == nil {
		now = time.Now
	}
	return &serverTable{now: now, by: map[netip.AddrPort]*serverStat{}}
}

// success records an answer and how long it took.
func (t *serverTable) success(addr netip.AddrPort, rtt time.Duration) {
	now := t.now()

	t.mu.Lock()
	defer t.mu.Unlock()

	s := t.statLocked(addr, now)
	if s.srtt == 0 {
		s.srtt = rtt
	} else {
		s.srtt = time.Duration(float64(s.srtt)*(1-rttAlpha) + float64(rtt)*rttAlpha)
	}
	// A success clears the penalty rather than decaying it. The server is
	// demonstrably working now, and making it serve out a penalty it has
	// already disproved would keep a recovered server behind a broken one.
	s.penalty, s.penaltyAt = 0, now
	s.lastUsed = now
}

// failure records a server that did not answer, or answered uselessly.
func (t *serverTable) failure(addr netip.AddrPort) {
	now := t.now()

	t.mu.Lock()
	defer t.mu.Unlock()

	s := t.statLocked(addr, now)
	s.penalty = decayed(s.penalty, s.penaltyAt, now) + penaltyStep
	if s.penalty > penaltyCap {
		s.penalty = penaltyCap
	}
	s.penaltyAt = now
	s.lastUsed = now
}

// order returns the addresses best first.
//
// A copy: the caller's slice comes from a cached delegation and reordering it
// in place would reorder what every other resolution sees.
func (t *serverTable) order(addrs []netip.AddrPort) []netip.AddrPort {
	if len(addrs) < 2 {
		return addrs
	}
	now := t.now()

	t.mu.Lock()
	cost := make(map[netip.AddrPort]time.Duration, len(addrs))
	for _, a := range addrs {
		s, known := t.by[a]
		if !known {
			cost[a] = unknownRTT
			continue
		}
		rtt := s.srtt
		if rtt == 0 {
			rtt = unknownRTT
		}
		cost[a] = rtt + decayed(s.penalty, s.penaltyAt, now)
	}
	t.mu.Unlock()

	out := append([]netip.AddrPort(nil), addrs...)
	sort.SliceStable(out, func(i, j int) bool {
		ci, cj := cost[out[i]], cost[out[j]]
		if ci != cj {
			return ci < cj
		}
		// A total order, so two servers that have never been measured are
		// tried in the same sequence on every query rather than in whatever
		// order a map iteration produced. Arbitrary but stable beats
		// arbitrary and varying: it makes a failure reproducible.
		return out[i].String() < out[j].String()
	})
	return out
}

// statLocked returns the entry for an address, making room if needed.
func (t *serverTable) statLocked(addr netip.AddrPort, now time.Time) *serverStat {
	if s, ok := t.by[addr]; ok {
		return s
	}
	if len(t.by) >= maxServerStats {
		t.evictLocked()
	}
	s := &serverStat{lastUsed: now}
	t.by[addr] = s
	return s
}

// evictLocked drops the least recently used entries.
//
// A bounded scan rather than a heap: this runs once per insertion past the
// bound, the table is a few thousand entries, and a resolver that spent a
// millisecond maintaining a priority queue of nameserver addresses would be
// spending it in the wrong place.
func (t *serverTable) evictLocked() {
	const drop = maxServerStats / 8
	type aged struct {
		addr netip.AddrPort
		at   time.Time
	}
	oldest := make([]aged, 0, len(t.by))
	for a, s := range t.by {
		oldest = append(oldest, aged{a, s.lastUsed})
	}
	sort.Slice(oldest, func(i, j int) bool { return oldest[i].at.Before(oldest[j].at) })
	for i := 0; i < drop && i < len(oldest); i++ {
		delete(t.by, oldest[i].addr)
	}
}

// decayed returns a penalty reduced by the time since it was set.
func decayed(penalty time.Duration, at, now time.Time) time.Duration {
	if penalty <= 0 || at.IsZero() {
		return 0
	}
	elapsed := now.Sub(at)
	if elapsed <= 0 {
		return penalty
	}
	steps := float64(elapsed) / float64(penaltyDecay)
	shed := time.Duration(math.Min(steps, math.MaxInt64/2)) * time.Second
	if shed >= penalty {
		return 0
	}
	return penalty - shed
}

// ServerStat is one address's measured behaviour, for diagnostics.
type ServerStat struct {
	Address netip.AddrPort
	SRTT    time.Duration
	Penalty time.Duration
}

// ServerStats returns what the resolver has learned about the authoritative
// servers it has spoken to, best first.
//
// For `dnsdaddy daddybound status` and the diagnostics page. It is the answer
// to "why is this zone slow" that an operator cannot otherwise get: a
// nameserver carrying a large penalty is one this resolver has been failing to
// reach.
func (r *Resolver) ServerStats() []ServerStat {
	now := r.now()

	r.servers.mu.Lock()
	defer r.servers.mu.Unlock()

	out := make([]ServerStat, 0, len(r.servers.by))
	for a, s := range r.servers.by {
		out = append(out, ServerStat{
			Address: a,
			SRTT:    s.srtt,
			Penalty: decayed(s.penalty, s.penaltyAt, now),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SRTT != out[j].SRTT {
			return out[i].SRTT < out[j].SRTT
		}
		return out[i].Address.String() < out[j].Address.String()
	})
	return out
}
