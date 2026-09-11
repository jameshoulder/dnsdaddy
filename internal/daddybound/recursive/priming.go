package recursive

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Root priming: replacing the compiled-in hints with the root's own answer.
//
// Hints are a bootstrap and nothing more. They say where to ask the first
// question; they are not authenticated, they are not a trust anchor, and they
// go stale as root server addresses change. Priming asks the root for its own
// NS RRset, which is the authoritative statement of where the root lives, and
// uses that afterwards.
//
// What priming is not: a licence to fetch configuration from the Internet.
// Nothing here downloads a hints file, and a failed priming falls back to the
// compiled-in addresses rather than to whatever answered.

// PrimingState is the health of the root bootstrap, for the status surface.
type PrimingState struct {
	// Primed reports that the root NS RRset was learned from a root server.
	Primed bool
	// At is when that last succeeded.
	At time.Time
	// Servers is how many root addresses are currently usable.
	Servers int
	// Err is why the last attempt failed, empty on success.
	Err string
	// UsingHints reports that the resolver is running on the compiled-in
	// addresses because priming has not succeeded. Not fatal — the hints are
	// usually right — but it is the thing to look at when the root seems
	// unreachable.
	UsingHints bool
}

// primeInterval is how long a successful priming is trusted before being
// refreshed. The root NS RRset carries a multi-day TTL; this is deliberately
// shorter so a resolver that has been up for weeks is not running on a
// fortnight-old answer.
const primeInterval = 12 * time.Hour

type rootState struct {
	mu      sync.RWMutex
	addrs   []netip.AddrPort
	state   PrimingState
	priming bool
}

// rootServers returns addresses for the root, priming if needed.
//
// Priming failure is not fatal: the compiled-in hints are returned instead,
// and the state records that. A resolver that refused to start because one
// root server was unreachable would be less available than one that uses the
// addresses it shipped with, and the security properties do not depend on
// priming — they depend on DNSSEC validating what the root says.
func (r *Resolver) rootServers(ctx context.Context) ([]netip.AddrPort, error) {
	r.root.mu.RLock()
	fresh := r.root.state.Primed && r.now().Sub(r.root.state.At) < primeInterval
	addrs := append([]netip.AddrPort(nil), r.root.addrs...)
	r.root.mu.RUnlock()

	if fresh && len(addrs) > 0 {
		return addrs, nil
	}
	if primed, err := r.prime(ctx); err == nil && len(primed) > 0 {
		return primed, nil
	}

	hinted := r.hintAddrs()
	if len(hinted) == 0 {
		return nil, fmt.Errorf("%w: no usable root hint addresses", ErrNoReachableServer)
	}
	return hinted, nil
}

func (r *Resolver) hintAddrs() []netip.AddrPort {
	var out []netip.AddrPort
	for _, h := range r.hints {
		for _, a := range h.Addr {
			if r.targetAllowed(a) {
				out = append(out, netip.AddrPortFrom(a, 53))
			}
		}
	}
	return out
}

// prime asks the root for its own NS RRset.
func (r *Resolver) prime(ctx context.Context) ([]netip.AddrPort, error) {
	r.root.mu.Lock()
	if r.root.priming {
		// Another resolution is already priming. Use what we have rather
		// than sending a second burst at the root servers.
		addrs := append([]netip.AddrPort(nil), r.root.addrs...)
		r.root.mu.Unlock()
		if len(addrs) > 0 {
			return addrs, nil
		}
		return nil, fmt.Errorf("priming in progress")
	}
	r.root.priming = true
	r.root.mu.Unlock()

	defer func() {
		r.root.mu.Lock()
		r.root.priming = false
		r.root.mu.Unlock()
	}()

	var lastErr error
	for _, server := range r.hintAddrs() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		msg, err := r.ex.Exchange(ctx, server, query(".", dns.TypeNS, r.cfg.UDPSize))
		if err != nil {
			lastErr = err
			continue
		}
		addrs, names := r.rootFromPriming(msg)
		if len(addrs) == 0 {
			lastErr = fmt.Errorf("root server %s returned no usable addresses", server)
			continue
		}

		r.root.mu.Lock()
		r.root.addrs = addrs
		r.root.state = PrimingState{Primed: true, At: r.now(), Servers: len(addrs)}
		r.root.mu.Unlock()

		// The priming answer is a delegation like any other, so the walk can
		// start from it rather than re-priming.
		glue := map[string][]netip.Addr{}
		for name, as := range r.primingGlue(msg, names) {
			glue[name] = as
		}
		// The root's own NS RRset TTL, from the priming answer. The root
		// publishes a multi-day one; priming refreshes on its own schedule
		// (primeInterval) regardless, so this only decides how long the
		// cached delegation stands in between.
		r.cache.PutDelegation(".", names, glue, rootNSTTL(msg))
		return addrs, nil
	}

	r.root.mu.Lock()
	r.root.state = PrimingState{
		Primed: false, At: r.now(), Err: errString(lastErr), UsingHints: true,
		Servers: len(r.hintAddrs()),
	}
	r.root.mu.Unlock()
	if lastErr == nil {
		lastErr = fmt.Errorf("%w: no root hint answered", ErrNoReachableServer)
	}
	return nil, lastErr
}

// rootFromPriming extracts the root NS names and their addresses.
//
// Bailiwick applies here too, and it is not a formality: this reply comes from
// an unauthenticated bootstrap address. A record for anything other than the
// root, or an address for a name the answer did not list as a root server, is
// discarded — otherwise the first packet to arrive at startup could seed the
// cache with whatever it liked.
func (r *Resolver) rootFromPriming(msg *dns.Msg) ([]netip.AddrPort, []string) {
	names := map[string]bool{}
	var ordered []string
	for _, rr := range append(append([]dns.RR{}, msg.Answer...), msg.Ns...) {
		ns, ok := rr.(*dns.NS)
		if !ok || dns.CanonicalName(ns.Hdr.Name) != "." {
			continue
		}
		n := dns.CanonicalName(ns.Ns)
		if !names[n] {
			names[n] = true
			ordered = append(ordered, n)
		}
	}
	if len(names) == 0 {
		return nil, nil
	}

	var out []netip.AddrPort
	for _, as := range r.primingGlue(msg, ordered) {
		for _, a := range as {
			out = append(out, netip.AddrPortFrom(a, 53))
		}
	}
	return out, ordered
}

func (r *Resolver) primingGlue(msg *dns.Msg, names []string) map[string][]netip.Addr {
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	out := map[string][]netip.Addr{}
	for _, rr := range msg.Extra {
		addr, ok := addrFromRR(rr)
		if !ok {
			continue
		}
		owner := dns.CanonicalName(rr.Header().Name)
		if !want[owner] || !r.targetAllowed(addr) {
			continue
		}
		if len(out[owner]) >= r.cfg.Limits.MaxAddrsPerNS {
			continue
		}
		out[owner] = append(out[owner], addr)
	}
	return out
}

// PrimingState reports the root bootstrap health.
func (r *Resolver) PrimingState() PrimingState {
	r.root.mu.RLock()
	defer r.root.mu.RUnlock()
	s := r.root.state
	if !s.Primed {
		s.UsingHints = true
		if s.Servers == 0 {
			s.Servers = len(r.hintAddrs())
		}
	}
	return s
}

// Prime forces a priming attempt, for startup and for the status command.
func (r *Resolver) Prime(ctx context.Context) error {
	_, err := r.prime(ctx)
	return err
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// rootNSTTL is the shortest TTL among the root's own NS records in a priming
// answer, or zero when there are none.
func rootNSTTL(msg *dns.Msg) uint32 {
	var ttl uint32
	for _, set := range [][]dns.RR{msg.Answer, msg.Ns} {
		for _, rr := range set {
			ns, ok := rr.(*dns.NS)
			if !ok || dns.CanonicalName(ns.Hdr.Name) != "." {
				continue
			}
			if ttl == 0 || ns.Hdr.Ttl < ttl {
				ttl = ns.Hdr.Ttl
			}
		}
	}
	return ttl
}
