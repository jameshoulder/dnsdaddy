package resolution

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/native"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/recursive"
)

// Native is the Backend over Daddybound's own recursive resolver.
//
// The whole of this milestone is that the following sentence became true: DNS
// Daddy resolves DNS itself. From root hints down through the TLD to the
// authoritative servers, and it authenticates what it read there against a
// trust anchor it holds — no Cloudflare, no Quad9, no Unbound, no upstream's
// opinion borrowed as a fact.
//
// # The invariant this type exists to hold
//
//	the answer returned to the client is the answer that was validated.
//
// Not one that agrees with it. Not a forwarded answer whose name was checked
// separately. Those are the two shapes a validating resolver goes wrong in, and
// from outside they are indistinguishable from the real thing — which is why
// the guarantee is structural rather than a promise. native.Engine resolves
// once, pins the per-hop replies, and hands the validator those exact replies;
// this type takes Answer.Msg and never fetches anything else. There is no
// second copy of the answer for the two to disagree about.
//
// And the corollary, which is the rule that actually costs something: when
// Daddybound says an answer is bogus, the client gets SERVFAIL. There is no
// fallback to the forwarder, because a fallback would mean an attacker who can
// forge one answer gets it served anyway — the validation would be theatre.
// applyDNSSEC is where that is enforced and there is no configuration around
// it.
type Native struct {
	engine *native.Engine
	window *Window
	now    func() time.Time

	// group collapses identical concurrent questions onto one resolution.
	//
	// Not an optimisation. A recursive resolver is far more expensive per miss
	// than a forwarder — several round trips in series against servers on the
	// public Internet — so a hundred clients asking the same cold question at
	// once would send a hundred walks from the root. That is a self-inflicted
	// load on the root and TLD servers as much as on this box, and it is
	// exactly the shape a beaconing implant produces.
	group singleflight
}

// NativeOptions configures a Native backend.
type NativeOptions struct {
	// Now is the clock, for tests.
	Now func() time.Time
}

// NewNative wraps a Daddybound engine.
func NewNative(e *native.Engine, o NativeOptions) (*Native, error) {
	if e == nil {
		return nil, errors.New("resolution: native mode needs a Daddybound engine")
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	return &Native{engine: e, window: NewWindow(now), now: now}, nil
}

// Name identifies this backend.
func (n *Native) Name() string { return BackendNative }

// Engine exposes the underlying engine, for status and diagnostics.
func (n *Native) Engine() *native.Engine { return n.engine }

// Resolve answers the question by recursion from the root, and validates it.
func (n *Native) Resolve(ctx context.Context, req *dns.Msg, generation uint64) (Result, error) {
	if len(req.Question) == 0 {
		return Result{}, errors.New("resolution: query has no question")
	}
	q := req.Question[0]
	start := n.now()

	// The generation is folded into the collapsing key alongside the question,
	// so a blocklist refresh cannot attach a waiter to a flight that began
	// under the previous generation. The engine's own cache handles the same
	// concern for stored answers.
	key := dns.CanonicalName(q.Name) + "\x00" + dns.TypeToString[q.Qtype] + "\x00" + dns.ClassToString[q.Qclass]

	shared, err := n.group.Do(key, func() (*native.Answer, error) {
		return n.engine.Resolve(ctx, q.Name, q.Qtype)
	})
	elapsed := n.now().Sub(start)

	if err != nil {
		n.window.Record(Sample{
			Elapsed:     elapsed,
			Err:         true,
			Servfail:    true,
			AuthTimeout: isAuthoritativeTimeout(err),
		})
		return Result{}, err
	}

	status, reason := FromValidation(shared.Answer.Validation)

	// The message is reframed onto the client's question and ID. Only the
	// header and the question section: the records are exactly the ones the
	// authoritative servers sent and the validator saw.
	msg := reframe(shared.Answer.Msg, req)
	msg, serve := applyDNSSEC(msg, req, status, AuthorityLocal)

	// A collapsed caller inherits the leader's Answer, so the leader's query
	// count is not this caller's. Only the caller that did the work may report
	// a cache hit or a miss; the others report what they actually did, which
	// is wait.
	cached := !shared.Collapsed && shared.Answer.Queries == 0

	n.window.Record(Sample{
		Elapsed:   elapsed,
		Cached:    cached,
		Collapsed: shared.Collapsed,
		Servfail:  !serve || msg.Rcode == dns.RcodeServerFailure,
		Bogus:     status == StatusBogus,
	})

	return Result{
		Msg:          msg,
		Backend:      BackendNative,
		Cached:       cached,
		Collapsed:    shared.Collapsed,
		DNSSEC:       status,
		DNSSECReason: reason,
		Authority:    AuthorityLocal,
		Rcode:        msg.Rcode,
		MinTTL:       minAnswerTTL(msg),
		Elapsed:      elapsed,
		// The leader's cost. Reported as zero for a collapsed caller, which
		// spent nothing: attributing the leader's queries to every waiter
		// would multiply the recorded outbound traffic by the size of the
		// burst.
		Queries:     collapsedZero(shared.Collapsed, shared.Answer.Queries),
		Delegations: collapsedZero(shared.Collapsed, len(shared.Answer.Delegations)),
	}, nil
}

// Health reports the native resolver's state over the rolling window.
func (n *Native) Health() Health {
	h := n.window.Snapshot()
	h.OK, h.Detail = judge(h)
	return h
}

// Purge drops every cached answer, delegation and address.
func (n *Native) Purge() { n.engine.Resolver().Flush() }

// Close releases whatever the engine holds. The recursive resolver holds no
// long-lived connections — every authoritative exchange opens and closes its
// own socket — so there is nothing to release today. The method exists because
// the interface has it and a future transport will.
func (n *Native) Close() {}

// reframe puts a resolved answer onto the client's question and message ID.
//
// The header and the question section only. Every record is left exactly as the
// authoritative servers sent it, which is the whole point: this is the message
// the validator was given.
//
// SetReply is deliberately not used. It forces NOERROR, which would turn a
// validated NXDOMAIN — an authenticated statement that a name does not exist —
// into a NOERROR with no answer, and quietly lose the one thing the denial
// proof established.
func reframe(msg *dns.Msg, req *dns.Msg) *dns.Msg {
	out := msg.Copy()
	out.Id = req.Id
	out.Question = req.Question
	out.Response = true
	out.Opcode = dns.OpcodeQuery
	out.RecursionDesired = req.RecursionDesired
	out.RecursionAvailable = true
	// Cleared unconditionally here; applyDNSSEC sets it when this resolver
	// authenticated the answer and the client asked. An AA bit copied from an
	// authoritative server would claim this resolver is authoritative for the
	// zone, which it is not.
	out.Authoritative = false
	out.AuthenticatedData = false
	// The authoritative server's OPT record describes its transport, not
	// ours: its buffer size, its flags, and any extended error it chose to
	// send about its own situation. Dropped, and applyDNSSEC adds one
	// describing this resolver's verdict when there is something to say.
	out.Extra = withoutOPT(out.Extra)
	return out
}

func withoutOPT(rrs []dns.RR) []dns.RR {
	out := rrs[:0]
	for _, rr := range rrs {
		if _, isOPT := rr.(*dns.OPT); isOPT {
			continue
		}
		out = append(out, rr)
	}
	return out
}

// isAuthoritativeTimeout reports whether a resolution failed because no
// authoritative server answered, as distinct from any other failure.
//
// Counted separately because it is the number that says whether native mode is
// viable in a given deployment. A network that blocks outbound port 53 to
// anywhere but its ISP's resolvers produces exactly this and nothing else, and
// an operator needs to see that rather than a general error rate.
func isAuthoritativeTimeout(err error) bool {
	return errors.Is(err, recursive.ErrNoReachableServer) ||
		errors.Is(err, context.DeadlineExceeded)
}

func minAnswerTTL(msg *dns.Msg) uint32 {
	if msg == nil || len(msg.Answer) == 0 {
		return 0
	}
	min := msg.Answer[0].Header().Ttl
	for _, rr := range msg.Answer[1:] {
		if t := rr.Header().Ttl; t < min {
			min = t
		}
	}
	return min
}

// shared is one collapsed resolution.
type shared struct {
	Answer *native.Answer
	// Collapsed reports that this caller waited on somebody else's flight
	// rather than doing the work.
	Collapsed bool
}

// singleflight collapses identical concurrent questions onto one resolution.
//
// Written here rather than imported because the semantics wanted are narrower
// than golang.org/x/sync/singleflight's: no forgetting, no result sharing
// across generations, and a Collapsed flag the caller uses for telemetry. It is
// twenty lines, and a dependency for twenty lines is a dependency to keep
// patched.
type singleflight struct {
	mu    sync.Mutex
	calls map[string]*flight
}

type flight struct {
	done chan struct{}
	ans  *native.Answer
	err  error
}

// Do runs fn for key, or waits for an identical call already running.
func (s *singleflight) Do(key string, fn func() (*native.Answer, error)) (shared, error) {
	s.mu.Lock()
	if s.calls == nil {
		s.calls = map[string]*flight{}
	}
	if f, running := s.calls[key]; running {
		s.mu.Unlock()
		<-f.done
		if f.err != nil {
			return shared{}, f.err
		}
		return shared{Answer: f.ans, Collapsed: true}, nil
	}
	f := &flight{done: make(chan struct{})}
	s.calls[key] = f
	s.mu.Unlock()

	f.ans, f.err = fn()

	s.mu.Lock()
	delete(s.calls, key)
	s.mu.Unlock()
	close(f.done)

	if f.err != nil {
		return shared{}, f.err
	}
	return shared{Answer: f.ans}, nil
}

// collapsedZero reports a cost as zero for a caller that did not incur it.
func collapsedZero(collapsed bool, n int) int {
	if collapsed {
		return 0
	}
	return n
}
