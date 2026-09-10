package recursive

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Limits bound the work one resolution may do.
//
// Every one of these bounds a loop whose length an attacker chooses. A
// delegation chain, a CNAME chain, the number of nameservers in a referral and
// the number of addresses per nameserver are all values that arrive from the
// network, so all of them are budgets rather than expectations. Hitting one is
// a refusal with a reason, never a partial answer presented as a whole one.
type Limits struct {
	// MaxDelegations bounds how many referrals one resolution may follow.
	// A name has at most 127 labels, so a legitimate chain is far shorter;
	// this exists for the hierarchy that refers downwards for ever.
	MaxDelegations int
	// MaxCNAMEs bounds one alias chain.
	MaxCNAMEs int
	// MaxNSPerZone bounds how many nameservers are kept from one referral.
	MaxNSPerZone int
	// MaxAddrsPerNS bounds addresses per nameserver.
	MaxAddrsPerNS int
	// MaxQueries bounds total outgoing questions for one resolution,
	// including those spent resolving nameserver names. It is the backstop
	// that makes the others belt and braces.
	MaxQueries int
	// MaxNSResolutionDepth bounds recursion into "resolve the address of the
	// nameserver that will tell me the address of the nameserver...".
	// Without it a hierarchy that names its nameservers in a zone that names
	// its nameservers in the first zone recurses until the stack gives out.
	MaxNSResolutionDepth int
}

// DefaultLimits are sized for a resolver on a small box facing a hostile
// Internet, not for a record-setting benchmark.
func DefaultLimits() Limits {
	return Limits{
		MaxDelegations:       24,
		MaxCNAMEs:            12,
		MaxNSPerZone:         12,
		MaxAddrsPerNS:        4,
		MaxQueries:           64,
		MaxNSResolutionDepth: 4,
	}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxDelegations <= 0 {
		l.MaxDelegations = d.MaxDelegations
	}
	if l.MaxCNAMEs <= 0 {
		l.MaxCNAMEs = d.MaxCNAMEs
	}
	if l.MaxNSPerZone <= 0 {
		l.MaxNSPerZone = d.MaxNSPerZone
	}
	if l.MaxAddrsPerNS <= 0 {
		l.MaxAddrsPerNS = d.MaxAddrsPerNS
	}
	if l.MaxQueries <= 0 {
		l.MaxQueries = d.MaxQueries
	}
	if l.MaxNSResolutionDepth <= 0 {
		l.MaxNSResolutionDepth = d.MaxNSResolutionDepth
	}
	return l
}

// Config configures a Resolver.
type Config struct {
	// RootHints bootstraps the first query. Empty means the compiled-in set.
	RootHints []RootHint
	// Exchange sends one question to one server. Nil means ordinary port 53
	// DNS over UDP with a TCP retry on truncation.
	Exchange Exchanger
	// Cache is shared across resolutions. Nil means a private default one.
	Cache  *Cache
	Limits Limits
	// UDPSize is the advertised EDNS(0) buffer.
	UDPSize uint16
	// Timeout bounds one exchange with one server.
	Timeout time.Duration
	// QnameMinimisation sends the shortest question each level needs to
	// answer instead of the full name. On by default; see qmin.go.
	QnameMinimisation *bool

	// AllowNonGlobalTargets permits contacting loopback and private
	// addresses as authoritative servers.
	//
	// It exists for the deterministic laboratory, whose root, TLD and child
	// servers all live on 127.0.0.1, and it is off in every configuration a
	// deployment can produce. A resolver that followed public delegations to
	// private addresses is a network scanner with a DNS interface; see
	// usableTarget.
	AllowNonGlobalTargets bool

	// Now is the clock, for tests that need TTL expiry to be deterministic.
	Now func() time.Time
}

// Resolver answers questions by asking authoritative servers, starting at the
// root.
type Resolver struct {
	cfg   Config
	hints []RootHint
	cache *Cache
	ex    Exchanger
	now   func() time.Time

	root  rootState
	stats Stats
}

// New builds a Resolver.
func New(cfg Config) *Resolver {
	cfg.Limits = cfg.Limits.withDefaults()
	if cfg.UDPSize == 0 {
		cfg.UDPSize = 1232
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.QnameMinimisation == nil {
		on := true
		cfg.QnameMinimisation = &on
	}
	hints := cfg.RootHints
	if len(hints) == 0 {
		hints = DefaultRootHints()
	}
	ex := cfg.Exchange
	if ex == nil {
		ex = &netExchanger{
			udpTimeout:     cfg.Timeout,
			tcpTimeout:     cfg.Timeout,
			udpSize:        cfg.UDPSize,
			allowNonGlobal: cfg.AllowNonGlobalTargets,
		}
	}
	cache := cfg.Cache
	if cache == nil {
		cache = NewCache(CacheOptions{Now: cfg.Now})
	}
	return &Resolver{cfg: cfg, hints: hints, cache: cache, ex: ex, now: cfg.Now}
}

// Step is one thing the resolver did, for a trace.
type Step struct {
	// Zone is the zone whose servers were asked.
	Zone string
	// Server is the address asked, empty for a cache hit.
	Server string
	// Question as sent, which under QNAME minimisation is not always the
	// question the caller asked.
	QName string
	QType uint16
	// Kind is what came back: "referral", "answer", "cname", "nodata",
	// "nxdomain", "cached", "error".
	Kind string
	// Detail carries the referral target, the error, or a short note.
	Detail  string
	Elapsed time.Duration
}

func (s Step) String() string {
	at := s.Server
	if at == "" {
		at = "cache"
	}
	return fmt.Sprintf("%-24s %-30s %-6s %-9s %s",
		s.Zone, s.QName, dns.TypeToString[s.QType], s.Kind, s.Detail)
}

// Delegation is a zone cut the resolver actually traversed.
//
// This is the fact that lets the DNSSEC engine stop guessing where zone cuts
// are: a referral from the parent is direct evidence that the child is a zone
// cut, and the absence of one across a whole resolution is evidence that the
// intervening names are not. See issue #64 and standards.md §5.5.
type Delegation struct {
	// Parent is the zone that issued the referral.
	Parent string
	// Child is the delegated zone.
	Child string
	// NS are the nameserver names the parent supplied.
	NS []string
}

// Result is one completed resolution.
type Result struct {
	// Msg is the response as received from the authoritative server. The
	// answer returned to a client in Live mode, and the material the
	// validator is given, are both taken from here — see the same-answer
	// guarantee in live.go.
	Msg *dns.Msg
	// Zone is the zone the answer came from: the deepest zone cut traversed.
	Zone string
	// Delegations lists every zone cut crossed, parent first.
	Delegations []Delegation
	// Trace is what the resolver did, in order.
	Trace []Step
	// Queries is how many questions left the process.
	Queries int
	Elapsed time.Duration
}

// Stats are cumulative counters for observability.
type Stats struct {
	Queries    uint64
	Failures   uint64
	CacheHits  uint64
	CacheMiss  uint64
	Truncated  uint64
	Mismatched uint64
}

var (
	// ErrLimit is returned when a resolution hit one of its bounds. It is
	// deliberately distinguishable from a network failure: "I stopped early"
	// is not evidence about the data, and a validator must not read it as
	// one.
	ErrLimit = errors.New("recursive: resolution limit reached")
	// ErrNoReachableServer is returned when every authoritative server for a
	// zone failed to answer.
	ErrNoReachableServer = errors.New("recursive: no authoritative server answered")
	// ErrLame is returned when a server answers without authority for a zone
	// it was supposed to serve.
	ErrLame = errors.New("recursive: lame delegation")
)

// resolution carries the state of one Resolve call.
type resolution struct {
	r       *Resolver
	ctx     context.Context
	trace   []Step
	queries int
	dels    []Delegation
	start   time.Time
}

// Resolve answers one question by iterative resolution from the root.
func (r *Resolver) Resolve(ctx context.Context, name string, rrtype uint16) (*Result, error) {
	rs := &resolution{r: r, ctx: ctx, start: r.now()}
	qname := dns.CanonicalName(name)

	msg, zone, err := rs.resolveWithAliases(qname, rrtype, 0)
	if err != nil {
		return nil, err
	}
	return &Result{
		Msg:         msg,
		Zone:        zone,
		Delegations: rs.dels,
		Trace:       rs.trace,
		Queries:     rs.queries,
		Elapsed:     r.now().Sub(rs.start),
	}, nil
}

// resolveWithAliases resolves qname, following CNAME chains.
//
// The chain is followed here rather than inside the delegation walk because
// each hop is a fresh resolution from the root: a CNAME may point anywhere,
// and the servers for the target zone have nothing to do with the servers that
// produced the alias.
func (rs *resolution) resolveWithAliases(qname string, rrtype uint16, hop int) (*dns.Msg, string, error) {
	if hop > rs.r.cfg.Limits.MaxCNAMEs {
		return nil, "", fmt.Errorf("%w: alias chain longer than %d", ErrLimit, rs.r.cfg.Limits.MaxCNAMEs)
	}

	msg, zone, err := rs.resolveOnce(qname, rrtype)
	if err != nil {
		return nil, "", err
	}

	// A CNAME that answers the question asked is the answer; only a CNAME
	// for a different type needs following.
	if rrtype == dns.TypeCNAME || msg.Rcode != dns.RcodeSuccess {
		return msg, zone, nil
	}
	target := cnameTarget(msg, qname, rrtype)
	if target == "" {
		return msg, zone, nil
	}

	next, nextZone, err := rs.resolveWithAliases(target, rrtype, hop+1)
	if err != nil {
		// The alias itself resolved; the target did not. Returning what we
		// have with the failure attached would invite a caller to treat a
		// half-followed chain as an answer, so it is an error.
		return nil, "", fmt.Errorf("alias %s -> %s: %w", qname, target, err)
	}

	// Splice: the client asked about qname and must receive the chain that
	// leads to the answer, not just its final hop.
	out := next.Copy()
	out.Question = []dns.Question{{Name: qname, Qtype: rrtype, Qclass: dns.ClassINET}}
	out.Answer = append(append([]dns.RR{}, aliasRecords(msg, qname)...), next.Answer...)
	return out, nextZone, nil
}

// cnameTarget returns the CNAME target for qname, or "".
func cnameTarget(msg *dns.Msg, qname string, rrtype uint16) string {
	for _, rr := range msg.Answer {
		c, ok := rr.(*dns.CNAME)
		if !ok {
			continue
		}
		if dns.CanonicalName(c.Hdr.Name) != qname {
			continue
		}
		// An answer that already carries the requested type alongside the
		// alias needs no second resolution.
		for _, other := range msg.Answer {
			if other.Header().Rrtype == rrtype && dns.CanonicalName(other.Header().Name) == dns.CanonicalName(c.Target) {
				return ""
			}
		}
		return dns.CanonicalName(c.Target)
	}
	return ""
}

// aliasRecords returns the CNAME (and any DNAME) records for qname.
func aliasRecords(msg *dns.Msg, qname string) []dns.RR {
	var out []dns.RR
	for _, rr := range msg.Answer {
		switch rr.(type) {
		case *dns.CNAME, *dns.DNAME:
			out = append(out, rr)
		default:
			_ = rr
		}
	}
	_ = qname
	return out
}

// resolveOnce walks delegations from the root to the servers for qname and
// returns their answer. It does not follow CNAMEs.
func (rs *resolution) resolveOnce(qname string, rrtype uint16) (*dns.Msg, string, error) {
	if cached, ok := rs.r.cache.GetMsg(qname, rrtype); ok {
		rs.r.stats.CacheHits++
		rs.step(Step{Zone: "", QName: qname, QType: rrtype, Kind: "cached"})
		return cached, "", nil
	}
	rs.r.stats.CacheMiss++

	zone, servers, err := rs.startingPoint(qname)
	if err != nil {
		return nil, "", err
	}

	for depth := 0; depth <= rs.r.cfg.Limits.MaxDelegations; depth++ {
		msg, err := rs.askZone(zone, servers, qname, rrtype)
		if err != nil {
			return nil, "", err
		}

		child, ns, glue, isReferral := rs.classifyReferral(zone, qname, msg)
		if !isReferral {
			rs.r.cache.PutMsg(qname, rrtype, msg)
			return msg, zone, nil
		}

		next, err := rs.serversFor(child, ns, glue, 0)
		if err != nil {
			return nil, "", err
		}
		rs.dels = append(rs.dels, Delegation{Parent: zone, Child: child, NS: ns})
		rs.r.cache.PutDelegation(child, ns, glue)
		zone, servers = child, next
	}
	return nil, "", fmt.Errorf("%w: more than %d delegations for %s",
		ErrLimit, rs.r.cfg.Limits.MaxDelegations, qname)
}

// startingPoint returns the deepest zone cut already known for qname, so a
// resolution does not walk from the root every time.
func (rs *resolution) startingPoint(qname string) (string, []netip.AddrPort, error) {
	if zone, addrs, ok := rs.r.cache.BestDelegation(qname); ok && len(addrs) > 0 {
		return zone, addrs, nil
	}
	addrs, err := rs.r.rootServers(rs.ctx)
	if err != nil {
		return "", nil, err
	}
	return ".", addrs, nil
}

// askZone puts one question to the servers for a zone, trying them in turn.
//
// Servers are tried in a rotated order so that one unlucky first choice is not
// permanently the first choice, and a server that fails is not retried within
// the same resolution.
func (rs *resolution) askZone(zone string, servers []netip.AddrPort, qname string, rrtype uint16) (*dns.Msg, error) {
	if len(servers) == 0 {
		return nil, fmt.Errorf("%w: no servers for %s", ErrNoReachableServer, zone)
	}

	askName, askType := qname, rrtype
	if *rs.r.cfg.QnameMinimisation {
		askName, askType = minimisedQuestion(zone, qname, rrtype)
	}

	var lastErr error
	for _, server := range servers {
		if err := rs.ctx.Err(); err != nil {
			return nil, err
		}
		if rs.queries >= rs.r.cfg.Limits.MaxQueries {
			return nil, fmt.Errorf("%w: more than %d queries for %s",
				ErrLimit, rs.r.cfg.Limits.MaxQueries, qname)
		}
		if !rs.r.targetAllowed(server.Addr()) {
			continue
		}

		started := rs.r.now()
		rs.queries++
		rs.r.stats.Queries++
		msg, err := rs.r.ex.Exchange(rs.ctx, server, query(askName, askType, rs.r.cfg.UDPSize))
		elapsed := rs.r.now().Sub(started)
		if err != nil {
			rs.r.stats.Failures++
			if errors.Is(err, ErrMismatchedReply) {
				rs.r.stats.Mismatched++
			}
			lastErr = err
			rs.step(Step{Zone: zone, Server: server.String(), QName: askName, QType: askType,
				Kind: "error", Detail: err.Error(), Elapsed: elapsed})
			continue
		}

		// A server that answers SERVFAIL or REFUSED for a zone it was
		// delegated is lame. Try the next one rather than reporting the
		// zone broken on one server's word.
		if msg.Rcode == dns.RcodeServerFailure || msg.Rcode == dns.RcodeRefused {
			lastErr = fmt.Errorf("%w: %s answered %s for %s",
				ErrLame, server, dns.RcodeToString[msg.Rcode], zone)
			rs.step(Step{Zone: zone, Server: server.String(), QName: askName, QType: askType,
				Kind: "error", Detail: dns.RcodeToString[msg.Rcode], Elapsed: elapsed})
			continue
		}

		// Under QNAME minimisation an empty NOERROR for an intermediate
		// name means "this name exists and has no records of that type",
		// which is not an answer to the client's question — it means keep
		// descending. Retry unminimised at this level so the caller sees a
		// real answer or a real referral.
		if askName != qname && isEmptyNoData(msg) {
			rs.step(Step{Zone: zone, Server: server.String(), QName: askName, QType: askType,
				Kind: "nodata", Detail: "minimised probe: descending", Elapsed: elapsed})
			rs.queries++
			rs.r.stats.Queries++
			full, ferr := rs.r.ex.Exchange(rs.ctx, server, query(qname, rrtype, rs.r.cfg.UDPSize))
			if ferr != nil {
				lastErr = ferr
				continue
			}
			msg = full
		}

		rs.step(Step{Zone: zone, Server: server.String(), QName: askName, QType: askType,
			Kind: describe(msg), Detail: summarise(msg), Elapsed: elapsed})
		return msg, nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("%w: %s", ErrNoReachableServer, zone)
	}
	return nil, lastErr
}

// classifyReferral decides whether msg is a referral, and if so to where.
//
// A referral is a NOERROR with no answer whose authority section carries NS
// records for a zone strictly below the one asked. Everything else — an
// answer, a NODATA, an NXDOMAIN, or an authority section pointing sideways or
// upwards — terminates the walk.
func (rs *resolution) classifyReferral(zone, qname string, msg *dns.Msg) (child string, ns []string, glue map[string][]netip.Addr, ok bool) {
	if msg.Rcode != dns.RcodeSuccess || len(msg.Answer) > 0 || msg.Authoritative {
		return "", nil, nil, false
	}

	names := map[string]bool{}
	var child0 string
	for _, rr := range msg.Ns {
		nsrr, isNS := rr.(*dns.NS)
		if !isNS {
			continue
		}
		owner := dns.CanonicalName(nsrr.Hdr.Name)

		// The delegated zone must be strictly below the zone we asked, and
		// at or above the name we are looking for. A referral that fails
		// either is not a step towards an answer: downwards-only is what
		// terminates the walk, and covering qname is what stops a server
		// sending the resolver off to an unrelated part of the tree.
		if !strictlyBelow(zone, owner) || !inBailiwick(owner, qname) {
			continue
		}
		if child0 == "" {
			child0 = owner
		}
		if owner != child0 {
			continue
		}
		if len(names) >= rs.r.cfg.Limits.MaxNSPerZone {
			break
		}
		names[dns.CanonicalName(nsrr.Ns)] = true
	}
	if child0 == "" || len(names) == 0 {
		return "", nil, nil, false
	}

	out := make([]string, 0, len(names))
	for n := range names {
		out = append(out, n)
	}
	sort.Strings(out)
	return child0, out, acceptableGlue(child0, names, msg.Extra), true
}

// serversFor turns a referral's nameserver names into addresses.
//
// Glue is used where the parent was entitled to supply it. Anything else is
// resolved as a fresh question, which is the only safe way to learn the
// address of an out-of-bailiwick nameserver: the parent has no authority over
// that name and its word for it would be an invitation to redirect the
// resolver anywhere.
func (rs *resolution) serversFor(zone string, ns []string, glue map[string][]netip.Addr, depth int) ([]netip.AddrPort, error) {
	var out []netip.AddrPort
	add := func(addrs []netip.Addr) {
		for i, a := range addrs {
			if i >= rs.r.cfg.Limits.MaxAddrsPerNS {
				break
			}
			if !rs.r.targetAllowed(a) {
				continue
			}
			out = append(out, netip.AddrPortFrom(a, 53))
		}
	}

	for _, name := range ns {
		add(glue[name])
	}
	if len(out) > 0 {
		return out, nil
	}

	// No usable glue. Every name here has to be resolved, and that is a
	// recursion: bounded, because a hierarchy can be built where each
	// nameserver name needs another lookup for ever.
	if depth >= rs.r.cfg.Limits.MaxNSResolutionDepth {
		return nil, fmt.Errorf("%w: nameserver resolution deeper than %d for %s",
			ErrLimit, rs.r.cfg.Limits.MaxNSResolutionDepth, zone)
	}
	for _, name := range ns {
		if addrs, ok := rs.r.cache.GetAddrs(name); ok {
			add(addrs)
			continue
		}
		for _, t := range []uint16{dns.TypeA, dns.TypeAAAA} {
			if rs.queries >= rs.r.cfg.Limits.MaxQueries {
				break
			}
			msg, _, err := rs.resolveOnce(name, t)
			if err != nil {
				continue
			}
			var addrs []netip.Addr
			for _, rr := range msg.Answer {
				if addr, ok := addrFromRR(rr); ok && dns.CanonicalName(rr.Header().Name) == name {
					addrs = append(addrs, addr)
				}
			}
			if len(addrs) > 0 {
				rs.r.cache.PutAddrs(name, addrs, msgTTL(msg))
				add(addrs)
			}
		}
		if len(out) > 0 {
			break
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no address for any nameserver of %s", ErrNoReachableServer, zone)
	}
	return out, nil
}

func (rs *resolution) step(s Step) {
	// Bounded: a trace is a diagnostic, and an unbounded one is a way to
	// spend memory on a name that refers downwards for ever.
	if len(rs.trace) < 256 {
		rs.trace = append(rs.trace, s)
	}
}

// targetAllowed applies the non-global address rule, with the laboratory
// escape hatch.
func (r *Resolver) targetAllowed(addr netip.Addr) bool {
	if r.cfg.AllowNonGlobalTargets {
		return addr.IsValid()
	}
	return usableTarget(addr)
}

func addrFromRR(rr dns.RR) (netip.Addr, bool) {
	switch v := rr.(type) {
	case *dns.A:
		a, ok := netip.AddrFromSlice(v.A.To4())
		return a, ok
	case *dns.AAAA:
		a, ok := netip.AddrFromSlice(v.AAAA.To16())
		return a.Unmap(), ok
	}
	return netip.Addr{}, false
}

func isEmptyNoData(msg *dns.Msg) bool {
	if msg.Rcode != dns.RcodeSuccess || len(msg.Answer) > 0 {
		return false
	}
	for _, rr := range msg.Ns {
		if _, ok := rr.(*dns.NS); ok {
			return false
		}
	}
	return true
}

func describe(msg *dns.Msg) string {
	switch {
	case msg.Rcode == dns.RcodeNameError:
		return "nxdomain"
	case msg.Rcode != dns.RcodeSuccess:
		return strings.ToLower(dns.RcodeToString[msg.Rcode])
	case len(msg.Answer) > 0:
		for _, rr := range msg.Answer {
			if _, ok := rr.(*dns.CNAME); ok {
				return "cname"
			}
		}
		return "answer"
	default:
		for _, rr := range msg.Ns {
			if _, ok := rr.(*dns.NS); ok {
				return "referral"
			}
		}
		return "nodata"
	}
}

func summarise(msg *dns.Msg) string {
	switch describe(msg) {
	case "referral":
		for _, rr := range msg.Ns {
			if ns, ok := rr.(*dns.NS); ok {
				return "-> " + dns.CanonicalName(ns.Hdr.Name)
			}
		}
	case "answer", "cname":
		return fmt.Sprintf("%d record(s)", len(msg.Answer))
	}
	return ""
}

// Stats returns a snapshot of the counters.
func (r *Resolver) Stats() Stats { return r.stats }

// CacheStats exposes the cache's own counters.
func (r *Resolver) CacheStats() CacheStats { return r.cache.Stats() }
