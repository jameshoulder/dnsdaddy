// Package reclab is a deterministic authoritative DNS hierarchy for testing
// iterative resolution.
//
// The existing internal/daddybound/lab serves a whole signed hierarchy from
// one address, which is right for a validator: it answers whatever is asked
// and the validator's job is to check the signatures. It cannot exercise
// recursion, because recursion is precisely the business of being *referred*
// from one server to another.
//
// So this package runs a real DNS server per zone, each on its own loopback
// port, each authoritative for exactly its own zone and issuing referrals for
// anything below a delegation. Resolving through it exercises the same code
// that resolves through the real root — the resolver cannot tell the
// difference, which is what makes the test meaningful.
//
// Everything is on 127.0.0.1, so a resolver pointed at it must be built with
// Config.AllowNonGlobalTargets. That is the only thing tests are permitted to
// relax, and it is why that flag exists rather than a general "skip the safety
// checks" switch.
package reclab

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

// Zone is one authoritative server's contents.
type Zone struct {
	// Name is the zone apex, canonical and dot-terminated.
	Name string
	// Records are the RRs this zone is authoritative for.
	Records []dns.RR
	// Delegations maps a child zone name to the nameserver names for it.
	Delegations map[string][]string
	// Glue maps a nameserver name to the addresses this zone hands out for
	// it. A zone that supplies glue for a name outside the child being
	// delegated is doing something a resolver must reject, which is exactly
	// what some tests want it to do.
	Glue map[string][]netip.AddrPort
	// NoGlue stops the laboratory filling in addresses for this zone's
	// delegations, so a resolver has to go and resolve the nameserver names
	// for itself.
	NoGlue bool
	// Lame makes this server answer REFUSED, simulating a delegation to a
	// server that does not serve the zone.
	Lame bool
	// DropUDP makes it ignore UDP entirely, so the resolver has to fail over.
	DropUDP bool
	// TruncateUDP makes every UDP answer set TC, forcing a TCP retry.
	TruncateUDP bool
	// Rewrite lets a test corrupt an outgoing reply after it is built —
	// wrong question, wrong ID, poisoned Additional section.
	Rewrite func(req, reply *dns.Msg)

	// Answer, when set, decides the reply's contents instead of Records.
	//
	// It exists so a zone's data can come from somewhere that already knows
	// how to build a signed one. This package can construct referrals and
	// NODATA and NXDOMAIN, and deliberately cannot construct an RRSIG, an
	// NSEC chain or a signed DS — internal/daddybound/lab does all of that,
	// and duplicating it here would mean a resolver tested against zones
	// signed by a second implementation of the same rules.
	//
	// Glue is still this package's business: lab knows nameserver names and
	// has no idea what address anything listens on, so the addresses are
	// filled in afterwards from Delegations. See Signed.
	Answer func(qname string, qtype uint16, do bool) Reply
}

// Reply is what a Zone.Answer callback produces.
//
// Authoritative is carried explicitly rather than inferred. A referral and a
// NODATA both have an empty answer section and differ in exactly this bit,
// and guessing it from the authority section's contents would make the
// laboratory's idea of a referral disagree with the resolver's on precisely
// the cases worth testing.
type Reply struct {
	Rcode         int
	Answer        []dns.RR
	Authority     []dns.RR
	Extra         []dns.RR
	Authoritative bool
}

// Hierarchy is a running set of authoritative servers.
type Hierarchy struct {
	mu      sync.Mutex
	servers map[string]*server
	queries []Query

	// synthetic maps the address a zone advertises in glue to the address its
	// server actually listens on.
	//
	// Glue records carry an address and no port: port 53 is implied by the
	// protocol. A test cannot bind port 53, so each zone advertises a
	// distinct 127.0.0.N address and Exchanger translates it to the
	// ephemeral port the server really has. Everything above that
	// translation — referral handling, glue acceptance, bailiwick, the DNS
	// wire format, real UDP and TCP sockets — is the production path
	// unchanged.
	synthetic map[netip.Addr]netip.AddrPort
	next      byte

	// writeErrs records replies the laboratory could not send.
	writeErrs []string
}

// WriteErrors returns replies the laboratory failed to send. A test that sees
// an unexplained timeout should check this first.
func (h *Hierarchy) WriteErrors() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.writeErrs...)
}

// Query records one question a resolver asked, and of whom.
//
// The record exists because "did the resolver leak the full name to the root?"
// is a question about what was sent, and the only honest way to answer it is
// to look.
type Query struct {
	Zone  string
	Name  string
	Type  uint16
	Proto string
}

func (q Query) String() string {
	return fmt.Sprintf("%-16s <- %-32s %s/%s", q.Zone, q.Name, dns.TypeToString[q.Type], q.Proto)
}

type server struct {
	zone Zone
	udp  *dns.Server
	tcp  *dns.Server
	addr netip.AddrPort
	// advertised is the 127.0.0.N address this zone appears at in glue.
	advertised netip.Addr
	h          *Hierarchy
}

// Start brings up one server per zone and returns the hierarchy.
func Start(t *testing.T, zones ...Zone) *Hierarchy {
	t.Helper()

	h := &Hierarchy{
		servers:   map[string]*server{},
		synthetic: map[netip.Addr]netip.AddrPort{},
		next:      1,
	}
	for _, z := range zones {
		z.Name = dns.CanonicalName(z.Name)
		s := &server{zone: z, h: h}
		s.start(t)
		s.advertised = h.assign(s.addr)
		h.servers[z.Name] = s
	}
	h.wireGlue()
	t.Cleanup(h.Stop)
	return h
}

// wireGlue fills in the addresses a parent hands out for its children.
//
// A delegation names its child's nameservers; the addresses are glue the
// parent supplies. In a laboratory those addresses are not known until the
// child's server is listening, so they are filled in here rather than being
// written into each test by hand. A zone that sets Glue explicitly keeps it,
// which is how the hostile cases — out-of-bailiwick glue, glue for a name
// that was never delegated — are written.
func (h *Hierarchy) wireGlue() {
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, s := range h.servers {
		if s.zone.NoGlue {
			continue
		}
		for child, names := range s.zone.Delegations {
			target, ok := h.servers[dns.CanonicalName(child)]
			if !ok {
				continue
			}
			if s.zone.Glue == nil {
				s.zone.Glue = map[string][]netip.AddrPort{}
			}
			for _, n := range names {
				n = dns.CanonicalName(n)
				if len(s.zone.Glue[n]) > 0 {
					continue
				}
				s.zone.Glue[n] = []netip.AddrPort{
					netip.AddrPortFrom(target.advertised, 53),
				}
			}
		}
	}
}

// assign gives a real listener a synthetic advertised address.
func (h *Hierarchy) assign(real netip.AddrPort) netip.Addr {
	h.mu.Lock()
	defer h.mu.Unlock()
	addr := netip.AddrFrom4([4]byte{127, 0, 0, h.next})
	h.next++
	if h.next == 0 {
		panic("reclab: too many zones")
	}
	h.synthetic[addr] = real
	return addr
}

// Exchanger returns a transport that speaks real DNS to the laboratory.
//
// It differs from production in exactly one respect: an advertised 127.0.0.N
// address is translated to the ephemeral port that zone's server is really
// listening on. Real sockets, real wire format, real truncation and TCP
// retry — only the port lookup is synthetic, because a test cannot bind 53.
func (h *Hierarchy) Exchanger(inner recursiveExchanger) recursiveExchanger {
	return &translating{h: h, inner: inner}
}

// recursiveExchanger mirrors recursive.Exchanger without importing it, which
// would be circular: the recursive package's tests import this one.
type recursiveExchanger interface {
	Exchange(ctx context.Context, server netip.AddrPort, m *dns.Msg) (*dns.Msg, error)
}

type translating struct {
	h     *Hierarchy
	inner recursiveExchanger
}

func (t *translating) Exchange(ctx context.Context, server netip.AddrPort, m *dns.Msg) (*dns.Msg, error) {
	t.h.mu.Lock()
	real, ok := t.h.synthetic[server.Addr()]
	t.h.mu.Unlock()
	if ok {
		server = real
	}
	return t.inner.Exchange(ctx, server, m)
}

// Addr returns the address a zone advertises, for a parent's glue or for the
// resolver's root hints. It is the synthetic 127.0.0.N address, which
// Exchanger translates back to the real listener.
func (h *Hierarchy) Addr(zone string) netip.AddrPort {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.servers[dns.CanonicalName(zone)]
	if !ok {
		panic("reclab: no server for zone " + zone)
	}
	return netip.AddrPortFrom(s.advertised, 53)
}

// Queries returns every question asked, in order.
func (h *Hierarchy) Queries() []Query {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]Query(nil), h.queries...)
}

// QueriesTo returns the questions asked of one zone's server.
func (h *Hierarchy) QueriesTo(zone string) []Query {
	z := dns.CanonicalName(zone)
	var out []Query
	for _, q := range h.Queries() {
		if q.Zone == z {
			out = append(out, q)
		}
	}
	return out
}

// Stop shuts every server down.
func (h *Hierarchy) Stop() {
	h.mu.Lock()
	servers := make([]*server, 0, len(h.servers))
	for _, s := range h.servers {
		servers = append(servers, s)
	}
	h.servers = map[string]*server{}
	h.mu.Unlock()

	for _, s := range servers {
		if s.udp != nil {
			_ = s.udp.Shutdown()
		}
		if s.tcp != nil {
			_ = s.tcp.Shutdown()
		}
	}
}

func (s *server) start(t *testing.T) {
	t.Helper()

	pc, ln := bindPair(t)
	ap, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("reclab: parse addr: %v", err)
	}
	s.addr = ap

	started := make(chan struct{}, 2)
	s.udp = &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(s.serve("udp")),
		NotifyStartedFunc: func() { started <- struct{}{} }}
	s.tcp = &dns.Server{Listener: ln, Handler: dns.HandlerFunc(s.serve("tcp")),
		NotifyStartedFunc: func() { started <- struct{}{} }}
	go func() { _ = s.udp.ActivateAndServe() }()
	go func() { _ = s.tcp.ActivateAndServe() }()
	<-started
	<-started
}

// bindPair takes the same ephemeral port number on TCP and UDP.
//
// A DNS server listens on one port over both protocols, and a resolver retries
// over TCP when an answer is truncated — which signed answers carrying keys and
// signatures do routinely. So the two have to match.
//
// The retry is not defensive padding. TCP and UDP have separate port spaces:
// asking the kernel for an ephemeral port on one says nothing about whether the
// same number is free on the other, so binding one and then the other is a race
// against everything else on the machine. It lost, as "bind: address already in
// use" inside a resolution test that reads like a resolver fault rather than a
// harness one. internal/daddybound/lab hit the same thing and solved it the
// same way; this is that fix, here.
//
// TCP first because it is the scarcer of the two — listening sockets linger in
// TIME_WAIT, and far more software on a shared runner wants a TCP port than a
// UDP one. Choosing the number from the scarcer space makes the second bind the
// one likely to succeed.
func bindPair(t *testing.T) (net.PacketConn, net.Listener) {
	t.Helper()

	const attempts = 16
	var lastErr error
	for i := 0; i < attempts; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("reclab: listen tcp: %v", err)
		}
		pc, err := net.ListenPacket("udp", ln.Addr().String())
		if err == nil {
			return pc, ln
		}
		lastErr = err
		_ = ln.Close()
	}
	t.Fatalf("reclab: could not bind udp and tcp on one loopback port in %d attempts: %v",
		attempts, lastErr)
	return nil, nil
}

func (s *server) serve(proto string) func(dns.ResponseWriter, *dns.Msg) {
	return func(w dns.ResponseWriter, req *dns.Msg) {
		if len(req.Question) != 1 {
			return
		}
		q := req.Question[0]
		name := dns.CanonicalName(q.Name)

		s.h.mu.Lock()
		s.h.queries = append(s.h.queries, Query{Zone: s.zone.Name, Name: name, Type: q.Qtype, Proto: proto})
		s.h.mu.Unlock()

		if s.zone.DropUDP && proto == "udp" {
			return
		}

		reply := s.answer(req, name, q.Qtype)
		if s.zone.TruncateUDP && proto == "udp" {
			reply.Truncated = true
			reply.Answer, reply.Ns, reply.Extra = nil, nil, nil
		}
		if s.zone.Rewrite != nil {
			s.zone.Rewrite(req, reply)
		}
		if err := w.WriteMsg(reply); err != nil {
			// Recorded rather than discarded. A laboratory server that fails
			// to answer looks exactly like a network timeout from the
			// resolver's side, and chasing that costs far more than the
			// bookkeeping here: an unpackable SOA once cost two seconds per
			// test and looked like a resolver bug.
			s.h.mu.Lock()
			s.h.writeErrs = append(s.h.writeErrs, fmt.Sprintf("%s: %v", s.zone.Name, err))
			s.h.mu.Unlock()
		}
	}
}

func (s *server) answer(req *dns.Msg, name string, qtype uint16) *dns.Msg {
	reply := new(dns.Msg)
	reply.SetReply(req)
	reply.RecursionAvailable = false
	// Signed answers carry keys and signatures and do not fit in 512 octets.
	// Without echoing an OPT record the library truncates every one of them,
	// which reads as a broken zone rather than as a missing EDNS option.
	if opt := req.IsEdns0(); opt != nil {
		reply.SetEdns0(4096, opt.Do())
	}

	if s.zone.Lame {
		reply.Rcode = dns.RcodeRefused
		return reply
	}

	if s.zone.Answer != nil {
		do := false
		if opt := req.IsEdns0(); opt != nil {
			do = opt.Do()
		}
		r := s.zone.Answer(name, qtype, do)
		reply.Rcode = r.Rcode
		reply.Answer = r.Answer
		reply.Ns = r.Authority
		reply.Extra = append(reply.Extra, r.Extra...)
		reply.Authoritative = r.Authoritative
		s.attachGlue(reply)
		return reply
	}

	// Delegated? Refer, deepest delegation first so a nested hierarchy works.
	if child, ns, ok := s.delegationFor(name); ok {
		reply.Authoritative = false
		for _, n := range ns {
			reply.Ns = append(reply.Ns, &dns.NS{
				Hdr: dns.RR_Header{Name: child, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
				Ns:  n,
			})
			for _, ap := range s.zone.Glue[n] {
				reply.Extra = append(reply.Extra, glueRR(n, ap.Addr()))
			}
		}
		return reply
	}

	reply.Authoritative = true
	for _, rr := range s.zone.Records {
		if dns.CanonicalName(rr.Header().Name) != name {
			continue
		}
		if rr.Header().Rrtype == qtype || rr.Header().Rrtype == dns.TypeCNAME {
			reply.Answer = append(reply.Answer, dns.Copy(rr))
		}
	}
	if len(reply.Answer) > 0 {
		// A real server ships the addresses of any nameservers it names, so
		// a priming answer for "." carries the root servers' addresses. A
		// laboratory that omitted them would make root priming untestable.
		for _, rr := range reply.Answer {
			ns, ok := rr.(*dns.NS)
			if !ok {
				continue
			}
			target := dns.CanonicalName(ns.Ns)
			for _, cand := range s.zone.Records {
				if dns.CanonicalName(cand.Header().Name) != target {
					continue
				}
				switch cand.(type) {
				case *dns.A, *dns.AAAA:
					reply.Extra = append(reply.Extra, dns.Copy(cand))
				}
			}
		}
		return reply
	}

	// No records of that type. NXDOMAIN if the name has none at all,
	// otherwise an empty NOERROR with the zone's SOA, as a real server does.
	exists := false
	for _, rr := range s.zone.Records {
		if dns.CanonicalName(rr.Header().Name) == name {
			exists = true
			break
		}
	}
	if !exists && !strings.HasSuffix(name, s.zone.Name) {
		reply.Rcode = dns.RcodeRefused
		return reply
	}
	if !exists {
		reply.Rcode = dns.RcodeNameError
	}
	reply.Ns = append(reply.Ns, soa(s.zone.Name))
	return reply
}

// attachGlue fills in the addresses for nameservers this zone refers to.
//
// A referral built from zone data names its nameservers and cannot know where
// they listen: an address belongs to a running server, and the zone was
// written before one existed. This is the join, and it is the same in-bailiwick
// glue a real parent publishes — an address for a name inside the child being
// delegated, because nothing else could supply it.
func (s *server) attachGlue(reply *dns.Msg) {
	have := map[string]bool{}
	for _, rr := range reply.Extra {
		switch rr.(type) {
		case *dns.A, *dns.AAAA:
			have[dns.CanonicalName(rr.Header().Name)] = true
		}
	}
	for _, rr := range reply.Ns {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		target := dns.CanonicalName(ns.Ns)
		if have[target] {
			continue
		}
		for _, ap := range s.zone.Glue[target] {
			reply.Extra = append(reply.Extra, glueRR(target, ap.Addr()))
			have[target] = true
		}
	}
}

// delegationFor finds the deepest delegation covering name.
func (s *server) delegationFor(name string) (string, []string, bool) {
	best := ""
	for child := range s.zone.Delegations {
		c := dns.CanonicalName(child)
		if c == name || strings.HasSuffix(name, "."+c) {
			if len(c) > len(best) {
				best = c
			}
		}
	}
	if best == "" {
		return "", nil, false
	}
	return best, s.zone.Delegations[best], true
}

func glueRR(name string, addr netip.Addr) dns.RR {
	if addr.Is4() {
		return &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
			A:   addr.AsSlice(),
		}
	}
	return &dns.AAAA{
		Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 3600},
		AAAA: addr.AsSlice(),
	}
}

func soa(zone string) dns.RR {
	// "ns." + "." is "ns..", which is not a domain name and does not pack.
	// The root needs its own spelling; getting this wrong produced a
	// laboratory server that answered nothing and looked like a network
	// timeout.
	ns, mbox := "ns."+zone, "hostmaster."+zone
	if zone == "." {
		ns, mbox = "ns.", "hostmaster."
	}
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:      ns,
		Mbox:    mbox,
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  300,
	}
}

// A builds an address record, for test hierarchies.
func A(name, addr string) dns.RR {
	return &dns.A{
		Hdr: dns.RR_Header{Name: dns.CanonicalName(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
		A:   netip.MustParseAddr(addr).AsSlice(),
	}
}

// CNAME builds an alias record.
func CNAME(name, target string) dns.RR {
	return &dns.CNAME{
		Hdr:    dns.RR_Header{Name: dns.CanonicalName(name), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 3600},
		Target: dns.CanonicalName(target),
	}
}
