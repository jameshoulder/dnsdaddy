package lab

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Server serves a Hierarchy over real DNS on loopback.
//
// It exists so that a reference validator — which speaks DNS and nothing else
// — can be pointed at exactly the same records Daddybound validated in
// memory. A differential comparison is only evidence if both sides saw the
// same bytes; two separately constructed copies of "the same" zone would make
// every disagreement ambiguous.
type Server struct {
	udp  *dns.Server
	tcp  *dns.Server
	addr string

	closeOnce sync.Once

	// mu guards queries, which records what a validator actually asked for.
	//
	// It is here because "what does this validator know about zone cuts" is
	// otherwise a matter of opinion. A DNSSEC disagreement between two
	// implementations usually turns on what each one looked up, and the only
	// way to settle that is to look at the queries rather than to reason
	// about what they ought to have sent.
	mu      sync.Mutex
	queries []Query
}

// Query is one question a validator asked.
type Query struct {
	Name   string
	Type   uint16
	DOBit  bool
	Rcode  int
	Answer int
}

// String renders a query for a test log.
func (q Query) String() string {
	return fmt.Sprintf("%-34s %-7s -> %s (%d records)",
		q.Name, dns.TypeToString[q.Type], dns.RcodeToString[q.Rcode], q.Answer)
}

// StartServer binds UDP and TCP on an ephemeral loopback port and serves h.
//
// Both protocols, because a validator retries over TCP when an answer is
// truncated, and DNSSEC answers carrying keys and signatures truncate
// routinely.
func (h *Hierarchy) StartServer() (*Server, error) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("lab: listen udp: %w", err)
	}
	addr := pc.LocalAddr().String()

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		_ = pc.Close()
		return nil, fmt.Errorf("lab: listen tcp on %s: %w", addr, err)
	}

	s := &Server{addr: addr}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		h.answer(s, w, req)
	})
	s.udp = &dns.Server{PacketConn: pc, Handler: handler}
	s.tcp = &dns.Server{Listener: ln, Handler: handler}

	if err := s.startBoth(); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

func (s *Server) startBoth() error {
	for _, srv := range []*dns.Server{s.udp, s.tcp} {
		started := make(chan struct{})
		srv.NotifyStartedFunc = func() { close(started) }
		go srv.ActivateAndServe() //nolint:errcheck // reported by Close
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			return fmt.Errorf("lab: %s listener did not start on %s", srv.Net, s.addr)
		}
	}
	return nil
}

// Addr is the host:port both listeners share.
func (s *Server) Addr() string { return s.addr }

// Queries returns everything asked of this server so far, in order.
func (s *Server) Queries() []Query {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Query(nil), s.queries...)
}

// Asked reports whether a validator looked up one specific (name, type).
func (s *Server) Asked(name string, rrtype uint16) bool {
	want := dns.CanonicalName(name)
	for _, q := range s.Queries() {
		if q.Name == want && q.Type == rrtype {
			return true
		}
	}
	return false
}

func (s *Server) record(q Query) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queries = append(s.queries, q)
}

// Close shuts both listeners down. Safe to call more than once.
func (s *Server) Close() error {
	var err error
	s.closeOnce.Do(func() {
		if s.udp != nil {
			if e := s.udp.Shutdown(); e != nil {
				err = e
			}
		}
		if s.tcp != nil {
			if e := s.tcp.Shutdown(); e != nil && err == nil {
				err = e
			}
		}
	})
	return err
}

// answer serves one query from the hierarchy, recording what was asked.
func (h *Hierarchy) answer(s *Server, w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	// Recursion available, because a validator under test is usually pointed
	// here as a forwarder rather than as an authoritative server, and will
	// discard answers from a server that says it cannot recurse.
	m.RecursionAvailable = true

	// Signatures and keys make answers large, so the response has to say how
	// much it can send. Without this the library caps at 512 octets and a
	// DNSKEY RRset with its signature is truncated on every query — which
	// looks like a broken zone rather than a missing EDNS option.
	if opt := req.IsEdns0(); opt != nil {
		m.SetEdns0(4096, opt.Do())
	}
	if len(req.Question) != 1 {
		m.Rcode = dns.RcodeFormatError
		writeOrServfail(w, m)
		return
	}

	q := req.Question[0]
	// Canonicalised, because a validator that randomises query case
	// (0x20 encoding) sends names whose casing differs from the zone's. An
	// exact string match here answers NXDOMAIN for every such query, and the
	// resulting failure looks like a validation bug rather than a harness
	// one. This has caught out an earlier iteration of this harness, which
	// is why it is a comment rather than just a function call.
	name := dns.CanonicalName(q.Name)

	records := h.sets[setKey{name: name, rrtype: q.Qtype}]
	wantDNSSEC := false
	if opt := req.IsEdns0(); opt != nil {
		wantDNSSEC = opt.Do()
	}

	if len(records) > 0 {
		m.Answer = filterSignatures(records, wantDNSSEC)
		s.record(Query{Name: name, Type: q.Qtype, DOBit: wantDNSSEC, Rcode: m.Rcode, Answer: len(m.Answer)})
		writeOrServfail(w, m)
		return
	}

	// No data of that type. Whether the name exists at all decides between
	// NODATA and NXDOMAIN, and the enclosing zone's SOA goes in the
	// authority section either way so the asker can tell a real absence from
	// a broken server.
	zone := h.enclosingZone(name)
	if zone != nil {
		if soa := zone.sets[setKey{name: zone.Name, rrtype: dns.TypeSOA}]; len(soa) > 0 {
			m.Ns = filterSignatures(soa, wantDNSSEC)
		}
	}
	if !h.nameExists(name) {
		m.Rcode = dns.RcodeNameError
	}
	s.record(Query{Name: name, Type: q.Qtype, DOBit: wantDNSSEC, Rcode: m.Rcode, Answer: 0})
	writeOrServfail(w, m)
}

// writeOrServfail sends the response, falling back to SERVFAIL if it cannot
// be packed.
//
// Dropping the response instead — which is what ignoring WriteMsg's error
// amounts to — makes a scenario the lab cannot serialise look like a
// scenario the validator under test was slow about. That cost seventeen
// seconds of retries and one misattributed disagreement before it was
// noticed. An explicit SERVFAIL says "this harness could not answer", which
// is a different sentence from "this validator could not decide".
func writeOrServfail(w dns.ResponseWriter, m *dns.Msg) {
	if err := w.WriteMsg(m); err == nil {
		return
	}
	fail := new(dns.Msg)
	fail.SetRcode(m, dns.RcodeServerFailure)
	_ = w.WriteMsg(fail)
}

// filterSignatures drops RRSIGs when the asker did not set DO.
func filterSignatures(records []dns.RR, wantDNSSEC bool) []dns.RR {
	if wantDNSSEC {
		return append([]dns.RR{}, records...)
	}
	out := make([]dns.RR, 0, len(records))
	for _, rr := range records {
		if _, isSig := rr.(*dns.RRSIG); !isSig {
			out = append(out, rr)
		}
	}
	return out
}

// nameExists reports whether the hierarchy holds any record at name.
func (h *Hierarchy) nameExists(name string) bool {
	for k := range h.sets {
		if k.name == name {
			return true
		}
	}
	return false
}

// enclosingZone returns the deepest zone that contains name.
func (h *Hierarchy) enclosingZone(name string) *Zone {
	var best *Zone
	for _, z := range h.Zones {
		if !dns.IsSubDomain(z.Name, name) {
			continue
		}
		if best == nil || dns.CountLabel(z.Name) > dns.CountLabel(best.Name) {
			best = z
		}
	}
	return best
}

// AnchorDS renders the hierarchy's trust anchor in the DS presentation form a
// reference validator accepts in a trust-anchor file or configuration option.
func (h *Hierarchy) AnchorDS() string {
	return fmt.Sprintf("%s IN DS %d %d %d %X",
		h.Anchor.Name, h.Anchor.KeyTag, h.Anchor.Algorithm, h.Anchor.DigestType, h.Anchor.Digest)
}
