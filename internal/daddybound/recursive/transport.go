package recursive

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Exchanger sends one question to one authoritative server.
//
// An interface so the resolver can be driven by a laboratory that never opens
// a socket, and so the real transport can be tested for its own properties
// without a resolver wrapped around it.
type Exchanger interface {
	Exchange(ctx context.Context, server netip.AddrPort, m *dns.Msg) (*dns.Msg, error)
}

// NewNetExchanger builds the production transport.
//
// Exported so the deterministic laboratory can wrap it rather than substitute
// for it: the lab needs to translate an advertised address to an ephemeral
// port, and everything else — UDP, EDNS, truncation, the TCP retry, reply
// matching — must be the code that runs in production or the tests prove
// nothing about it.
func NewNetExchanger(timeout time.Duration, udpSize uint16, allowNonGlobal bool) Exchanger {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	if udpSize == 0 {
		udpSize = 1232
	}
	return &netExchanger{
		udpTimeout:     timeout,
		tcpTimeout:     timeout,
		udpSize:        udpSize,
		allowNonGlobal: allowNonGlobal,
	}
}

// ErrMismatchedReply is returned when a reply does not correspond to the
// question that was asked.
//
// Its own error rather than a generic failure because it is the signature of
// an off-path spoofing attempt, and a resolver that cannot distinguish "the
// server said no" from "somebody else answered for it" cannot report the
// difference either.
var ErrMismatchedReply = errors.New("reply does not match the question sent")

// netExchanger talks to authoritative servers over ordinary port 53 DNS.
//
// Plain DNS is not an oversight. Native recursion to authoritative servers is
// UDP and TCP on port 53; there is no DoT or DoH to an authoritative server to
// speak, and pretending otherwise would be a marketing claim rather than a
// transport. Confidentiality on this path comes from QNAME minimisation
// (qmin.go), which reduces what each level is told rather than encrypting what
// it is told.
type netExchanger struct {
	udpTimeout time.Duration
	tcpTimeout time.Duration
	udpSize    uint16
	// allowNonGlobal mirrors Config.AllowNonGlobalTargets. The check lives
	// here as well as at the call sites because this is the function that
	// opens the socket — the last place it can be made, and the only one a
	// new caller cannot forget.
	allowNonGlobal bool
}

// Exchange sends m to server and returns a reply that has been checked against
// the question.
//
// On a truncated UDP answer it retries over TCP, which is ordinary rather than
// exceptional: a signed answer carrying keys and signatures does not fit in a
// UDP datagram often enough that a resolver without TCP is not a resolver.
func (e *netExchanger) Exchange(ctx context.Context, server netip.AddrPort, m *dns.Msg) (*dns.Msg, error) {
	// Refused here as well as at the call sites. This is the function that
	// actually opens the socket, so it is the last place the check can be
	// made and the only one that cannot be bypassed by a new caller.
	if !e.allowNonGlobal && !usableTarget(server.Addr()) {
		return nil, fmt.Errorf("refusing to contact non-global address %s", server.Addr())
	}

	q := m.Copy()
	// A fresh random ID per attempt. miekg/dns seeds these from crypto/rand;
	// what matters here is that a retry never reuses the previous ID, so an
	// attacker who saw one query cannot answer the next.
	q.Id = dns.Id()

	reply, err := e.exchange(ctx, "udp", server, q)
	if err != nil {
		return nil, err
	}
	if !reply.Truncated {
		return reply, nil
	}

	q.Id = dns.Id()
	reply, err = e.exchange(ctx, "tcp", server, q)
	if err != nil {
		return nil, fmt.Errorf("tcp retry after truncation: %w", err)
	}
	return reply, nil
}

func (e *netExchanger) exchange(ctx context.Context, network string, server netip.AddrPort, q *dns.Msg) (*dns.Msg, error) {
	timeout := e.udpTimeout
	if network == "tcp" {
		timeout = e.tcpTimeout
	}
	c := &dns.Client{
		Net:          network,
		Timeout:      timeout,
		DialTimeout:  timeout,
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
	}
	if network == "udp" {
		// The advertised size caps what an authoritative server may send in
		// one datagram. Larger is fewer TCP retries; too large invites
		// fragmentation, which is itself a spoofing aid. 1232 is the value
		// the DNS flag-day guidance settled on as fitting a 1280-octet IPv6
		// MTU with headers.
		c.UDPSize = e.udpSize
	}

	reply, _, err := c.ExchangeContext(ctx, q, server.String())
	if err != nil {
		return nil, err
	}
	if reply == nil {
		return nil, errors.New("empty reply")
	}
	if err := matchesQuestion(q, reply); err != nil {
		return nil, err
	}
	return reply, nil
}

// matchesQuestion checks a reply against the query it claims to answer.
//
// Three things, all cheap and all necessary. The ID and the echoed question
// are what an off-path attacker has to guess to inject a reply, and a resolver
// that skips either accepts the first packet to arrive. The QR bit is the
// difference between an answer and somebody else's question arriving on our
// socket.
//
// Case-insensitive on the name, because a server may echo the question in a
// different case and several deliberately randomise it.
func matchesQuestion(q, reply *dns.Msg) error {
	if reply.Id != q.Id {
		return fmt.Errorf("%w: id %d, want %d", ErrMismatchedReply, reply.Id, q.Id)
	}
	if !reply.Response {
		return fmt.Errorf("%w: QR bit not set", ErrMismatchedReply)
	}
	if len(reply.Question) != len(q.Question) {
		return fmt.Errorf("%w: %d questions, want %d", ErrMismatchedReply, len(reply.Question), len(q.Question))
	}
	for i, want := range q.Question {
		got := reply.Question[i]
		if got.Qtype != want.Qtype || got.Qclass != want.Qclass ||
			!strings.EqualFold(dns.CanonicalName(got.Name), dns.CanonicalName(want.Name)) {
			return fmt.Errorf("%w: answered %s %s, asked %s %s", ErrMismatchedReply,
				got.Name, dns.TypeToString[got.Qtype], want.Name, dns.TypeToString[want.Qtype])
		}
	}
	return nil
}

// query builds an outgoing question with the EDNS(0) options native recursion
// needs.
//
// DO is set on every query: the validator needs RRSIG, NSEC and NSEC3 records
// and there is no second chance to ask for them. CD is *not* set — that flag
// is a request to a validating resolver, and we are talking to authoritative
// servers, which do not validate anything on our behalf.
//
// No EDNS Client Subnet. Sending it would hand every authoritative server on
// the path a piece of the client's network identity for a latency benefit DNS
// Daddy has not asked for, and it is not something to switch on by default.
func query(name string, rrtype uint16, udpSize uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), rrtype)
	// Authoritative servers do not recurse, and asking them to is a mark of a
	// broken resolver that some of them log or refuse.
	m.RecursionDesired = false
	m.SetEdns0(udpSize, true)
	return m
}
