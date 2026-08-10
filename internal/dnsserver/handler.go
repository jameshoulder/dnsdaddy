// Package dnsserver exposes the resolver over UDP, TCP, DNS-over-TLS, and
// DNS-over-HTTPS.
package dnsserver

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/blocklist"
	"github.com/jameshoulder/dnsdaddy/internal/domainutil"
	"github.com/jameshoulder/dnsdaddy/internal/policy"
	"github.com/jameshoulder/dnsdaddy/internal/querylog"
	"github.com/jameshoulder/dnsdaddy/internal/resolver"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// Handler answers DNS questions: it attributes the client to a network, applies
// that network's policy, and either synthesises a block response or forwards
// the question upstream.
type Handler struct {
	engine   *policy.Engine
	resolver *resolver.Resolver
	lists    *blocklist.Holder
	qlog     *querylog.Logger
	log      *slog.Logger

	logClientIP     bool
	queryLogEnabled bool
	refuseANY       bool
	timeout         time.Duration

	// allowedClients restricts which source addresses may resolve at all.
	// Empty means no restriction; config.validateNotAnOpenResolver refuses to
	// start with a public listener and an empty list unless the operator has
	// explicitly opted in.
	allowedClients []netip.Prefix

	queries atomic.Uint64
	blocked atomic.Uint64
	errors  atomic.Uint64
	refused atomic.Uint64
}

// HandlerOptions configures a Handler.
type HandlerOptions struct {
	LogClientIP bool
	// QueryLogEnabled is the global privacy switch (config.Logging.QueryLog).
	// It is ANDed with the per-policy LogQueries flag: either one turning
	// persistence off is enough — a policy cannot opt back into logging that
	// the operator has disabled instance-wide.
	QueryLogEnabled bool
	Timeout         time.Duration
	// AllowedClients restricts which source addresses may resolve.
	AllowedClients []netip.Prefix
	// RefuseANY answers ANY queries locally per RFC 8482 rather than
	// forwarding them.
	RefuseANY bool
}

// NewHandler wires the resolution path together.
func NewHandler(
	engine *policy.Engine,
	res *resolver.Resolver,
	lists *blocklist.Holder,
	qlog *querylog.Logger,
	log *slog.Logger,
	o HandlerOptions,
) *Handler {
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Handler{
		engine:          engine,
		resolver:        res,
		lists:           lists,
		qlog:            qlog,
		log:             log,
		logClientIP:     o.LogClientIP,
		queryLogEnabled: o.QueryLogEnabled,
		refuseANY:       o.RefuseANY,
		allowedClients:  o.AllowedClients,
		timeout:         timeout,
	}
}

// clientAllowed reports whether a source address may use this resolver.
//
// An address we could not parse is allowed through: that only happens for
// transports where the peer is identified some other way (a DoH token), and
// failing those closed would break roaming clients for no security gain.
func (h *Handler) clientAllowed(addr netip.Addr) bool {
	if len(h.allowedClients) == 0 || !addr.IsValid() {
		return true
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	for _, p := range h.allowedClients {
		if p.Addr().Is4() != addr.Is4() {
			continue
		}
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// RefusedClients returns how many queries were rejected by the client ACL.
func (h *Handler) RefusedClients() uint64 { return h.refused.Load() }

// maxPresentationNameLen bounds the qname we are willing to process. RFC 1035
// caps a name at 253 bytes on the wire; presentation-form escaping can expand
// each byte to four characters, so this leaves generous headroom while still
// refusing names that exist only to make us do work.
const maxPresentationNameLen = 1024

// requestMeta describes where a query arrived from.
type requestMeta struct {
	clientAddr netip.Addr
	proto      string
	// networkID, when set, overrides IP-based attribution. DoH and DoT clients
	// present a per-network token, which is the only way to attribute a roaming
	// laptop on a coffee-shop IP to the right policy.
	networkID string
}

// ServeDNS implements dns.Handler for the UDP, TCP, and DoT listeners.
func (h *Handler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	meta := requestMeta{proto: "udp"}
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		meta.proto = "tcp"
	}
	if ap, err := netip.ParseAddrPort(w.RemoteAddr().String()); err == nil {
		meta.clientAddr = ap.Addr()
	}
	if tokenNetwork, ok := w.(networkIdentified); ok {
		meta.networkID = tokenNetwork.NetworkID()
		meta.proto = "dot"
	}

	resp := h.Handle(context.Background(), req, meta)
	if resp == nil {
		return
	}
	// Respect the client's advertised UDP buffer so we set TC correctly rather
	// than emitting a datagram the client cannot receive.
	if meta.proto == "udp" {
		resp.Truncate(udpSize(req, w))
	}
	if err := w.WriteMsg(resp); err != nil {
		h.log.Debug("write dns response", "error", err)
	}
}

// networkIdentified is implemented by listeners that know which network a
// connection belongs to before the query arrives.
type networkIdentified interface {
	NetworkID() string
}

// Handle resolves one message and returns the response to send.
func (h *Handler) Handle(ctx context.Context, req *dns.Msg, meta requestMeta) *dns.Msg {
	if req == nil || len(req.Question) == 0 {
		return errorResponse(req, dns.RcodeFormatError)
	}
	// Only standard queries in the IN class are ours to answer.
	if req.Opcode != dns.OpcodeQuery {
		return errorResponse(req, dns.RcodeNotImplemented)
	}
	if len(req.Question) != 1 {
		// A crafted message could carry a clean first question — the one
		// policy evaluates — alongside a second, different one that would
		// otherwise ride upstream unevaluated. Almost no real resolver sends
		// more than one question per message, so refusing costs nothing.
		return errorResponse(req, dns.RcodeFormatError)
	}
	if req.Question[0].Qclass != dns.ClassINET {
		return errorResponse(req, dns.RcodeNotImplemented)
	}

	// The client ACL is checked before any other work, and deliberately does
	// not write a query-log row: an unauthorised source could otherwise fill
	// the log (and the disk) with entries the operator never asked for. The
	// refusal is counted for /metrics instead.
	if meta.networkID == "" && !h.clientAllowed(meta.clientAddr) {
		h.refused.Add(1)
		return errorResponse(req, dns.RcodeRefused)
	}

	// RFC 8482: answer ANY with a minimal synthesised response rather than
	// forwarding it. ANY replies are large, which makes them the classic
	// amplification lever, and essentially nothing legitimate depends on them.
	if h.refuseANY && req.Question[0].Qtype == dns.TypeANY {
		h.queries.Add(1)
		return rfc8482Response(req)
	}

	h.queries.Add(1)
	start := time.Now()

	q := req.Question[0]
	name := strings.TrimSuffix(strings.ToLower(q.Name), ".")

	// A DNS name is at most 253 bytes in presentation form, but escaping
	// (\255, \.) can legitimately inflate that roughly fourfold. Anything past
	// that is not a real name, and refusing it here bounds the work every
	// downstream stage does — the policy engine's suffix walk in particular
	// costs one step per byte. Found by FuzzSuffixes.
	if len(name) > maxPresentationNameLen {
		return errorResponse(req, dns.RcodeFormatError)
	}

	normalized := domainutil.Normalize(name)
	if normalized == "" {
		// Names we cannot normalise (root, malformed labels) are forwarded
		// unfiltered rather than blocked: refusing them would break edge cases
		// like the root NS query without protecting anyone.
		normalized = name
	}

	var match policy.Match
	if meta.networkID != "" {
		if m, ok := h.engine.MatchNetworkID(meta.networkID); ok {
			match = m
		} else {
			match = h.engine.MatchClient(meta.clientAddr)
		}
	} else {
		match = h.engine.MatchClient(meta.clientAddr)
	}

	decision := h.engine.Evaluate(match.PolicyID, normalized)
	// The instance-wide switch and the per-policy switch both have to agree to
	// persist a row; either one saying no is enough to keep this query out of
	// the query_log table. Statistics are unaffected either way — see
	// querylog.Logger.Record's persist parameter.
	persist := h.queryLogEnabled && decision.LogQuery

	event := store.QueryEvent{
		Time:      time.Now().UTC(),
		NetworkID: match.NetworkID,
		Domain:    normalized,
		QType:     qtypeString(q.Qtype),
		Proto:     meta.proto,
		Category:  decision.Category,
		Source:    decision.Source,
		Reason:    decision.Reason,
	}
	if h.logClientIP && meta.clientAddr.IsValid() {
		event.ClientIP = meta.clientAddr.String()
		event.ClientName = h.engine.ClientName(event.ClientIP)
	}

	if decision.Blocked {
		h.blocked.Add(1)
		event.Action = store.ActionBlocked
		event.ElapsedMS = int(time.Since(start).Milliseconds())
		h.qlog.Record(event, persist)
		return blockResponse(req, decision.BlockMode)
	}

	rctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()

	res, err := h.resolver.Resolve(rctx, req, h.lists.Generation())
	event.ElapsedMS = int(time.Since(start).Milliseconds())

	if err != nil {
		h.errors.Add(1)
		event.Action = store.ActionError
		event.Reason = "Upstream resolution failed: " + err.Error()
		h.qlog.Record(event, persist)
		h.log.Debug("resolution failed", "domain", normalized, "error", err)
		return errorResponse(req, dns.RcodeServerFailure)
	}

	event.Action = store.ActionAllowed
	event.Cached = res.Cached
	if event.Reason == "" {
		event.Reason = "Resolved"
	}
	h.qlog.Record(event, persist)
	return res.Msg
}

// Stats reports handler counters.
func (h *Handler) Stats() (queries, blocked, errs uint64) {
	return h.queries.Load(), h.blocked.Load(), h.errors.Load()
}

// blockResponse synthesises the answer for a blocked name.
func blockResponse(req *dns.Msg, mode store.BlockMode) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.RecursionAvailable = true

	switch mode {
	case store.BlockRefused:
		m.Rcode = dns.RcodeRefused
		return m

	case store.BlockZeroIP:
		q := req.Question[0]
		// A short TTL keeps a client from caching the block past an
		// allow-listing, so a false positive is fixed in seconds not hours.
		hdr := dns.RR_Header{Name: q.Name, Class: dns.ClassINET, Ttl: 60}
		switch q.Qtype {
		case dns.TypeA:
			hdr.Rrtype = dns.TypeA
			m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: net.IPv4zero})
		case dns.TypeAAAA:
			hdr.Rrtype = dns.TypeAAAA
			m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: net.IPv6zero})
		}
		// For any other qtype an empty NOERROR is the honest answer: we have
		// no address to null-route.
		return m

	default: // store.BlockNXDOMAIN
		m.Rcode = dns.RcodeNameError
		return m
	}
}

// rfc8482Response answers an ANY query with a single HINFO record, as RFC 8482
// specifies, instead of enumerating every record for the name.
func rfc8482Response(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.RecursionAvailable = true
	m.Answer = []dns.RR{&dns.HINFO{
		Hdr: dns.RR_Header{
			Name:   req.Question[0].Name,
			Rrtype: dns.TypeHINFO,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Cpu: "RFC8482",
	}}
	return m
}

func errorResponse(req *dns.Msg, rcode int) *dns.Msg {
	m := new(dns.Msg)
	if req != nil {
		m.SetRcode(req, rcode)
	} else {
		m.Rcode = rcode
	}
	m.RecursionAvailable = true
	return m
}

func udpSize(req *dns.Msg, w dns.ResponseWriter) int {
	if opt := req.IsEdns0(); opt != nil {
		if size := int(opt.UDPSize()); size >= dns.MinMsgSize {
			if size > dns.MaxMsgSize {
				size = dns.MaxMsgSize
			}
			return size
		}
	}
	if u, ok := w.(interface{ UDPSize() int }); ok {
		if size := u.UDPSize(); size >= dns.MinMsgSize {
			return size
		}
	}
	return dns.MinMsgSize
}

func qtypeString(t uint16) string {
	if s, ok := dns.TypeToString[t]; ok {
		return s
	}
	return "TYPE" + itoa(int(t))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
