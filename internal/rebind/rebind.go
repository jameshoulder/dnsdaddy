// Package rebind decides whether an address may leave this resolver.
//
// The threat is classic DNS rebinding ([T8]): a name the operator's browser
// treats as a public origin answers with a private, loopback, or link-local
// address, so a page loaded from that origin can reach a service that was only
// ever exposed to the local network. The router's admin page, a database
// bound to 127.0.0.1, a cloud instance's metadata endpoint at 169.254.169.254.
// Nothing about the DNS is malformed — the answer is a perfectly valid A
// record — which is why no amount of DNSSEC or upstream trust prevents it.
//
// This is the first engine in DNS Daddy that withholds part of an answer. The
// upstream may happily return 10.0.0.1; the decision about whether that
// reaches the client is ours.
//
// # What is inspected
//
// A and AAAA records in the answer and additional sections, and the
// ipv4hint / ipv6hint parameters of SVCB and HTTPS records. The hints matter
// as much as the address records: browsers query HTTPS records and will
// connect to a hinted address before any A lookup happens, so a filter that
// ignored them would leave the control fully bypassable by a zone that
// publishes an HTTPS record.
//
// # What is not
//
// Addresses embedded in record types that are not address records — a TXT
// record containing "10.0.0.1", an SRV target that later resolves to one.
// The first is not something a client connects to; the second is a separate
// lookup, and that lookup is filtered when it happens.
//
// [T8]: ../../docs/threat-model.md
package rebind

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

// Class labels why an address was filtered. It is a small closed set because
// it ends up as a Prometheus label, and a label taken from anything an
// attacker chooses is an unbounded cardinality explosion.
type Class string

const (
	ClassPrivate     Class = "private"
	ClassLoopback    Class = "loopback"
	ClassLinkLocal   Class = "link_local"
	ClassULA         Class = "ula"
	ClassCGNAT       Class = "cgnat"
	ClassUnspecified Class = "unspecified"
	ClassOther       Class = "other"
)

// Classes is every class that can appear, so metrics can be emitted at zero
// rather than springing into existence on the first occurrence.
func Classes() []Class {
	return []Class{ClassPrivate, ClassLoopback, ClassLinkLocal, ClassULA, ClassCGNAT, ClassUnspecified, ClassOther}
}

// EmptyAction is what a client sees when every address in an answer was
// filtered. Each is a different contract and the operator picks deliberately.
type EmptyAction string

const (
	// EmptyNoData answers NOERROR with no records: "this name exists and has
	// no address you may have". The default, because it is true.
	EmptyNoData EmptyAction = "nodata"
	// EmptyNXDOMAIN answers "this name does not exist", which is a lie that
	// some clients cache harder and that hides the filtering from anyone
	// debugging it. Offered because some operators prefer the bluntness.
	EmptyNXDOMAIN EmptyAction = "nxdomain"
	// EmptyRefused answers REFUSED: "I will not answer this". The most honest
	// about the fact that a decision was made, and the most likely to make a
	// stub resolver try another server.
	EmptyRefused EmptyAction = "refused"
)

// DefaultRangeStrings is the shipped filter list, in the form an operator
// would write it.
//
// 100.64.0.0/10 is included and is the entry most likely to be questioned. It
// is RFC 6598 carrier-grade NAT space: never globally routable, and on a
// deployment behind CGNAT — a home connection on a modern ISP, or a Tailscale
// network — it addresses machines on the operator's own side of the boundary
// exactly as 10/8 does. A public name answering with one is the same attack.
// Operators who use that space for something they genuinely want to reach by
// public name exempt it per policy.
var DefaultRangeStrings = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"0.0.0.0/8",
	"100.64.0.0/10",
	"::1/128",
	"::/128",
	"fc00::/7",
	"fe80::/10",
}

// DefaultRanges parses DefaultRangeStrings. The list is a constant, so a parse
// failure is a programming error rather than a configuration one.
func DefaultRanges() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(DefaultRangeStrings))
	for _, s := range DefaultRangeStrings {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

// Config describes the filter.
type Config struct {
	// Ranges are the address ranges that must not reach a client. Replacing
	// rather than extending the defaults is deliberate: an operator who has
	// thought about this hard enough to edit the list should get the list they
	// wrote, not the list they wrote plus assumptions.
	Ranges []netip.Prefix
	// EmptyAction is what the client sees when everything was filtered.
	EmptyAction EmptyAction
}

// Filter is the compiled answer policy. It holds no per-query state, so one
// instance serves every query on the resolver concurrently.
//
// A nil *Filter filters nothing, so "switched off" is a nil pointer rather
// than a filter configured to permit everything — there is no arithmetic to
// get wrong when the feature is off.
type Filter struct {
	ranges      []netip.Prefix
	emptyAction EmptyAction
}

// New compiles a Config.
//
// An empty range list is an error rather than a filter that permits
// everything. "Enabled, and filtering nothing" is the worst state this package
// can be in: it protects nobody while presenting as a control, which is how an
// operator comes to believe a machine is unreachable when it is not.
func New(cfg Config) (*Filter, error) {
	if len(cfg.Ranges) == 0 {
		return nil, fmt.Errorf("rebinding filter has no ranges; it would filter nothing while appearing to be on")
	}
	switch cfg.EmptyAction {
	case EmptyNoData, EmptyNXDOMAIN, EmptyRefused:
	default:
		return nil, fmt.Errorf("unknown empty_action %q, want %q, %q or %q",
			cfg.EmptyAction, EmptyNoData, EmptyNXDOMAIN, EmptyRefused)
	}

	ranges := make([]netip.Prefix, 0, len(cfg.Ranges))
	for _, p := range cfg.Ranges {
		if p.IsValid() {
			ranges = append(ranges, p.Masked())
		}
	}
	if len(ranges) == 0 {
		return nil, fmt.Errorf("rebinding filter has no valid ranges")
	}
	return &Filter{ranges: ranges, emptyAction: cfg.EmptyAction}, nil
}

// Ranges returns the compiled filter list, for diagnostics.
func (f *Filter) Ranges() []netip.Prefix {
	if f == nil {
		return nil
	}
	return append([]netip.Prefix(nil), f.ranges...)
}

// EmptyAction returns what a fully filtered answer becomes, for diagnostics.
func (f *Filter) EmptyAction() EmptyAction {
	if f == nil {
		return ""
	}
	return f.emptyAction
}

// Exemptions is a set of ranges a policy is willing to receive anyway.
//
// Split-horizon DNS is ordinary: office.example.com resolving to 10.1.2.3 on
// the office network is the configuration working, not an attack. Without an
// escape hatch this control could not be on by default, so the escape hatch is
// part of the design rather than a concession to it.
type Exemptions []netip.Prefix

// ParseExemptions compiles operator-written CIDRs.
//
// A default route is refused. Exempting 0.0.0.0/0 or ::/0 turns the filter off
// for that policy while leaving every status display saying it is on, which is
// strictly worse than switching it off: an operator who switched it off knows
// they did. There is also no split-horizon deployment that needs it — "every
// address in the world is internal to us" is not a network.
func ParseExemptions(cidrs []string) (Exemptions, error) {
	var out Exemptions
	for _, raw := range cidrs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("rebinding exemption %q is not a CIDR: %w", raw, err)
		}
		if p.Bits() == 0 {
			return nil, fmt.Errorf("rebinding exemption %q exempts every address, which would disable the filter "+
				"while leaving it reported as on; exempt the ranges you actually use", raw)
		}
		if p.Addr() != p.Masked().Addr() {
			return nil, fmt.Errorf("rebinding exemption %q has host bits set; write %s", raw, p.Masked())
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// MustExemptions is ParseExemptions for tests and constants.
func MustExemptions(cidrs ...string) Exemptions {
	e, err := ParseExemptions(cidrs)
	if err != nil {
		panic(err)
	}
	return e
}

// Covers reports whether addr is exempt.
//
// A zero-length prefix is ignored here as well as rejected at parse time. The
// two belong together: the parse check stops one being written, and this stops
// one that reached the database another way — an older binary, a hand-edited
// row — from silently disabling the filter.
func (e Exemptions) Covers(addr netip.Addr) bool {
	for _, p := range e {
		if p.Bits() == 0 {
			continue
		}
		if p.Addr().Is4() != addr.Is4() {
			continue
		}
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// Strings renders the set for diagnostics and reasons.
func (e Exemptions) Strings() []string {
	out := make([]string, 0, len(e))
	for _, p := range e {
		out = append(out, p.String())
	}
	return out
}

// Removed records one address that did not reach the client.
type Removed struct {
	// Name is the owner of the record the address came from.
	Name string
	// Addr is the address, normalised: an IPv4-mapped IPv6 address is recorded
	// as the IPv4 address it embeds, because that is what a client would have
	// connected to.
	Addr netip.Addr
	// Range is the filter range that matched.
	Range netip.Prefix
	// Class is the coarse reason, for metrics.
	Class Class
}

// Result describes what the filter did to one message.
type Result struct {
	// Changed is whether anything was removed.
	Changed bool
	// Emptied is whether the answer had addresses and now has none, so
	// EmptyAction was applied.
	Emptied bool
	// Removed lists what went, for the query log.
	Removed []Removed
	// Action is the empty action applied, empty unless Emptied.
	Action EmptyAction
}

// Reason is a sentence for the query log, naming the address, the range that
// matched, and the policy that did not exempt it.
//
// Written for somebody reading it back to a user over the phone, which is the
// same standard the rest of the query log's reasons are held to: an operator
// whose intranet stopped working needs to be told which address was withheld
// and which policy to exempt it on, not that "a filter applied".
func (r Result) Reason(policyID string) string {
	if len(r.Removed) == 0 {
		return ""
	}
	first := r.Removed[0]
	var b strings.Builder
	b.WriteString("Answer contained ")
	b.WriteString(first.Addr.String())
	b.WriteString(", which is in the filtered range ")
	b.WriteString(first.Range.String())
	if len(r.Removed) > 1 {
		fmt.Fprintf(&b, " (and %d other filtered address(es))", len(r.Removed)-1)
	}
	if policyID != "" {
		b.WriteString(", and policy ")
		b.WriteString(policyID)
		b.WriteString(" does not exempt it")
	}
	if r.Emptied {
		b.WriteString("; no usable address remained")
	}
	return b.String()
}

// Apply filters msg in place and reports what it did.
//
// In place, and that is safe because of a property of the packages upstream of
// here rather than an accident: resolver.Cache.Get returns a deep copy and
// resolver.reattach copies again, so the message handed to a caller is never
// shared with the cache or with another concurrent query. TestTheCachedAnswer
// IsNeverMutated in internal/dnsserver pins that, because if it ever stopped
// being true this function would quietly corrupt the cache for every client.
func (f *Filter) Apply(msg *dns.Msg, exempt Exemptions) Result {
	if f == nil || msg == nil {
		return Result{}
	}
	// An error response carries no addresses, and rewriting one into something
	// else would be inventing a failure that did not happen.
	if msg.Rcode != dns.RcodeSuccess {
		return Result{}
	}

	var res Result
	hadAddress := countAddresses(msg.Answer) > 0

	msg.Answer, res.Removed = f.sweep(msg.Answer, exempt, res.Removed)
	msg.Extra, res.Removed = f.sweep(msg.Extra, exempt, res.Removed)
	res.Changed = len(res.Removed) > 0

	// Emptied is about address records only. Stripping an SVCB hint leaves a
	// usable record behind — the client falls back to A and AAAA — so treating
	// that as an emptied answer would turn a working lookup into a fabricated
	// NXDOMAIN.
	if hadAddress && countAddresses(msg.Answer) == 0 {
		res.Emptied = true
		res.Action = f.emptyAction
		f.empty(msg)
	}
	return res
}

// empty applies the configured action to a message whose addresses have all
// been filtered.
//
// The answer section is cleared completely, including any CNAME. A client left
// holding an alias whose only addresses were withheld has been handed a broken
// answer with no error in it: it will follow the chain, find nothing, and hang
// rather than fail. Clearing the section makes the outcome the one the
// operator configured.
func (f *Filter) empty(msg *dns.Msg) {
	msg.Answer = nil
	msg.Extra = keepOPT(msg.Extra)
	switch f.emptyAction {
	case EmptyNXDOMAIN:
		msg.Rcode = dns.RcodeNameError
	case EmptyRefused:
		msg.Rcode = dns.RcodeRefused
	default:
		msg.Rcode = dns.RcodeSuccess
	}
}

// sweep removes filtered addresses from one section, appending what it removed.
func (f *Filter) sweep(rrs []dns.RR, exempt Exemptions, removed []Removed) ([]dns.RR, []Removed) {
	if len(rrs) == 0 {
		return rrs, removed
	}
	out := rrs[:0]
	for _, rr := range rrs {
		switch v := rr.(type) {
		case *dns.A:
			if addr, ok := f.judge(v.A, exempt); ok {
				removed = append(removed, record(v.Hdr.Name, addr, f.match(addr)))
				continue
			}
		case *dns.AAAA:
			if addr, ok := f.judge(v.AAAA, exempt); ok {
				removed = append(removed, record(v.Hdr.Name, addr, f.match(addr)))
				continue
			}
		case *dns.SVCB:
			removed = f.sweepHints(v.Hdr.Name, &v.Value, exempt, removed)
		case *dns.HTTPS:
			removed = f.sweepHints(v.Hdr.Name, &v.Value, exempt, removed)
		}
		out = append(out, rr)
	}
	// The tail of the backing array still references the dropped records;
	// clearing it lets them be collected rather than pinned by a slice that
	// outlives the query.
	for i := len(out); i < len(rrs); i++ {
		rrs[i] = nil
	}
	return out, removed
}

// sweepHints filters the address hints on an SVCB or HTTPS record.
//
// A hint list that loses every address has the parameter removed rather than
// left empty: an empty hint list is not what a zone would publish, and some
// clients treat the parameter's presence as meaningful.
func (f *Filter) sweepHints(name string, values *[]dns.SVCBKeyValue, exempt Exemptions, removed []Removed) []Removed {
	kept := (*values)[:0]
	for _, kv := range *values {
		switch h := kv.(type) {
		case *dns.SVCBIPv4Hint:
			var keep []net.IP
			for _, ip := range h.Hint {
				if addr, ok := f.judge(ip, exempt); ok {
					removed = append(removed, record(name, addr, f.match(addr)))
					continue
				}
				keep = append(keep, ip)
			}
			if len(keep) == 0 {
				continue
			}
			h.Hint = keep
		case *dns.SVCBIPv6Hint:
			var keep []net.IP
			for _, ip := range h.Hint {
				if addr, ok := f.judge(ip, exempt); ok {
					removed = append(removed, record(name, addr, f.match(addr)))
					continue
				}
				keep = append(keep, ip)
			}
			if len(keep) == 0 {
				continue
			}
			h.Hint = keep
		}
		kept = append(kept, kv)
	}
	for i := len(kept); i < len(*values); i++ {
		(*values)[i] = nil
	}
	*values = kept
	return removed
}

// judge normalises a wire address and reports whether it must be withheld.
func (f *Filter) judge(ip net.IP, exempt Exemptions) (netip.Addr, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		// A record whose address bytes are not an address is not something to
		// pass through: it cannot be judged, and anything a client does with
		// it is undefined.
		return netip.Addr{}, true
	}
	addr = normalise(addr)
	if !f.filtered(addr) {
		return addr, false
	}
	if exempt.Covers(addr) {
		return addr, false
	}
	return addr, true
}

// normalise unwraps an IPv4-mapped IPv6 address and drops any zone.
//
// ::ffff:10.0.0.1 is 10.0.0.1 as far as a client's socket is concerned, so
// comparing it against the IPv6 ranges alone would let every filtered IPv4
// range through by writing it in IPv6 notation.
func normalise(addr netip.Addr) netip.Addr {
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	return addr.WithZone("")
}

func (f *Filter) filtered(addr netip.Addr) bool {
	return f.match(addr).IsValid()
}

// match returns the filter range containing addr, or the zero prefix.
func (f *Filter) match(addr netip.Addr) netip.Prefix {
	if !addr.IsValid() {
		return netip.Prefix{}
	}
	for _, p := range f.ranges {
		if p.Addr().Is4() != addr.Is4() {
			continue
		}
		if p.Contains(addr) {
			return p
		}
	}
	return netip.Prefix{}
}

func record(name string, addr netip.Addr, p netip.Prefix) Removed {
	return Removed{Name: strings.TrimSuffix(name, "."), Addr: addr, Range: p, Class: classify(addr, p)}
}

// classify reduces an address to the small label set metrics use.
//
// Derived from the address rather than from which configured range matched,
// so an operator who edits the range list still gets meaningful labels — and
// so the label set stays closed whatever they write.
func classify(addr netip.Addr, p netip.Prefix) Class {
	switch {
	case !addr.IsValid():
		return ClassOther
	case addr.IsUnspecified():
		return ClassUnspecified
	case addr.IsLoopback():
		return ClassLoopback
	case addr.IsLinkLocalUnicast(), addr.IsLinkLocalMulticast():
		return ClassLinkLocal
	case addr.Is4() && cgnat.Contains(addr):
		return ClassCGNAT
	case !addr.Is4() && ula.Contains(addr):
		return ClassULA
	case addr.IsPrivate():
		return ClassPrivate
	case addr.Is4() && unspecifiedV4.Contains(addr):
		// 0.0.0.0/8 beyond 0.0.0.0 itself: "this network", never a
		// destination.
		return ClassUnspecified
	case p.IsValid():
		return ClassOther
	default:
		return ClassOther
	}
}

var (
	cgnat         = netip.MustParsePrefix("100.64.0.0/10")
	ula           = netip.MustParsePrefix("fc00::/7")
	unspecifiedV4 = netip.MustParsePrefix("0.0.0.0/8")
)

func countAddresses(rrs []dns.RR) int {
	n := 0
	for _, rr := range rrs {
		switch rr.(type) {
		case *dns.A, *dns.AAAA:
			n++
		}
	}
	return n
}

// keepOPT strips a section down to its OPT record.
//
// EDNS0 lives in the additional section. Clearing that section wholesale when
// an answer is emptied would drop the OPT record with it, which silently
// downgrades the client's advertised buffer size and its DO bit — breaking
// large answers and DNSSEC-aware clients for a reason that has nothing to do
// with either.
func keepOPT(rrs []dns.RR) []dns.RR {
	out := rrs[:0]
	for _, rr := range rrs {
		if _, ok := rr.(*dns.OPT); ok {
			out = append(out, rr)
		}
	}
	for i := len(out); i < len(rrs); i++ {
		rrs[i] = nil
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
