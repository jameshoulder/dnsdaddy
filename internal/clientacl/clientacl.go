// Package clientacl decides which source addresses may query the resolver.
//
// This is deliberately a package of its own, and not a corner of the policy
// engine, because the two answer different questions and conflating them is
// the specific confusion this code exists to remove:
//
//	policy      what DNS Daddy does with a client's queries once it accepts them
//	clientacl   whether DNS Daddy accepts queries from that client at all
//
// A network added in the dashboard has always done the first. Until now it did
// not do the second, so an operator could add their network, see it listed,
// and still be answered REFUSED by a resolver that reported itself healthy on
// every other surface.
//
// # The effective ACL
//
// Two sources, combined by union:
//
//	bootstrap   dns.allowed_client_cidrs / DNSDADDY_ALLOWED_CLIENT_CIDRS.
//	            Config and environment, read once at startup. This is what
//	            headless and automated deployments set, and what existing
//	            installations already have.
//	managed     networks created in the dashboard that carry an explicit
//	            "allow this network to use DNS Daddy" permission. Stored in
//	            SQLite, changeable at runtime.
//
// Union, rather than intersection or replacement, for reasons worth stating:
//
//   - Intersection is unusable. The shipped bootstrap ACL is the private
//     ranges, so a VPS operator permitting their own public address in the
//     dashboard would be permitted nothing, which is exactly the failure this
//     work exists to fix.
//   - Replacement — migrate the environment value into the database and stop
//     reading it — makes a later edit of .env silently do nothing. That trades
//     one invisible source of truth for another, and breaks every deployment
//     whose configuration is managed by Ansible or a Compose file.
//   - Union has one rule an operator can hold in their head: a permission
//     grants, and nothing else revokes it. Each source stays separately
//     inspectable, in `dnsdaddy doctor` and at /api/v1/diagnostics.
//
// The consequence, stated plainly because it can surprise: there are no deny
// rules. A narrower network without permission does not carve a hole in a
// broader permitted range. Set.Shadowed reports exactly that situation so the
// product can say so rather than leaving it to be discovered.
//
// # An empty bootstrap ACL stays unrestricted
//
// An empty dns.allowed_client_cidrs means "refuse nothing", and config
// validation only permits it alongside loopback-only listeners or an explicit
// dns.allow_public_resolver. Adding the first dashboard permission must not
// silently convert that into "refuse everything except this one range" — that
// would narrow a running deployment's behaviour as a side effect of an
// unrelated click. So an unrestricted set stays unrestricted, permissions are
// recorded for when the ACL is populated, and the diagnostics say what is
// happening.
package clientacl

import (
	"fmt"
	"net/netip"
	"strings"
)

// Network is a configured network reduced to what admission needs.
type Network struct {
	ID   string
	Name string
	// Enabled is the network's own on/off switch. A disabled network permits
	// nothing, on the principle that "disabled" should not leave a hole open.
	Enabled bool
	// AllowResolver is the operator's explicit "allow this network to use DNS
	// Daddy". False — the default for every network that predates this
	// feature — grants nothing.
	AllowResolver bool
	CIDRs         []string
}

// prefixes returns what n contributes to the effective ACL, alongside any
// entries that did not parse.
//
// The three conditions are the whole of the rule, and they live here so that
// Compute and the "could this write change who is admitted?" question below
// cannot drift apart: a disabled network permits nothing, an unpermitted one
// permits nothing, and a permitted one with no ranges — the catch-all — has
// none to contribute. A range that fails to parse is reported rather than
// quietly permitting less than the operator wrote, but only for a network that
// would otherwise have granted something; a typo in a disabled network is not
// yet anybody's problem.
func (n Network) prefixes() (prefixes []netip.Prefix, invalid []string) {
	if !n.Enabled || !n.AllowResolver {
		return nil, nil
	}
	for _, raw := range n.CIDRs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		p, err := ParsePrefix(raw)
		if err != nil {
			invalid = append(invalid, raw)
			continue
		}
		prefixes = append(prefixes, p)
	}
	return prefixes, invalid
}

// Grant is one permitted range, carrying where it came from so a diagnostic
// can name the network an operator should go and look at.
type Grant struct {
	NetworkID   string `json:"networkId"`
	NetworkName string `json:"networkName"`
	CIDR        string `json:"cidr"`
	Public      bool   `json:"public"`
	// Source names where this range came from, ready to render:
	// `network "HQ"`, or SourceBootstrap. It exists because public exposure
	// has to be reported for both halves of the union — a headless deployment
	// that permits a public client through the environment is exposed exactly
	// as much as one that does it from the dashboard, and a warning that only
	// looked at grants told it there was no public exposure at all.
	Source string       `json:"source"`
	Prefix netip.Prefix `json:"-"`
}

// Shadow records a network that is reachable even though it was never given
// permission, because some broader permitted range already covers it.
//
// Not an error and not a fault: a /32 exists inside a permitted /24 to give
// one host a different policy, and that is a perfectly reasonable thing to
// want. It is reported because "I did not tick the box and it still works" is
// otherwise indistinguishable from a bug in the ACL.
type Shadow struct {
	NetworkID   string `json:"networkId"`
	NetworkName string `json:"networkName"`
	CIDR        string `json:"cidr"`
	// CoveredBy is the permitted range that already contains CIDR.
	CoveredBy string `json:"coveredBy"`
	// Source names where CoveredBy came from: a network's name, or
	// SourceBootstrap.
	Source string `json:"source"`
}

// SourceBootstrap names the configuration-file/environment source in evidence
// strings, so an operator knows which of the two places to go and edit.
const SourceBootstrap = "dns.allowed_client_cidrs"

// Cover describes how much of a prefix the effective ACL permits.
type Cover int

const (
	// CoverNone: no part of the prefix may resolve.
	CoverNone Cover = iota
	// CoverPartial: some of it may, and the rest is REFUSED — the state most
	// worth reporting, because it looks like intermittent breakage.
	CoverPartial
	// CoverFull: all of it may resolve.
	CoverFull
)

// Set is an immutable snapshot of the effective ACL.
//
// Built once per configuration change and read from the DNS hot path, so
// everything it needs at query time is precomputed.
type Set struct {
	unrestricted bool
	bootstrap    []netip.Prefix
	bootstrapRaw []string
	grants       []Grant
	shadowed     []Shadow
	// all is the union, deduplicated: what Allows scans.
	all []netip.Prefix
	// invalid holds entries that did not parse, so a typo is reported rather
	// than silently permitting less than the operator wrote.
	invalid []string
	// allowPublic is dns.allow_public_resolver. It changes nothing about who
	// is admitted — an empty ACL admits everyone either way — but it is the
	// difference between a deliberate public resolver and a loopback-only
	// deployment, and a diagnostic that cannot tell those apart has to hedge
	// on both.
	allowPublic bool
}

// Compute builds the effective ACL from its two sources.
//
// It never fails: a malformed entry is collected into Set.Invalid rather than
// rejecting the whole configuration, because the alternative on a reload is a
// resolver that keeps a stale ACL and says nothing. Bootstrap CIDRs are
// validated at config load, and managed CIDRs at write time, so anything
// arriving here malformed is already an anomaly worth reporting.
func Compute(bootstrapCIDRs []string, allowPublicResolver bool, networks []Network) *Set {
	s := &Set{bootstrapRaw: trimAll(bootstrapCIDRs), allowPublic: allowPublicResolver}

	for _, raw := range s.bootstrapRaw {
		p, err := ParsePrefix(raw)
		if err != nil {
			s.invalid = append(s.invalid, raw)
			continue
		}
		s.bootstrap = append(s.bootstrap, p)
	}

	for _, n := range networks {
		prefixes, invalid := n.prefixes()
		s.invalid = append(s.invalid, invalid...)
		for _, p := range prefixes {
			s.grants = append(s.grants, Grant{
				NetworkID:   n.ID,
				NetworkName: n.Name,
				CIDR:        p.String(),
				Public:      PrefixIsPublic(p),
				Source:      "network " + quoteName(n.Name),
				Prefix:      p,
			})
		}
	}

	// An empty bootstrap ACL means "refuse nothing", which config validation
	// only allows for loopback-only listeners or a deliberate public
	// resolver. Permissions are still recorded above — they are what the
	// dashboard shows and what takes effect the moment an ACL is set — but
	// they must not narrow a deployment that currently refuses nothing.
	if len(s.bootstrap) == 0 {
		s.unrestricted = true
		return s
	}

	seen := make(map[netip.Prefix]bool, len(s.bootstrap)+len(s.grants))
	for _, p := range s.bootstrap {
		if !seen[p] {
			seen[p] = true
			s.all = append(s.all, p)
		}
	}
	for _, g := range s.grants {
		if !seen[g.Prefix] {
			seen[g.Prefix] = true
			s.all = append(s.all, g.Prefix)
		}
	}

	s.shadowed = findShadowed(s, networks)
	return s
}

// findShadowed reports networks that can resolve without having been given
// permission, because a broader permitted range already covers them.
func findShadowed(s *Set, networks []Network) []Shadow {
	var out []Shadow
	for _, n := range networks {
		if !n.Enabled || n.AllowResolver {
			continue
		}
		for _, raw := range n.CIDRs {
			p, err := ParsePrefix(strings.TrimSpace(raw))
			if err != nil {
				continue
			}
			if cover, src, ok := coveringPrefix(s, p); ok {
				out = append(out, Shadow{
					NetworkID:   n.ID,
					NetworkName: n.Name,
					CIDR:        p.String(),
					CoveredBy:   cover,
					Source:      src,
				})
			}
		}
	}
	return out
}

// coveringPrefix finds a permitted range that wholly contains p, and names
// where it came from. Bootstrap is checked first so the evidence points at the
// configuration file when both could explain it — that is the source an
// operator is least likely to be looking at.
func coveringPrefix(s *Set, p netip.Prefix) (cidr, source string, ok bool) {
	for _, b := range s.bootstrap {
		if covers(b, p) {
			return b.String(), SourceBootstrap, true
		}
	}
	for _, g := range s.grants {
		if covers(g.Prefix, p) {
			return g.CIDR, "network " + quoteName(g.NetworkName), true
		}
	}
	return "", "", false
}

// quoteName renders a network name for an evidence string.
func quoteName(name string) string {
	if name == "" {
		return "(unnamed)"
	}
	return "\"" + name + "\""
}

// covers reports whether outer wholly contains inner.
func covers(outer, inner netip.Prefix) bool {
	if outer.Addr().Is4() != inner.Addr().Is4() {
		return false
	}
	return outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}

// Allows reports whether addr may use this resolver.
//
// An address we could not parse is allowed through: that only happens for
// transports where the peer is identified some other way (a DoH token), and
// failing those closed would break roaming clients for no security gain.
func (s *Set) Allows(addr netip.Addr) bool {
	if s == nil || s.unrestricted || !addr.IsValid() {
		return true
	}
	addr = Normalize(addr)
	for _, p := range s.all {
		if p.Addr().Is4() != addr.Is4() {
			continue
		}
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// Normalize puts a peer address into the form prefix matching expects.
//
// Two adjustments, both load-bearing:
//
//	Is4In6   a v4 client arriving over a dual-stack socket is reported as
//	         ::ffff:10.0.0.1, which no 10.0.0.0/8 prefix contains.
//	zone     a link-local peer is reported with a scope zone ("fe80::1%eth0"),
//	         and netip.Prefix.Contains rejects any zoned address outright
//	         because prefixes carry no zone. The zone names the interface the
//	         address was seen on, not the address's membership of a prefix, so
//	         dropping it is what makes fe80::/10 mean what it says.
//
// The limitation the second one leaves is honest: the same fe80:: address can
// exist on two interfaces, so link-local cannot be told apart by interface.
func Normalize(addr netip.Addr) netip.Addr {
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	return addr.WithZone("")
}

// Unrestricted reports whether every source address is accepted.
func (s *Set) Unrestricted() bool { return s != nil && s.unrestricted }

// AllowPublicResolver reports the operator's explicit opt-in to running a
// public resolver.
func (s *Set) AllowPublicResolver() bool { return s != nil && s.allowPublic }

// Every accessor tolerates a nil receiver. A nil Set is what a caller holding
// an unconfigured controller gets, and a diagnostic or a dashboard handler
// panicking on the way to explaining a misconfiguration would be a poor joke.
// Nil reads as "nothing configured", which is also what Allows does.

// Bootstrap returns the configured CIDRs as the operator wrote them.
func (s *Set) Bootstrap() []string {
	if s == nil {
		return nil
	}
	return append([]string(nil), s.bootstrapRaw...)
}

// Grants returns the dashboard-managed permissions.
func (s *Set) Grants() []Grant {
	if s == nil {
		return nil
	}
	return append([]Grant(nil), s.grants...)
}

// Shadowed returns networks reachable without their own permission.
func (s *Set) Shadowed() []Shadow {
	if s == nil {
		return nil
	}
	return append([]Shadow(nil), s.shadowed...)
}

// Invalid returns entries that did not parse.
func (s *Set) Invalid() []string {
	if s == nil {
		return nil
	}
	return append([]string(nil), s.invalid...)
}

// Effective returns the union that Allows scans, as strings. Empty when the
// set is unrestricted, which is not the same thing as permitting nothing —
// check Unrestricted first.
func (s *Set) Effective() []string {
	if s == nil {
		return nil
	}
	out := make([]string, 0, len(s.all))
	for _, p := range s.all {
		out = append(out, p.String())
	}
	return out
}

// PublicGrants returns every permitted range that is publicly routable,
// whichever half of the union it came from.
//
// Both halves, deliberately. An operator who sets
// DNSDADDY_ALLOWED_CLIENT_CIDRS=203.0.113.42/32 on a headless box is exposed
// to the internet exactly as much as one who ticks a box in the dashboard, and
// a warning that scanned only the dashboard told them there was no public
// exposure at all — a false negative on the one check that exists to catch
// this. Each entry names its Source so the operator knows where to go.
func (s *Set) PublicGrants() []Grant {
	if s == nil {
		return nil
	}
	var out []Grant
	for i, p := range s.bootstrap {
		if !PrefixIsPublic(p) {
			continue
		}
		// Quote the operator's own spelling where it survives, so the evidence
		// matches what they wrote in the file.
		raw := p.String()
		if i < len(s.bootstrapRaw) {
			raw = s.bootstrapRaw[i]
		}
		out = append(out, Grant{
			CIDR:   raw,
			Public: true,
			Source: SourceBootstrap,
			Prefix: p,
		})
	}
	for _, g := range s.grants {
		if g.Public {
			out = append(out, g)
		}
	}
	return out
}

// PublicPrefixes returns the distinct publicly routable ranges the effective
// ACL permits.
//
// Distinct, where PublicGrants deliberately is not. A range listed in
// dns.allowed_client_cidrs *and* ticked on a network is two things to say to
// an operator — closing it means removing it from both places — but it is one
// range, and a gauge that reported two would show public exposure doubling
// when nothing about the exposure changed.
func (s *Set) PublicPrefixes() []string {
	if s == nil {
		return nil
	}
	var (
		out  []string
		seen = map[string]bool{}
	)
	for _, g := range s.PublicGrants() {
		key := g.Prefix.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	return out
}

// Cover reports how much of p the effective ACL permits.
//
// Full coverage is decided by single-prefix containment: some permitted prefix
// is no more specific than p and contains its base address. That is sound but
// not complete — two permitted prefixes could between them cover p without
// either containing it (10.0.0.0/9 and 10.128.0.0/9 covering 10.0.0.0/8).
// Such a configuration is reported as partial rather than full, which
// over-warns in a rare case instead of under-warning in a common one.
//
// Sampling the base address alone is what this replaces, and it was wrong in a
// way that mattered: a network of 10.0.0.0/8 against an ACL of 10.0.0.0/16
// starts at a permitted address while almost every client in it is refused.
func (s *Set) Cover(p netip.Prefix) Cover {
	if s == nil {
		return CoverFull // nothing configured refuses nothing
	}
	if s.unrestricted {
		return CoverFull
	}
	if !p.IsValid() {
		return CoverNone
	}

	overlaps := false
	for _, a := range s.all {
		if a.Addr().Is4() != p.Addr().Is4() {
			continue
		}
		if a.Bits() <= p.Bits() && a.Contains(p.Addr()) {
			return CoverFull
		}
		// More specific than p: it can only cover part of it.
		if p.Contains(a.Addr()) {
			overlaps = true
		}
	}
	if overlaps {
		return CoverPartial
	}
	return CoverNone
}

// AdmissionChangesFor reports whether storing n in the state described could
// change who this snapshot admits.
//
// AdmissionChangesWithout asks the same question for removing a network
// entirely.
//
// This exists because "did the write touch a field that decides admission?" is
// the wrong question, and answering it produced two false alarms. A network
// permitted in a deployment whose bootstrap ACL is empty changes nothing —
// an unrestricted ACL refuses nobody, so a grant has nothing to add. Neither
// does one whose ranges some other permitted network, or the bootstrap list,
// already covers. In both cases a failed reload was raising "a permission you
// revoked may still be honoured", which stands until an unrelated write
// succeeds, over a change that could not have altered admission at all — and
// DELETE was answering 200 to say client access might be out of date when the
// enforced and desired sets were provably identical.
//
// The comparison is against the snapshot in force rather than against the
// database, which is what makes it the right question: if the ACL being
// enforced already admits exactly who the stored state calls for, then a
// reload failing to publish leaves nothing wrong to warn about. It also means
// a concurrent writer that has already published a snapshot including this
// change is correctly read as "in force".
//
// Coverage uses the same single-prefix containment rule as Cover, so two
// permitted halves that between them cover a range do not count as covering
// it. That errs towards "this could have changed access", which is the safe
// direction: the cost is a warning that turns out to be unnecessary, where the
// other way round is a revocation nobody is told failed.
func (s *Set) AdmissionChangesFor(n Network) bool {
	prefixes, _ := n.prefixes()
	return s.admissionChanges(n.ID, prefixes)
}

// AdmissionChangesWithout reports whether removing this network altogether
// could change who this snapshot admits.
//
// The network is identified by ID and nothing else, because what a deletion
// withdraws from the enforced ACL is exactly what this snapshot holds for it.
// An earlier version also counted the row the removing transaction returned,
// on the reasoning that the database knows what the network contributed where
// a lagging snapshot might not. That had it backwards: a grant the snapshot
// does not hold is a grant that is not being enforced, so withdrawing it
// changes nothing about who is admitted, whether the snapshot lacks it because
// a concurrent reload already applied the deletion or because an earlier
// reload failed. Counting it produced the standing "your revocation may not be
// in force" alarm for a revocation that was.
func (s *Set) AdmissionChangesWithout(networkID string) bool {
	return s.admissionChanges(networkID, nil)
}

// admissionChanges compares the admission set this snapshot enforces against
// the one it would enforce with networkID contributing exactly after.
//
// Both sets share every prefix from the bootstrap list and from other
// networks, so only the two differing contributions need testing: each prefix
// leaving has to still be covered by what remains, and each arriving has to
// have been covered already.
func (s *Set) admissionChanges(networkID string, after []netip.Prefix) bool {
	if s == nil || s.unrestricted {
		// An unrestricted ACL refuses nobody, and Compute keeps it that way no
		// matter what is permitted, so no grant can change admission.
		return false
	}

	var before []netip.Prefix
	rest := make([]netip.Prefix, 0, len(s.bootstrap)+len(s.grants))
	rest = append(rest, s.bootstrap...)
	for _, g := range s.grants {
		if g.NetworkID == networkID {
			before = append(before, g.Prefix)
			continue
		}
		rest = append(rest, g.Prefix)
	}
	if len(before) == 0 && len(after) == 0 {
		return false
	}

	// Built with their own backing arrays: rest has spare capacity, and
	// appending to it twice would have the second write clobber the first.
	afterAll := concat(rest, after)
	beforeAll := concat(rest, before)

	for _, p := range before {
		if !coveredBy(afterAll, p) {
			return true
		}
	}
	for _, p := range after {
		if !coveredBy(beforeAll, p) {
			return true
		}
	}
	return false
}

func concat(a, b []netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(a)+len(b))
	out = append(out, a...)
	return append(out, b...)
}

// coveredBy reports whether some prefix in list wholly contains p.
func coveredBy(list []netip.Prefix, p netip.Prefix) bool {
	for _, a := range list {
		if covers(a, p) {
			return true
		}
	}
	return false
}

// ServesOnlyLoopback reports that nothing but this machine itself may resolve.
//
// The one state in which "no client can use this resolver" is a true statement
// rather than a guess. It is deliberately not "no network carries a
// permission": a stock LAN install has no permissions at all and serves every
// private range perfectly well, and telling that operator their clients will
// be REFUSED is precisely the misleading message this product exists to stop
// producing.
func (s *Set) ServesOnlyLoopback() bool {
	if s == nil || s.unrestricted || len(s.all) == 0 {
		return false
	}
	for _, p := range s.all {
		if !p.Addr().IsLoopback() {
			return false
		}
	}
	return true
}

// ParsePrefix accepts a CIDR or a bare address, returning the masked prefix.
// A bare address becomes a single-host prefix, which is what people type when
// they mean "just this machine".
func ParsePrefix(raw string) (netip.Prefix, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.Prefix{}, fmt.Errorf("empty address")
	}
	if !strings.Contains(raw, "/") {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid address %q", raw)
		}
		addr = Normalize(addr)
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}
	p, err := netip.ParsePrefix(raw)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid CIDR %q", raw)
	}
	// An IPv4-mapped prefix ("::ffff:10.0.0.0/104") would never match a
	// normalised v4 peer. Unmapping the base address keeps the two comparable.
	if p.Addr().Is4In6() {
		bits := p.Bits() - 96
		if bits < 0 {
			return netip.Prefix{}, fmt.Errorf("invalid CIDR %q", raw)
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), bits)
	}
	return p.Masked(), nil
}

func trimAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if t := strings.TrimSpace(s); t != "" {
			out = append(out, t)
		}
	}
	return out
}
