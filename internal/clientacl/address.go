package clientacl

import "net/netip"

// privateRanges is the address space that is not reachable from the public
// internet, and so needs no acknowledgement before a network is permitted to
// use the resolver.
//
// Deliberately its own list rather than a reference to
// config.DefaultAllowedClientCIDRs. The two coincide today, but they answer
// different questions — "what does a stock install serve?" versus "is this
// address reachable from the internet?" — and tying them together would mean
// that editing the shipped default silently changed which ranges an operator
// must affirm. TestPrivateRangesMatchTheShippedDefault asserts the current
// relationship, so a divergence is a test failure to think about rather than a
// silent change of a security prompt.
var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),      // "this network" (RFC 1122)
	netip.MustParsePrefix("10.0.0.0/8"),     // RFC 1918
	netip.MustParsePrefix("127.0.0.0/8"),    // loopback
	netip.MustParsePrefix("169.254.0.0/16"), // link-local
	netip.MustParsePrefix("172.16.0.0/12"),  // RFC 1918
	netip.MustParsePrefix("192.168.0.0/16"), // RFC 1918
	netip.MustParsePrefix("100.64.0.0/10"),  // carrier-grade NAT (RFC 6598); what Tailscale hands out
	netip.MustParsePrefix("::1/128"),        // loopback
	netip.MustParsePrefix("fc00::/7"),       // unique local (RFC 4193)
	netip.MustParsePrefix("fe80::/10"),      // link-local
}

// PrefixIsPublic reports whether any address in p is reachable from the public
// internet.
//
// Erring towards "public" is deliberate. This gates a confirmation prompt, and
// the cost of asking about a range that turns out to be private is one extra
// click; the cost of not asking about one that turns out to be public is an
// operator who has opened their resolver to the internet without being told.
//
// So the documentation ranges (203.0.113.0/24 and friends) count as public.
// They are inside globally routable space, they are what every example in the
// documentation uses to stand in for a real public address, and treating them
// as private would make the examples behave differently from the thing they
// are examples of.
func PrefixIsPublic(p netip.Prefix) bool {
	if !p.IsValid() {
		return false
	}
	for _, r := range privateRanges {
		if covers(r, p) {
			return false
		}
	}
	return true
}

// AddrIsPublic reports whether a single address is reachable from the public
// internet.
func AddrIsPublic(addr netip.Addr) bool {
	addr = Normalize(addr)
	if !addr.IsValid() {
		return false
	}
	return PrefixIsPublic(netip.PrefixFrom(addr, addr.BitLen()))
}

// IsUniversal reports whether p is a default route — 0.0.0.0/0 or ::/0 —
// which as a resolver permission means "anyone on the internet".
//
// This is the one shape the dashboard will not write at any level of
// confirmation. The project already has an authority for "I intend to run a
// public resolver": dns.allow_public_resolver, set in configuration, where
// changing it is a deliberate act with a restart attached. Adding a second,
// easier route to the same outcome through a web form would make that control
// decorative — an open resolver is found and conscripted into amplification
// attacks within days, and by then it is the operator's address in the abuse
// report.
func IsUniversal(p netip.Prefix) bool { return p.IsValid() && p.Bits() == 0 }

// CoversEntireFamily reports whether prefixes between them admit every address
// of IPv4, or every address of IPv6.
//
// IsUniversal only recognises a literal default route, which is one spelling of
// an open resolver out of many. 0.0.0.0/1 and 128.0.0.0/1 each pass it and
// together admit the whole internet, and there is nothing special about halves:
// any complete tiling does it. The dashboard refuses to create an open
// resolver, so it has to refuse every way of writing one.
//
// Sibling merging rather than interval arithmetic, so IPv6 needs no 128-bit
// integers: absorb any prefix another already contains, then repeatedly replace
// a pair of siblings with their parent. A set that tiles the family collapses
// to /0; one that does not cannot.
func CoversEntireFamily(prefixes []netip.Prefix) bool {
	return coversFamily(prefixes, true) || coversFamily(prefixes, false)
}

// coversFamily reports whether prefixes for the selected family merge to a
// default route. It ignores invalid prefixes and IPv4-mapped prefixes shorter
// than /96; other mapped prefixes are treated as IPv4.
func coversFamily(prefixes []netip.Prefix, v4 bool) bool {
	// Merge siblings as they arrive. Each merge shortens a prefix by one bit,
	// so even an adversarial list takes O(n * addressBits), not repeated
	// pairwise rescans under the network configuration write lock.
	set := make(map[netip.Prefix]struct{}, len(prefixes))
	for _, p := range prefixes {
		if !p.IsValid() {
			continue
		}
		if p.Addr().Is4In6() {
			if p.Bits() < 96 {
				continue
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		p = p.Masked()
		if p.Addr().Is4() != v4 {
			continue
		}
		for {
			if p.Bits() == 0 {
				return true
			}
			if _, exists := set[p]; exists {
				break
			}
			sib, ok := sibling(p)
			if !ok {
				break
			}
			if _, exists := set[sib]; !exists {
				set[p] = struct{}{}
				break
			}
			delete(set, sib)
			p = netip.PrefixFrom(p.Addr(), p.Bits()-1).Masked()
		}
	}
	return false
}

// sibling returns the prefix sharing p's parent: same length, last significant
// bit flipped.
func sibling(p netip.Prefix) (netip.Prefix, bool) {
	if p.Bits() == 0 {
		return netip.Prefix{}, false
	}
	bit := p.Bits() - 1
	if p.Addr().Is4() {
		b := p.Addr().As4()
		b[bit/8] ^= 1 << (7 - bit%8)
		return netip.PrefixFrom(netip.AddrFrom4(b), p.Bits()).Masked(), true
	}
	b := p.Addr().As16()
	b[bit/8] ^= 1 << (7 - bit%8)
	return netip.PrefixFrom(netip.AddrFrom16(b), p.Bits()).Masked(), true
}
