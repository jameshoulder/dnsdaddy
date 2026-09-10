package recursive

import (
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

// The rules in this file are the difference between a resolver and a way to
// have arbitrary records written into your cache.
//
// A server answering for one zone can put anything it likes in any section of
// its reply. The classic attack is exactly that: ask for a name in a zone the
// attacker controls, and have the reply carry a record for a bank. Every such
// attack is defeated by one question asked consistently — *was this server
// entitled to speak about this name?* — so that question lives here rather
// than being re-derived at each call site.

// inBailiwick reports whether a server authoritative for zone may speak about
// name.
//
// "May speak about" means name is at or below zone. A server for com. may
// answer about example.com.; a server for example.com. may not answer about
// example.org., and neither may answer about the root.
//
// Both names must already be canonical.
func inBailiwick(zone, name string) bool {
	if zone == "." {
		return true
	}
	if name == zone {
		return true
	}
	// Label-aligned, not string suffix. "notexample.com." ends with
	// "example.com." and is a different zone entirely; accepting it here
	// would hand an attacker who registers notexample.com the right to speak
	// about example.com, which is the whole attack this function exists to
	// refuse.
	return strings.HasSuffix(name, "."+zone)
}

// strictlyBelow reports whether child is a proper descendant of parent, which
// is what a referral has to be.
//
// A server that answers a query for example.com. with a referral to com. — or
// to example.com. itself — is either broken or trying to walk the resolver
// back up the tree, and following either produces a loop.
func strictlyBelow(parent, child string) bool {
	if parent == child {
		return false
	}
	if parent == "." {
		return child != "."
	}
	return strings.HasSuffix(child, "."+parent)
}

// acceptableGlue filters an Additional section down to the addresses a server
// was entitled to supply.
//
// Two conditions, and both are load-bearing:
//
//   - the record's owner must be one of the nameserver names this referral
//     actually gave, so an unrelated address record cannot ride along;
//   - the owner must be inside the delegated zone, which is what "in-bailiwick
//     glue" means. A delegation of example.com. may carry addresses for
//     ns1.example.com. because nothing else can: those names live inside the
//     zone being delegated and asking for them would be circular. It may not
//     carry an address for ns1.example.org., because that name is somebody
//     else's to answer for and we can go and ask them.
//
// Out-of-bailiwick nameserver names are not rejected — they are extremely
// common and perfectly legitimate — they are simply resolved separately rather
// than believed on the word of the referring server.
func acceptableGlue(zone string, nsNames map[string]bool, extra []dns.RR) map[string][]netip.Addr {
	out := map[string][]netip.Addr{}
	for _, rr := range extra {
		var (
			owner = dns.CanonicalName(rr.Header().Name)
			addr  netip.Addr
		)
		switch v := rr.(type) {
		case *dns.A:
			a, ok := netip.AddrFromSlice(v.A.To4())
			if !ok {
				continue
			}
			addr = a
		case *dns.AAAA:
			a, ok := netip.AddrFromSlice(v.AAAA.To16())
			if !ok {
				continue
			}
			addr = a
		default:
			continue
		}
		if !nsNames[owner] {
			continue
		}
		if !inBailiwick(zone, owner) {
			continue
		}
		out[owner] = append(out[owner], addr.Unmap())
	}
	return out
}

// usableTarget reports whether a nameserver address may be contacted while
// resolving a public name.
//
// A delegation is data supplied by whoever runs the parent zone, and following
// it means opening a connection to an address of their choosing. Left
// unchecked that turns the resolver into a probe for whatever is reachable
// from the machine it runs on: an attacker publishes ns1.evil.example with a
// 127.0.0.1 or 10.0.0.1 address, asks DNS Daddy to resolve a name under it,
// and learns from the timing what is listening there.
//
// So non-global addresses are refused as authoritative-server targets. This
// bounds a real capability rather than a theoretical one, and it is
// deliberately a property of *recursion into the public DNS* — if DNS Daddy
// later serves local or split-horizon zones, that is a separate configured
// path with its own rules and not something a hostile public delegation should
// be able to reach by accident.
func usableTarget(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	switch {
	case addr.IsUnspecified(),
		addr.IsLoopback(),
		addr.IsPrivate(),
		addr.IsLinkLocalUnicast(),
		addr.IsLinkLocalMulticast(),
		addr.IsInterfaceLocalMulticast(),
		addr.IsMulticast():
		return false
	}
	// Ranges netip does not classify but which are not somewhere a public
	// authoritative server lives either.
	if addr.Is4() {
		b := addr.As4()
		switch {
		case b[0] == 100 && b[1]&0xc0 == 64: // 100.64.0.0/10, CGNAT
			return false
		case b[0] == 192 && b[1] == 0 && b[2] == 0: // 192.0.0.0/24, IETF protocol assignments
			return false
		case b[0] == 192 && b[1] == 0 && b[2] == 2, // TEST-NET-1
			b[0] == 198 && b[1] == 51 && b[2] == 100, // TEST-NET-2
			b[0] == 203 && b[1] == 0 && b[2] == 113:  // TEST-NET-3
			return false
		case b[0] == 198 && b[1]&0xfe == 18: // 198.18.0.0/15, benchmarking
			return false
		case b[0] >= 240: // 240.0.0.0/4, reserved, and 255.255.255.255
			return false
		}
		return true
	}
	b := addr.As16()
	switch {
	case b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8: // 2001:db8::/32, documentation
		return false
	case b[0]&0xfe == 0xfc: // fc00::/7, unique-local
		return false
	case b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b: // 64:ff9b::/96, NAT64 of v4
		return false
	}
	return true
}
