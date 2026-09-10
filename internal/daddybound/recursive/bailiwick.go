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

// scrub removes from a reply every record the answering server had no
// authority to assert.
//
// This is the same question inBailiwick answers, asked of the whole message
// rather than of one name, and it closes the oldest hole in DNS. A server
// authoritative for one zone controls every byte of its replies. Nothing in
// the protocol stops the nameserver for a throwaway domain answering a query
// about one of its own names and attaching, in the same message:
//
//	bank.example.  A  6.6.6.6
//
// A resolver that keeps that record has been poisoned by a server it chose to
// talk to, no spoofing required. Doing this at the message level is what makes
// the rule impossible to forget: whatever a section is for, a record in it
// that names something outside the answering zone is discarded, counted, and
// never reaches the cache, the validator or a client.
//
// It also withdraws a subtler licence. resolveOnce stops chasing a CNAME when
// the reply already carries the requested type for the target — a sensible
// shortcut when the target is in the same zone, and a forgery when it is not,
// because the record is then one operator's claim about another's data.
// Scrubbing before the shortcut is evaluated means it can only fire on records
// the answering zone was entitled to publish; an out-of-zone target is
// resolved by asking the servers that own it. Removing the scrub makes
// TestAnOutOfZoneCNAMETargetIsResolvedRatherThanBelieved fail with
// example.com's server deciding what a name under bank.co.uk resolves to.
//
// The OPT pseudo-record is kept. It carries no zone data — it is the
// transport's own metadata about buffer sizes and flags, its owner is the root
// by construction, and dropping it would take the extended rcode and any EDE
// with it.
//
// Returns the message and how many records were removed. A non-zero count is
// not an error: plenty of real servers are merely sloppy. It is counted so
// that "this zone keeps trying to tell us about other people's names" is
// visible rather than inferred.
func scrub(zone string, msg *dns.Msg) (*dns.Msg, int) {
	removed := 0
	keep := func(rrs []dns.RR) []dns.RR {
		if len(rrs) == 0 {
			return rrs
		}
		out := make([]dns.RR, 0, len(rrs))
		for _, rr := range rrs {
			if _, isOPT := rr.(*dns.OPT); isOPT {
				out = append(out, rr)
				continue
			}
			if !inBailiwick(zone, dns.CanonicalName(rr.Header().Name)) {
				removed++
				continue
			}
			out = append(out, rr)
		}
		return out
	}

	msg.Answer = keep(msg.Answer)
	msg.Ns = keep(msg.Ns)
	msg.Extra = keep(msg.Extra)
	return msg, removed
}

// aliasChain returns the alias records in msg that lead away from qname, in
// chain order.
//
// Only the records on the chain. A zone is entitled to publish aliases for
// every name it holds and a reply may legitimately carry several; splicing all
// of them into one resolution's answer hands a client CNAMEs for names it
// never asked about, presented as part of its own answer. What the client
// asked for is the chain from qname, so that is what is returned.
//
// DNAME is included when its owner is a proper ancestor of the name being
// followed, because that is exactly the condition under which a DNAME applies
// (RFC 6672 §3.2): it rewrites the suffix of a descendant, and the CNAME it
// synthesises is the next link. A DNAME anywhere else in the reply is not part
// of this chain.
//
// The RRSIGs covering those aliases come with them. Leaving them behind would
// hand a validator a signed zone's CNAME with no signature over it, which is
// indistinguishable from a stripped one — so a correctly signed alias chain
// would be reported Bogus, and the splice itself would be the forgery. See
// TestASignedAliasKeepsTheSignatureThatCoversIt.
func aliasChain(msg *dns.Msg, qname string) []dns.RR {
	var (
		out     []dns.RR
		at      = dns.CanonicalName(qname)
		visited = map[string]bool{}
		// onChain remembers which owner names the chain passed through, so
		// the signature sweep below can tell a signature over this chain
		// from one over an alias the client never asked about.
		onChain = map[string]bool{}
	)
	// Each pass consumes one owner name and a name already visited stops the
	// walk, so a reply whose CNAMEs form a cycle terminates here rather than
	// spinning.
	for !visited[at] {
		visited[at] = true

		var next string
		for _, rr := range msg.Answer {
			owner := dns.CanonicalName(rr.Header().Name)
			switch v := rr.(type) {
			case *dns.CNAME:
				if owner != at {
					continue
				}
				out = append(out, rr)
				onChain[owner] = true
				next = dns.CanonicalName(v.Target)
			case *dns.DNAME:
				if !strictlyBelow(owner, at) {
					continue
				}
				// The DNAME belongs in the answer; the CNAME it synthesises,
				// if the server sent one, is picked up by the CNAME case on
				// the next pass.
				out = append(out, rr)
				onChain[owner] = true
			}
			if next != "" {
				break
			}
		}
		if next == "" {
			break
		}
		at = next
	}
	if len(out) == 0 {
		return out
	}

	for _, rr := range msg.Answer {
		sig, ok := rr.(*dns.RRSIG)
		if !ok {
			continue
		}
		if sig.TypeCovered != dns.TypeCNAME && sig.TypeCovered != dns.TypeDNAME {
			continue
		}
		if !onChain[dns.CanonicalName(sig.Hdr.Name)] {
			continue
		}
		out = append(out, rr)
	}
	return out
}
