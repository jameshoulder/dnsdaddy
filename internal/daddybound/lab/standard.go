package lab

import (
	"net"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
)

// The lab's hierarchy lives under .dnsdaddylab, a name that is not delegated
// anywhere and never will be.
//
// The choice of name is not cosmetic. An earlier experiment used .test, which
// is reserved by RFC 6761 §6.2, and libunbound answers NXDOMAIN for it
// without querying anything — the harness looked broken when it was the name
// that was wrong. A name with no special-use registration avoids that class
// of confusion entirely, in Daddybound and in any reference validator pointed
// at the same data.
const (
	RootZone   = "."
	MiddleZone = "dnsdaddylab."
	LeafZone   = "example.dnsdaddylab."
	AnswerName = "www.example.dnsdaddylab."
	// MailName carries the multi-record MX RRset described in StandardSpec.
	MailName = "mail.example.dnsdaddylab."

	// UnsignedZone is delegated from the middle zone with NS and no DS. The
	// parent's NSEC proves the absence, which is the only authenticated
	// route to RFC 4033 §5's Insecure.
	UnsignedZone = "unsigned.dnsdaddylab."
	// UnsignedName is a name inside that insecurely delegated zone.
	UnsignedName = "host.unsigned.dnsdaddylab."
	// InsecureAliasName is a CNAME inside that insecurely delegated zone,
	// pointing back at a name in a signed one. Nothing authenticates the
	// redirection itself, so the answer it leads to cannot be reported Secure
	// however well signed the destination is.
	InsecureAliasName = "alias.unsigned.dnsdaddylab."

	// WildcardOwner is a wildcard two labels below the leaf apex rather than
	// directly beneath it, so a validator that assumes the source of
	// synthesis is always "*.<apex>" gets the wrong answer here. RFC 4592
	// §3.3.1 anchors it at the closest encloser.
	WildcardOwner = "*.wild.example.dnsdaddylab."
	// WildcardMatch has no records of its own and is answered by expansion.
	WildcardMatch = "anything.wild.example.dnsdaddylab."

	// EmptyNonTerminal owns nothing and exists only because DeepName is
	// below it. An NSEC zone publishes no NSEC at such a name (RFC 4035
	// §2.3), so a NODATA there is proved by a spanning record instead.
	EmptyNonTerminal = "ent.example.dnsdaddylab."
	// DeepName is what makes EmptyNonTerminal exist.
	DeepName = "deep.ent.example.dnsdaddylab."

	// MissingName exists in no zone, for name-error proofs.
	MissingName = "nope.example.dnsdaddylab."

	// OtherZone is a second signed zone delegated from the middle zone, so
	// an alias can cross a zone cut without leaving the chain of trust.
	OtherZone = "other.dnsdaddylab."
	// OtherName is the address record that zone publishes.
	OtherName = "target.other.dnsdaddylab."

	// AliasName is a CNAME to AnswerName inside the same zone.
	AliasName = "alias.example.dnsdaddylab."
	// CrossZoneAlias points into OtherZone: signed, and a different chain.
	CrossZoneAlias = "cross.example.dnsdaddylab."
	// AliasToInsecure points into the zone delegated without a DS, so the
	// answer stops being authenticated part-way along the chain.
	AliasToInsecure = "downgrade.example.dnsdaddylab."
	// Alias chain of three hops ending at AnswerName.
	AliasHop1 = "hop1.example.dnsdaddylab."
	AliasHop2 = "hop2.example.dnsdaddylab."
	AliasHop3 = "hop3.example.dnsdaddylab."
	// AliasLoopA and AliasLoopB point at each other.
	AliasLoopA = "loopa.example.dnsdaddylab."
	AliasLoopB = "loopb.example.dnsdaddylab."
	// WildcardAliasOwner is a wildcard CNAME; WildcardAliasMatch is answered
	// by expanding it, so the alias itself owes a denial proof.
	WildcardAliasOwner = "*.aka.example.dnsdaddylab."
	WildcardAliasMatch = "anything.aka.example.dnsdaddylab."

	// DnameOwner redirects everything beneath it to the leaf apex, so
	// DnameMatch is answered by substitution and resolves to AnswerName.
	// Nothing exists at DnameOwner's subdomains, which is what RFC 6672 §2.4
	// requires of a zone containing a DNAME.
	DnameOwner = "moved.example.dnsdaddylab."
	DnameMatch = "www.moved.example.dnsdaddylab."
)

// AnswerAddress is the address the leaf zone publishes for AnswerName. It is
// in 192.0.2.0/24, the RFC 5737 documentation range.
var (
	AnswerAddress   = net.IPv4(192, 0, 2, 1)
	WildcardAddress = net.IPv4(192, 0, 2, 2)
	DeepAddress     = net.IPv4(192, 0, 2, 3)
	UnsignedAddress = net.IPv4(192, 0, 2, 4)
	OtherAddress    = net.IPv4(192, 0, 2, 5)
)

// Signature validity for the standard hierarchy. Fixed instants rather than
// offsets from now, so that a recorded trace stays meaningful a year later
// and so that a test can sit exactly on either inclusive boundary.
var (
	Inception  = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	Expiration = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
)

// Now is an instant comfortably inside the standard validity window, for
// tests that are not about time.
func Now() time.Time { return time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC) }

// StandardSpec describes the reference hierarchy:
//
//	.                        signed, and the trust anchor
//	  dnsdaddylab.           delegated from the root with a DS
//	    example.dnsdaddylab. delegated from dnsdaddylab with a DS
//	      www.example.dnsdaddylab. A 192.0.2.1
//
// Three zones is the smallest hierarchy that exercises everything a chain
// walk does more than once: two delegations, so a bug that only works for the
// first DS is caught, and a leaf whose answer lives below the deepest zone
// apex rather than at it.
func StandardSpec() Spec {
	return Spec{
		Seed:       "daddybound-v0.1-standard",
		Inception:  Inception,
		Expiration: Expiration,
		Zones: []ZoneSpec{
			{
				Name:      RootZone,
				Algorithm: dnssec.AlgED25519,
				Records:   []dns.RR{soa(RootZone), ns(RootZone, "ns.dnsdaddylab.")},
			},
			{
				Name:      MiddleZone,
				Algorithm: dnssec.AlgED25519,
				Records:   []dns.RR{soa(MiddleZone), ns(MiddleZone, "ns.dnsdaddylab.")},
			},
			{
				Name:      LeafZone,
				Algorithm: dnssec.AlgED25519,
				Records: []dns.RR{
					soa(LeafZone),
					ns(LeafZone, "ns.dnsdaddylab."),
					a(AnswerName, AnswerAddress),
					// A multi-record RRset whose members expose RFC 4034
					// §6.3's ordering rule, so the standard hierarchy
					// exercises it on every run rather than only in a unit
					// test.
					//
					// MX RDATA is a two-octet preference followed by the
					// exchange name. Preference 10 with a long exchange has
					// *longer* RDATA than preference 20 with a short one, and
					// must still sort first because ordering is over RDATA
					// rather than over record length. A validator that sorts
					// packed records reverses these two, builds different
					// signed bytes from the signer, and reports this
					// correctly signed RRset as Bogus.
					mx(MailName, 10, "mail-primary.example.dnsdaddylab."),
					mx(MailName, 20, "mx.example.dnsdaddylab."),
					mx(MailName, 30, "a.example.dnsdaddylab."),

					// A wildcard, and a name below an empty non-terminal.
					// Both are in the standard hierarchy rather than in a
					// scenario-specific one so that every positive run
					// exercises the shapes a denial proof has to reason
					// about, not only the runs that are about denial.
					a(WildcardOwner, WildcardAddress),
					a(DeepName, DeepAddress),

					// Aliases. A CNAME is the answer to a query for any
					// other type at the same name (RFC 1034 §3.6.2), so
					// each of these is reached by asking for an address and
					// getting a redirection instead.
					cname(AliasName, AnswerName),
					cname(CrossZoneAlias, OtherName),
					cname(AliasToInsecure, UnsignedName),
					cname(AliasHop1, AliasHop2),
					cname(AliasHop2, AliasHop3),
					cname(AliasHop3, AnswerName),
					cname(AliasLoopA, AliasLoopB),
					cname(AliasLoopB, AliasLoopA),
					cname(WildcardAliasOwner, AnswerName),

					// A DNAME, which redirects a whole subtree rather than
					// one name and whose synthesised CNAME is unsigned by
					// design (RFC 6672 §5.3.1).
					dname(DnameOwner, LeafZone),
				},
			},
			{
				// A second signed zone under the same parent, so an alias
				// can cross a zone cut and still be authenticated. Without a
				// sibling, "cross-zone" would only ever mean parent-to-child
				// and the case where the target needs its own chain walk
				// from the anchor would never be exercised.
				Name:      OtherZone,
				Parent:    MiddleZone,
				Algorithm: dnssec.AlgED25519,
				Records: []dns.RR{
					soa(OtherZone),
					ns(OtherZone, "ns.dnsdaddylab."),
					a(OtherName, OtherAddress),
				},
			},
			{
				// Delegated with NS and no DS. The zone below is signed and
				// unreachable: nothing authenticates its keys, so a
				// validator must treat everything in it as Insecure rather
				// than verify it against keys it has no reason to trust.
				Name:      UnsignedZone,
				Parent:    MiddleZone,
				Insecure:  true,
				Algorithm: dnssec.AlgED25519,
				Records: []dns.RR{
					soa(UnsignedZone),
					ns(UnsignedZone, "ns.dnsdaddylab."),
					a(UnsignedName, UnsignedAddress),
					cname(InsecureAliasName, AnswerName),
				},
			},
		},
	}
}

// Standard builds the reference hierarchy.
func Standard() (*Hierarchy, error) { return Build(StandardSpec()) }

// Config returns a dnssec.Config wired to this hierarchy's trust anchor and
// pinned to a fixed clock, which is what makes a lab run reproducible.
func (h *Hierarchy) Config(at time.Time) (dnssec.Config, error) {
	anchors, err := dnssec.NewTrustAnchors(h.Anchor)
	if err != nil {
		return dnssec.Config{}, err
	}
	return dnssec.Config{
		Anchors:  anchors,
		Policy:   dnssec.DefaultPolicy(),
		Clock:    dnssec.FixedClock{Instant: at},
		Verifier: dnssec.StdVerifier(),
		Limits:   dnssec.DefaultLimits(),
	}, nil
}

// Validator returns a validator reading from this hierarchy.
func (h *Hierarchy) Validator(at time.Time) (*dnssec.Validator, error) {
	cfg, err := h.Config(at)
	if err != nil {
		return nil, err
	}
	return dnssec.New(h, cfg), nil
}

// soa gives each zone an apex SOA. Beyond realism, it is what an
// authoritative server puts in the authority section of a NODATA or NXDOMAIN
// response, and a reference validator pointed at this hierarchy needs one to
// tell "no such data" from "the server is broken".
func soa(zone string) dns.RR {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:      "ns.dnsdaddylab.",
		Mbox:    "hostmaster.dnsdaddylab.",
		Serial:  1,
		Refresh: 3600, Retry: 900, Expire: 604800, Minttl: 300,
	}
}

func ns(zone, target string) dns.RR {
	return &dns.NS{
		Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
		Ns:  target,
	}
}

func mx(name string, pref uint16, target string) dns.RR {
	return &dns.MX{
		Hdr:        dns.RR_Header{Name: name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 3600},
		Preference: pref,
		Mx:         target,
	}
}

func dname(name, target string) dns.RR {
	return &dns.DNAME{
		Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeDNAME, Class: dns.ClassINET, Ttl: 3600},
		Target: target,
	}
}

func cname(name, target string) dns.RR {
	return &dns.CNAME{
		Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 3600},
		Target: target,
	}
}

func a(name string, ip net.IP) dns.RR {
	return &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
		A:   ip,
	}
}

// NSEC3Spec is the same hierarchy signed with NSEC3 instead of NSEC.
//
// The same names, the same records, the same keys: only the denial mechanism
// changes. Keeping everything else identical is what makes the two suites
// comparable — a scenario that passes under NSEC and fails under NSEC3 has
// isolated the difference to the denial logic, which is the only thing this
// milestone changed.
//
// Parameters follow RFC 9276 §3.1: iterations 0 and an empty salt. A separate
// scenario raises the iteration count, because a validator's behaviour at a
// value no zone should publish is exactly what an attacker will choose.
//
// The middle zone uses opt-out, so the insecure delegation beneath it has no
// NSEC3 record of its own and must be proved insecure through the opt-out
// branch of RFC 5155 §8.9. That is the shape almost every large TLD serves,
// and the one place opt-out is allowed to establish anything.
func NSEC3Spec() Spec {
	spec := StandardSpec()
	spec.Seed = "daddybound-nsec3-standard"
	for i := range spec.Zones {
		spec.Zones[i].NSEC3 = true
		spec.Zones[i].NSEC3Iterations = 0
		spec.Zones[i].NSEC3Salt = ""
		if dns.CanonicalName(spec.Zones[i].Name) == MiddleZone {
			spec.Zones[i].NSEC3OptOut = true
		}
	}
	return spec
}

// NSEC3 builds the NSEC3-signed hierarchy.
func NSEC3() (*Hierarchy, error) { return Build(NSEC3Spec()) }
