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
)

// AnswerAddress is the address the leaf zone publishes for AnswerName. It is
// in 192.0.2.0/24, the RFC 5737 documentation range.
var AnswerAddress = net.IPv4(192, 0, 2, 1)

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

func a(name string, ip net.IP) dns.RR {
	return &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
		A:   ip,
	}
}
