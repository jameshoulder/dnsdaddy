// Package recursive is Daddybound's own iterative DNS resolver.
//
// It starts at the root and follows referrals to the authoritative servers for
// a name, which is what makes Daddybound a resolver rather than a client of
// one. internal/daddybound/netsource asks a public recursive resolver to do
// this work; this package does it. The distinction matters beyond tidiness: a
// validator that asks Cloudflare for a DNSKEY is trusting Cloudflare's view of
// the DNS, and the entire point of local validation is not to.
//
// # What it does not do
//
// It is not a general-purpose serving cache and does not try to be one. There
// is no prefetching, no serve-stale, no RFC 8767 behaviour and no attempt to
// be the fastest resolver on the Internet. It resolves correctly, refuses
// clearly, and stays inside bounds small enough for a 1 vCPU box.
//
// # Security posture
//
// Every input arrives from a server an attacker may control, and the response
// to that is structural rather than a list of checks bolted on:
//
//   - Nothing is believed because it appeared in a response. A record is
//     accepted only if the server sending it is authoritative for the name
//     (see bailiwick.go), which is what stops the classic cache-poisoning
//     shapes where an answer for one zone carries records for another.
//   - Every reply is matched against the question that was sent, on ID,
//     question section and the address it came back from.
//   - Every loop an attacker chooses the length of is bounded, and hitting a
//     bound is a refusal with a reason rather than a resolver that stops
//     answering.
//
// DNSSEC is deliberately not this package's job. It resolves; the validator in
// internal/daddybound/dnssec decides what the result means. Keeping those
// apart is what lets the validator be driven from the laboratory, from a
// forwarder, or from here without changing.
package recursive

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

// RootHint is one root server's name and addresses.
type RootHint struct {
	Name string
	Addr []netip.Addr
}

// RootHintsSource records where the compiled-in hints came from, so an
// operator can tell how old they are without reading the source.
//
// Root server addresses change rarely — a handful of times a decade — and a
// stale hint is survivable because priming re-learns the real set from any one
// server that still answers. It is not survivable if every address has moved,
// which is the case this metadata exists to let someone notice.
const (
	RootHintsSource  = "https://www.internic.net/domain/named.root"
	RootHintsVersion = "2024-06-14"
)

// defaultRootHints is the IANA root server set.
//
// Addresses only. Root hints are a bootstrap: they say where to ask the first
// question, and nothing else. They are not trust anchors, they are not
// authenticated, and nothing is believed because it appeared here — priming
// replaces them with the root's own signed answer at startup. That separation
// is deliberate and is why a stale hints file is an availability problem
// rather than a security one.
var defaultRootHints = []RootHint{
	{"a.root-servers.net.", mustAddrs("198.41.0.4", "2001:503:ba3e::2:30")},
	{"b.root-servers.net.", mustAddrs("170.247.170.2", "2801:1b8:10::b")},
	{"c.root-servers.net.", mustAddrs("192.33.4.12", "2001:500:2::c")},
	{"d.root-servers.net.", mustAddrs("199.7.91.13", "2001:500:2d::d")},
	{"e.root-servers.net.", mustAddrs("192.203.230.10", "2001:500:a8::e")},
	{"f.root-servers.net.", mustAddrs("192.5.5.241", "2001:500:2f::f")},
	{"g.root-servers.net.", mustAddrs("192.112.36.4", "2001:500:12::d0d")},
	{"h.root-servers.net.", mustAddrs("198.97.190.53", "2001:500:1::53")},
	{"i.root-servers.net.", mustAddrs("192.36.148.17", "2001:7fe::53")},
	{"j.root-servers.net.", mustAddrs("192.58.128.30", "2001:503:c27::2:30")},
	{"k.root-servers.net.", mustAddrs("193.0.14.129", "2001:7fd::1")},
	{"l.root-servers.net.", mustAddrs("199.7.83.42", "2001:500:9f::42")},
	{"m.root-servers.net.", mustAddrs("202.12.27.33", "2001:dc3::35")},
}

func mustAddrs(in ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(in))
	for _, s := range in {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			panic("recursive: bad compiled-in root hint " + s + ": " + err.Error())
		}
		out = append(out, addr)
	}
	return out
}

// DefaultRootHints returns a copy of the compiled-in hints.
func DefaultRootHints() []RootHint {
	out := make([]RootHint, len(defaultRootHints))
	for i, h := range defaultRootHints {
		out[i] = RootHint{Name: h.Name, Addr: append([]netip.Addr(nil), h.Addr...)}
	}
	return out
}

// ParseRootHints reads a named.root-style zone file.
//
// Only A, AAAA and NS records for the root are read, and everything else is
// ignored rather than rejected: the published file carries comments, an SOA
// and a trailing NS set, and refusing to start because of a record we do not
// need would be a poor trade. What is not tolerated is a file that yields no
// usable address at all, because that is indistinguishable at runtime from a
// resolver that cannot start and should say so now.
func ParseRootHints(text string) ([]RootHint, error) {
	byName := map[string][]netip.Addr{}
	var order []string
	names := map[string]bool{}

	zp := dns.NewZoneParser(strings.NewReader(text), ".", "roothints")
	zp.SetIncludeAllowed(false)
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		switch v := rr.(type) {
		case *dns.NS:
			if dns.CanonicalName(v.Hdr.Name) == "." {
				names[dns.CanonicalName(v.Ns)] = true
			}
		case *dns.A:
			addAddr(byName, &order, v.Hdr.Name, v.A.String())
		case *dns.AAAA:
			addAddr(byName, &order, v.Hdr.Name, v.AAAA.String())
		}
	}
	if err := zp.Err(); err != nil {
		return nil, fmt.Errorf("parse root hints: %w", err)
	}

	out := make([]RootHint, 0, len(order))
	for _, name := range order {
		// A hints file that lists NS records is trusted for which names are
		// root servers; one that lists only addresses (some do) is taken at
		// face value, because there is nothing else to go on.
		if len(names) > 0 && !names[name] {
			continue
		}
		out = append(out, RootHint{Name: name, Addr: byName[name]})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("parse root hints: no root server addresses found")
	}
	return out, nil
}

func addAddr(byName map[string][]netip.Addr, order *[]string, name, addr string) {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return
	}
	n := dns.CanonicalName(name)
	if _, seen := byName[n]; !seen {
		*order = append(*order, n)
	}
	byName[n] = append(byName[n], a)
}
