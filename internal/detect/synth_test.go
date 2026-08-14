package detect

import (
	"fmt"
	"math/rand"
	"strings"
	"time"
)

// Synthetic traffic generators.
//
// Every corpus here is deterministic: seeded PRNGs, fixed base times, no
// wall-clock reads. A detection test that passes four times out of five is
// worse than no test, because it teaches whoever sees the failure to re-run
// rather than to look.
//
// The corpora exist in pairs. For each malicious pattern there is a benign one
// that shares its most obvious property — a CDN generates as many unique
// subdomains as a tunnel does, a mail server issues as many TXT lookups as a
// TXT channel — because the only thing worth measuring about a heuristic is
// whether it separates those two.

const (
	base32Alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	hexAlphabet    = "0123456789abcdef"
	lowerAlphabet  = "abcdefghijklmnopqrstuvwxyz"
)

// baseTime is the fixed start point for every generated corpus.
var baseTime = time.Date(2026, 3, 14, 9, 0, 0, 0, time.UTC)

func randomLabel(r *rand.Rand, alphabet string, n int) string {
	var b strings.Builder
	b.Grow(n)
	for i := 0; i < n; i++ {
		b.WriteByte(alphabet[r.Intn(len(alphabet))])
	}
	return b.String()
}

// obs is a terse Observation constructor for tests.
func obs(t time.Time, client, qname, qtype, rcode string) Observation {
	return Observation{
		Time:     t,
		ClientIP: client,
		QName:    qname,
		QType:    qtype,
		Rcode:    rcode,
		Proto:    "udp",
	}
}

// tunnelTraffic models an encoding tunnel: a fresh high-entropy name per
// message, under one attacker-controlled parent, using a record type that can
// carry a reply.
//
// A repeated name would be answered from cache and never reach the attacker's
// nameserver, so uniqueness is not a stylistic choice by the tool author — it
// is what the transport requires, and it is why cardinality is the strongest
// single signal available.
func tunnelTraffic(client, parent string, n int, seed int64) []Observation {
	r := rand.New(rand.NewSource(seed))
	out := make([]Observation, 0, n)
	t := baseTime
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("%s.%s.%s",
			randomLabel(r, base32Alphabet, 55),
			randomLabel(r, base32Alphabet, 40),
			parent)
		out = append(out, obs(t, client, name, "TXT", "NOERROR"))
		t = t.Add(900 * time.Millisecond)
	}
	return out
}

// cdnTraffic models the benign pattern most easily mistaken for a tunnel:
// very high subdomain cardinality under one parent.
//
// The differences that should keep it quiet are the ones that matter
// operationally — the labels are short and structured rather than long and
// encoded, the record type is an address lookup, and the answers resolve.
func cdnTraffic(client, parent string, n int, seed int64) []Observation {
	r := rand.New(rand.NewSource(seed))
	out := make([]Observation, 0, n)
	t := baseTime
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("img-%05d-%s.assets.%s", i, randomLabel(r, lowerAlphabet, 4), parent)
		out = append(out, obs(t, client, name, "A", "NOERROR"))
		t = t.Add(400 * time.Millisecond)
	}
	return out
}

// browsingTraffic models an ordinary workstation: a small set of real domains,
// address lookups, bursty timing, and the occasional failure.
func browsingTraffic(client string, n int, seed int64) []Observation {
	r := rand.New(rand.NewSource(seed))
	sites := []string{
		"bbc.co.uk", "github.com", "google.com", "wikipedia.org", "gov.uk",
		"microsoft.com", "stackoverflow.com", "theguardian.com",
	}
	hosts := []string{"www", "static", "api", "cdn", "assets", "login"}
	types := []string{"A", "A", "A", "AAAA", "HTTPS"}

	out := make([]Observation, 0, n)
	t := baseTime
	for i := 0; i < n; i++ {
		name := hosts[r.Intn(len(hosts))] + "." + sites[r.Intn(len(sites))]
		rcode := "NOERROR"
		if r.Intn(25) == 0 {
			rcode = "NXDOMAIN"
		}
		out = append(out, obs(t, client, name, types[r.Intn(len(types))], rcode))
		// Bursty: mostly close together, occasionally a long pause.
		if r.Intn(6) == 0 {
			t = t.Add(time.Duration(2+r.Intn(20)) * time.Second)
		} else {
			t = t.Add(time.Duration(30+r.Intn(400)) * time.Millisecond)
		}
	}
	return out
}

// dnsblTraffic models a mail server performing blocklist lookups: an IP
// address reversed into labels beneath a reputation provider, thousands of
// times an hour.
//
// This is the canonical false positive for tunnelling detection, and it is the
// reason the shipped exclusion list exists rather than being an optional
// extra.
func dnsblTraffic(client, provider string, n int, seed int64) []Observation {
	r := rand.New(rand.NewSource(seed))
	out := make([]Observation, 0, n)
	t := baseTime
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("%d.%d.%d.%d.%s",
			r.Intn(256), r.Intn(256), r.Intn(256), r.Intn(256), provider)
		rcode := "NXDOMAIN" // a clean IP is not listed, so most lookups fail
		if r.Intn(20) == 0 {
			rcode = "NOERROR"
		}
		out = append(out, obs(t, client, name, "A", rcode))
		t = t.Add(150 * time.Millisecond)
	}
	return out
}

// mailTXTTraffic models a mail server reading sender policy: heavy TXT volume,
// all of it standard infrastructure records.
func mailTXTTraffic(client string, n int, seed int64) []Observation {
	r := rand.New(rand.NewSource(seed))
	domains := []string{
		"example.com", "supplier.co.uk", "newsletter.io", "bank.example",
		"customer.org", "partner.net",
	}
	patterns := []string{
		"_dmarc.%s",
		"%s",
		"selector1._domainkey.%s",
		"selector2._domainkey.%s",
		"_mta-sts.%s",
	}
	out := make([]Observation, 0, n)
	t := baseTime
	for i := 0; i < n; i++ {
		d := domains[r.Intn(len(domains))]
		name := fmt.Sprintf(patterns[r.Intn(len(patterns))], d)
		out = append(out, obs(t, client, name, "TXT", "NOERROR"))
		t = t.Add(300 * time.Millisecond)
	}
	return out
}

// txtChannelTraffic models TXT used as a data channel: unique high-entropy
// names, TXT throughout, under a single parent.
func txtChannelTraffic(client, parent string, n int, seed int64) []Observation {
	r := rand.New(rand.NewSource(seed))
	out := make([]Observation, 0, n)
	t := baseTime
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("%s.%s", randomLabel(r, base32Alphabet, 32), parent)
		out = append(out, obs(t, client, name, "TXT", "NOERROR"))
		t = t.Add(time.Second)
	}
	return out
}

// dgaTraffic models a domain generation algorithm walking its candidate list:
// many unrelated registered domains, random second-level labels, rotating
// TLDs, nearly all NXDOMAIN.
func dgaTraffic(client string, n int, seed int64) []Observation {
	r := rand.New(rand.NewSource(seed))
	tlds := []string{"com", "net", "info", "biz", "org", "top"}
	out := make([]Observation, 0, n)
	t := baseTime
	for i := 0; i < n; i++ {
		sld := randomLabel(r, lowerAlphabet, 12+r.Intn(6))
		name := fmt.Sprintf("%s.%s", sld, tlds[r.Intn(len(tlds))])
		rcode := "NXDOMAIN"
		if r.Intn(30) == 0 {
			rcode = "NOERROR" // the one the operator actually registered
		}
		out = append(out, obs(t, client, name, "A", rcode))
		t = t.Add(1200 * time.Millisecond)
	}
	return out
}

// beaconTraffic models a fixed-interval check-in with a little jitter.
func beaconTraffic(client, name string, n int, period time.Duration, jitter float64, ttl uint32, seed int64) []Observation {
	r := rand.New(rand.NewSource(seed))
	out := make([]Observation, 0, n)
	t := baseTime
	for i := 0; i < n; i++ {
		o := obs(t, client, name, "A", "NOERROR")
		o.AnswerTTL = ttl
		out = append(out, o)
		drift := (r.Float64()*2 - 1) * jitter * float64(period)
		t = t.Add(period + time.Duration(drift))
	}
	return out
}

// nxdomainSearchSuffixTraffic models the classic benign NXDOMAIN burst: a
// stale DHCP search domain appended to short names that were never meant to be
// qualified.
//
// It is deliberately built so that most failures land on names with no public
// suffix, which is exactly why the detector excludes those from scoring.
func nxdomainSearchSuffixTraffic(client string, n int, seed int64) []Observation {
	r := rand.New(rand.NewSource(seed))
	hosts := []string{"printer", "fileserver", "wpad", "intranet", "timeclock", "nas"}
	out := make([]Observation, 0, n)
	t := baseTime
	for i := 0; i < n; i++ {
		name := hosts[r.Intn(len(hosts))] + ".corp.internal"
		out = append(out, obs(t, client, name, "A", "NXDOMAIN"))
		t = t.Add(200 * time.Millisecond)
	}
	return out
}

// ipv6ReverseTraffic models PTR lookups for IPv6 addresses: 32 single-hex
// labels per query, maximal cardinality and near-maximal entropy, entirely
// routine.
func ipv6ReverseTraffic(client string, n int, seed int64) []Observation {
	r := rand.New(rand.NewSource(seed))
	out := make([]Observation, 0, n)
	t := baseTime
	for i := 0; i < n; i++ {
		nibbles := make([]string, 32)
		for j := range nibbles {
			nibbles[j] = string(hexAlphabet[r.Intn(16)])
		}
		name := strings.Join(nibbles, ".") + ".ip6.arpa"
		out = append(out, obs(t, client, name, "PTR", "NXDOMAIN"))
		t = t.Add(250 * time.Millisecond)
	}
	return out
}

// hashReputationTraffic models an endpoint agent checking file hashes against
// a vendor's DNS-based reputation service.
//
// By shape this is a tunnel: long hex labels, one per lookup, mostly
// NXDOMAIN. It is used to demonstrate that the exclusion list — not the
// scoring — is what keeps it quiet.
func hashReputationTraffic(client, provider string, n int, seed int64) []Observation {
	r := rand.New(rand.NewSource(seed))
	out := make([]Observation, 0, n)
	t := baseTime
	for i := 0; i < n; i++ {
		name := randomLabel(r, hexAlphabet, 40) + "." + provider
		rcode := "NXDOMAIN"
		if r.Intn(15) == 0 {
			rcode = "NOERROR"
		}
		out = append(out, obs(t, client, name, "A", rcode))
		t = t.Add(200 * time.Millisecond)
	}
	return out
}

// singleSignalTraffic drives exactly one tunnel signal — label entropy — to a
// contributing level while leaving the rest quiet.
//
// It exists to pin the multi-signal gate, which is the concrete answer to
// "high entropy equals malicious". The labels are genuinely random, and the
// detector must still stay silent because nothing else about the traffic looks
// like a channel: the names are short, cardinality is low, the record type
// carries no payload, and everything resolves.
func singleSignalTraffic(client, parent string, n int, seed int64) []Observation {
	r := rand.New(rand.NewSource(seed))
	// A small pool of names, reused, so subdomain cardinality stays low.
	pool := make([]string, 40)
	for i := range pool {
		pool[i] = randomLabel(r, base32Alphabet, 14)
	}
	out := make([]Observation, 0, n)
	t := baseTime
	for i := 0; i < n; i++ {
		out = append(out, obs(t, client, pool[r.Intn(len(pool))]+"."+parent, "A", "NOERROR"))
		t = t.Add(500 * time.Millisecond)
	}
	return out
}

// feed runs a corpus through a detector and evaluates at the end of the
// window.
func feed(d Detector, ex *Exclusions, corpus []Observation, at time.Time) []Finding {
	for _, o := range corpus {
		e := Event{Observation: o}
		e.Parent, e.Sub, e.HasParent = split(o.QName)
		e.Labels = labelsOf(o.QName)
		if !o.Blocked {
			switch o.Rcode {
			case "NXDOMAIN":
				e.NXDomain = true
			case "SERVFAIL":
				e.ServFail = true
			}
		}
		e.Excluded = ex.Excluded(o.QName)
		d.Observe(&e)
	}
	return d.Evaluate(at)
}

// windowEnd returns a time past the end of a corpus's observation window.
func windowEnd(window time.Duration) time.Time {
	return baseTime.Add(window + time.Second)
}
