// Package domainutil normalises DNS names and walks their parent suffixes.
//
// Every blocklist, allow-list, and query-log entry passes through Normalize so
// that "EVIL.COM.", "evil.com", and "0.0.0.0 evil.com" all end up as the same
// key. Matching is suffix-based: blocking "evil.com" also blocks
// "login.evil.com", which is what an operator expects when they paste a domain
// into a block list.
package domainutil

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// MaxLen is the maximum length of a DNS name in presentation format.
const MaxLen = 253

// Normalize lower-cases a domain, strips the root dot, any scheme or path a
// user may have pasted in, and rejects anything that is not a plausible DNS
// name. It returns "" for input that cannot be used as a domain.
func Normalize(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	// Tolerate a pasted URL: "https://evil.com/path?x=1" -> "evil.com".
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	// Strip userinfo and port.
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.LastIndex(s, ":"); i >= 0 && !strings.Contains(s, "]") {
		// Only treat as a port if what follows is all digits, so we do not
		// mangle a bare IPv6 literal.
		if isDigits(s[i+1:]) {
			s = s[:i]
		}
	}

	s = strings.ToLower(strings.Trim(s, "."))
	if s == "" || len(s) > MaxLen {
		return ""
	}

	// A domain we can match on must have at least one label and use only
	// LDH characters plus the underscore some service records rely on.
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return ""
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
			default:
				return ""
			}
		}
	}
	return s
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// Suffixes calls fn with the domain and each of its parent suffixes, longest
// first, stopping early if fn returns true. It allocates nothing, which matters
// because it runs on every DNS query.
//
//	Suffixes("a.b.evil.com", fn) -> "a.b.evil.com", "b.evil.com", "evil.com", "com"
func Suffixes(domain string, fn func(suffix string) bool) {
	for {
		if fn(domain) {
			return
		}
		i := strings.IndexByte(domain, '.')
		if i < 0 {
			return
		}
		domain = domain[i+1:]
	}
}

// IsSubdomainOf reports whether domain equals parent or sits beneath it.
func IsSubdomainOf(domain, parent string) bool {
	if domain == parent {
		return true
	}
	return len(domain) > len(parent) &&
		strings.HasSuffix(domain, parent) &&
		domain[len(domain)-len(parent)-1] == '.'
}

// internalTLDs are top-level names that denote a private namespace rather than
// a domain somebody registered.
//
// The public suffix list is not enough on its own here. Its default rule
// treats any unrecognised top-level label as a suffix, so "printer.corp.local"
// comes back with a perfectly well-formed registered domain of "corp.local" —
// and a stale search suffix appended to every short name on the network then
// looks like a client walking a domain list. Naming these explicitly is the
// only accurate way to exclude them.
//
// Deliberately absent: .test and .example. RFC 2606 and RFC 6761 reserve those
// for documentation and testing, they essentially never appear on a production
// network, and the lab scenarios in labs/ use .example precisely so they
// exercise the same code path real traffic does. Adding them here would make
// every lab scenario silently untestable.
//
// Sources: RFC 6761 (Special-Use Domain Names), RFC 6762 (mDNS, .local),
// RFC 8375 (home.arpa), and ICANN's 2024 designation of .internal for private
// use.
var internalTLDs = map[string]bool{
	"local":       true, // RFC 6762 multicast DNS
	"localhost":   true, // RFC 6761
	"invalid":     true, // RFC 6761
	"internal":    true, // ICANN private-use designation, 2024
	"home":        true,
	"lan":         true,
	"corp":        true,
	"intranet":    true,
	"private":     true,
	"localdomain": true,
	"workgroup":   true,
}

// RegisteredDomain separates a name into its registered domain (eTLD+1) and
// everything below it.
//
// The public suffix list is what makes "many subdomains under one parent"
// mean the same thing for example.com and example.co.uk. Without it, grouping
// on the last two labels would treat every .co.uk site as a subdomain of
// co.uk and every tunnel under a country-code domain would be invisible.
//
// ok is false for names with no registered domain:
//
//	single labels ("printer", and the random probes Chrome resolves at
//	startup to detect NXDOMAIN hijacking)
//	names that are themselves a public suffix ("co.uk")
//	names under a private-namespace top-level label (see internalTLDs)
//
// Callers must handle that case explicitly rather than falling back to the raw
// name. A stale search suffix appended to every short name on the network is
// the single loudest source of behavioural false positives there is, and this
// is where it gets removed.
func RegisteredDomain(name string) (parent, sub string, ok bool) {
	if name == "" {
		return "", "", false
	}
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		if internalTLDs[name[i+1:]] {
			return "", "", false
		}
	} else {
		// No dot at all: a single label, which cannot have a registered domain.
		return "", "", false
	}
	parent, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil || parent == "" {
		return "", "", false
	}
	// A query for the registered domain itself is ordinary and must still be
	// attributed to that domain: apex lookups are exactly what a domain
	// generation algorithm produces, so treating them as "no parent" would
	// blind the DGA and NXDOMAIN detectors to their main input. Sub is empty,
	// which is what the tunnel detector keys off to skip them — a tunnel needs
	// labels below the parent by construction.
	if parent == name {
		return parent, "", true
	}
	if !strings.HasSuffix(name, "."+parent) {
		return "", "", false
	}
	return parent, name[:len(name)-len(parent)-1], true
}
