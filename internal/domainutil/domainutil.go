// Package domainutil normalises DNS names and walks their parent suffixes.
//
// Every blocklist, allow-list, and query-log entry passes through Normalize so
// that "EVIL.COM.", "evil.com", and "0.0.0.0 evil.com" all end up as the same
// key. Matching is suffix-based: blocking "evil.com" also blocks
// "login.evil.com", which is what an operator expects when they paste a domain
// into a block list.
package domainutil

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/net/idna"
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

// NormalizeInput turns an operator-typed name into the form the query log
// holds, or reports why it cannot.
//
// The query log stores what arrived on the wire, which for an
// internationalised name is its A-label ("xn--bcher-kva.example"), and an
// operator investigating "bücher.example" has to land on the same rows.
// This converts a Unicode name to its A-labels first — IDNA 2008 lookup
// rules, which is the same conversion a browser applies before sending a
// query — and then applies Normalize, so case, a trailing dot and a pasted
// URL are handled exactly as they are everywhere else.
//
// Not for the DNS hot path: it allocates, and names on the wire are already
// A-labels. It is for the one place a person types a name.
func NormalizeInput(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("a domain name is required")
	}
	if len(s) > 4*MaxLen {
		return "", errors.New("the name is too long to be a domain")
	}
	ascii := s
	if !isASCII(s) {
		converted, err := idna.Lookup.ToASCII(s)
		if err != nil {
			return "", fmt.Errorf("the name is not a valid internationalised domain: %v", err)
		}
		ascii = converted
	}
	out := Normalize(ascii)
	if out == "" {
		return "", errors.New("the name is not a valid domain")
	}
	return out, nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
