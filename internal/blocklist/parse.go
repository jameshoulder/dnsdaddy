package blocklist

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/jameshoulder/dnsdaddy/internal/domainutil"
)

// Format identifies how a feed's lines are laid out.
type Format string

const (
	// FormatAuto sniffs each line, accepting any of the formats below.
	FormatAuto Format = "auto"
	// FormatHosts is "0.0.0.0 evil.com" / "127.0.0.1 evil.com".
	FormatHosts Format = "hosts"
	// FormatDomains is one bare domain per line.
	FormatDomains Format = "domains"
	// FormatAdblock is "||evil.com^" Adblock Plus syntax.
	FormatAdblock Format = "adblock"
	// FormatObservatory is the DNS Daddy Threat Observatory's JSON indicator
	// document. It is the one format that is not line-based, and the one whose
	// entries carry their own category — see observatory.go.
	FormatObservatory Format = "observatory"
)

// Loopback addresses that a hosts-format feed uses as the sink.
var sinkAddrs = map[string]bool{
	"0.0.0.0":   true,
	"127.0.0.1": true,
	"::":        true,
	"::1":       true,
	"::0":       true,
}

// Parse reads a feed and calls emit for every domain it contains. It never
// returns a parse error for a single malformed line: threat feeds are
// third-party text files that routinely contain junk, and one bad line must not
// cost us an entire category of protection. Unusable lines are counted and
// reported instead.
//
// The returned counts are (accepted, skipped).
func Parse(r io.Reader, format Format, emit func(domain string)) (int, int, error) {
	if format == FormatObservatory {
		// Guarded rather than silently sniffed: line-parsing a JSON document
		// would quietly extract nonsense from it instead of failing.
		return 0, 0, fmt.Errorf("format %q is JSON, not line-based; use ParseObservatory", format)
	}

	sc := bufio.NewScanner(r)
	// Some feeds ship very long comment banners; 1 MiB is generous but bounded.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var accepted, skipped int
	for sc.Scan() {
		line := sc.Text()
		domain, ok := parseLine(line, format)
		if !ok {
			if isIgnorable(line) {
				continue
			}
			skipped++
			continue
		}
		emit(domain)
		accepted++
	}
	if err := sc.Err(); err != nil {
		return accepted, skipped, err
	}
	return accepted, skipped, nil
}

// isIgnorable reports whether a line is a comment or blank, and so should not
// count against the feed's skip tally.
func isIgnorable(line string) bool {
	t := strings.TrimSpace(line)
	if t == "" {
		return true
	}
	switch t[0] {
	case '#', '!', ';':
		return true
	}
	// Adblock cosmetic and exception rules are valid syntax we simply don't use.
	return strings.HasPrefix(t, "@@") || strings.Contains(t, "##")
}

func parseLine(line string, format Format) (string, bool) {
	// Strip trailing comments, which hosts files use for attribution.
	if i := strings.IndexAny(line, "#!"); i >= 0 {
		line = line[:i]
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return "", false
	}

	switch format {
	case FormatHosts:
		return parseHosts(line)
	case FormatDomains:
		return parseDomain(line)
	case FormatAdblock:
		return parseAdblock(line)
	default:
		return parseAuto(line)
	}
}

func parseAuto(line string) (string, bool) {
	if strings.HasPrefix(line, "||") {
		return parseAdblock(line)
	}
	if strings.ContainsAny(line, " \t") {
		return parseHosts(line)
	}
	return parseDomain(line)
}

func parseHosts(line string) (string, bool) {
	fields := strings.Fields(line)
	switch len(fields) {
	case 0:
		return "", false
	case 1:
		// Some "hosts" feeds omit the sink address entirely.
		return parseDomain(fields[0])
	}

	if !sinkAddrs[fields[0]] {
		// Not a sink entry — could be a real /etc/hosts mapping we must not
		// treat as a block, or a leading domain with trailing junk.
		if domainutil.Normalize(fields[0]) != "" && !looksLikeIP(fields[0]) {
			return parseDomain(fields[0])
		}
		return "", false
	}

	// "0.0.0.0 evil.com www.evil.com" is legal; take the first name. Feeds that
	// pack several names on one line are rare enough that the extras are not
	// worth the complexity of a multi-value emit path.
	return parseDomain(fields[1])
}

func parseAdblock(line string) (string, bool) {
	if !strings.HasPrefix(line, "||") {
		return "", false
	}
	line = strings.TrimPrefix(line, "||")
	if i := strings.IndexAny(line, "^$/"); i >= 0 {
		line = line[:i]
	}
	// Rules carrying options ($third-party, $script) are request-type filters
	// that DNS cannot honour; blocking the domain outright would over-block.
	return parseDomain(line)
}

func parseDomain(s string) (string, bool) {
	// A bare IP address in a domain list is not something we can block by name.
	if looksLikeIP(s) {
		return "", false
	}
	d := domainutil.Normalize(s)
	if d == "" {
		return "", false
	}
	// Single-label entries ("localhost", "com") would block enormous swathes of
	// the namespace if a feed shipped one by mistake.
	if !strings.Contains(d, ".") {
		return "", false
	}
	return d, true
}

func looksLikeIP(s string) bool {
	if strings.Contains(s, ":") {
		return true // IPv6 literal
	}
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		for i := 0; i < len(p); i++ {
			if p[i] < '0' || p[i] > '9' {
				return false
			}
		}
	}
	return true
}
