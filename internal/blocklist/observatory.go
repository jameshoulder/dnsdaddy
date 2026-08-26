package blocklist

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/catalog"
)

// ObservatoryRecord is one indicator from the Threat Observatory, resolved down
// to what the index needs: a domain and the category to file it under.
type ObservatoryRecord struct {
	Domain string
	// Category is the DNS Daddy category the indicator's own labels mapped to,
	// or empty when none of them were recognised. The caller falls back to the
	// feed's configured category in that case.
	Category string
	Severity string
	Family   string
}

// ObservatoryResult reports what a feed document contained.
type ObservatoryResult struct {
	// GeneratedAt is when the Observatory built the document, if it said.
	GeneratedAt time.Time
	// Source is the document's self-declared origin. It is logged, not trusted:
	// TLS is what establishes who served the file.
	Source string
	// Accepted counts indicators emitted; Skipped counts those rejected as
	// unusable (an IP, a bare TLD, a malformed entry).
	Accepted int
	Skipped  int
	// BelowSeverity counts indicators dropped by the minimum-severity floor.
	// Kept separate from Skipped so an operator can tell "the feed is full of
	// junk" from "I asked for critical only".
	BelowSeverity int
}

// observatoryIndicator mirrors one entry in the feed document.
//
// Every field that is not a plain string is decoded as RawMessage and
// interpreted separately. A feed is a file served by a remote host, and one
// indicator whose "categories" arrived as a string instead of an array must
// cost that indicator, not the entire category of protection the feed provides.
type observatoryIndicator struct {
	Value      string          `json:"value"`
	Domain     string          `json:"domain"`
	Type       string          `json:"type"`
	Severity   string          `json:"severity"`
	Family     string          `json:"family"`
	Categories json.RawMessage `json:"categories"`
	Category   json.RawMessage `json:"category"`
}

// ParseObservatory reads a Threat Observatory feed document and calls emit for
// every usable domain indicator.
//
// Parsing is streaming and deliberately forgiving, for the same reason the
// line-based parser is: this is a file fetched over the network, and a single
// malformed indicator must not cost an operator a whole feed's worth of
// blocking. Unusable indicators are counted and skipped.
//
// minSeverity, when non-empty, drops indicators whose declared severity is
// below it. An indicator with no recognisable severity is always kept — losing
// intelligence because a field was missing is the wrong failure mode here.
func ParseObservatory(r io.Reader, minSeverity string, emit func(ObservatoryRecord)) (ObservatoryResult, error) {
	var res ObservatoryResult
	floor := catalog.SeverityRank(minSeverity)

	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil {
		return res, fmt.Errorf("observatory feed is not JSON: %w", err)
	}

	delim, _ := tok.(json.Delim)
	switch delim {
	case '[':
		// A bare array of indicators, with no envelope. Not the documented
		// shape, but cheap to accept and it keeps a hand-rolled test fixture or
		// a trimmed-down mirror working.
		return res, parseIndicatorArray(dec, floor, &res, emit)
	case '{':
	default:
		return res, fmt.Errorf("observatory feed is not a JSON object or array")
	}

	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return res, fmt.Errorf("read observatory feed: %w", err)
		}
		key, _ := keyTok.(string)
		switch key {
		case "indicators":
			t, err := dec.Token()
			if err != nil {
				return res, fmt.Errorf("read observatory indicators: %w", err)
			}
			if d, ok := t.(json.Delim); !ok || d != '[' {
				return res, fmt.Errorf(`observatory feed field "indicators" is not an array`)
			}
			if err := parseIndicatorArray(dec, floor, &res, emit); err != nil {
				return res, err
			}
		case "generated_at":
			if s, ok := decodeString(dec); ok {
				if ts, err := time.Parse(time.RFC3339, s); err == nil {
					res.GeneratedAt = ts.UTC()
				}
			}
		case "source":
			if s, ok := decodeString(dec); ok {
				res.Source = s
			}
		default:
			// Skip the value of any field we do not use, so the Observatory can
			// add metadata without every deployed resolver rejecting the file.
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return res, fmt.Errorf("read observatory feed field %q: %w", key, err)
			}
		}
	}
	return res, nil
}

// parseIndicatorArray consumes indicators until the closing bracket. The
// opening bracket has already been read.
func parseIndicatorArray(dec *json.Decoder, floor int, res *ObservatoryResult, emit func(ObservatoryRecord)) error {
	for dec.More() {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			// A decode failure here is structural — the stream position is no
			// longer trustworthy — so it stops the parse. Whatever was emitted
			// before this point stands.
			return fmt.Errorf("read observatory indicator: %w", err)
		}
		rec, ok, belowFloor := decodeIndicator(raw, floor)
		switch {
		case ok:
			emit(rec)
			res.Accepted++
		case belowFloor:
			res.BelowSeverity++
		default:
			res.Skipped++
		}
	}
	// Consume the closing bracket so a caller reading further fields resumes
	// in the right place.
	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("read observatory indicators: %w", err)
	}
	return nil
}

// decodeIndicator turns one raw indicator into a record. It reports whether the
// record is usable, and separately whether it was dropped by the severity floor.
func decodeIndicator(raw json.RawMessage, floor int) (rec ObservatoryRecord, ok bool, belowFloor bool) {
	var ind observatoryIndicator
	if err := json.Unmarshal(raw, &ind); err != nil {
		// A type mismatch on one field (say a numeric "severity") still fills
		// in the fields that did decode, so fall through and use what we have
		// rather than discarding an otherwise good indicator.
		if _, isType := err.(*json.UnmarshalTypeError); !isType {
			return rec, false, false
		}
	}

	if !observatoryTypeIsDomain(ind.Type) {
		// IP, URL, and hash indicators are real intelligence, but there is no
		// name for a DNS resolver to block. The Observatory's richer endpoints
		// are where those belong; see docs/threat-intel.md.
		return rec, false, false
	}

	value := ind.Value
	if value == "" {
		value = ind.Domain
	}
	// parseDomain applies the same guards as every other feed format: no bare
	// IPs, no single-label entries that would blackhole a whole TLD.
	domain, valid := parseDomain(value)
	if !valid {
		return rec, false, false
	}

	if rank := catalog.SeverityRank(ind.Severity); floor > 0 && rank > 0 && rank < floor {
		return rec, false, true
	}

	labels := decodeStringList(ind.Categories)
	labels = append(labels, decodeStringList(ind.Category)...)
	category, _ := catalog.BestObservatoryCategory(labels)

	return ObservatoryRecord{
		Domain:   domain,
		Category: category,
		Severity: ind.Severity,
		Family:   ind.Family,
	}, true, false
}

// observatoryTypeIsDomain reports whether an indicator type names something a
// DNS resolver can block. An absent type is treated as a domain: the feed is
// primarily a domain feed, and the guards in parseDomain catch anything that
// is not actually a name.
func observatoryTypeIsDomain(t string) bool {
	switch normaliseToken(t) {
	case "", "domain", "hostname", "host", "fqdn", "dns":
		return true
	}
	return false
}

// decodeStringList accepts either a JSON array of strings or a single string,
// ignoring anything else it finds. Feeds drift; a category field that arrived
// as a bare string is still perfectly readable intelligence.
func decodeStringList(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return list
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return []string{single}
	}
	// An array with mixed element types: keep the strings, drop the rest.
	var mixed []any
	if err := json.Unmarshal(raw, &mixed); err == nil {
		out := make([]string, 0, len(mixed))
		for _, v := range mixed {
			if s, isStr := v.(string); isStr {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// decodeString reads the next value as a string, consuming it either way.
func decodeString(dec *json.Decoder) (string, bool) {
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

// normaliseToken lowercases and trims a feed-supplied token so that "Domain",
// " domain " and "DOMAIN" all compare equal.
func normaliseToken(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
