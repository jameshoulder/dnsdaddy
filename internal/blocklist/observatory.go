package blocklist

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/catalog"
)

// ObservatoryRecord is one indicator from the Threat Observatory, resolved down
// to what the index needs: a domain and the categories to file it under.
type ObservatoryRecord struct {
	Domain string
	// Categories are the DNS Daddy categories the indicator's own labels mapped
	// to, most severe first. Empty when none of them was recognised, in which
	// case the caller falls back to the feed's configured category.
	//
	// All of them are kept. An indicator tagged both malware and C2 is blocked
	// by a malware-only policy and by a C2-only policy alike.
	Categories []string
}

// ObservatoryResult reports what a feed document contained.
type ObservatoryResult struct {
	// GeneratedAt is when the Observatory built the document, if it said.
	GeneratedAt time.Time
	// Source is the document's self-declared origin, not an authenticated identity.
	// It is retained for callers but must not be logged: it may contain secrets.
	// TLS is what establishes who served the file.
	Source string
	// Accepted counts indicators emitted; Skipped counts those rejected as
	// unusable (an IP, a bare TLD, a malformed entry).
	Accepted int
	Skipped  int
}

// observatoryIndicator mirrors one entry in the feed document.
//
// Every field that is not a plain string is decoded as RawMessage and
// interpreted separately. A feed is a file served by a remote host, and one
// indicator whose "categories" arrived as a string instead of an array must
// cost that indicator, not the entire category of protection the feed provides.
// Fields the Observatory carries but DNS Daddy does not act on — severity,
// family, last_seen — are deliberately absent. They belong to the Observatory's
// own judgement about what to publish; what a resolver does with a published
// indicator is a policy question, answered by the category machinery.
type observatoryIndicator struct {
	Value      string          `json:"value"`
	Domain     string          `json:"domain"`
	Type       string          `json:"type"`
	Categories json.RawMessage `json:"categories"`
	Category   json.RawMessage `json:"category"`
}

// ParseObservatory reads a Threat Observatory feed document and calls emit for
// every usable domain indicator.
//
// Parsing is streaming and deliberately forgiving about the shape of an
// individual indicator, for the same reason the line-based parser is: a single
// malformed entry must not cost an operator a whole feed's worth of blocking.
// Unusable indicators are counted and skipped.
//
// It is not forgiving about the document as a whole. A document that is
// truncated, malformed, or not shaped like a feed at all returns an error, and
// the caller is expected to discard it rather than treat it as a small feed —
// see ValidateObservatory, which is this same function with nothing to emit to.
func ParseObservatory(r io.Reader, emit func(ObservatoryRecord)) (ObservatoryResult, error) {
	return parseObservatory(r, emit)
}

// ValidateObservatory reports whether r holds a complete, well-formed
// Observatory document. It streams the document and buffers at most one bounded JSON value.
//
// This is what stands between a bad response and the operator's blocklist. A
// feed download is replacing a dataset that is currently blocking traffic, and
// a body that stops halfway is not a smaller dataset — it is thousands of
// malicious domains silently becoming resolvable again. The same goes for a
// 200 response carrying an HTML error page, or a JSON document that parses
// perfectly and simply is not a feed: `{"error":"rate limited"}` is complete,
// well-formed, and would quietly empty the feed it replaced.
//
// So the rule is all or nothing, and the check is the parser itself, run with
// nothing to emit to. That is deliberate. A validator that agreed with the
// parser on the day it was written and drifted afterwards would be worse than
// none: it would wave through a document the loader then refuses, which is
// precisely the failure it exists to prevent — the good cache replaced, the
// refresh recorded as successful, and the feed contributing nothing.
func ValidateObservatory(r io.Reader) error {
	_, err := parseObservatory(r, nil)
	return err
}

// parseObservatory is the single implementation behind both ParseObservatory
// and ValidateObservatory. emit may be nil, which makes it a validating pass
// that still walks every byte with bounded per-value buffering.
func parseObservatory(r io.Reader, emit func(ObservatoryRecord)) (ObservatoryResult, error) {
	ctx := context.Background()
	return parseObservatoryLimited(ctx, &countedReader{ctx: ctx, r: r, left: 128 << 20}, 1000000, func(rec ObservatoryRecord) error {
		if emit != nil {
			emit(rec)
		}
		return nil
	})
}

// decodeIndicator turns one raw indicator into a record, reporting whether it
// is usable.
func decodeIndicator(raw json.RawMessage) (rec ObservatoryRecord, ok bool) {
	var ind observatoryIndicator
	if err := json.Unmarshal(raw, &ind); err != nil {
		// A type mismatch on one field still fills in the fields that did
		// decode, so fall through and use what we have rather than discarding
		// an otherwise good indicator.
		if _, isType := err.(*json.UnmarshalTypeError); !isType {
			return rec, false
		}
	}

	if !observatoryTypeIsDomain(ind.Type) {
		// IP, URL, and hash indicators are real intelligence, but there is no
		// name for a DNS resolver to block. The Observatory's richer endpoints
		// are where those belong; see docs/threat-intel.md.
		return rec, false
	}

	value := ind.Value
	if value == "" {
		value = ind.Domain
	}
	// parseDomain applies the same guards as every other feed format: no bare
	// IPs, no single-label entries that would blackhole a whole TLD.
	domain, valid := parseDomain(value)
	if !valid {
		return rec, false
	}

	labels := decodeStringList(ind.Categories)
	labels = append(labels, decodeStringList(ind.Category)...)

	return ObservatoryRecord{
		Domain:     domain,
		Categories: catalog.MapObservatoryCategories(labels),
	}, true
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

// normaliseToken lowercases and trims a feed-supplied token so that "Domain",
// " domain " and "DOMAIN" all compare equal.
func normaliseToken(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
