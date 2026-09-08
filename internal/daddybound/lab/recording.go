package lab

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
)

// A dnssec.Source that records what was asked of it.
//
// This exists to settle arguments with measurement. "What does this validator
// know about the zone cuts" is otherwise a matter of opinion, and a DNSSEC
// disagreement between two implementations usually turns on what each one
// looked up rather than on how it reasoned about what it found. The
// authoritative server already records the questions a reference validator
// asks over the wire; this records the questions Daddybound asks in memory,
// so the two lists can be put side by side.

// Recorder wraps a Source and keeps the questions in order.
type Recorder struct {
	inner dnssec.Source

	mu      sync.Mutex
	queries []Query
}

// Recording returns a Source that answers from this hierarchy and remembers
// what it was asked.
func (h *Hierarchy) Recording() *Recorder { return &Recorder{inner: h} }

// Lookup implements dnssec.Source.
func (r *Recorder) Lookup(ctx context.Context, name string, rrtype uint16) (dnssec.Response, error) {
	resp, err := r.inner.Lookup(ctx, name, rrtype)

	q := Query{Name: dns.CanonicalName(name), Type: rrtype, DOBit: true, Rcode: resp.Rcode, Answer: len(resp.Answer)}
	r.mu.Lock()
	r.queries = append(r.queries, q)
	r.mu.Unlock()
	return resp, err
}

// Queries returns everything asked so far, in order.
func (r *Recorder) Queries() []Query {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Query(nil), r.queries...)
}

// NamesAsked returns the distinct names queried for one type, sorted.
//
// Sorted and deduplicated because the interesting question is "did it ask
// about this cut at all", not how many times or in what order. Two validators
// may reach the same knowledge by different routes.
func NamesAsked(queries []Query, rrtype uint16) []string {
	seen := map[string]bool{}
	for _, q := range queries {
		if q.Type == rrtype {
			seen[q.Name] = true
		}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// FormatQueries renders a query list for a test log, one per line.
func FormatQueries(queries []Query) string {
	out := ""
	for _, q := range queries {
		out += fmt.Sprintf("  %s\n", q)
	}
	if out == "" {
		return "  (nothing was asked)\n"
	}
	return out
}
