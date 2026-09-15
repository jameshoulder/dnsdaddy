package dnssec_test

import (
	"context"
	"testing"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
)

// countingDelegationSource records every call the walk makes, of either kind.
//
// Both kinds matter and the distinction between them is exactly what this file
// is about. Lookup fetches a record; ZoneCutsFor establishes a boundary, which
// on a real iterative resolver means walking down to the name and asking. Both
// cost packets, so both must be spent from the same budget.
type countingDelegationSource struct {
	inner     dnssec.Source
	lookups   int
	zoneCuts  int
	cuts      map[string]bool
	noOpinion bool
}

func (c *countingDelegationSource) Lookup(ctx context.Context, name string, rrtype uint16) (dnssec.Response, error) {
	c.lookups++
	return c.inner.Lookup(ctx, name, rrtype)
}

func (c *countingDelegationSource) ZoneCutsFor(ctx context.Context, name string) (map[string]bool, bool) {
	c.zoneCuts++
	if c.noOpinion {
		return nil, false
	}
	n := dns.CanonicalName(name)
	return map[string]bool{n: c.cuts[n]}, true
}

func (c *countingDelegationSource) total() int { return c.lookups + c.zoneCuts }

// The lookup budget must bound every question the walk provokes, not only the
// ones whose answers it reads.
//
// MaxLookups is documented as bounding "calls to the Source across one
// validation", and it is the only thing standing between a hostile hierarchy
// and an unbounded number of packets per query. Until this change it counted
// Lookup and ignored ZoneCutsFor entirely — so a walk that consulted the
// source about a delegation at every candidate name spent real queries that
// the budget never saw. The deeper the name, the further past the bound it
// went.
//
// Non-vacuity: remove the budget check and increment from delegationKnown and
// this fails, reporting a total above the limit.
func TestEstablishingDelegationsIsSpentFromTheLookupBudget(t *testing.T) {
	h, err := lab.Standard()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	cfg, err := h.Config(lab.Now())
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	for _, budget := range []int{1, 2, 3, 5, 8, 13} {
		t.Run(dns.TypeToString[dns.TypeA]+"/"+itoa(budget), func(t *testing.T) {
			cfg := cfg
			cfg.Limits.MaxLookups = budget

			// The authority sections are stripped so that no delegation is
			// ever provable from the response itself and the walk has to
			// consult the source at every candidate — which is the shape
			// that spends the most.
			src := &countingDelegationSource{
				inner: suppressingSource{inner: h},
				cuts:  map[string]bool{},
			}
			dnssec.New(src, cfg).Validate(context.Background(), lab.DeepName, dns.TypeA)

			if src.total() > budget {
				t.Errorf("the walk made %d source calls (%d lookups + %d delegation questions) "+
					"against a budget of %d; the budget does not bound the work",
					src.total(), src.lookups, src.zoneCuts, budget)
			}
		})
	}
}

// At the budget the honest answer is "I could not tell", which lands on the
// assumption the walk has always had — and the verdict must be the one a walk
// with no delegation source at all would reach.
//
// A resource limit is not evidence about the data. Letting an exhausted budget
// produce a different verdict from an absent capability would make the limit
// itself an input to validation.
func TestAtTheBudgetTheVerdictIsTheOneWithoutAnyDelegationSource(t *testing.T) {
	h, err := lab.Standard()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	cfg, err := h.Config(lab.Now())
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	cfg.Limits.MaxLookups = 2

	starved := suppressingSource{inner: h}
	// One source can answer but will be cut off by the budget; the other has
	// no capability at all. They must agree.
	budgeted := &countingDelegationSource{inner: starved, cuts: map[string]bool{
		dns.CanonicalName(lab.LeafZone): true,
	}}
	plain := dnssec.New(starved, cfg).Validate(context.Background(), lab.AnswerName, dns.TypeA)
	limited := dnssec.New(budgeted, cfg).Validate(context.Background(), lab.AnswerName, dns.TypeA)

	if plain.Status != limited.Status {
		t.Errorf("a budget-exhausted delegation source changed the verdict: %s without the "+
			"capability, %s with it\n%s", plain.Status, limited.Status, limited.Trace())
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
