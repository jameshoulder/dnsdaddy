package dnssec_test

import (
	"context"
	"sync"
	"testing"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
)

// A verdict must be a function of the question and the records, and of
// nothing else — not of what was validated before it, and not of what is
// being validated alongside it.
//
// The concern is specific rather than general hygiene. One Validator is meant
// to serve many queries, and if anything survived between them an attacker
// would have a lever nobody is watching: ask a question that leaves the
// validator in a state where the *next* question, which somebody else asked,
// comes out differently. That is the shape of a cache-poisoning bug rather
// than a validation bug, and no amount of RFC conformance rules it out.
//
// Two ways it can fail, so two properties:
//
//   - **Order.** Running every question through one Validator, then running
//     each on its own, must give the same answers. A validator carrying
//     anything forward gives itself away here.
//   - **Concurrency.** The same questions in parallel must agree with the
//     serial run. Under -race this also catches a shared structure being
//     written without a lock, which is the mechanism by which the first
//     property would break.
func TestAVerdictDoesNotDependOnWhatCameBefore(t *testing.T) {
	h, err := lab.Standard()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	cfg, err := h.Config(lab.Now())
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	type question struct {
		name   string
		rrtype uint16
	}
	// Deliberately mixed: Secure, Bogus, Insecure and Indeterminate all
	// appear, because a leak between two questions with the same verdict
	// would be invisible.
	questions := []question{
		{lab.AnswerName, dns.TypeA},
		{lab.MissingName, dns.TypeA},
		{lab.UnsignedName, dns.TypeA},
		{lab.AliasHop1, dns.TypeA},
		{lab.AliasLoopA, dns.TypeA},
		{lab.DnameMatch, dns.TypeA},
		{lab.AliasToInsecure, dns.TypeA},
		{lab.WildcardMatch, dns.TypeA},
		{lab.EmptyNonTerminal, dns.TypeA},
		{lab.AnswerName, dns.TypeANY},
		{"www.somewhere-else.invalid.", dns.TypeA},
	}

	// Each on its own validator, which is the reference: nothing can have
	// been carried in.
	alone := make([]dnssec.ValidationResult, len(questions))
	for i, q := range questions {
		alone[i] = dnssec.New(h, cfg).Validate(context.Background(), q.name, q.rrtype)
	}

	t.Run("one validator, in sequence", func(t *testing.T) {
		shared := dnssec.New(h, cfg)
		// Twice through, so a leak that only appears on a second visit to
		// the same name is caught as well.
		for pass := 0; pass < 2; pass++ {
			for i, q := range questions {
				got := shared.Validate(context.Background(), q.name, q.rrtype)
				if got.Status != alone[i].Status || got.Reason != alone[i].Reason {
					t.Fatalf("pass %d, %s/%s: %s (%s) in sequence, %s (%s) on its own",
						pass, q.name, dns.TypeToString[q.rrtype],
						got.Status, got.Reason, alone[i].Status, alone[i].Reason)
				}
			}
		}
	})

	t.Run("one validator, in parallel", func(t *testing.T) {
		shared := dnssec.New(h, cfg)
		var wg sync.WaitGroup
		for round := 0; round < 8; round++ {
			for i, q := range questions {
				wg.Add(1)
				go func(i int, q question) {
					defer wg.Done()
					got := shared.Validate(context.Background(), q.name, q.rrtype)
					if got.Status != alone[i].Status || got.Reason != alone[i].Reason {
						t.Errorf("%s/%s in parallel: %s (%s), want %s (%s)",
							q.name, dns.TypeToString[q.rrtype],
							got.Status, got.Reason, alone[i].Status, alone[i].Reason)
					}
				}(i, q)
			}
		}
		wg.Wait()
	})
}

// The trace must belong to the validation that produced it.
//
// A shared recorder would show up here long before it showed up as a wrong
// verdict, and a trace that mixed two validations is the diagnostic
// equivalent of the same bug: an operator reading it would be told about
// somebody else's query.
func TestATraceBelongsToItsOwnValidation(t *testing.T) {
	h, err := lab.Standard()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	cfg, err := h.Config(lab.Now())
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	shared := dnssec.New(h, cfg)

	first := shared.Validate(context.Background(), lab.AnswerName, dns.TypeA)
	second := shared.Validate(context.Background(), lab.MissingName, dns.TypeA)
	third := shared.Validate(context.Background(), lab.AnswerName, dns.TypeA)

	if first.Trace() != third.Trace() {
		t.Errorf("the same question produced two different traces from one validator:\n%s\n---\n%s",
			first.Trace(), third.Trace())
	}
	if first.Trace() == second.Trace() {
		t.Error("two different questions produced the same trace")
	}
}
