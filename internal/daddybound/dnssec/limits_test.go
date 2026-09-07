package dnssec_test

import (
	"context"
	"testing"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
)

// Every input a validator sees comes from the network, so every loop over it
// is a loop whose length an adversary chooses. These assert that hitting a
// bound produces a refusal with a reason, and — the part that matters — that
// the refusal is never a verdict. "I stopped early" is not evidence about the
// data, and reporting it as Bogus or Secure would be inventing some.

func labValidator(t *testing.T, limits dnssec.Limits) *dnssec.Validator {
	t.Helper()
	h, err := lab.Standard()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	cfg, err := h.Config(lab.Now())
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	cfg.Limits = limits
	return dnssec.New(h, cfg)
}

func TestCancelledContextIsNeverAVerdict(t *testing.T) {
	v := labValidator(t, dnssec.DefaultLimits())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got := v.Validate(ctx, lab.AnswerName, dns.TypeA)
	if got.Status != dnssec.StatusIndeterminate {
		t.Errorf("status = %s, want indeterminate\n%s", got.Status, got.Trace())
	}
	if got.Reason != dnssec.ReasonCancelled {
		t.Errorf("reason = %s, want %s", got.Reason, dnssec.ReasonCancelled)
	}
}

func TestLookupBudgetIsNeverAVerdict(t *testing.T) {
	// One lookup is enough to fetch the anchor zone's DNSKEY RRset and no
	// further, so the walk stops partway down a chain it would otherwise
	// complete.
	v := labValidator(t, dnssec.Limits{MaxZones: 24, MaxLookups: 1, MaxSignatures: 16, MaxKeys: 16})

	got := v.Validate(context.Background(), lab.AnswerName, dns.TypeA)
	if got.Status != dnssec.StatusIndeterminate {
		t.Errorf("status = %s, want indeterminate\n%s", got.Status, got.Trace())
	}
	if got.Reason != dnssec.ReasonResourceLimit {
		t.Errorf("reason = %s, want %s\n%s", got.Reason, dnssec.ReasonResourceLimit, got.Trace())
	}
}

func TestKeyAndSignatureBudgetsAreNeverAVerdict(t *testing.T) {
	for _, tc := range []struct {
		name   string
		limits dnssec.Limits
	}{
		{"keys", dnssec.Limits{MaxZones: 24, MaxLookups: 64, MaxSignatures: 16, MaxKeys: 0}},
		{"signatures", dnssec.Limits{MaxZones: 24, MaxLookups: 64, MaxSignatures: 0, MaxKeys: 16}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := labValidator(t, tc.limits)
			got := v.Validate(context.Background(), lab.AnswerName, dns.TypeA)
			if got.Status != dnssec.StatusIndeterminate {
				t.Errorf("status = %s, want indeterminate\n%s", got.Status, got.Trace())
			}
			if got.Reason != dnssec.ReasonResourceLimit {
				t.Errorf("reason = %s, want %s\n%s", got.Reason, dnssec.ReasonResourceLimit, got.Trace())
			}
		})
	}
}

// A limit must never turn into an accusation. Reaching a bound says something
// about this validator's configuration and nothing about the data, so it
// cannot produce Bogus — and obviously must not produce Secure.
func TestNoBudgetProducesAVerdictOnValidData(t *testing.T) {
	for _, limits := range []dnssec.Limits{
		{MaxZones: 1, MaxLookups: 64, MaxSignatures: 16, MaxKeys: 16},
		{MaxZones: 24, MaxLookups: 2, MaxSignatures: 16, MaxKeys: 16},
		{MaxZones: 24, MaxLookups: 64, MaxSignatures: 1, MaxKeys: 16},
		{MaxZones: 24, MaxLookups: 64, MaxSignatures: 16, MaxKeys: 1},
	} {
		v := labValidator(t, limits)
		got := v.Validate(context.Background(), lab.AnswerName, dns.TypeA)
		if got.Status == dnssec.StatusBogus {
			t.Errorf("limits %+v produced bogus on correctly signed data\n%s", limits, got.Trace())
		}
	}
}

// The trace is evidence, and evidence that reorders between runs cannot be
// diffed — not against an earlier run, and not against a reference
// validator's. Nothing in the walk may iterate a map to produce a step.
func TestTraceIsDeterministic(t *testing.T) {
	for _, sc := range lab.Scenarios() {
		t.Run(sc.Name, func(t *testing.T) {
			first := traceOnce(t, sc)
			for i := 0; i < 5; i++ {
				if got := traceOnce(t, sc); got != first {
					t.Fatalf("trace differed between runs\nfirst:\n%s\nrun %d:\n%s", first, i+2, got)
				}
			}
		})
	}
}

func traceOnce(t *testing.T, sc lab.Scenario) string {
	t.Helper()
	h, err := sc.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	v, err := h.Validator(sc.At)
	if err != nil {
		t.Fatalf("validator: %v", err)
	}
	return v.Validate(context.Background(), sc.Query, sc.QType).Trace()
}

// The lab's keys are derived from a seed so that a failing case can be
// reproduced exactly and kept. If key derivation stopped being a function of
// the seed, every recorded trace and every stored signature would become
// unreproducible, and the fact would be silent.
func TestLabKeysAreReproducible(t *testing.T) {
	first, err := lab.Standard()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	second, err := lab.Standard()
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}

	if len(first.Zones) != len(second.Zones) {
		t.Fatalf("zone counts differ: %d and %d", len(first.Zones), len(second.Zones))
	}
	for i := range first.Zones {
		a, b := first.Zones[i], second.Zones[i]
		if a.Key.PublicKey != b.Key.PublicKey {
			t.Errorf("%s: key material differs between builds", a.Name)
		}
		if a.Key.KeyTag() != b.Key.KeyTag() {
			t.Errorf("%s: key tag %d then %d", a.Name, a.Key.KeyTag(), b.Key.KeyTag())
		}
	}
	if first.AnchorDS() != second.AnchorDS() {
		t.Errorf("trust anchor differs between builds:\n %s\n %s", first.AnchorDS(), second.AnchorDS())
	}
}

// Ed25519 signs deterministically, so a rebuilt hierarchy is byte-identical
// down to the signatures. That is what makes a stored signed message usable
// as a regression fixture rather than merely a re-run.
func TestLabSignaturesAreReproducible(t *testing.T) {
	first, err := lab.Standard()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	second, err := lab.Standard()
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}

	a, b := first.Records(), second.Records()
	if len(a) != len(b) {
		t.Fatalf("record counts differ: %d and %d", len(a), len(b))
	}
	for i := range a {
		if a[i].String() != b[i].String() {
			t.Errorf("record %d differs between builds:\n %s\n %s", i, a[i], b[i])
		}
	}
}
