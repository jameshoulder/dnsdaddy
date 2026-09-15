package differential

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
)

// More than one resolving view, because agreement through a single one proves
// less than it looks like it proves.
//
// The live corpus compares Daddybound against two independent oracles, which
// is real evidence about the validators. It was not evidence about the
// records: Daddybound, libunbound and delv all read through one forwarder
// address, so all three judged whatever that one resolver chose to hand over.
// A resolver that serves a stale DNSKEY, a filtered answer, or a truncated
// chain makes all three agree — and unanimous agreement on the same wrong
// input is the most convincing wrong answer available.
//
// A view is one way of obtaining records, applied to every validator in it.
// Running the corpus through two views does not make any single comparison
// stronger; it makes a new kind of disagreement visible. Where Daddybound
// reaches different verdicts for one question depending on who supplied the
// records, that is a fact about the Internet or about Daddybound, and either
// way it is worth seeing rather than averaging away.

// A View is one resolving view: a name for reports and the resolver every
// validator in that view reads through.
type View struct {
	// Name identifies the view in a report. Reports are read months later by
	// someone who was not there, so an address alone is not enough.
	Name string
	// Server is the host:port every validator in this view reads through.
	Server string
	// Why records what makes this view independent of the others. It is
	// printed in the report header, because a second view that turned out to
	// be the same infrastructure under another address would be worse than
	// one view: it would look like corroboration.
	Why string
}

func (v View) String() string { return v.Name + " (" + v.Server + ")" }

// DefaultViews are the views the corpus uses when the operator names none.
//
// Two operators, two codebases, two networks. The choice of the second is not
// arbitrary and is worth stating:
//
//   - 1.1.1.1 is Cloudflare's, validates DNSSEC itself, and is what the
//     corpus used when it had one view. It is kept first so that a run today
//     is comparable with the runs already quoted in the documentation.
//   - 9.9.9.10 is Quad9's *unsecured* resolver: no DNSSEC validation and no
//     blocklist. 9.9.9.9 would have been the obvious address and is the wrong
//     one — it validates and filters, so for the deliberately broken names in
//     this corpus it returns SERVFAIL where the raw records are what a
//     validator under test needs to see. Choosing it would have manufactured
//     disagreements that say nothing about Daddybound.
//
// Neither is a dependency of the shipped resolver. Both are reached only by
// an opt-in test.
func DefaultViews() []View {
	return []View{
		{
			Name:   "cloudflare",
			Server: "1.1.1.1:53",
			Why:    "Cloudflare's own resolver implementation; validates DNSSEC",
		},
		{
			Name:   "quad9-unsecured",
			Server: "9.9.9.10:53",
			Why:    "Quad9's unsecured endpoint, a different operator and network; no validation and no blocklist, so broken names arrive as records rather than as SERVFAIL",
		},
	}
}

// ParseViews reads an operator's view list.
//
// Each entry is "addr" or "name=addr"; a missing port means 53. An empty spec
// means DefaultViews.
//
// Duplicate servers are refused rather than deduplicated, and that refusal is
// the point of this function existing at all. Two entries pointing at one
// resolver look like two views in the report header and in the summary
// counts, while being exactly the single view this whole change exists to
// stop relying on. Silently collapsing them would produce a run that claims
// corroboration it does not have.
func ParseViews(spec string) ([]View, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return DefaultViews(), nil
	}

	var out []View
	seen := map[string]string{}
	for _, raw := range strings.Split(spec, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		name, addr := "", entry
		if i := strings.IndexByte(entry, '='); i >= 0 {
			name, addr = strings.TrimSpace(entry[:i]), strings.TrimSpace(entry[i+1:])
		}
		if addr == "" {
			return nil, fmt.Errorf("view %q has no server address", entry)
		}
		if _, _, err := net.SplitHostPort(addr); err != nil {
			addr = net.JoinHostPort(addr, "53")
		}
		if name == "" {
			name = addr
		}
		if first, dup := seen[addr]; dup {
			return nil, fmt.Errorf("views %q and %q are the same resolver (%s); "+
				"two names for one view is not two views", first, name, addr)
		}
		seen[addr] = name
		out = append(out, View{Name: name, Server: addr, Why: "named by the operator"})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no views in %q", spec)
	}
	return out, nil
}

// ViewVerdict is Daddybound's own verdict for one question under one view.
type ViewVerdict struct {
	View   string
	Status dnssec.ValidationStatus
	Reason dnssec.Reason
}

// ViewDisagreement is one question on which Daddybound reached different
// verdicts depending on who supplied the records.
//
// This is an outcome in its own right, not a skip and not a failure. It says
// the answer depended on the path, which is information the single-view
// corpus could not produce at all: with one view there was nothing to differ
// from. Whether the cause is a resolver serving something odd or Daddybound
// being sensitive to how records arrive, the run should say so rather than
// pick one view and call it the answer.
type ViewDisagreement struct {
	Scenario string
	// Verdicts is every view's verdict, ordered by view name so that two runs
	// of the same disagreement read the same way.
	Verdicts []ViewVerdict
}

// Line renders one disagreement for a report.
func (d ViewDisagreement) Line() string {
	parts := make([]string, 0, len(d.Verdicts))
	for _, v := range d.Verdicts {
		// Status is a uint8 with a String method, not a string. Converting it
		// directly yields a control byte, which renders as an invisible
		// report line — caught by the test that reads the line back.
		s := v.View + "=" + v.Status.String()
		if v.Reason != "" {
			s += "(" + string(v.Reason) + ")"
		}
		parts = append(parts, s)
	}
	return d.Scenario + ": " + strings.Join(parts, " vs ")
}

// FindViewDisagreements returns the questions whose verdict depended on the
// view.
//
// A question seen by fewer than two views is not a disagreement and not an
// agreement — it is one observation, and reporting it either way would be
// inventing a comparison that did not happen.
func FindViewDisagreements(byScenario map[string][]ViewVerdict) []ViewDisagreement {
	var out []ViewDisagreement
	for scenario, verdicts := range byScenario {
		if len(verdicts) < 2 {
			continue
		}
		same := true
		for _, v := range verdicts[1:] {
			if v.Status != verdicts[0].Status {
				same = false
				break
			}
		}
		if same {
			continue
		}
		ordered := append([]ViewVerdict(nil), verdicts...)
		sort.Slice(ordered, func(i, j int) bool { return ordered[i].View < ordered[j].View })
		out = append(out, ViewDisagreement{Scenario: scenario, Verdicts: ordered})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Scenario < out[j].Scenario })
	return out
}

// IsFailure reports whether a class is a result the lab suite must fail on.
//
// Agreement and a declared known gap are the only two outcomes that are not a
// failure. A reference error counts as one here because in the laboratory the
// oracle is reading a hierarchy served on loopback: if it cannot answer,
// something is broken that will make every other result untrustworthy. The
// live corpus treats it differently and says so, because there the oracle is
// crossing the Internet.
func (c Class) IsFailure() bool {
	switch c {
	case ClassMatch, ClassKnownGap:
		return false
	default:
		return true
	}
}
