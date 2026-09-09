package differential

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// The real-world corpus: the same comparison, asked of the live Internet.
//
// The lab scenarios establish that Daddybound reads the standards the way
// two other implementations do, on data built to make each rule reachable.
// What they cannot establish is that the rules are the right *set* — that no
// shape occurring in the wild falls outside every scenario anyone thought to
// write. Only real names can answer that, because nobody has to think of them.
//
// Two disciplines make the answer worth having, and both are about the corpus
// rather than the code.
//
// The names are not chosen by verdict. Most come from a public ranked list,
// sampled by rank arithmetic, with nothing inspected before inclusion and
// nothing removed after; the rest are named for a DNSSEC *shape* the ranked
// sample reaches only by luck. A corpus assembled from names Daddybound
// happens to handle would measure nothing at all, which is why the file
// records where each entry came from and the loader here refuses one that
// does not.
//
// And no expected verdict is stored. The oracles produce them at run time.
// A file of expectations would date the moment a zone re-signed, and worse,
// it would let a Daddybound change be "confirmed" by editing the file.

// CorpusEntry is one question to put to every validator.
type CorpusEntry struct {
	// Category says which shape this entry is here to exercise, or which
	// sample it was drawn from. It groups the report; it never affects the
	// comparison.
	Category string
	Name     string
	QType    uint16
}

// String renders an entry the way the corpus file stores it.
func (e CorpusEntry) String() string {
	return fmt.Sprintf("%s\t%s\t%s", e.Category, dns.TypeToString[e.QType], e.Name)
}

// ParseCorpus reads the corpus file format: category, query type and name,
// tab separated, with '#' comments and blank lines ignored.
//
// Strict about every field. A corpus is evidence, and a loader that quietly
// skipped a line it could not read would shrink the evidence without saying
// so — the failure mode where a run reports "all 400 names agree" because 200
// of them were dropped by a typo.
func ParseCorpus(r io.Reader) ([]CorpusEntry, error) {
	var out []CorpusEntry
	seen := map[string]bool{}

	sc := bufio.NewScanner(r)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Split(text, "\t")
		if len(fields) != 3 {
			return nil, fmt.Errorf("corpus line %d: want category, type and name separated by tabs, got %q", line, text)
		}
		category, typeName, name := strings.TrimSpace(fields[0]), strings.TrimSpace(fields[1]), strings.TrimSpace(fields[2])

		qtype, ok := dns.StringToType[typeName]
		if !ok {
			return nil, fmt.Errorf("corpus line %d: %q is not a record type mnemonic", line, typeName)
		}
		if qtype == dns.TypeANY {
			// Not a refusal of ANY — the engine implements RFC 6840 §4.2 —
			// but a refusal to compare it here. delv and libunbound
			// disagree with each other about what a partially valid ANY
			// answer means, so every ANY entry would land in the report as
			// a divergence between the oracles rather than a finding about
			// Daddybound. The lab covers ANY, where the response is known
			// exactly.
			return nil, fmt.Errorf("corpus line %d: ANY is covered by the lab, not by the live corpus", line)
		}
		if _, ok := dns.IsDomainName(name); !ok {
			return nil, fmt.Errorf("corpus line %d: %q is not a domain name", line, name)
		}
		if !strings.HasSuffix(name, ".") {
			return nil, fmt.Errorf("corpus line %d: %q is not fully qualified", line, name)
		}
		if category == "" {
			return nil, fmt.Errorf("corpus line %d: no category", line)
		}

		key := dns.CanonicalName(name) + "/" + typeName
		if seen[key] {
			// Duplicates would weight one name more heavily than another in
			// the totals without anyone intending it, which is the quiet
			// way a percentage stops meaning what it says.
			return nil, fmt.Errorf("corpus line %d: %s is already in the corpus", line, key)
		}
		seen[key] = true

		out = append(out, CorpusEntry{Category: category, Name: dns.CanonicalName(name), QType: qtype})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("corpus: %w", err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("corpus: no entries")
	}
	return out, nil
}

// CorpusReport is a Report grouped by the corpus categories.
type CorpusReport struct {
	Report
	Categories map[string]Report
}

// CorpusSummary renders the whole run: totals, then a breakdown by category,
// then every comparison that was not a plain match.
//
// The false-Secure list is printed first and in full even when it is empty,
// because a number that is usually zero is a number people stop reading. A
// line saying so is harder to skim past than its absence.
func (c CorpusReport) Summary() string {
	out := "REAL-WORLD CORPUS\n" + c.Report.Summary()

	out += "\nby category\n"
	names := make([]string, 0, len(c.Categories))
	for k := range c.Categories {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, name := range names {
		r := c.Categories[name]
		line := fmt.Sprintf("  %-22s", name)
		for _, count := range r.Counts() {
			if count.N > 0 {
				line += fmt.Sprintf(" %s=%d", count.Class, count.N)
			}
		}
		out += line + "\n"
	}
	return out
}

// GroupByCategory splits a set of comparisons into per-category reports.
//
// The category comes from the corpus entry, so it is a statement about why
// the name is in the file rather than about what happened to it.
func GroupByCategory(oracle string, comparisons []Comparison, categoryOf func(scenario string) string) CorpusReport {
	out := CorpusReport{
		Report:     Report{Oracle: oracle, Comparisons: comparisons},
		Categories: map[string]Report{},
	}
	for _, c := range comparisons {
		cat := categoryOf(c.Scenario)
		r := out.Categories[cat]
		r.Oracle = oracle
		r.Comparisons = append(r.Comparisons, c)
		out.Categories[cat] = r
	}
	return out
}
