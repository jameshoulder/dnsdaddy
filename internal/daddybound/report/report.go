// Package report builds the Daddybound laboratory conformance package.
//
// The report is evidence that the offline signed laboratory agrees with the
// standards Daddybound claims to implement. It is not a production readiness
// score, an independent audit or a claim that Live mode is reliable.
package report

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
)

// Document is the machine-readable conformance package.
type Document struct {
	Title        string    `json:"title"`
	GeneratedAt  time.Time `json:"generatedAt"`
	Revision     string    `json:"revision,omitempty"`
	Experimental bool      `json:"experimental"`
	Claims       []string  `json:"claims"`
	NonClaims    []string  `json:"nonClaims"`
	Summary      Summary   `json:"summary"`
	Scenarios    []Result  `json:"scenarios"`
	KnownGaps    []Gap     `json:"knownGaps"`
	NoOracle     []Gap     `json:"noOracle"`
	Evidence     Evidence  `json:"evidence"`
	Milestone    Milestone `json:"milestone"`
}

// Summary counts the laboratory run.
type Summary struct {
	Scenarios int            `json:"scenarios"`
	Agreed    int            `json:"agreed"`
	Disagreed int            `json:"disagreed"`
	ByFamily  map[string]int `json:"byFamily"`
	ByExpect  map[string]int `json:"byExpect"`
}

// Result is one laboratory scenario outcome.
type Result struct {
	Name     string `json:"name"`
	Family   string `json:"family"`
	Status   string `json:"status"`
	Reason   string `json:"reason,omitempty"`
	Expected string `json:"expected"`
	Agrees   bool   `json:"agrees"`
	Why      string `json:"why"`
	KnownGap string `json:"knownGap,omitempty"`
	NoOracle string `json:"noOracle,omitempty"`
}

// Gap is a documented KnownGap or NoOracle annotation.
type Gap struct {
	Name   string `json:"name"`
	Family string `json:"family"`
	Text   string `json:"text"`
}

// Evidence points at the commands and documents that produce further evidence.
type Evidence struct {
	OfflineLab     string   `json:"offlineLab"`
	Differential   string   `json:"differential"`
	Corpus         string   `json:"corpus"`
	Fuzz           string   `json:"fuzz"`
	Documents      []string `json:"documents"`
	NativeCDAndAD  string   `json:"nativeCdAndAd"`
	EncryptedNoPtx string   `json:"encryptedNoPlaintextFallback"`
}

// Milestone tracks the Verified Trust checklist at a coarse grain.
type Milestone struct {
	Name  string `json:"name"`
	Doc   string `json:"doc"`
	Items []Item `json:"items"`
	Note  string `json:"note"`
}

// Item is one checklist row with an honest status.
type Item struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Status   string `json:"status"` // available | partial | planned
	Evidence string `json:"evidence"`
}

// Options control report generation.
type Options struct {
	Revision string
	Now      time.Time
	// Scenarios defaults to lab.Scenarios().
	Scenarios []lab.Scenario
}

// Build runs the offline laboratory and assembles the conformance document.
func Build(opts Options) (Document, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	scenarios := opts.Scenarios
	if scenarios == nil {
		scenarios = lab.Scenarios()
	}

	doc := Document{
		Title:        "Daddybound laboratory conformance",
		GeneratedAt:  now,
		Revision:     opts.Revision,
		Experimental: true,
		Claims: []string{
			"The offline signed laboratory reaches the verdict each scenario requires.",
			"Known gaps and no-oracle cases are named rather than papered over.",
			"This package can be regenerated from the same binary and source revision.",
		},
		NonClaims: []string{
			"Unrestricted agreement with every reading of the DNSSEC standards (known gaps remain named).",
			"Production reliability of Live mode.",
			"An independent professional security review.",
			"Zero unexplained differences against Unbound/BIND on every live Internet name.",
			"A measured false-positive rate for behavioural detection.",
			"Certification under ISO 27001, SOC 2, Cyber Essentials or HIPAA.",
		},
		Summary: Summary{
			ByFamily: map[string]int{},
			ByExpect: map[string]int{},
		},
		Evidence: Evidence{
			OfflineLab:   "dnsdaddy daddybound validate  |  make daddybound-report",
			Differential: "make test-daddybound  (needs libunbound-dev, bind9-dnsutils, cgo)",
			Corpus:       "make corpus  (network; several minutes; not a PR gate)",
			Fuzz:         "make fuzz-daddybound",
			Documents: []string{
				"docs/daddybound/validation-lab.md",
				"docs/daddybound/standards.md",
				"docs/daddybound/security-model.md",
				"docs/maturity/verified-trust.md",
			},
			NativeCDAndAD:  "internal/daddybound/native/client_test.go; forward_test.go (upstream AD never inherited)",
			EncryptedNoPtx: "docs/encrypted-dns.md; resolver encrypted_* tests (no plaintext fallback)",
		},
		Milestone: verifiedTrustChecklist(),
	}

	for _, sc := range scenarios {
		h, err := sc.Build(lab.StandardSpec())
		if err != nil {
			return Document{}, fmt.Errorf("scenario %s: %w", sc.Name, err)
		}
		v, err := h.Validator(sc.At)
		if err != nil {
			return Document{}, fmt.Errorf("scenario %s: %w", sc.Name, err)
		}
		got := v.Validate(context.Background(), sc.Query, sc.QType)
		agrees := got.Status == sc.Expect && (sc.Reason == "" || got.Reason == sc.Reason)
		family := string(sc.Family)
		if family == "" {
			family = "unclassified"
		}
		doc.Summary.Scenarios++
		doc.Summary.ByFamily[family]++
		doc.Summary.ByExpect[sc.Expect.String()]++
		if agrees {
			doc.Summary.Agreed++
		} else {
			doc.Summary.Disagreed++
		}
		row := Result{
			Name: sc.Name, Family: family,
			Status: got.Status.String(), Reason: got.Reason.String(),
			Expected: sc.Expect.String(), Agrees: agrees, Why: sc.Why,
			KnownGap: sc.KnownGap, NoOracle: sc.NoOracle,
		}
		doc.Scenarios = append(doc.Scenarios, row)
		if sc.KnownGap != "" {
			doc.KnownGaps = append(doc.KnownGaps, Gap{Name: sc.Name, Family: family, Text: sc.KnownGap})
		}
		if sc.NoOracle != "" {
			doc.NoOracle = append(doc.NoOracle, Gap{Name: sc.Name, Family: family, Text: sc.NoOracle})
		}
	}
	return doc, nil
}

// WriteJSON emits the document as indented JSON.
func WriteJSON(w io.Writer, doc Document) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// WriteMarkdown emits a human-readable conformance summary.
func WriteMarkdown(w io.Writer, doc Document) error {
	var b bytes.Buffer
	fmt.Fprintf(&b, "# %s\n\n", doc.Title)
	fmt.Fprintf(&b, "Generated: `%s`  \n", doc.GeneratedAt.Format(time.RFC3339))
	if doc.Revision != "" {
		fmt.Fprintf(&b, "Revision: `%s`  \n", doc.Revision)
	}
	fmt.Fprintf(&b, "Status: **experimental**\n\n")

	fmt.Fprintln(&b, "## What this report claims")
	fmt.Fprintln(&b)
	for _, c := range doc.Claims {
		fmt.Fprintf(&b, "- %s\n", c)
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## What this report does not claim")
	fmt.Fprintln(&b)
	for _, c := range doc.NonClaims {
		fmt.Fprintf(&b, "- %s\n", c)
	}
	fmt.Fprintln(&b)

	fmt.Fprintln(&b, "## Laboratory summary")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "| Metric | Value |\n| --- | ---: |\n")
	fmt.Fprintf(&b, "| Scenarios | %d |\n", doc.Summary.Scenarios)
	fmt.Fprintf(&b, "| Agreed with scenario expectations | %d |\n", doc.Summary.Agreed)
	fmt.Fprintf(&b, "| Disagreed | %d |\n", doc.Summary.Disagreed)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "### By family")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "| Family | Count |")
	fmt.Fprintln(&b, "| --- | ---: |")
	for _, family := range sortedKeys(doc.Summary.ByFamily) {
		fmt.Fprintf(&b, "| `%s` | %d |\n", family, doc.Summary.ByFamily[family])
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "### By expected verdict")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "| Expected | Count |")
	fmt.Fprintln(&b, "| --- | ---: |")
	for _, status := range sortedKeys(doc.Summary.ByExpect) {
		fmt.Fprintf(&b, "| `%s` | %d |\n", status, doc.Summary.ByExpect[status])
	}
	fmt.Fprintln(&b)

	if doc.Summary.Disagreed > 0 {
		fmt.Fprintln(&b, "## Failures")
		fmt.Fprintln(&b)
		for _, sc := range doc.Scenarios {
			if sc.Agrees {
				continue
			}
			fmt.Fprintf(&b, "- `%s` expected `%s`, got `%s` (`%s`)\n", sc.Name, sc.Expected, sc.Status, sc.Reason)
		}
		fmt.Fprintln(&b)
	}

	fmt.Fprintln(&b, "## Documented known gaps")
	fmt.Fprintln(&b)
	if len(doc.KnownGaps) == 0 {
		fmt.Fprintln(&b, "_None annotated._")
		fmt.Fprintln(&b)
	} else {
		for _, g := range doc.KnownGaps {
			fmt.Fprintf(&b, "### `%s` (`%s`)\n\n%s\n\n", g.Name, g.Family, wrapPara(g.Text))
		}
	}

	fmt.Fprintln(&b, "## No-oracle scenarios")
	fmt.Fprintln(&b)
	if len(doc.NoOracle) == 0 {
		fmt.Fprintln(&b, "_None annotated._")
		fmt.Fprintln(&b)
	} else {
		for _, g := range doc.NoOracle {
			fmt.Fprintf(&b, "### `%s` (`%s`)\n\n%s\n\n", g.Name, g.Family, wrapPara(g.Text))
		}
	}

	fmt.Fprintln(&b, "## How to reproduce and extend")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "- Offline laboratory: `%s`\n", doc.Evidence.OfflineLab)
	fmt.Fprintf(&b, "- Differential vs Unbound/delv: `%s`\n", doc.Evidence.Differential)
	fmt.Fprintf(&b, "- Real-world corpus: `%s`\n", doc.Evidence.Corpus)
	fmt.Fprintf(&b, "- Fuzz targets: `%s`\n", doc.Evidence.Fuzz)
	fmt.Fprintf(&b, "- CD/AD independence tests: `%s`\n", doc.Evidence.NativeCDAndAD)
	fmt.Fprintf(&b, "- Encrypted no-plaintext-fallback: `%s`\n", doc.Evidence.EncryptedNoPtx)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "Documents:")
	fmt.Fprintln(&b)
	for _, d := range doc.Evidence.Documents {
		fmt.Fprintf(&b, "- `%s`\n", d)
	}
	fmt.Fprintln(&b)

	fmt.Fprintf(&b, "## Milestone: %s\n\n", doc.Milestone.Name)
	fmt.Fprintf(&b, "%s\n\n", doc.Milestone.Note)
	fmt.Fprintln(&b, "| ID | Item | Status | Evidence |")
	fmt.Fprintln(&b, "| --- | --- | --- | --- |")
	for _, item := range doc.Milestone.Items {
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", item.ID, item.Title, item.Status, item.Evidence)
	}
	fmt.Fprintln(&b)

	_, err := io.Copy(w, &b)
	return err
}

func verifiedTrustChecklist() Milestone {
	return Milestone{
		Name: "DNS Daddy: Verified Trust",
		Doc:  "docs/maturity/verified-trust.md",
		Note: "Statuses describe repository evidence today. partial means implemented evidence with named gaps; planned means not yet an evidence package.",
		Items: []Item{
			{ID: "VT-1.1", Title: "DNSSEC interop suite vs Unbound and BIND delv", Status: "partial", Evidence: "make test-daddybound; differential/"},
			{ID: "VT-1.2", Title: "Valid / unsigned / expired / forged / malformed / bad-delegation cases", Status: "partial", Evidence: "lab.Scenarios families positive + chain-failure"},
			{ID: "VT-1.3", Title: "NSEC / NSEC3 / CNAME / DNAME / wildcards / algorithm edges", Status: "partial", Evidence: "lab families nsec, nsec3, alias; algorithm positives"},
			{ID: "VT-1.4", Title: "RFC 5011 rollover, recovery, clock skew", Status: "partial", Evidence: "trustanchors/; differential timemodel_test.go"},
			{ID: "VT-1.5", Title: "Local validation never inherits upstream AD", Status: "available", Evidence: "native/forward_test.go; observe source CD=1"},
			{ID: "VT-1.6", Title: "CD=1 handling documented and tested", Status: "partial", Evidence: "native/client_test.go; docs/daddybound/README.md CD=1 managed-client policy"},
			{ID: "VT-1.7", Title: "Reproducible malicious-DNS laboratory", Status: "partial", Evidence: "lab/ scenarios + Server; not a full packet-adversary harness"},
			{ID: "VT-1.8", Title: "Independent adversarial review of Daddybound", Status: "planned", Evidence: "external engagement required"},
			{ID: "VT-1.9", Title: "Published DNSSEC conformance report", Status: "partial", Evidence: "this package + docs/maturity/verified-trust.md"},
			{ID: "VT-2.1", Title: "Extended fuzz of DNS wire / DoH / feeds / backup", Status: "partial", Evidence: "make fuzz-daddybound; expand beyond daddybound"},
			{ID: "VT-2.2", Title: "AuthN/session/token/CSRF/SSRF review evidence", Status: "partial", Evidence: "docs/security-testing.md; CI security workflow"},
			{ID: "VT-2.3", Title: "Hardened container/host deployment guide", Status: "partial", Evidence: "docs/deploy.md; Dockerfile non-root where possible"},
			{ID: "VT-2.4", Title: "Signed releases, SPDX SBOM, checksum verification", Status: "partial", Evidence: "roadmap Phase 2; existing checksums/SBOM inputs"},
			{ID: "VT-2.5", Title: "Security release gate", Status: "planned", Evidence: "process + reviewer approval"},
			{ID: "VT-2.6", Title: "External audit published with remediations", Status: "planned", Evidence: "commission when evidence package is reviewable"},
		},
	}
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func wrapPara(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	return s
}
