package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
)

// Daddybound's command surface is deliberately small and deliberately
// incapable.
//
// It runs the deterministic offline laboratory and prints what the validation
// engine concluded and why. It cannot be pointed at the Internet, it cannot
// be pointed at a running deployment, and there is no flag that makes it
// enforce anything. That is a structural property rather than an unfinished
// feature: v0.1 performs no recursive resolution, so there is nothing to
// point at a real name with, and adding a switch that appeared to do so would
// be the single most misleading thing this command could offer.
//
// The resolver does not import internal/daddybound. Running this subcommand
// does not touch a configuration file, a database, or a socket.

// runDaddybound dispatches the daddybound subcommands.
func runDaddybound(args []string) error {
	if len(args) == 0 {
		daddyboundUsage(os.Stdout)
		return nil
	}

	switch args[0] {
	case "lab":
		return daddyboundLab(args[1:])
	case "scenarios":
		return daddyboundScenarios(args[1:])
	case "validate":
		return daddyboundValidate(args[1:])
	case "help", "-h", "--help":
		daddyboundUsage(os.Stdout)
		return nil
	default:
		daddyboundUsage(os.Stderr)
		return fmt.Errorf("unknown daddybound command %q", args[0])
	}
}

func daddyboundUsage(w io.Writer) {
	fmt.Fprint(w, `dnsdaddy daddybound — the experimental DNSSEC validation engine

  EXPERIMENTAL. Daddybound is not a production DNSSEC validator and must not
  be relied upon as one. It answers no queries and enforces no policy. These
  commands run a signed laboratory built in memory; they cannot be pointed at
  the Internet or at a running deployment.

Usage:
  dnsdaddy daddybound lab                 show the laboratory hierarchy and its trust anchor
  dnsdaddy daddybound scenarios           list the scenarios and what each one proves
  dnsdaddy daddybound validate [flags]    run the scenarios and report each verdict

Validate flags:
  -scenario name   run one scenario by name (default: all)
  -trace           print the full step trace for each scenario
  -json            emit results as JSON

Exits non-zero if any scenario reaches a verdict other than the one the
standards require of it.
`)
}

// daddyboundLab prints the hierarchy, so an operator can see what is being
// validated before reading a verdict about it.
func daddyboundLab(args []string) error {
	fs := newFlagSet("daddybound lab")
	asJSON := fs.Bool("json", false, "emit as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	h, err := lab.Standard()
	if err != nil {
		return fmt.Errorf("building the laboratory: %w", err)
	}

	if *asJSON {
		type zoneOut struct {
			Name      string `json:"name"`
			Algorithm string `json:"algorithm"`
			KeyTag    uint16 `json:"keyTag"`
			Delegated bool   `json:"delegatedByDS"`
		}
		out := struct {
			TrustAnchor  string    `json:"trustAnchor"`
			Zones        []zoneOut `json:"zones"`
			Experimental bool      `json:"experimental"`
		}{TrustAnchor: h.AnchorDS(), Experimental: true}
		for _, z := range h.Zones {
			out.Zones = append(out.Zones, zoneOut{
				Name: z.Name, Algorithm: z.Algorithm.Name(),
				KeyTag: z.Key.KeyTag(), Delegated: z.DS != nil,
			})
		}
		return writeJSON(os.Stdout, out)
	}

	fmt.Println("Daddybound laboratory (experimental; in memory, never on the network)")
	fmt.Println()
	fmt.Print(h.Description())
	fmt.Println()
	fmt.Printf("trust anchor: %s\n", h.AnchorDS())
	fmt.Printf("answer:       %s A %s\n", lab.AnswerName, lab.AnswerAddress)
	fmt.Printf("signatures:   valid %s to %s\n",
		lab.Inception.Format(time.RFC3339), lab.Expiration.Format(time.RFC3339))
	return nil
}

// daddyboundScenarios lists what the laboratory can construct and, for each,
// why it exists. A scenario nobody can justify is a scenario nobody will
// maintain, so the justification is part of the output rather than a comment.
func daddyboundScenarios(args []string) error {
	fs := newFlagSet("daddybound scenarios")
	asJSON := fs.Bool("json", false, "emit as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	scenarios := lab.Scenarios()
	if *asJSON {
		type out struct {
			Name     string `json:"name"`
			Expect   string `json:"expect"`
			Reason   string `json:"reason,omitempty"`
			Why      string `json:"why"`
			KnownGap string `json:"knownGap,omitempty"`
		}
		list := make([]out, 0, len(scenarios))
		for _, sc := range scenarios {
			list = append(list, out{
				Name: sc.Name, Expect: sc.Expect.String(),
				Reason: sc.Reason.String(), Why: sc.Why, KnownGap: sc.KnownGap,
			})
		}
		return writeJSON(os.Stdout, list)
	}

	for _, sc := range scenarios {
		fmt.Printf("%-26s expects %s", sc.Name, sc.Expect)
		if sc.Reason != "" {
			fmt.Printf(" (%s)", sc.Reason)
		}
		fmt.Println()
		printWrapped(sc.Why, "  ")
		if sc.KnownGap != "" {
			fmt.Println("  known gap against a reference validator:")
			printWrapped(sc.KnownGap, "    ")
		}
		fmt.Println()
	}
	return nil
}

// daddyboundValidate runs the scenarios and reports each verdict.
func daddyboundValidate(args []string) error {
	fs := newFlagSet("daddybound validate")
	only := fs.String("scenario", "", "run one scenario by name")
	trace := fs.Bool("trace", false, "print the full step trace")
	asJSON := fs.Bool("json", false, "emit results as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	scenarios := lab.Scenarios()
	if *only != "" {
		filtered := scenarios[:0]
		for _, sc := range scenarios {
			if sc.Name == *only {
				filtered = append(filtered, sc)
			}
		}
		if len(filtered) == 0 {
			return fmt.Errorf("no scenario named %q; try `dnsdaddy daddybound scenarios`", *only)
		}
		scenarios = filtered
	}

	type resultOut struct {
		Scenario string   `json:"scenario"`
		Status   string   `json:"status"`
		Reason   string   `json:"reason"`
		Expected string   `json:"expected"`
		Agrees   bool     `json:"agrees"`
		Steps    []string `json:"steps,omitempty"`
	}

	var results []resultOut
	failures := 0

	for _, sc := range scenarios {
		h, err := sc.Build()
		if err != nil {
			return fmt.Errorf("scenario %s: %w", sc.Name, err)
		}
		v, err := h.Validator(sc.At)
		if err != nil {
			return fmt.Errorf("scenario %s: %w", sc.Name, err)
		}

		got := v.Validate(context.Background(), sc.Query, sc.QType)
		agrees := got.Status == sc.Expect && (sc.Reason == "" || got.Reason == sc.Reason)
		if !agrees {
			failures++
		}

		r := resultOut{
			Scenario: sc.Name, Status: got.Status.String(), Reason: got.Reason.String(),
			Expected: sc.Expect.String(), Agrees: agrees,
		}
		if *trace || *asJSON {
			for _, s := range got.Steps {
				r.Steps = append(r.Steps, s.String())
			}
		}
		results = append(results, r)

		if !*asJSON {
			mark := "ok  "
			if !agrees {
				mark = "FAIL"
			}
			fmt.Printf("%s %-26s %-14s %s\n", mark, sc.Name, got.Status, got.Reason)
			if *trace {
				fmt.Println(indent(got.Trace(), "       "))
			}
		}
	}

	if *asJSON {
		if err := writeJSON(os.Stdout, results); err != nil {
			return err
		}
	} else {
		fmt.Println()
		fmt.Printf("%s, %d disagreed with the standards\n", plural(len(results), "scenario"), failures)
		fmt.Println()
		fmt.Println("Daddybound is EXPERIMENTAL. These results say the engine agrees with")
		fmt.Println("its own laboratory. They do not make it a production DNSSEC validator.")
	}

	if failures > 0 {
		return fmt.Errorf("%d scenarios reached a verdict the standards do not permit", failures)
	}
	return nil
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func indent(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n")
}

// printWrapped renders prose at terminal width using doctor's wrap, so both
// commands break lines the same way.
func printWrapped(s, prefix string) {
	for _, line := range wrap(s, 74-len(prefix)) {
		fmt.Println(prefix + line)
	}
}

// plural renders a count with its noun, so a single-scenario run does not
// report "1 scenarios".
func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
