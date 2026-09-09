package differential_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
)

// What each validator asks, rather than what each one concludes.
//
// A DNSSEC disagreement usually turns on what the two implementations looked
// up. Arguing about it from the verdicts alone is guesswork; the lab records
// both sides — the authoritative server logs what a reference validator asks
// over the wire, and lab.Recorder logs what Daddybound asks its Source — so
// the question can be answered by reading two lists.
//
// This is the instrumentation Phase 4 of the milestone calls for, and it is a
// test rather than a script so that a change in Daddybound's query pattern
// shows up as a failure instead of as folklore.

// zoneCuts are the delegation points between the anchor and the answer in the
// standard hierarchy. A validator that has not asked about a name cannot know
// whether it is a zone cut.
var zoneCuts = []string{lab.MiddleZone, lab.LeafZone}

func daddyboundQueries(t *testing.T, sc lab.Scenario) []lab.Query {
	t.Helper()
	h, err := sc.Build(lab.StandardSpec())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	cfg, err := h.Config(sc.At)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	rec := h.Recording()
	dnssec.New(rec, cfg).Validate(context.Background(), sc.Query, sc.QType)
	return rec.Queries()
}

// TestDaddyboundAsksAboutEveryZoneCut is the property the whole chain walk
// depends on.
//
// Daddybound derives the containing zone by walking delegations rather than by
// reading the signer name off an RRSIG, which is the stricter reading of
// RFC 4035 §5.3.1 and the source of the one unresolved disagreement in this
// suite. That reading only means anything if the walk actually asks. A version
// that quietly skipped a DS question would be taking the signer's word for the
// cut while claiming not to.
func TestDaddyboundAsksAboutEveryZoneCut(t *testing.T) {
	sc := scenarioNamed(t, "valid")
	asked := lab.NamesAsked(daddyboundQueries(t, sc), dns.TypeDS)

	for _, cut := range zoneCuts {
		if !contains(asked, cut) {
			t.Errorf("no DS question for the zone cut at %s; the walk cannot have derived it\nasked: %v", cut, asked)
		}
	}
}

// TestDaddyboundStillAsksWhenTheSignerLies is the measurement that the
// foreign-zone-signature disagreement turns on.
//
// In that scenario an ancestor zone signs a delegated child's data. libunbound
// and delv both accept it; Daddybound refuses. The explanation on record is
// that both oracles take the containing zone from the RRSIG's signer name,
// while Daddybound re-derives it from the delegations it crossed.
//
// That explanation is only worth anything if Daddybound's query pattern is
// unchanged by the lie — if it asks the same DS questions whether or not the
// signature names the right zone. Were the queries to differ, the refusal
// would be an artefact of having looked somewhere else rather than of
// applying a stricter rule to the same evidence.
func TestDaddyboundStillAsksWhenTheSignerLies(t *testing.T) {
	honest := lab.NamesAsked(daddyboundQueries(t, scenarioNamed(t, "valid")), dns.TypeDS)
	lying := lab.NamesAsked(daddyboundQueries(t, scenarioNamed(t, "foreign-zone-signature")), dns.TypeDS)

	if strings.Join(honest, ",") != strings.Join(lying, ",") {
		t.Errorf("the DS questions changed when the signer name changed, so the refusal is about what was looked up rather than about the rule\n honest: %v\n  lying: %v",
			honest, lying)
	}
	if len(honest) == 0 {
		t.Fatal("no DS questions at all; this test measured nothing")
	}
}

// TestDelvNeverLearnsTheCutItIsAcceptingAcross settles the open question by
// measurement rather than by argument, and the answer was not the one on
// record.
//
// The foreign-zone-signature scenario has an ancestor zone signing a
// delegated child's data. Both reference validators accept it and Daddybound
// refuses. Two explanations were possible, calling for different responses:
// either delv learns where the cut is and accepts the ancestor's signature
// deliberately — in which case two mature implementations read RFC 4035
// §5.3.1 differently and the question is a real one — or it never learns,
// in which case Daddybound is better informed rather than merely stricter.
//
// The queries settle it. delv asks for the answer, then follows the RRSIG's
// signer name upwards: dnsdaddylab DNSKEY, dnsdaddylab DS, root DNSKEY. It
// never asks about example.dnsdaddylab at all, so it never discovers that the
// name it is validating lies below a zone cut. It cannot apply "the signer's
// name MUST be the zone that contains the RRset" because it has not
// established which zone that is.
//
// This test pins the measurement. If delv's query pattern changes, the
// explanation in docs/daddybound/standards.md §5.8 is out of date and needs
// re-deriving rather than re-asserting.
func TestDelvNeverLearnsTheCutItIsAcceptingAcross(t *testing.T) {
	if _, err := os.Stat("/usr/bin/delv"); err != nil {
		t.Skip("delv is not installed; this measurement needs a second implementation")
	}

	sc := scenarioNamed(t, "foreign-zone-signature").Shifted(time.Since(lab.Now()))
	h, err := sc.Build(lab.StandardSpec())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	srv, err := h.StartServer()
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
	defer srv.Close() //nolint:errcheck // the measurement is the outcome

	out, err := runDelv(t, h, srv, sc)
	if err != nil {
		t.Fatalf("delv: %v\n%s", err, out)
	}

	asked := lab.NamesAsked(srv.Queries(), dns.TypeDS)
	knewTheCut := contains(asked, lab.LeafZone)
	accepted := strings.Contains(out, "; fully validated")

	t.Logf("delv asked for DS at: %v", asked)
	t.Logf("every question delv asked:\n%s", lab.FormatQueries(srv.Queries()))

	if !accepted {
		t.Fatalf("delv refused this answer, which contradicts the disagreement recorded against "+
			"the foreign-zone-signature scenario; the KnownGap text needs revisiting\n%s", out)
	}
	if knewTheCut {
		t.Fatalf("delv asked for %s DS and accepted anyway, so it does know the cut. "+
			"standards.md §5.8 says the opposite and must be re-derived, not patched", lab.LeafZone)
	}

	// The state of the world as measured: it accepted, and it never asked.
	// Daddybound refuses on information delv did not gather.
	t.Logf("confirmed: delv accepted without ever asking about the cut at %s", lab.LeafZone)
}

// TestDaddyboundGathersWhatDelvDoesNot is the other half of the same
// measurement, and the reason the difference is not simply "Daddybound is
// fussier".
//
// Daddybound descends the delegations from the anchor, so by the time it
// validates the answer it has an authenticated DS and DNSKEY for the zone
// that actually contains the name. That is why it can apply RFC 4035 §5.3.1's
// rule at all. The refusal follows from evidence delv never collected.
func TestDaddyboundGathersWhatDelvDoesNot(t *testing.T) {
	queries := daddyboundQueries(t, scenarioNamed(t, "foreign-zone-signature"))
	ds := lab.NamesAsked(queries, dns.TypeDS)
	keys := lab.NamesAsked(queries, dns.TypeDNSKEY)

	if !contains(ds, lab.LeafZone) {
		t.Errorf("no DS question for %s, so Daddybound is refusing without having established the cut either\nasked: %v",
			lab.LeafZone, ds)
	}
	if !contains(keys, lab.LeafZone) {
		t.Errorf("no DNSKEY question for %s\nasked: %v", lab.LeafZone, keys)
	}
}

func scenarioNamed(t *testing.T, name string) lab.Scenario {
	t.Helper()
	for _, sc := range lab.Scenarios() {
		if sc.Name == name {
			return sc
		}
	}
	t.Fatalf("no scenario named %q", name)
	return lab.Scenario{}
}

func contains(haystack []string, needle string) bool {
	want := dns.CanonicalName(needle)
	for _, s := range haystack {
		if dns.CanonicalName(s) == want {
			return true
		}
	}
	return false
}

// runDelv asks delv one question against the lab's server, with a trust
// anchor written in BIND's static-ds form.
//
// Kept here rather than reused from the refdelv oracle because that package
// deliberately reports only a verdict: it maps delv's words onto the four RFC
// 4033 states and throws the rest away, which is right for a comparison and
// useless for a measurement. What is wanted here is the trace.
func runDelv(t *testing.T, h *lab.Hierarchy, srv *lab.Server, sc lab.Scenario) (string, error) {
	t.Helper()

	anchorFile := filepath.Join(t.TempDir(), "anchor.conf")
	content := fmt.Sprintf("trust-anchors {\n  %q static-ds %d %d %d %q;\n};\n",
		h.Anchor.Name, h.Anchor.KeyTag, h.Anchor.Algorithm, h.Anchor.DigestType,
		strings.ToUpper(hex.EncodeToString(h.Anchor.Digest)))
	if err := os.WriteFile(anchorFile, []byte(content), 0o600); err != nil {
		return "", err
	}

	host, port, ok := strings.Cut(srv.Addr(), ":")
	if !ok {
		return "", fmt.Errorf("cannot split %q into host and port", srv.Addr())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// #nosec G204 -- every argument is either a literal or a value this test
	// constructed: a loopback address and port from the listener it just
	// opened, a temporary file path, and a scenario name from a compiled-in
	// table. Nothing here comes from outside the process.
	cmd := exec.CommandContext(ctx, "delv",
		"@"+host, "-p", port, "-a", anchorFile,
		"-t", dns.TypeToString[sc.QType], sc.Query, "+vtrace")
	out, err := cmd.CombinedOutput()
	return string(out), err
}
