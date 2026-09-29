package api

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/observe"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/trustanchors"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// fakeAnchors is a trust-anchor manager in whatever state a test needs.
type fakeAnchors struct {
	tp     trustanchors.TrustPoint
	viable bool
	health trustanchors.Health
}

func (f fakeAnchors) TrustPoint() trustanchors.TrustPoint { return f.tp }
func (f fakeAnchors) Viable() bool                        { return f.viable }
func (f fakeAnchors) Health() trustanchors.Health         { return f.health }

func TestDNSSECStatusWithLearnOffSaysNothingIsRunning(t *testing.T) {
	h := newHarness(t)
	h.login()

	var body dnssecStatus
	h.getJSON("/api/v1/dnssec/status", &body)

	if body.Mode.Effective != "off" || body.Mode.Enforcing || !body.Mode.Experimental {
		t.Errorf("mode = %+v", body.Mode)
	}
	if body.Mode.Live.Available || body.Mode.Live.Reason == "" {
		t.Errorf("live = %+v, want unavailable with a reason", body.Mode.Live)
	}
	if body.Resolution.Source != "none" || !strings.Contains(body.Resolution.Transport, "none") {
		t.Errorf("resolution = %+v, want none", body.Resolution)
	}
	if body.Anchors.Available || body.Anchors.Unavailable == "" {
		t.Errorf("anchors = %+v, want unavailable with a reason", body.Anchors)
	}
	if body.Runtime.Available || body.Runtime.Health != "unavailable" {
		t.Errorf("runtime = %+v, want unavailable", body.Runtime)
	}
	if body.Evidence.Sufficient {
		t.Error("evidence reported sufficient with nothing running")
	}
	if body.Enforcing || !body.Experimental {
		t.Error("top-level labels lost")
	}
}

func TestDNSSECStatusReportsAnchorsWithoutKeyMaterial(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.api.Config.DNS.LocalDNSSECValidation = "observe"
	h.api.LocalDNSSECModeSource = "installation_default"
	now := time.Now().UTC().Truncate(time.Second)
	h.api.Anchors = fakeAnchors{
		viable: true,
		tp: trustanchors.TrustPoint{
			Zone: ".",
			Keys: []trustanchors.ManagedKey{
				{Key: ". 172800 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3", KeyTag: 20326, Algorithm: 8, Flags: 257,
					State: trustanchors.StateValid, Seeded: true, FirstSeen: now.Add(-40 * 24 * time.Hour), LastSeen: now},
				{Key: ". 172800 IN DNSKEY 257 3 8 AwEAAbcdefSECRETLOOKINGMATERIAL", KeyTag: 38696, Algorithm: 8, Flags: 257,
					State: trustanchors.StateAddPend, FirstSeen: now.Add(-2 * 24 * time.Hour), LastSeen: now,
					AddHoldDownUntil: now.Add(28 * 24 * time.Hour)},
			},
			LastRefresh: now, LastSuccess: now.Add(-time.Hour), LastError: "fetching the . DNSKEY RRset: timeout",
			NextRefresh: now.Add(time.Hour),
		},
		health: trustanchors.Health{Saves: 3, SaveErrors: 1, LastSaveError: "permission denied", LastSaveAt: now.Add(-time.Hour)},
	}
	h.api.DNSSEC = fixedStats{observe.Stats{Observed: 10, Resolution: observe.ResolutionNative,
		ByStatus: map[observe.Status]uint64{observe.StatusSecure: 9, observe.StatusTimeout: 1}}}

	resp, raw := h.do(http.MethodGet, "/api/v1/dnssec/status", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d: %s", resp.StatusCode, raw)
	}
	text := string(raw)
	if strings.Contains(text, "AwEAA") || strings.Contains(text, "SECRETLOOKING") {
		t.Fatal("the status body carries key material")
	}
	if strings.Contains(text, h.dir) {
		t.Error("the status body carries the data directory path")
	}

	var body dnssecStatus
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if body.Mode.ChosenBy != "installation_default" || body.Mode.Configured != "observe" || body.Mode.Effective != "observe" {
		t.Errorf("mode = %+v", body.Mode)
	}
	if body.Resolution.Source != "native" || !strings.Contains(body.Resolution.Transport, "port 53") ||
		!strings.Contains(body.Resolution.Transport, "not protected by") {
		t.Errorf("resolution = %+v, want native plaintext port 53, distinguished from the encrypted upstream", body.Resolution)
	}
	a := body.Anchors
	if !a.Available || !a.Viable || a.TrustedKeys != 1 || len(a.Keys) != 2 {
		t.Errorf("anchors = %+v", a)
	}
	if a.Keys[0].KeyTag != 20326 || a.Keys[0].State != "valid" || !a.Keys[0].Trusted || !a.Keys[0].Seeded {
		t.Errorf("first key = %+v", a.Keys[0])
	}
	if a.Keys[1].State != "addpend" || a.Keys[1].Trusted || a.Keys[1].AddHoldDownUntil == nil {
		t.Errorf("second key = %+v", a.Keys[1])
	}
	if a.Refresh.LastError == "" || a.Refresh.LastSuccess == nil || a.Refresh.Next == nil {
		t.Errorf("refresh = %+v", a.Refresh)
	}
	if a.Persistence.State != "failing" || a.Persistence.SaveErrors != 1 || a.Persistence.File != "daddybound-anchors.json" {
		t.Errorf("persistence = %+v, want failing with the bare file name", a.Persistence)
	}
}

func TestDNSSECStatusSeparatesPopulationsAndNeverScoresReadiness(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.api.Config.DNS.LocalDNSSECValidation = "observe"
	h.api.DNSSEC = fixedStats{observe.Stats{Observed: 6, Dropped: 1, Resolution: observe.ResolutionNative,
		ByStatus: map[observe.Status]uint64{observe.StatusSecure: 4, observe.StatusBogus: 1, observe.StatusUnreachable: 1}}}

	mk := func(id, upstream, status, dis, resolution string, cached bool) store.DNSSECObservation {
		o := obs(id, "x.example", upstream, status, dis)
		o.Resolution, o.Cached = resolution, cached
		return o
	}
	seedObservations(t, h.store,
		mk("a", "validated", "secure", "", "native", false),
		mk("b", "validated", "bogus", observe.DisagreeLocalBogusUpstreamValidated, "native", false),
		mk("c", "validated", "bogus", observe.DisagreeLocalBogusUpstreamValidated, "native", true),
		mk("d", "validated", "bogus", observe.DisagreeLocalBogusUpstreamValidated, "forwarded", false),
		mk("e", "validated", "timeout", "", "native", false),
		mk("f", "servfail", "secure", "", "native", false),
	)

	var body dnssecStatus
	h.getJSON("/api/v1/dnssec/status?hours=24", &body)

	find := func(resolution string, cached, comparable bool) *dnssecPopulation {
		for i := range body.Populations {
			p := &body.Populations[i]
			if p.Resolution == resolution && p.Cached == cached && p.Comparable == comparable {
				return p
			}
		}
		return nil
	}
	nativeLive := find("native", false, true)
	if nativeLive == nil || nativeLive.Total != 2 || nativeLive.Disagreements[observe.DisagreeLocalBogusUpstreamValidated] != 1 {
		t.Errorf("native, non-cached, comparable = %+v, want 2 rows with 1 disagreement", nativeLive)
	}
	nativeCached := find("native", true, true)
	if nativeCached == nil || nativeCached.Total != 1 || !strings.Contains(nativeCached.Note, "not evidence") {
		t.Errorf("native cached = %+v, want its own population that says it is not evidence of a forged answer", nativeCached)
	}
	forwarded := find("forwarded", false, true)
	if forwarded == nil || forwarded.Total != 1 || !strings.Contains(forwarded.Note, "upstream") {
		t.Errorf("forwarded = %+v", forwarded)
	}
	notComparable := find("native", false, false)
	if notComparable == nil || notComparable.Total != 2 {
		t.Errorf("not comparable = %+v, want the timeout and the servfail rows", notComparable)
	}
	for _, p := range body.Populations {
		if !p.Comparable {
			for class, n := range p.Disagreements {
				if n != 0 {
					t.Errorf("a non-comparable population counts %d %s", n, class)
				}
			}
		}
	}

	// Runtime and stored are separate scopes with separate numbers.
	if body.Runtime.Scope != "since_start" || body.Runtime.Observed != 6 || body.Runtime.Health != "degraded" {
		t.Errorf("runtime = %+v, want since_start, 6 observed, degraded by the drop", body.Runtime)
	}
	if body.Runtime.Unreachable != 1 {
		t.Errorf("runtime.unreachable = %d, want 1", body.Runtime.Unreachable)
	}
	if body.Stored.Total != 6 || body.Stored.RetainedRows != 6 || body.Stored.ObservingSince == nil {
		t.Errorf("stored = %+v", body.Stored)
	}

	// Evidence: insufficient, never scored, linked to the issues.
	ev := body.Evidence
	if ev.Sufficient {
		t.Fatal("evidence reported sufficient")
	}
	if !strings.Contains(ev.Note, "insufficient") || !strings.Contains(ev.Note, "no threshold") {
		t.Errorf("evidence note = %q", ev.Note)
	}
	if len(ev.Issues) != 2 || !strings.Contains(ev.Issues[0], "/issues/67") || !strings.Contains(ev.Issues[1], "/issues/65") {
		t.Errorf("issues = %v", ev.Issues)
	}
	percent := regexp.MustCompile(`\d+(\.\d+)?\s*%`)
	for _, c := range ev.Criteria {
		if c.Status != "not_quantified" {
			t.Errorf("criterion %s has status %q; nothing in this release may be scored", c.ID, c.Status)
		}
		if percent.MatchString(c.Measured) {
			t.Errorf("criterion %s states a percentage: %q", c.ID, c.Measured)
		}
	}
	var disagreement *dnssecCriterion
	for i := range ev.Criteria {
		if ev.Criteria[i].ID == "disagreement" {
			disagreement = &ev.Criteria[i]
		}
	}
	if disagreement == nil || !strings.Contains(disagreement.Measured, "1 of 2") {
		t.Errorf("disagreement criterion = %+v, want 1 of 2 comparable native observations", disagreement)
	}
}

func TestDNSSECStatusIsReadOnlyAndAnchorMetricsHaveClosedLabels(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.api.Config.DNS.LocalDNSSECValidation = "observe"
	h.api.Anchors = fakeAnchors{viable: false, tp: trustanchors.TrustPoint{Zone: ".", NeedsIntervention: true,
		InterventionNote: "every key at this trust point has been revoked", LastError: "x"}}

	before := h.countRows(t, "dnssec_observations")
	var body dnssecStatus
	h.getJSON("/api/v1/dnssec/status", &body)
	h.getJSON("/api/v1/dnssec/status", &body)
	if h.countRows(t, "dnssec_observations") != before {
		t.Error("polling the status wrote observations")
	}
	if body.Anchors.Viable || !body.Anchors.NeedsIntervention || body.Anchors.InterventionNote == "" {
		t.Errorf("anchors = %+v, want not viable and needing intervention", body.Anchors)
	}
	if body.Anchors.Persistence.State != "not_yet_written" {
		t.Errorf("persistence = %+v, want not_yet_written rather than ok for a manager that has saved nothing", body.Anchors.Persistence)
	}

	metrics := h.getMetrics()
	for _, want := range []string{
		"dnsdaddy_dnssec_anchor_viable 0",
		`dnsdaddy_dnssec_anchor_keys{state="valid"} 0`,
		"dnsdaddy_dnssec_anchor_refresh_failing 1",
	} {
		if !strings.Contains(metrics, want) {
			t.Errorf("/metrics lacks %q", want)
		}
	}
	for _, line := range strings.Split(metrics, "\n") {
		if strings.HasPrefix(line, "dnsdaddy_dnssec_anchor_keys{") && !strings.Contains(line, "{state=") {
			t.Errorf("unexpected label on %s", line)
		}
	}
}
