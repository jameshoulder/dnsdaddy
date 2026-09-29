package api

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/detect"
	"github.com/jameshoulder/dnsdaddy/internal/learning"
)

func TestLearningRoutesRequireAuthenticationAndStayReadOnly(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{"/api/v1/learning/status", "/api/v1/learning/clients"} {
		resp, _ := h.do(http.MethodGet, path, nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s unauthenticated = %d", path, resp.StatusCode)
		}
	}
	h.login()
	e, err := learning.New(learning.Options{StatePath: filepath.Join(h.dir, "learning.json")}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.api.Learning = e
	if !e.Observe(detect.Observation{Time: time.Now(), ClientIP: "192.0.2.1", QName: "portal.example", QType: "A", Rcode: "NOERROR"}) {
		t.Fatal("observation rejected")
	}
	before := e.Status()
	for _, path := range []string{"/api/v1/learning/status", "/api/v1/learning/clients", "/api/v1/learning/clients?client=192.0.2.1"} {
		resp, raw := h.do(http.MethodGet, path, nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s = %d: %s", path, resp.StatusCode, raw)
		}
		if strings.Contains(string(raw), h.dir) {
			t.Fatal("learning response exposed state-file path")
		}
	}
	after := e.Status()
	if after.Observations != before.Observations || after.Queue != before.Queue || after.Windows != before.Windows {
		t.Fatal("GET changed learning/training state")
	}
}

func TestLearningDisabledResponseDoesNotImplyBaselineOrEfficacy(t *testing.T) {
	h := newHarness(t)
	h.login()
	var s learning.Status
	h.getJSON("/api/v1/learning/status", &s)
	if s.Enabled || s.Enforces || s.Running || s.Mode != "off" || !s.Experimental || s.Recent == nil {
		t.Fatalf("disabled status: %+v", s)
	}
	resp, raw := h.do(http.MethodGet, "/api/v1/learning/clients", nil)
	resp.Body.Close()
	var body struct {
		Enabled bool                  `json:"enabled"`
		Clients []learning.ClientView `json:"clients"`
		Total   int                   `json:"total"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if body.Enabled || body.Clients == nil || body.Total != 0 {
		t.Fatalf("disabled clients: %s", raw)
	}
}

func TestLearningClientReadBoundsAndPrivacyKeysAreExplicit(t *testing.T) {
	h := newHarness(t)
	h.login()
	for _, query := range []string{"limit=0", "limit=501", "limit=many", "client=not-a-client", "client=network:", "client=network:%0Ainjected"} {
		resp, raw := h.do(http.MethodGet, "/api/v1/learning/clients?"+query, nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s = %d: %s", query, resp.StatusCode, raw)
		}
	}
	for _, query := range []string{"client=network:lab", "client=unattributed", "client=::ffff:192.0.2.1"} {
		resp, raw := h.do(http.MethodGet, "/api/v1/learning/clients?"+query, nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !strings.Contains(string(raw), `"found":false`) {
			t.Fatalf("%s = %d: %s", query, resp.StatusCode, raw)
		}
	}
}

func TestFailedLearnerIsUnavailableWithoutPretendingToBeColdStart(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.api.LearningError = "invalid saved model at " + filepath.Join(h.dir, "private-model.json")
	resp, raw := h.do(http.MethodGet, "/api/v1/learning/status", nil)
	resp.Body.Close()
	var s learning.Status
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || !s.Enabled || s.Available || s.Running || s.Mode != "unavailable" || s.Error == "" || !strings.Contains(s.CounterScope, "not being collected") {
		t.Fatalf("failed learner status: %s", raw)
	}
	if strings.Contains(string(raw), h.dir) || strings.Contains(string(raw), "private-model.json") {
		t.Fatal("local startup error exposed a private path")
	}
	resp, raw = h.do(http.MethodGet, "/api/v1/learning/clients?client=192.0.2.10", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(raw), `"found":null`) || !strings.Contains(string(raw), `"available":false`) {
		t.Fatalf("unknown saved baseline presented as absent: %s", raw)
	}
	resp, raw = h.do(http.MethodGet, "/api/v1/learning/clients", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.Contains(string(raw), `"total":0`) || !strings.Contains(string(raw), `"error":`) {
		t.Fatalf("unavailable client population fabricated: %s", raw)
	}
	metrics := h.getMetrics()
	if !strings.Contains(metrics, "dnsdaddy_learning_enabled 1") || !strings.Contains(metrics, "dnsdaddy_learning_available 0") || strings.Contains(metrics, "dnsdaddy_learning_received_total") {
		t.Fatalf("unavailable learner metrics imply observations: %s", metrics)
	}
}
