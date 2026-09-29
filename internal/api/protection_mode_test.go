package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/observe"
	"github.com/jameshoulder/dnsdaddy/internal/protection"
)

type modeControlStub struct {
	state   DNSSECRuntimeState
	changes int
}

func (m *modeControlStub) State() DNSSECRuntimeState { return m.state }
func (m *modeControlStub) SetMode(_ context.Context, mode string) error {
	m.changes++
	m.state.Effective = mode
	m.state.NativeAvailable = mode != config.LocalDNSSECOff
	return nil
}

func TestModeChangeRequiresAuthenticationOriginAndTransportAcknowledgement(t *testing.T) {
	h := newHarness(t)
	m := &modeControlStub{state: DNSSECRuntimeState{Configured: "unset", Effective: "off", ChosenBy: "dashboard"}}
	h.api.DNSSECControl = m
	resp, _ := h.do(http.MethodPut, "/api/v1/dnssec/mode", map[string]any{"mode": "enforce", "acknowledgeNativeTransport": true})
	if resp.StatusCode != http.StatusUnauthorized || m.changes != 0 {
		t.Fatal("unauthenticated mode change")
	}
	h.login()
	resp, _ = h.do(http.MethodPut, "/api/v1/dnssec/mode", map[string]any{"mode": "enforce"})
	if resp.StatusCode != http.StatusBadRequest || m.changes != 0 {
		t.Fatal("native egress enabled without acknowledgement")
	}
	resp, body := h.do(http.MethodPut, "/api/v1/dnssec/mode", map[string]any{"mode": "enforce", "acknowledgeNativeTransport": true})
	if resp.StatusCode != http.StatusOK || m.changes != 1 {
		t.Fatalf("consented activation failed: %d %s", resp.StatusCode, body)
	}
	resp, body = h.do(http.MethodGet, "/api/v1/dnssec/status", nil)
	var status struct {
		Enforcing bool `json:"enforcing"`
		Mode      struct {
			Enforcing bool `json:"enforcing"`
			Live      struct {
				Enforcing bool `json:"enforcing"`
			} `json:"live"`
		} `json:"mode"`
	}
	if resp.StatusCode != 200 || json.Unmarshal(body, &status) != nil || !status.Enforcing || !status.Mode.Enforcing || !status.Mode.Live.Enforcing {
		t.Fatalf("status contradicts actual native selection: %s", body)
	}
}

func TestProtectionWritesPersistBeforePublishingAndRejectStaleVersion(t *testing.T) {
	h := newHarness(t)
	h.login()
	c, err := protection.New(protection.Default(), func(ctx context.Context, cfg protection.Config) error {
		b, _ := json.Marshal(cfg)
		return h.store.SetSetting(ctx, protection.SettingKey, string(b))
	})
	if err != nil {
		t.Fatal(err)
	}
	h.api.Protection = c
	cfg := c.Config()
	cfg.Rebinding.AllowDomains = []string{"corp.example"}
	resp, body := h.do(http.MethodPut, "/api/v1/protection", cfg)
	if resp.StatusCode != 200 {
		t.Fatalf("save failed: %s", body)
	}
	if c.Config().Version != cfg.Version+1 {
		t.Fatal("new version not published")
	}
	resp, _ = h.do(http.MethodPut, "/api/v1/protection", cfg)
	if resp.StatusCode != http.StatusConflict {
		t.Fatal("stale overwrite accepted")
	}
	cfg = c.Config()
	cfg.Rebinding.AllowDomains = []string{"com"}
	resp, _ = h.do(http.MethodPut, "/api/v1/protection", cfg)
	if resp.StatusCode != http.StatusBadRequest || c.Config().Rebinding.AllowDomains[0] != "corp.example" {
		t.Fatal("invalid public-suffix exception altered policy")
	}
	if _, err := h.store.GetSetting(context.Background(), protection.SettingKey); err != nil {
		t.Fatal("not persisted")
	}
}

func TestStoppedLearnStatusRetainsLossAndStatesItsScope(t *testing.T) {
	h := newHarness(t)
	h.api.DNSSECControl = &modeControlStub{state: DNSSECRuntimeState{
		Effective: config.LocalDNSSECOff,
		Observer:  fixedStats{s: observe.Stats{Dropped: 3}},
	}}
	rt := h.api.dnssecRuntimeStatus(time.Now())
	if !rt.Available || rt.Active || rt.Dropped != 3 || rt.Scope != "most_recent_learn_activation" || rt.Health != "degraded" || !strings.Contains(rt.HealthNote, "Learn is stopped") {
		t.Fatalf("inactive loss was hidden or mislabelled: %+v", rt)
	}
	legacy := h.api.dnssecRuntime()
	if legacy["active"] != false || legacy["scope"] != rt.Scope || legacy["dropped"] != uint64(3) {
		t.Fatalf("legacy runtime contradicts status: %+v", legacy)
	}
}
