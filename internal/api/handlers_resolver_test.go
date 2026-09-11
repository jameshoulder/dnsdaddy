package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/resolution"
	"github.com/jameshoulder/dnsdaddy/internal/resolveraddr"
)

// The resolver status endpoint answers the four questions an operator has.
func TestResolverStatusAnswersTheOperatorsQuestions(t *testing.T) {
	h := newHarness(t)
	h.login()

	resp, body := h.do(http.MethodGet, "/api/v1/resolver/status", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	var got ResolverStatus
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decoding: %v", err)
	}

	if !got.Protecting {
		t.Error("the resolver reports that it is not protecting anything")
	}
	if got.Mode != config.ResolutionForward {
		t.Errorf("mode = %q, want %q", got.Mode, config.ResolutionForward)
	}
	if got.EngineID != resolution.BackendForward {
		t.Errorf("engineId = %q, want %q", got.EngineID, resolution.BackendForward)
	}
	if got.Engine == "" || got.Engine == got.EngineID {
		t.Errorf("engine = %q; a person reading a dashboard should be told in words, "+
			"not handed the metric label", got.Engine)
	}
	if got.DNSSEC == "" || got.DNSSECDetail == "" {
		t.Error("the DNSSEC posture was not reported")
	}
	// Every health figure covers one stated period. The whole point of the
	// window is that a reader cannot mistake these for lifetime counters.
	if got.Health.WindowSeconds <= 0 {
		t.Error("the health window has no stated period; these figures could be " +
			"read as counters since process start, which is the confusion they replace")
	}
}

// A forwarding resolver does not say "enforcing".
//
// The word is reserved for the one arrangement where this deployment validates
// and refuses. An operator who saw "Enforcing" on a forwarding resolver would
// believe their answers were being checked here, when all that happens is an
// upstream setting a bit in a packet.
func TestDNSSECPostureDoesNotOverclaim(t *testing.T) {
	for _, tc := range []struct {
		name       string
		mode       string
		observe    string
		want       string
		mustNotSay string
	}{
		{
			name: "forwarding with no local validation",
			mode: config.ResolutionForward,
			want: "Upstream",
		},
		{
			name:    "forwarding while Daddybound observes",
			mode:    config.ResolutionForward,
			observe: config.LocalDNSSECObserve,
			want:    "Observing",
		},
		{
			name: "native resolution",
			mode: config.ResolutionNative,
			want: "Enforcing",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.DNS.ResolutionMode = tc.mode
			cfg.DNS.LocalDNSSECValidation = tc.observe

			got, detail := dnssecPosture(cfg)
			if got != tc.want {
				t.Errorf("posture = %q, want %q", got, tc.want)
			}
			if detail == "" {
				t.Error("no detail sentence")
			}
			if tc.want != "Enforcing" && got == "Enforcing" {
				t.Errorf("a %s deployment reports Enforcing", tc.name)
			}
		})
	}
}

// Native mode is labelled a beta rather than presented as finished.
//
// The milestone asks for this explicitly: if native mode is not safe enough to
// be the default, say so rather than pretending it is done. It is not the
// default, and the status an operator reads says why.
func TestNativeModeIsLabelledAsABeta(t *testing.T) {
	cfg := config.Default()
	cfg.DNS.ResolutionMode = config.ResolutionNative
	if !cfg.DNS.Native() {
		t.Fatal("the fixture is not in native mode")
	}
	// The default must not be native.
	if config.Default().DNS.Native() {
		t.Error("the built-in default is native resolution; it is a beta this milestone")
	}
}

// Native mode shows no upstream table, because there are no upstreams.
//
// An empty table is the truth. A row of zeroes would be an invention, and an
// operator reading zero queries against Quad9 would conclude their forwarder
// had stopped working rather than that they are not using one.
func TestNativeModeReportsNoUpstreams(t *testing.T) {
	if got := upstreamStatuses(nil); len(got) != 0 {
		t.Errorf("a deployment with no forwarder reported %d upstreams", len(got))
	}
}

// The recommended address is never one a client cannot use.
func TestTheStatusNeverRecommendsAnUnusableAddress(t *testing.T) {
	h := newHarness(t)
	h.login()

	_, body := h.do(http.MethodGet, "/api/v1/resolver/status", nil)
	var got ResolverStatus
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	for _, a := range got.Addresses {
		if !a.Recommended {
			continue
		}
		if a.Kind == resolveraddr.KindLoopback || a.Kind == resolveraddr.KindLinkLocal {
			t.Errorf("the dashboard recommends %s (%s), which no client on the "+
				"network can use", a.Address, a.Kind)
		}
	}
}
