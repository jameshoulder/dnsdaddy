package dnssec_test

import (
	"context"
	"testing"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
)

// A policy has four states, and three of them are easy to confuse with each
// other because two are empty and two are absent.
//
//   - the zero value: nobody configured anything, so the defaults apply;
//   - an explicitly empty policy: somebody asked for "permit nothing", and
//     must get it;
//   - a populated custom policy: exactly what was asked for;
//   - the default policy, asked for by name.
//
// Inferring "unconfigured" from map length collapses the first two, so a
// caller who deliberately disabled every algorithm silently receives
// Daddybound's defaults instead. That is the wrong direction for a security
// control to fail in: the operator believes they have turned something off.
func TestPolicyStatesAreDistinguished(t *testing.T) {
	tests := []struct {
		name   string
		policy dnssec.Policy
		// wantSecure is whether the standard hierarchy, which is signed with
		// Ed25519 and delegated with SHA-256, validates under this policy.
		wantSecure bool
		wantReason dnssec.Reason
	}{
		{
			name:       "the zero value takes the defaults",
			policy:     dnssec.Policy{},
			wantSecure: true,
			wantReason: dnssec.ReasonVerified,
		},
		{
			name:       "the default policy asked for by name",
			policy:     dnssec.DefaultPolicy(),
			wantSecure: true,
			wantReason: dnssec.ReasonVerified,
		},
		{
			name:       "an explicitly empty policy permits nothing",
			policy:     dnssec.NewPolicy(nil, nil),
			wantSecure: false,
			// The digest check runs first, at the delegation.
			wantReason: dnssec.ReasonDisallowedDigest,
		},
		{
			name: "a custom policy permits exactly what it names",
			policy: dnssec.NewPolicy(
				[]dnssec.Algorithm{dnssec.AlgED25519},
				[]dnssec.DigestType{dnssec.DigestSHA256},
			),
			wantSecure: true,
			wantReason: dnssec.ReasonVerified,
		},
		{
			name: "a custom policy that omits the zone's algorithm refuses it",
			policy: dnssec.NewPolicy(
				[]dnssec.Algorithm{dnssec.AlgRSASHA256},
				[]dnssec.DigestType{dnssec.DigestSHA256},
			),
			wantSecure: false,
			wantReason: dnssec.ReasonDisallowedAlgorithm,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, err := lab.Standard()
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			cfg, err := h.Config(lab.Now())
			if err != nil {
				t.Fatalf("config: %v", err)
			}
			cfg.Policy = tc.policy

			got := dnssec.New(h, cfg).Validate(context.Background(), lab.AnswerName, dns.TypeA)

			if got.Secure() != tc.wantSecure {
				t.Fatalf("secure = %v, want %v (status %s)\n%s", got.Secure(), tc.wantSecure, got.Status, got.Trace())
			}
			if got.Reason != tc.wantReason {
				t.Errorf("reason = %s, want %s\n%s", got.Reason, tc.wantReason, got.Trace())
			}
		})
	}
}

// The unit-level statement of the same thing, independent of the chain walk:
// an explicitly empty policy permits nothing, and reports it as a policy
// refusal rather than as a missing capability.
func TestExplicitlyEmptyPolicyPermitsNothing(t *testing.T) {
	empty := dnssec.NewPolicy(nil, nil)

	if !empty.Configured() {
		t.Error("an explicitly constructed policy reports itself unconfigured")
	}
	if (dnssec.Policy{}).Configured() {
		t.Error("the zero value reports itself configured")
	}

	for _, alg := range []dnssec.Algorithm{
		dnssec.AlgED25519, dnssec.AlgRSASHA256, dnssec.AlgECDSAP256SHA256,
	} {
		if empty.AllowsAlgorithm(alg) {
			t.Errorf("empty policy permits algorithm %s", alg.Name())
		}
		// Supported by this build, refused by policy: the reason must say
		// which, because they send an operator to different files.
		if reason := empty.CheckAlgorithm(alg); reason != dnssec.ReasonDisallowedAlgorithm {
			t.Errorf("CheckAlgorithm(%s) = %s, want %s", alg.Name(), reason, dnssec.ReasonDisallowedAlgorithm)
		}
	}
	for _, dt := range []dnssec.DigestType{dnssec.DigestSHA1, dnssec.DigestSHA256, dnssec.DigestSHA384} {
		if empty.AllowsDigest(dt) {
			t.Errorf("empty policy permits digest %s", dt.Name())
		}
		if reason := empty.CheckDigest(dt); reason != dnssec.ReasonDisallowedDigest {
			t.Errorf("CheckDigest(%s) = %s, want %s", dt.Name(), reason, dnssec.ReasonDisallowedDigest)
		}
	}
	if n := len(empty.Algorithms()); n != 0 {
		t.Errorf("empty policy lists %d algorithms", n)
	}
	if n := len(empty.Digests()); n != 0 {
		t.Errorf("empty policy lists %d digest types", n)
	}
}
