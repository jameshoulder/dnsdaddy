package native_test

import (
	"context"
	"testing"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/native"
)

// Every returned CNAME and the terminal address must authenticate, but the
// already authenticated zone keys need not be fetched and verified again for
// each of those checks. Without that reuse this five-hop chain exhausted the
// default 64-lookup budget despite using just three signed zones.
func TestForwardedSignedAliasChainFitsTheDefaultValidationBudget(t *testing.T) {
	for _, corruptTarget := range []bool{false, true} {
		name := "authentic"
		if corruptTarget {
			name = "forged_terminal_address"
		}
		t.Run(name, func(t *testing.T) {
			spec := lab.StandardSpec()
			start, second := "cdn1."+lab.LeafZone, "cdn2."+lab.LeafZone
			for i := range spec.Zones {
				if spec.Zones[i].Name != lab.LeafZone {
					continue
				}
				for _, link := range [][2]string{{start, second}, {second, lab.AliasHop1}} {
					spec.Zones[i].Records = append(spec.Zones[i].Records, &dns.CNAME{
						Hdr:    dns.RR_Header{Name: link[0], Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
						Target: link[1],
					})
				}
			}
			h, err := lab.Build(spec)
			if err != nil {
				t.Fatal(err)
			}
			if corruptTarget {
				if err := h.CorruptSignature(lab.LeafZone, lab.AnswerName, dns.TypeA); err != nil {
					t.Fatal(err)
				}
			}
			cfg, err := h.Config(labInstant())
			if err != nil {
				t.Fatal(err)
			}
			f := &forwardFixture{h: h}
			f.cfg = native.ForwardConfig{Exchange: f.exchange, Anchors: cfg.Anchors, Policy: cfg.Policy,
				Clock: cfg.Clock, Verifier: cfg.Verifier, Limits: cfg.Limits}
			ans, err := f.engine(t).Resolve(context.Background(), start, dns.TypeA)
			if err != nil {
				t.Fatal(err)
			}
			want := dnssec.StatusSecure
			if corruptTarget {
				want = dnssec.StatusBogus
			}
			if ans.Validation.Status != want {
				t.Fatalf("five-hop chain: got %s (%s), want %s; lookups=%d wire queries=%d\n%s",
					ans.Validation.Status, ans.Validation.Reason, want, ans.Lookups, ans.Queries, ans.Validation.Trace())
			}
			if ans.Lookups > dnssec.DefaultLimits().MaxLookups {
				t.Fatalf("validation exceeded the unchanged lookup budget: %d", ans.Lookups)
			}
		})
	}
}
