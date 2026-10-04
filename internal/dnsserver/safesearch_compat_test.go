package dnsserver

import (
	"context"
	"reflect"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/store"
	"github.com/miekg/dns"
)

// A compatibility boolean must not silently acquire answer-path semantics.
// Exercise the real handler with the local test upstream, never public search
// services. Future enforcement requires changing this contract deliberately.
func TestPhase1SafeSearchFlagDoesNotRewriteAnyEngineAnswer(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	for _, domain := range []string{"www.google.com", "www.bing.com", "www.youtube.com", "unsupported-search.example"} {
		t.Run(domain, func(t *testing.T) {
			var baseline []string
			for _, enabled := range []bool{false, true, false} {
				if _, err := h.store.UpdatePolicy(ctx, "p_standard", store.PolicyInput{SafeSearch: &enabled}); err != nil {
					t.Fatal(err)
				}
				if err := h.engine.Reload(ctx); err != nil {
					t.Fatal(err)
				}
				response := h.handler.Handle(ctx, query(domain, dns.TypeA), clientMeta("192.168.1.50"))
				if response == nil || response.Rcode != dns.RcodeSuccess || len(response.Answer) == 0 {
					t.Fatalf("local fixture must resolve with either flag value: %v", response)
				}
				answers := make([]string, 0, len(response.Answer))
				for _, record := range response.Answer {
					copy := dns.Copy(record)
					copy.Header().Ttl = 0 // Cache aging is unrelated to this flag.
					answers = append(answers, copy.String())
				}
				if baseline == nil {
					baseline = answers
				} else if !reflect.DeepEqual(baseline, answers) {
					t.Fatalf("safeSearch=%t changed the answer: got %v, want %v", enabled, answers, baseline)
				}
			}
		})
	}
}
