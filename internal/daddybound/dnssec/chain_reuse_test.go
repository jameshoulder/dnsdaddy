package dnssec_test

import (
	"context"
	"testing"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
)

func TestAuthenticatedZonesAreReusedOnlyWithinOneOperation(t *testing.T) {
	h, err := lab.Standard()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := h.Config(lab.Now())
	if err != nil {
		t.Fatal(err)
	}
	source := h.Recording()
	v := dnssec.New(source, cfg)
	questions := []dns.Question{
		{Name: lab.AliasHop1, Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: lab.AliasHop1, Qtype: dns.TypeCNAME, Qclass: dns.ClassINET},
		{Name: lab.AliasHop2, Qtype: dns.TypeCNAME, Qclass: dns.ClassINET},
		{Name: lab.AliasHop3, Qtype: dns.TypeCNAME, Qclass: dns.ClassINET},
		{Name: lab.AnswerName, Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}
	results := v.ValidateQuestions(context.Background(), questions)
	if len(results) != len(questions) {
		t.Fatalf("got %d results for %d questions", len(results), len(questions))
	}
	for _, result := range results {
		if !result.Secure() {
			t.Fatal(result.Trace())
		}
	}
	count := func(name string, rrtype uint16) int {
		n := 0
		for _, q := range source.Queries() {
			if q.Name == name && q.Type == rrtype {
				n++
			}
		}
		return n
	}
	for _, zone := range []string{lab.RootZone, lab.MiddleZone, lab.LeafZone} {
		if got := count(zone, dns.TypeDNSKEY); got != 1 {
			t.Fatalf("authenticated %s keys %d times in one operation", zone, got)
		}
	}
	for _, zone := range []string{lab.MiddleZone, lab.LeafZone} {
		if got := count(zone, dns.TypeDS); got != 1 {
			t.Fatalf("authenticated delegation to %s %d times in one operation", zone, got)
		}
	}

	// Reusing the Validator must still fetch and authenticate the trust
	// chain anew. A previous success cannot hide a changed DNSKEY response.
	if err := h.CorruptSignature(lab.RootZone, lab.RootZone, dns.TypeDNSKEY); err != nil {
		t.Fatal(err)
	}
	result := v.Validate(context.Background(), lab.AnswerName, dns.TypeA)
	if result.Status != dnssec.StatusBogus {
		t.Fatalf("trusted state escaped its operation: %s\n%s", result.Status, result.Trace())
	}
	if got := count(lab.RootZone, dns.TypeDNSKEY); got != 2 {
		t.Fatalf("new operation did not refetch the anchor zone: %d lookups", got)
	}
}
