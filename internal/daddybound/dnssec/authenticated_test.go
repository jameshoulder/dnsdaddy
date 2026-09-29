package dnssec_test

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
)

// A human-readable Secure trace on a different packet is not a receipt for
// client data. This exercises receipts from actual cryptographic validation.
func TestAuthenticatedReceiptBindsExactData(t *testing.T) {
	h, err := lab.Standard()
	if err != nil {
		t.Fatal(err)
	}
	v, err := h.Validator(lab.Now())
	if err != nil {
		t.Fatal(err)
	}
	result := v.Validate(context.Background(), lab.AnswerName, dns.TypeA)
	if !result.Secure() {
		t.Fatal(result.Trace())
	}
	response, err := h.Lookup(context.Background(), lab.AnswerName, dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	var records []dns.RR
	for _, rr := range response.Answer {
		if rr.Header().Rrtype == dns.TypeA {
			records = append(records, dns.Copy(rr))
		}
	}
	var receipt dnssec.AuthenticatedRRset
	found := false
	for _, candidate := range result.Authenticated {
		if candidate.Covers(records) {
			receipt, found = candidate, true
			break
		}
	}
	if !found {
		t.Fatal("verified answer has no exact authentication receipt")
	}
	if (dnssec.AuthenticatedRRset{}).Covers(records) {
		t.Fatal("zero receipt authenticated records")
	}
	records[0].Header().Ttl = 1
	records[0].Header().Name = "WWW.EXAMPLE.DNSDADDYLAB."
	if !receipt.Covers(records) {
		t.Fatal("TTL ageing and canonical casing changed signed content")
	}
	records[0].(*dns.A).A = net.IPv4(192, 0, 2, 99)
	if receipt.Covers(records) {
		t.Fatal("receipt authenticated replacement RDATA")
	}
	records[0].(*dns.A).A = net.IPv4(192, 0, 2, 1)
	records[0].Header().Name = "attacker.example.dnsdaddylab."
	if receipt.Covers(records) {
		t.Fatal("receipt authenticated a different owner")
	}
}

func TestBatchSharesOneLookupBudgetAcrossAllClientRRsets(t *testing.T) {
	h, err := lab.Standard()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := h.Config(lab.Now())
	if err != nil {
		t.Fatal(err)
	}
	firstSource := h.Recording()
	if result := dnssec.New(firstSource, cfg).Validate(context.Background(), lab.AnswerName, dns.TypeA); !result.Secure() {
		t.Fatal(result.Trace())
	}
	firstCost := len(firstSource.Queries())
	if firstCost == 0 {
		t.Fatal("fixture did not exercise supporting lookups")
	}
	cfg.Limits = dnssec.DefaultLimits()
	cfg.Limits.MaxLookups = firstCost
	source := h.Recording()
	questions := []dns.Question{
		{Name: lab.AnswerName, Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: lab.OtherName, Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}
	results := dnssec.New(source, cfg).ValidateQuestions(context.Background(), questions)
	if len(results) != 2 || !results[0].Secure() || results[1].Status != dnssec.StatusIndeterminate || results[1].Reason != dnssec.ReasonResourceLimit {
		t.Fatalf("batch did not share its work budget: %+v", results)
	}
	if got := len(source.Queries()); got != firstCost {
		t.Fatalf("batch made %d lookups, budget %d", got, firstCost)
	}
	cfg.Limits.MaxAnyRRsets = 1
	source = h.Recording()
	results = dnssec.New(source, cfg).ValidateQuestions(context.Background(), questions)
	if len(results) != 1 || results[0].Status != dnssec.StatusIndeterminate || results[0].Reason != dnssec.ReasonResourceLimit || len(source.Queries()) != 0 {
		t.Fatalf("oversized batch performed work or claimed a verdict: %+v", results)
	}
}
