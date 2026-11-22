package store

import (
	"testing"

	"github.com/miekg/dns"
)

func TestSummarizeAnswerAddressesHashesSortedUniques(t *testing.T) {
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "a.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: []byte{198, 51, 100, 2}},
		&dns.A{Hdr: dns.RR_Header{Name: "a.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: []byte{198, 51, 100, 1}},
		&dns.A{Hdr: dns.RR_Header{Name: "a.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120}, A: []byte{198, 51, 100, 1}},
		&dns.TXT{Hdr: dns.RR_Header{Name: "a.example.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 10}, Txt: []string{"secret"}},
	}
	sum := SummarizeAnswerAddresses(msg)
	if !sum.Recorded || sum.AddrCount != 2 || sum.MinTTL != 60 {
		t.Fatalf("summary = %+v", sum)
	}
	if sum.AddrSHA256 == "" || len(sum.AddrSHA256) != 64 {
		t.Fatalf("hash = %q", sum.AddrSHA256)
	}
	// Same addresses in different order must hash identically.
	msg2 := new(dns.Msg)
	msg2.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "a.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: []byte{198, 51, 100, 1}},
		&dns.A{Hdr: dns.RR_Header{Name: "a.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: []byte{198, 51, 100, 2}},
	}
	if SummarizeAnswerAddresses(msg2).AddrSHA256 != sum.AddrSHA256 {
		t.Fatal("hash not order-independent")
	}
}

func TestSummarizeAnswerAddressesIgnoresNonAddress(t *testing.T) {
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		&dns.CNAME{Hdr: dns.RR_Header{Name: "a.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 30}, Target: "b.example."},
	}
	if sum := SummarizeAnswerAddresses(msg); sum.Recorded {
		t.Fatalf("expected empty summary, got %+v", sum)
	}
}
