package resolver

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestSecurityEDNSClientSubnetIsNotForwardedOrReattached(t *testing.T) {
	question := new(dns.Msg)
	question.SetQuestion("example.com.", dns.TypeA)
	question.SetEdns0(1232, true)
	question.IsEdns0().Option = append(question.IsEdns0().Option, &dns.EDNS0_SUBNET{
		Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24,
		Address: net.ParseIP("192.0.2.1").To4(),
	})

	upstream := question.Copy()
	stripEDNSClientSubnet(upstream)
	if len(upstream.IsEdns0().Option) != 0 {
		t.Fatal("a shared upstream request retained client ECS")
	}
	if !upstream.IsEdns0().Do() {
		t.Fatal("stripping ECS also removed the DNSSEC DO bit")
	}

	answer := new(dns.Msg)
	answer.SetReply(question)
	answer.SetEdns0(1232, true)
	answer.IsEdns0().Option = append(answer.IsEdns0().Option, &dns.EDNS0_SUBNET{
		Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24,
		Address: net.ParseIP("192.0.2.1").To4(),
	})
	replied := reattach(answer, question)
	if got := replied.IsEdns0(); got == nil || len(got.Option) != 0 {
		t.Fatal("shared response retained another client's ECS")
	}
}

func TestSecurityECSRemovedFromEveryOPTWhilePreservingOtherRecords(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	makeOPT := func() *dns.OPT {
		return &dns.OPT{
			Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 1232},
			Option: []dns.EDNS0{
				&dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.ParseIP("192.0.2.1").To4()},
				&dns.EDNS0_NSID{Code: dns.EDNS0NSID, Nsid: "aabb"},
			},
		}
	}
	other := &dns.TXT{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{"keep"}}
	msg.Extra = []dns.RR{makeOPT(), other, makeOPT()}
	stripEDNSClientSubnet(msg)
	if len(msg.Extra) != 3 || msg.Extra[1] != other {
		t.Fatal("non-OPT records were modified or removed")
	}
	for _, idx := range []int{0, 2} {
		opt, ok := msg.Extra[idx].(*dns.OPT)
		if !ok || len(opt.Option) != 1 || opt.Option[0].Option() != dns.EDNS0NSID {
			t.Fatalf("OPT %d retained ECS or lost the non-sensitive option", idx)
		}
	}
}
