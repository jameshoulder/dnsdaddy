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
