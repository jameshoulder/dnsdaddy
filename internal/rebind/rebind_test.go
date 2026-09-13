package rebind_test

import (
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/rebind"
)

func mustFilter(t *testing.T, cfg rebind.Config) *rebind.Filter {
	t.Helper()
	f, err := rebind.New(cfg)
	if err != nil {
		t.Fatalf("rebind.New: %v", err)
	}
	return f
}

// defaults is the shipped filter: default ranges, NODATA when everything is
// stripped.
func defaults(t *testing.T) *rebind.Filter {
	t.Helper()
	return mustFilter(t, rebind.Config{
		Ranges:      rebind.DefaultRanges(),
		EmptyAction: rebind.EmptyNoData,
	})
}

func a(name, addr string) dns.RR {
	return &dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   netip.MustParseAddr(addr).AsSlice(),
	}
}

func aaaa(name, addr string) dns.RR {
	return &dns.AAAA{
		Hdr:  dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
		AAAA: netip.MustParseAddr(addr).AsSlice(),
	}
}

func cname(name, target string) dns.RR {
	return &dns.CNAME{
		Hdr:    dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
		Target: dns.Fqdn(target),
	}
}

// answer builds a NOERROR response to an A question for name.
func answer(name string, rrs ...dns.RR) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.Response = true
	m.Rcode = dns.RcodeSuccess
	m.Answer = rrs
	return m
}

// addrs lists the addresses left in the answer section, as strings.
func addrs(m *dns.Msg) []string {
	var out []string
	for _, rr := range m.Answer {
		switch v := rr.(type) {
		case *dns.A:
			out = append(out, v.A.String())
		case *dns.AAAA:
			out = append(out, v.AAAA.String())
		}
	}
	return out
}

// TestEveryDefaultRangeIsFiltered walks the shipped range list one address at
// a time. A name whose only address is in a filtered range must not reach the
// client with that address — that is the whole control, and a range silently
// missing from the default set is a hole that looks like protection.
func TestEveryDefaultRangeIsFiltered(t *testing.T) {
	f := defaults(t)

	for _, tc := range []struct {
		addr  string
		class rebind.Class
	}{
		{"10.1.2.3", rebind.ClassPrivate},
		{"172.16.5.5", rebind.ClassPrivate},
		{"192.168.1.1", rebind.ClassPrivate},
		{"127.0.0.1", rebind.ClassLoopback},
		{"169.254.169.254", rebind.ClassLinkLocal},
		{"0.0.0.0", rebind.ClassUnspecified},
		{"100.64.0.1", rebind.ClassCGNAT},
		{"::1", rebind.ClassLoopback},
		{"::", rebind.ClassUnspecified},
		{"fc00::1", rebind.ClassULA},
		{"fd12:3456::1", rebind.ClassULA},
		{"fe80::1", rebind.ClassLinkLocal},
	} {
		t.Run(tc.addr, func(t *testing.T) {
			ip := netip.MustParseAddr(tc.addr)
			var rr dns.RR
			if ip.Is4() {
				rr = a("evil.example", tc.addr)
			} else {
				rr = aaaa("evil.example", tc.addr)
			}
			m := answer("evil.example", rr)

			res := f.Apply(m, nil)
			if !res.Changed {
				t.Fatalf("%s was returned to the client unfiltered", tc.addr)
			}
			if got := addrs(m); len(got) != 0 {
				t.Errorf("addresses left in the answer: %v", got)
			}
			if !res.Emptied {
				t.Error("the answer lost its only address but was not reported as emptied")
			}
			if len(res.Removed) != 1 || res.Removed[0].Class != tc.class {
				t.Errorf("removed = %+v, want one %s", res.Removed, tc.class)
			}
		})
	}
}

// TestAPublicAddressIsUntouched. The filter must be invisible to the DNS that
// makes up almost all of it.
func TestAPublicAddressIsUntouched(t *testing.T) {
	f := defaults(t)
	for _, addr := range []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2001:4860:4860::8888", "2606:4700::1111"} {
		var rr dns.RR
		if netip.MustParseAddr(addr).Is4() {
			rr = a("example.com", addr)
		} else {
			rr = aaaa("example.com", addr)
		}
		m := answer("example.com", rr)
		res := f.Apply(m, nil)
		if res.Changed || res.Emptied {
			t.Errorf("%s was filtered", addr)
		}
		if got := addrs(m); len(got) != 1 || got[0] != addr {
			t.Errorf("answer for %s became %v", addr, got)
		}
	}
}

// TestAMixedAnswerKeepsOnlyThePublicAddress. The realistic rebinding payload
// is not a lone private address: it is a public address the browser will
// accept alongside a private one it will also try.
func TestAMixedAnswerKeepsOnlyThePublicAddress(t *testing.T) {
	f := defaults(t)
	m := answer("mixed.example",
		a("mixed.example", "8.8.8.8"),
		a("mixed.example", "10.0.0.1"),
		aaaa("mixed.example", "2606:4700::1111"),
		aaaa("mixed.example", "fd00::1"),
	)

	res := f.Apply(m, nil)
	if !res.Changed {
		t.Fatal("nothing was filtered")
	}
	if res.Emptied {
		t.Error("an answer that kept two public addresses was reported as emptied")
	}
	if m.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %s, want NOERROR: the answer is still usable", dns.RcodeToString[m.Rcode])
	}
	got := addrs(m)
	want := []string{"8.8.8.8", "2606:4700::1111"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("remaining addresses = %v, want %v", got, want)
	}
}

// TestAnIPv4MappedAddressIsJudgedByTheAddressItEmbeds. ::ffff:10.0.0.1 is
// 10.0.0.1 wearing a hat. A filter that compared it only against the IPv6
// ranges would pass it straight through, and a client's stack would connect to
// 10.0.0.1.
func TestAnIPv4MappedAddressIsJudgedByTheAddressItEmbeds(t *testing.T) {
	f := defaults(t)

	m := answer("mapped.example", aaaa("mapped.example", "::ffff:10.0.0.1"))
	res := f.Apply(m, nil)
	if !res.Changed {
		t.Fatal("::ffff:10.0.0.1 reached the client")
	}
	if res.Removed[0].Addr.String() != "10.0.0.1" {
		t.Errorf("the removal was recorded as %s, want the embedded 10.0.0.1", res.Removed[0].Addr)
	}

	// And the converse: a mapped public address is still public.
	pub := answer("mapped.example", aaaa("mapped.example", "::ffff:8.8.8.8"))
	if f.Apply(pub, nil).Changed {
		t.Error("::ffff:8.8.8.8 was filtered")
	}
}

// TestAnExemptionLetsSplitHorizonWork. Exemptions are the reason this control
// can be on by default: office.example.com legitimately resolving to 10.x is
// ordinary, and a filter without an escape hatch would break it.
func TestAnExemptionLetsSplitHorizonWork(t *testing.T) {
	f := defaults(t)
	exempt := rebind.MustExemptions("10.0.0.0/8")

	m := answer("office.example", a("office.example", "10.1.2.3"))
	if res := f.Apply(m, exempt); res.Changed {
		t.Fatal("an exempted address was filtered")
	}
	if got := addrs(m); len(got) != 1 || got[0] != "10.1.2.3" {
		t.Errorf("answer = %v, want the exempted address", got)
	}

	// The exemption is for that range only: everything else still filters.
	other := answer("office.example", a("office.example", "192.168.1.1"))
	if !f.Apply(other, exempt).Changed {
		t.Error("exempting 10.0.0.0/8 also exempted 192.168.0.0/16")
	}
}

// TestTheSameAnswerIsFilteredForAPolicyWithoutTheExemption is the pair to the
// test above, and the property that makes exemptions per-policy rather than
// global.
func TestTheSameAnswerIsFilteredForAPolicyWithoutTheExemption(t *testing.T) {
	f := defaults(t)
	rrs := []dns.RR{a("office.example", "10.1.2.3")}

	withExemption := answer("office.example", rrs[0])
	if f.Apply(withExemption, rebind.MustExemptions("10.0.0.0/8")).Changed {
		t.Error("policy A: the exempted address was filtered")
	}

	without := answer("office.example", a("office.example", "10.1.2.3"))
	res := f.Apply(without, nil)
	if !res.Changed || !res.Emptied {
		t.Error("policy B: an address it does not exempt was returned")
	}
}

// TestAMoreSpecificExemptionStillOnlyCoversItself. An operator exempting
// 192.168.10.0/24 has said nothing about the rest of 192.168/16.
func TestAMoreSpecificExemptionStillOnlyCoversItself(t *testing.T) {
	f := defaults(t)
	exempt := rebind.MustExemptions("192.168.10.0/24")

	inside := answer("in.example", a("in.example", "192.168.10.5"))
	if f.Apply(inside, exempt).Changed {
		t.Error("192.168.10.5 was filtered despite a /24 exemption covering it")
	}
	outside := answer("out.example", a("out.example", "192.168.11.5"))
	if !f.Apply(outside, exempt).Changed {
		t.Error("a /24 exemption leaked to a neighbouring /24")
	}
}

// TestADefaultRouteExemptionIsRefused. Exempting 0.0.0.0/0 turns the filter
// off for that policy while leaving it looking switched on, which is worse
// than switching it off: the operator believes they have a control.
func TestADefaultRouteExemptionIsRefused(t *testing.T) {
	for _, cidr := range []string{"0.0.0.0/0", "::/0"} {
		if _, err := rebind.ParseExemptions([]string{cidr}); err == nil {
			t.Errorf("%s was accepted as an exemption", cidr)
		}
	}
	// And a defensive read: an exemption set that somehow contains one must
	// not silently exempt everything.
	if rebind.Exemptions(nil).Covers(netip.MustParseAddr("10.0.0.1")) {
		t.Error("an empty exemption set exempted an address")
	}
}

// TestACNAMEWithNoUsableAddressHasADefinedOutcome. The brief's specific
// worry: a client left holding a CNAME pointing at a name whose only addresses
// were stripped has been given a broken answer with no error, and will hang
// rather than fail.
func TestACNAMEWithNoUsableAddressHasADefinedOutcome(t *testing.T) {
	f := defaults(t)
	m := answer("www.evil.example",
		cname("www.evil.example", "internal.evil.example"),
		a("internal.evil.example", "10.0.0.1"),
	)

	res := f.Apply(m, nil)
	if !res.Emptied {
		t.Fatal("a CNAME chain whose only address was stripped was not reported as emptied")
	}
	if len(m.Answer) != 0 {
		t.Errorf("the client was left holding %d record(s), want a clean NODATA", len(m.Answer))
	}
	if m.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %s, want NOERROR for nodata", dns.RcodeToString[m.Rcode])
	}
}

// TestACNAMEWithASurvivingAddressKeepsTheChain. The alias itself is not the
// problem and removing it would break a legitimate answer.
func TestACNAMEWithASurvivingAddressKeepsTheChain(t *testing.T) {
	f := defaults(t)
	m := answer("www.example.com",
		cname("www.example.com", "cdn.example.net"),
		a("cdn.example.net", "93.184.216.34"),
		a("cdn.example.net", "10.0.0.1"),
	)

	res := f.Apply(m, nil)
	if res.Emptied {
		t.Fatal("an answer with a surviving public address was emptied")
	}
	if len(m.Answer) != 2 {
		t.Errorf("answer has %d records, want the CNAME and the public address", len(m.Answer))
	}
	if _, ok := m.Answer[0].(*dns.CNAME); !ok {
		t.Error("the CNAME was dropped from an otherwise usable answer")
	}
}

// TestEmptyActionIsPinned. Each setting is a different contract with the
// client and an operator picks between them deliberately.
func TestEmptyActionIsPinned(t *testing.T) {
	for _, tc := range []struct {
		action rebind.EmptyAction
		rcode  int
	}{
		{rebind.EmptyNoData, dns.RcodeSuccess},
		{rebind.EmptyNXDOMAIN, dns.RcodeNameError},
		{rebind.EmptyRefused, dns.RcodeRefused},
	} {
		t.Run(string(tc.action), func(t *testing.T) {
			f := mustFilter(t, rebind.Config{Ranges: rebind.DefaultRanges(), EmptyAction: tc.action})
			m := answer("evil.example", a("evil.example", "10.0.0.1"))

			res := f.Apply(m, nil)
			if !res.Emptied {
				t.Fatal("not emptied")
			}
			if m.Rcode != tc.rcode {
				t.Errorf("rcode = %s, want %s", dns.RcodeToString[m.Rcode], dns.RcodeToString[tc.rcode])
			}
			if len(m.Answer) != 0 {
				t.Error("records survived an emptied answer")
			}
		})
	}
}

// TestAdditionalSectionAddressesAreFilteredToo. A stub resolver may use an
// address from the additional section rather than asking again, so leaving one
// there is the same hole by a different route.
func TestAdditionalSectionAddressesAreFilteredToo(t *testing.T) {
	f := defaults(t)
	m := answer("svc.example", a("svc.example", "8.8.8.8"))
	m.Extra = []dns.RR{a("internal.svc.example", "10.0.0.7")}

	res := f.Apply(m, nil)
	if !res.Changed {
		t.Fatal("an additional-section private address was left in place")
	}
	for _, rr := range m.Extra {
		if v, ok := rr.(*dns.A); ok && v.A.String() == "10.0.0.7" {
			t.Error("10.0.0.7 survived in the additional section")
		}
	}
}

// TestTheOPTRecordSurvives. EDNS0 lives in the additional section; dropping it
// while filtering would silently break DNSSEC-aware and large-buffer clients.
func TestTheOPTRecordSurvives(t *testing.T) {
	f := defaults(t)
	m := answer("evil.example", a("evil.example", "10.0.0.1"))
	m.SetEdns0(1232, true)

	f.Apply(m, nil)
	if m.IsEdns0() == nil {
		t.Error("the OPT record was removed along with the filtered addresses")
	}
}

// TestSVCBAddressHintsAreFiltered. Browsers query HTTPS records and will use
// ipv4hint/ipv6hint to connect before any A lookup. An unfiltered hint is a
// complete bypass of the control, not a cosmetic gap.
func TestSVCBAddressHintsAreFiltered(t *testing.T) {
	f := defaults(t)

	m := answer("svc.example")
	m.Question[0].Qtype = dns.TypeHTTPS
	m.Answer = []dns.RR{&dns.HTTPS{SVCB: dns.SVCB{
		Hdr:      dns.RR_Header{Name: dns.Fqdn("svc.example"), Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 60},
		Priority: 1, Target: dns.Fqdn("svc.example"),
		Value: []dns.SVCBKeyValue{
			&dns.SVCBIPv4Hint{Hint: []net.IP{
				netip.MustParseAddr("93.184.216.34").AsSlice(),
				netip.MustParseAddr("10.0.0.1").AsSlice(),
			}},
			&dns.SVCBIPv6Hint{Hint: []net.IP{netip.MustParseAddr("fd00::1").AsSlice()}},
		},
	}}}

	res := f.Apply(m, nil)
	if !res.Changed {
		t.Fatal("private addresses in SVCB hints reached the client")
	}

	svcb, ok := m.Answer[0].(*dns.HTTPS)
	if !ok {
		t.Fatalf("the HTTPS record was replaced by %T", m.Answer[0])
	}
	var v4 []string
	var sawV6 bool
	for _, kv := range svcb.Value {
		switch h := kv.(type) {
		case *dns.SVCBIPv4Hint:
			for _, ip := range h.Hint {
				v4 = append(v4, ip.String())
			}
		case *dns.SVCBIPv6Hint:
			sawV6 = true
		}
	}
	if len(v4) != 1 || v4[0] != "93.184.216.34" {
		t.Errorf("ipv4hint = %v, want only the public address", v4)
	}
	if sawV6 {
		t.Error("an ipv6hint with no surviving address was left on the record")
	}
}

// TestAnSVCBRecordWithNoAddressRecordsIsNotEmptied. Stripping hints leaves a
// usable HTTPS record — the client falls back to A/AAAA — so this must not
// trigger empty_action and turn a working lookup into NXDOMAIN.
func TestAnSVCBRecordWithNoAddressRecordsIsNotEmptied(t *testing.T) {
	f := mustFilter(t, rebind.Config{Ranges: rebind.DefaultRanges(), EmptyAction: rebind.EmptyNXDOMAIN})

	m := answer("svc.example")
	m.Answer = []dns.RR{&dns.HTTPS{SVCB: dns.SVCB{
		Hdr:      dns.RR_Header{Name: dns.Fqdn("svc.example"), Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 60},
		Priority: 1, Target: dns.Fqdn("."),
		Value: []dns.SVCBKeyValue{&dns.SVCBIPv4Hint{Hint: []net.IP{
			netip.MustParseAddr("10.0.0.1").AsSlice(),
		}}},
	}}}

	res := f.Apply(m, nil)
	if res.Emptied {
		t.Error("stripping a hint emptied the answer; the HTTPS record is still usable")
	}
	if m.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %s, want NOERROR", dns.RcodeToString[m.Rcode])
	}
	if len(m.Answer) != 1 {
		t.Errorf("the HTTPS record was dropped entirely")
	}
}

// TestADisabledFilterChangesNothing. The upgrade path: an installation that
// has not turned this on must see byte-identical answers.
func TestADisabledFilterChangesNothing(t *testing.T) {
	var f *rebind.Filter // nil is off

	m := answer("evil.example",
		a("evil.example", "10.0.0.1"),
		aaaa("evil.example", "fd00::1"),
	)
	before := m.String()

	res := f.Apply(m, nil)
	if res.Changed || res.Emptied || len(res.Removed) != 0 {
		t.Error("a nil filter reported changes")
	}
	if m.String() != before {
		t.Errorf("a nil filter altered the message:\n%s", m.String())
	}
}

// TestAnEmptyRangeSetIsRefused. "Enabled with nothing to filter" is the
// dangerous misconfiguration: it protects nothing and reads as protection.
func TestAnEmptyRangeSetIsRefused(t *testing.T) {
	if _, err := rebind.New(rebind.Config{EmptyAction: rebind.EmptyNoData}); err == nil {
		t.Error("a filter with no ranges was constructed")
	}
}

// TestAnUnknownEmptyActionIsRefused rather than silently defaulting: the
// difference between NODATA and NXDOMAIN is visible to every client.
func TestAnUnknownEmptyActionIsRefused(t *testing.T) {
	if _, err := rebind.New(rebind.Config{Ranges: rebind.DefaultRanges(), EmptyAction: "drop"}); err == nil {
		t.Error("an unknown empty_action was accepted")
	}
}

// TestAnErrorResponseIsLeftAlone. NXDOMAIN and SERVFAIL carry no addresses and
// must not be rewritten into something else.
func TestAnErrorResponseIsLeftAlone(t *testing.T) {
	f := defaults(t)
	for _, rcode := range []int{dns.RcodeNameError, dns.RcodeServerFailure, dns.RcodeRefused} {
		m := answer("nothing.example")
		m.Rcode = rcode
		res := f.Apply(m, nil)
		if res.Changed || res.Emptied {
			t.Errorf("%s was modified", dns.RcodeToString[rcode])
		}
		if m.Rcode != rcode {
			t.Errorf("rcode changed from %s to %s", dns.RcodeToString[rcode], dns.RcodeToString[m.Rcode])
		}
	}
}

// TestAnAnswerWithNoAddressesIsNotEmptied. A pure MX or TXT answer has no
// addresses to lose, and turning it into NODATA would be a fabricated failure.
func TestAnAnswerWithNoAddressesIsNotEmptied(t *testing.T) {
	f := mustFilter(t, rebind.Config{Ranges: rebind.DefaultRanges(), EmptyAction: rebind.EmptyNXDOMAIN})
	m := answer("example.com", &dns.TXT{
		Hdr: dns.RR_Header{Name: dns.Fqdn("example.com"), Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
		Txt: []string{"v=spf1 -all"},
	})

	res := f.Apply(m, nil)
	if res.Changed || res.Emptied {
		t.Error("a TXT-only answer was treated as emptied")
	}
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) != 1 {
		t.Error("a TXT-only answer was altered")
	}
}

// TestTheReasonNamesTheAddressAndTheRange. The operator reading a query log is
// often relaying it to someone on the phone; "filtered" alone does not let
// anybody act.
func TestTheReasonNamesTheAddressAndTheRange(t *testing.T) {
	f := defaults(t)
	m := answer("evil.example", a("evil.example", "10.1.2.3"))
	res := f.Apply(m, nil)

	reason := res.Reason("p_office")
	for _, want := range []string{"10.1.2.3", "10.0.0.0/8", "p_office"} {
		if !strings.Contains(reason, want) {
			t.Errorf("reason %q does not mention %q", reason, want)
		}
	}
}

// TestApplyIsSafeUnderConcurrentUse. One Filter is shared by every query on
// the resolver, so it must hold no per-query state. Run with -race.
func TestApplyIsSafeUnderConcurrentUse(t *testing.T) {
	f := defaults(t)
	exempt := rebind.MustExemptions("10.0.0.0/8")

	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				m := answer("mixed.example",
					a("mixed.example", "8.8.8.8"),
					a("mixed.example", "10.0.0.1"),
					a("mixed.example", "192.168.1.1"),
				)
				var ex rebind.Exemptions
				if g%2 == 0 {
					ex = exempt
				}
				res := f.Apply(m, ex)
				want := 1
				if g%2 == 0 {
					want = 2 // the exempt goroutines keep 10.0.0.1
				}
				if got := len(addrs(m)); got != want {
					t.Errorf("goroutine %d kept %d addresses, want %d (%v)", g, got, want, res.Removed)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

// TestOperatorRangesReplaceTheDefaults, so an operator who has a genuine
// reason to filter something else is not stuck with the shipped list.
func TestOperatorRangesReplaceTheDefaults(t *testing.T) {
	f := mustFilter(t, rebind.Config{
		Ranges:      []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		EmptyAction: rebind.EmptyNoData,
	})

	custom := answer("x.example", a("x.example", "203.0.113.9"))
	if !f.Apply(custom, nil).Changed {
		t.Error("the operator's own range was not filtered")
	}
	// And the defaults are genuinely replaced rather than merged.
	priv := answer("y.example", a("y.example", "10.0.0.1"))
	if f.Apply(priv, nil).Changed {
		t.Error("a default range was filtered although the operator replaced the list")
	}
}
