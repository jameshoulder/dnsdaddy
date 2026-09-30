package native_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/native"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/observe"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/recursive"
)

type forwardFixture struct {
	h       *lab.Hierarchy
	cfg     native.ForwardConfig
	mu      sync.Mutex
	queries []dns.Question
	mutate  func(*dns.Msg, *dns.Msg)
}

func forwardedFixture(t *testing.T) *forwardFixture {
	t.Helper()
	h, err := lab.Standard()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := h.Config(labInstant())
	if err != nil {
		t.Fatal(err)
	}
	f := &forwardFixture{h: h}
	f.cfg = native.ForwardConfig{Exchange: f.exchange, Anchors: cfg.Anchors, Policy: cfg.Policy,
		Clock: cfg.Clock, Verifier: cfg.Verifier, Limits: cfg.Limits}
	return f
}

func (f *forwardFixture) exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	if !q.RecursionDesired || !q.CheckingDisabled || q.AuthenticatedData || q.IsEdns0() == nil || !q.IsEdns0().Do() || len(q.IsEdns0().Option) != 0 {
		return nil, errors.New("material query did not request independent DNSSEC evidence without client metadata")
	}
	f.mu.Lock()
	f.queries = append(f.queries, q.Question[0])
	f.mu.Unlock()
	a, err := f.h.Lookup(ctx, q.Question[0].Name, q.Question[0].Qtype)
	if err != nil {
		return nil, err
	}
	m := new(dns.Msg)
	m.SetReply(q)
	m.RecursionAvailable = true
	m.AuthenticatedData = true // Never evidence for the local validator.
	m.Rcode, m.Answer, m.Ns = a.Rcode, a.Answer, a.Authority
	m = m.Copy()
	if f.mutate != nil {
		f.mutate(q, m)
	}
	return m, nil
}

func (f *forwardFixture) engine(t *testing.T) *native.ForwardEngine {
	t.Helper()
	e, err := native.NewForwardEngine(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func (f *forwardFixture) count(name string, rrtype uint16) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, q := range f.queries {
		if q.Name == name && q.Qtype == rrtype {
			n++
		}
	}
	return n
}

func TestForwardedRecordsAreLocallyValidatedThroughTheInjectedExchange(t *testing.T) {
	for _, tc := range []struct {
		name  string
		qtype uint16
		want  dnssec.ValidationStatus
	}{
		{lab.AnswerName, dns.TypeA, dnssec.StatusSecure},
		{lab.LeafZone, dns.TypeDNSKEY, dnssec.StatusSecure},
		{lab.LeafZone, dns.TypeDS, dnssec.StatusSecure},
		{lab.UnsignedName, dns.TypeA, dnssec.StatusInsecure},
		{lab.MissingName, dns.TypeA, dnssec.StatusSecure},
		{lab.AnswerName, dns.TypeAAAA, dnssec.StatusSecure},
		{lab.WildcardMatch, dns.TypeA, dnssec.StatusSecure},
		{lab.AliasName, dns.TypeA, dnssec.StatusSecure},
		{lab.CrossZoneAlias, dns.TypeA, dnssec.StatusSecure},
		{lab.AliasHop1, dns.TypeA, dnssec.StatusSecure},
		{lab.AliasToInsecure, dns.TypeA, dnssec.StatusInsecure},
		{lab.InsecureAliasName, dns.TypeA, dnssec.StatusInsecure},
		{lab.DnameMatch, dns.TypeA, dnssec.StatusSecure},
		{lab.DnameMatch, dns.TypeCNAME, dnssec.StatusSecure},
		{lab.WildcardAliasMatch, dns.TypeA, dnssec.StatusSecure},
		{lab.AnswerName, dns.TypeANY, dnssec.StatusSecure},
	} {
		t.Run(tc.name+"/"+dns.TypeToString[tc.qtype], func(t *testing.T) {
			f := forwardedFixture(t)
			ans, err := f.engine(t).Resolve(context.Background(), tc.name, tc.qtype)
			if err != nil {
				t.Fatal(err)
			}
			if ans.Validation.Status != tc.want {
				t.Fatalf("got %s (%s), want %s\n%s", ans.Validation.Status, ans.Validation.Reason, tc.want, ans.Validation.Trace())
			}
			if (tc.want == dnssec.StatusSecure && ans.Pinned == 0) || ans.Queries == 0 || len(ans.Delegations) != 0 || ans.Zone != "" {
				t.Fatalf("incorrect forwarded provenance: %+v", ans)
			}
			if ans.Msg.AuthenticatedData {
				t.Fatal("an upstream AD bit survived material processing")
			}
			if f.count(".", dns.TypeDNSKEY) != 1 {
				t.Fatal("root DNSKEY was not fetched exactly once through the selected exchange")
			}
		})
	}
}

func TestForwardedTamperingCannotBeRescuedByUpstreamADOrASecondAnswer(t *testing.T) {
	f := forwardedFixture(t)
	f.mutate = func(q, m *dns.Msg) {
		if q.Question[0].Name == lab.AnswerName && q.Question[0].Qtype == dns.TypeA {
			for _, rr := range m.Answer {
				if a, ok := rr.(*dns.A); ok {
					a.A = net.IPv4(6, 6, 6, 6)
				}
			}
		}
	}
	e := f.engine(t)
	c, err := native.NewClient(e, native.ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	q := new(dns.Msg)
	q.SetQuestion(lab.AnswerName, dns.TypeA)
	q.SetEdns0(1232, true)
	ans := c.ResolveClient(context.Background(), q)
	if ans.Msg.Rcode != dns.RcodeServerFailure || ans.ValidationStatus != "bogus" || ans.Msg.AuthenticatedData {
		t.Fatalf("forged AD-marked answer was not refused: %+v", ans)
	}
	if f.count(lab.AnswerName, dns.TypeA) != 1 {
		t.Fatal("the returned answer was independently re-fetched for validation")
	}
}

func TestForwardedDNAMEIsRecomputedAndBundledTargetDataDoesNotReplacePinnedAnswers(t *testing.T) {
	f := forwardedFixture(t)
	f.mutate = func(q, m *dns.Msg) {
		if q.Question[0].Name == lab.DnameMatch && q.Question[0].Qtype == dns.TypeA {
			for _, rr := range m.Answer {
				switch v := rr.(type) {
				case *dns.CNAME:
					v.Target = "attacker.invalid."
				case *dns.A:
					v.A = net.IPv4(6, 6, 6, 6)
				}
			}
		}
	}
	ans, err := f.engine(t).Resolve(context.Background(), lab.DnameMatch, dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if !ans.Validation.Secure() {
		t.Fatalf("DNAME failed: %s", ans.Validation.Trace())
	}
	for _, rr := range ans.Msg.Answer {
		if c, ok := rr.(*dns.CNAME); ok && c.Target != lab.AnswerName {
			t.Fatalf("forged synthesized alias escaped: %s", c)
		}
		if a, ok := rr.(*dns.A); ok && !a.A.Equal(lab.AnswerAddress) {
			t.Fatalf("bundled poison escaped: %s", a)
		}
	}
	if f.count("attacker.invalid.", dns.TypeA) != 0 || f.count(lab.AnswerName, dns.TypeA) != 1 {
		t.Fatal("alias redirection followed untrusted CNAME or failed to pin the real target")
	}
}

func TestForwardedUnsignedAliasDoesNotHideABogusSignedTarget(t *testing.T) {
	f := forwardedFixture(t)
	f.mutate = func(q, m *dns.Msg) {
		if q.Question[0].Name == lab.AnswerName && q.Question[0].Qtype == dns.TypeA {
			for _, rr := range m.Answer {
				if a, ok := rr.(*dns.A); ok {
					a.A = net.IPv4(6, 6, 6, 6)
				}
			}
		}
	}
	ans, err := f.engine(t).Resolve(context.Background(), lab.InsecureAliasName, dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if ans.Validation.Status != dnssec.StatusBogus {
		t.Fatalf("got %s, want bogus\n%s", ans.Validation.Status, ans.Validation.Trace())
	}
}

func TestForwardedMaterialIsBoundedAndDoesNotInventAValidationVerdict(t *testing.T) {
	f := forwardedFixture(t)
	f.cfg.MaxQueries = 1
	ans, err := f.engine(t).Resolve(context.Background(), lab.AnswerName, dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if ans.Validation.Status != dnssec.StatusIndeterminate || ans.Validation.Reason != dnssec.ReasonResourceLimit || ans.Queries != 1 {
		t.Fatalf("budget was misreported: %+v", ans.Validation)
	}
	f = forwardedFixture(t)
	_, err = f.engine(t).Resolve(context.Background(), lab.AliasLoopA, dns.TypeA)
	if !errors.Is(err, recursive.ErrLimit) {
		t.Fatalf("alias loop returned %v", err)
	}
}

func TestForwardedLargeMessagesCannotFillEveryQuerySlotWithRetainedMaterial(t *testing.T) {
	calls := 0
	limits := dnssec.DefaultLimits()
	limits.MaxAliasHops = 64
	e, err := native.NewForwardEngine(native.ForwardConfig{Limits: limits, Exchange: func(_ context.Context, q *dns.Msg) (*dns.Msg, error) {
		calls++
		m := new(dns.Msg)
		m.SetReply(q)
		name := q.Question[0].Name
		m.Answer = append(m.Answer, &dns.CNAME{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: fmt.Sprintf("hop%d.large.example.", calls)})
		// Each reply is individually wire-valid. Its unrelated records would
		// be removed before serving, but still cost memory while evidence is held.
		for i := 0; i < 250; i++ {
			m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{strings.Repeat("x", 200)}})
		}
		wire, packErr := m.Pack()
		if packErr != nil || len(wire) > dns.MaxMsgSize {
			t.Fatalf("fixture is not a valid bounded DNS message: bytes=%d err=%v", len(wire), packErr)
		}
		return m, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	ans, err := e.Resolve(context.Background(), "start.large.example.", dns.TypeA)
	if ans != nil || !errors.Is(err, recursive.ErrLimit) || calls >= 32 {
		t.Fatalf("material byte cap did not stop before the 64-query/alias caps: calls=%d answer=%v error=%v", calls, ans, err)
	}
}

func TestForwardedNSEC3ScenariosPreserveAuthenticatedDenialDecisions(t *testing.T) {
	for _, scenario := range lab.Scenarios() {
		if scenario.Family != lab.FamilyNSEC3 {
			continue
		}
		t.Run(scenario.Name, func(t *testing.T) {
			h, err := scenario.Build(lab.StandardSpec())
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := h.Config(scenario.At)
			if err != nil {
				t.Fatal(err)
			}
			f := &forwardFixture{h: h}
			f.cfg = native.ForwardConfig{Exchange: f.exchange, Anchors: cfg.Anchors, Policy: cfg.Policy, Clock: cfg.Clock, Verifier: cfg.Verifier, Limits: cfg.Limits}
			ans, err := f.engine(t).Resolve(context.Background(), scenario.Query, scenario.QType)
			if err != nil {
				t.Fatal(err)
			}
			if ans.Validation.Status != scenario.Expect {
				t.Fatalf("got %s (%s), want %s\n%s", ans.Validation.Status, ans.Validation.Reason, scenario.Expect, ans.Validation.Trace())
			}
		})
	}
}

func TestForwardedFailureAndCancellationCannotStartAnotherTransport(t *testing.T) {
	for _, failure := range []error{errors.New("encrypted peer unavailable"), context.Canceled, context.DeadlineExceeded} {
		calls := 0
		e, err := native.NewForwardEngine(native.ForwardConfig{Exchange: func(context.Context, *dns.Msg) (*dns.Msg, error) {
			calls++
			return nil, failure
		}})
		if err != nil {
			t.Fatal(err)
		}
		ans, err := e.Resolve(context.Background(), lab.AnswerName, dns.TypeA)
		if !errors.Is(err, failure) || ans != nil || calls != 1 {
			t.Fatalf("failure was replaced or retried outside the selected exchange: answer=%v err=%v calls=%d", ans, err, calls)
		}
	}
}

func TestForwardedResponseIdentityAndCompletenessAreRequired(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*dns.Msg)
	}{
		{"id", func(m *dns.Msg) { m.Id++ }},
		{"question", func(m *dns.Msg) { m.Question[0].Name = "other.invalid." }},
		{"type", func(m *dns.Msg) { m.Question[0].Qtype = dns.TypeTXT }},
		{"class", func(m *dns.Msg) { m.Question[0].Qclass = dns.ClassCHAOS }},
		{"opcode", func(m *dns.Msg) { m.Opcode = dns.OpcodeUpdate }},
		{"qr", func(m *dns.Msg) { m.Response = false }},
		{"truncated", func(m *dns.Msg) { m.Truncated = true }},
		{"servfail", func(m *dns.Msg) { m.Rcode = dns.RcodeServerFailure }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := forwardedFixture(t)
			f.mutate = func(_ *dns.Msg, m *dns.Msg) { tc.change(m) }
			if ans, err := f.engine(t).Resolve(context.Background(), lab.AnswerName, dns.TypeA); err == nil || ans != nil {
				t.Fatalf("malformed response accepted: %v %v", ans, err)
			}
		})
	}
}

func TestForwardedValidationReadsCurrentAnchorsRatherThanAnOldSecureCacheEntry(t *testing.T) {
	f := forwardedFixture(t)
	anchors := f.cfg.Anchors
	f.cfg.AnchorSource = func() dnssec.TrustAnchors { return anchors }
	e := f.engine(t)
	first, err := e.Resolve(context.Background(), lab.AnswerName, dns.TypeA)
	if err != nil || !first.Validation.Secure() {
		t.Fatalf("first resolution: %v %v", first, err)
	}
	anchors = dnssec.TrustAnchors{}
	second, err := e.Resolve(context.Background(), lab.AnswerName, dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if second.Validation.Status != dnssec.StatusIndeterminate {
		t.Fatalf("revoked anchor was bypassed: %s", second.Validation.Status)
	}
	if f.count(lab.AnswerName, dns.TypeA) != 2 {
		t.Fatal("material cache survived beyond one operation")
	}
}

func TestForwardedManagedKeysAndCheckingDisabledUseTheSameSelectedExchange(t *testing.T) {
	f := forwardedFixture(t)
	keys, err := native.NewForwardKeySource(f.exchange).DNSKEY(context.Background(), ".")
	if err != nil || len(keys) < 2 {
		t.Fatalf("keys=%v err=%v", keys, err)
	}
	c, err := native.NewClient(f.engine(t), native.ClientOptions{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	q := new(dns.Msg)
	q.SetQuestion(lab.AnswerName, dns.TypeA)
	q.CheckingDisabled = true
	q.SetEdns0(1232, true)
	ans := c.ResolveClient(context.Background(), q)
	if ans.ValidationStatus != "checking_disabled" || ans.Msg.AuthenticatedData || ans.Msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("CD semantics changed with encrypted transport: %+v", ans)
	}
	if f.count(".", dns.TypeDNSKEY) != 1 || f.count(lab.AnswerName, dns.TypeA) != 1 {
		t.Fatal("refresh or unchecked answer left the selected exchange")
	}
}

func TestForwardedLearnFailureDescribesTheSelectedEncryptedTransport(t *testing.T) {
	e, err := native.NewForwardEngine(native.ForwardConfig{Exchange: func(context.Context, *dns.Msg) (*dns.Msg, error) {
		return nil, errors.New("selected encrypted peer is unavailable")
	}})
	if err != nil {
		t.Fatal(err)
	}
	out := native.NewLearn(e).ResolveAndValidate(context.Background(), lab.AnswerName, dns.TypeA)
	if out.Failure != observe.StatusUnreachable || out.FailureCode != "encrypted_upstream_unavailable" || !strings.Contains(out.FailureReason, "encrypted") {
		t.Fatalf("forwarded failure was attributed to native authoritative recursion: %+v", out)
	}
}
