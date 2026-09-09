package observe_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/observe"
)

// fakeUpstream records what it was asked and replies with what a test set.
type fakeUpstream struct {
	mu    sync.Mutex
	asked []*dns.Msg
	reply func(*dns.Msg) (*dns.Msg, error)
}

func (f *fakeUpstream) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	f.mu.Lock()
	f.asked = append(f.asked, m.Copy())
	f.mu.Unlock()
	if f.reply != nil {
		return f.reply(m)
	}
	r := new(dns.Msg)
	r.SetReply(m)
	return r, nil
}

func (f *fakeUpstream) questions() []*dns.Msg {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*dns.Msg(nil), f.asked...)
}

func answerWith(ttl uint32) func(*dns.Msg) (*dns.Msg, error) {
	return func(m *dns.Msg) (*dns.Msg, error) {
		r := new(dns.Msg)
		r.SetReply(m)
		r.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{
				Name: m.Question[0].Name, Rrtype: dns.TypeA,
				Class: dns.ClassINET, Ttl: ttl,
			},
			A: []byte{192, 0, 2, 1},
		}}
		return r, nil
	}
}

// TestEveryQuestionCarriesDOAndCD is the reason this Source exists at all.
//
// Without DO there are no RRSIG, NSEC or NSEC3 records and nothing to
// validate. Without CD a validating upstream answers a bogus zone with
// SERVFAIL and no records, so Daddybound would never see the data it most
// needs to look at and its verdict would be a restatement of the upstream's.
// ADR 0002 §2.
func TestEveryQuestionCarriesDOAndCD(t *testing.T) {
	up := &fakeUpstream{reply: answerWith(300)}
	s := observe.NewSource([]observe.Exchanger{up}, observe.SourceOptions{})

	if _, err := s.Lookup(context.Background(), "example.test.", dns.TypeA); err != nil {
		t.Fatalf("lookup: %v", err)
	}
	asked := up.questions()
	if len(asked) != 1 {
		t.Fatalf("sent %d questions, want 1", len(asked))
	}
	m := asked[0]
	if !m.CheckingDisabled {
		t.Error("CD is not set: the upstream's own validator would filter the interesting cases")
	}
	opt := m.IsEdns0()
	if opt == nil {
		t.Fatal("no EDNS0 OPT: without DO there are no signatures to validate")
	}
	if !opt.Do() {
		t.Error("DO is not set")
	}
	if opt.UDPSize() < 1232 {
		t.Errorf("advertised UDP size %d is small enough to truncate ordinary signed answers", opt.UDPSize())
	}
}

// TestRepeatedQuestionsAreCached is what makes observation affordable.
//
// A chain walk asks for the root and TLD DNSKEY and DS records for every name
// it validates. Without a cache, observing a busy resolver would send tens of
// thousands of duplicate questions upstream.
func TestRepeatedQuestionsAreCached(t *testing.T) {
	up := &fakeUpstream{reply: answerWith(300)}
	s := observe.NewSource([]observe.Exchanger{up}, observe.SourceOptions{})

	for i := 0; i < 5; i++ {
		if _, err := s.Lookup(context.Background(), "example.test.", dns.TypeA); err != nil {
			t.Fatalf("lookup %d: %v", i, err)
		}
	}
	if n := len(up.questions()); n != 1 {
		t.Fatalf("sent %d questions for the same name, want 1", n)
	}
	if st := s.Stats(); st.Hits != 4 {
		t.Errorf("cache hits = %d, want 4", st.Hits)
	}
}

// TestFailuresAreNotCached keeps one lost packet from becoming a persistent
// verdict.
//
// A cached failure is inherited by every later name that needs the same
// DNSKEY, and an operator then sees a wave of Indeterminate observations
// tracing back to a single dropped datagram.
func TestFailuresAreNotCached(t *testing.T) {
	fail := true
	up := &fakeUpstream{reply: func(m *dns.Msg) (*dns.Msg, error) {
		if fail {
			return nil, errors.New("network is unreachable")
		}
		return answerWith(300)(m)
	}}
	s := observe.NewSource([]observe.Exchanger{up}, observe.SourceOptions{})

	if _, err := s.Lookup(context.Background(), "example.test.", dns.TypeA); err == nil {
		t.Fatal("a failing upstream produced no error")
	}
	fail = false
	if _, err := s.Lookup(context.Background(), "example.test.", dns.TypeA); err != nil {
		t.Fatalf("the failure was cached and poisoned the retry: %v", err)
	}
	if n := len(up.questions()); n != 2 {
		t.Fatalf("sent %d questions, want 2: the retry did not reach the network", n)
	}
}

// TestAHostileTTLCannotPinAnEntry bounds how long a record is believed.
//
// The TTL comes from whoever answered. Without a ceiling, a zone could hand
// the observer a DNSKEY with a decade-long TTL and keep a rolled-over key in
// use for the life of the process.
func TestAHostileTTLCannotPinAnEntry(t *testing.T) {
	now := time.Now()
	up := &fakeUpstream{reply: answerWith(4294967295)} // ~136 years
	s := observe.NewSource([]observe.Exchanger{up}, observe.SourceOptions{
		MaxTTL: time.Minute,
		Now:    func() time.Time { return now },
	})

	ctx := context.Background()
	if _, err := s.Lookup(ctx, "example.test.", dns.TypeA); err != nil {
		t.Fatalf("lookup: %v", err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := s.Lookup(ctx, "example.test.", dns.TypeA); err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if n := len(up.questions()); n != 2 {
		t.Fatalf("sent %d questions; the TTL ceiling was not applied", n)
	}
}

// TestAZeroTTLIsNotCached respects a zone that asked not to be.
func TestAZeroTTLIsNotCached(t *testing.T) {
	up := &fakeUpstream{reply: answerWith(0)}
	s := observe.NewSource([]observe.Exchanger{up}, observe.SourceOptions{})

	for i := 0; i < 3; i++ {
		if _, err := s.Lookup(context.Background(), "example.test.", dns.TypeA); err != nil {
			t.Fatalf("lookup: %v", err)
		}
	}
	if n := len(up.questions()); n != 3 {
		t.Fatalf("sent %d questions for a TTL-0 record, want 3", n)
	}
}

// TestTheCacheIsBounded stops observation becoming a memory leak driven by
// whoever chooses the query names.
func TestTheCacheIsBounded(t *testing.T) {
	up := &fakeUpstream{reply: answerWith(3600)}
	const max = 64
	s := observe.NewSource([]observe.Exchanger{up}, observe.SourceOptions{MaxEntries: max})

	ctx := context.Background()
	for i := 0; i < max*20; i++ {
		name := dns.Fqdn("n" + itoa(i) + ".example.test")
		if _, err := s.Lookup(ctx, name, dns.TypeA); err != nil {
			t.Fatalf("lookup %d: %v", i, err)
		}
	}
	// Every question was distinct, so every one reached the network. What is
	// under test is that the cache did not grow to hold them all: asking the
	// oldest names again must miss.
	before := len(up.questions())
	if _, err := s.Lookup(ctx, "n0.example.test.", dns.TypeA); err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(up.questions()) == before {
		t.Fatal("the first name was still cached after 1280 distinct questions; the cache is unbounded")
	}
}

// TestNamesAreCanonicalisedForCaching stops 0x20-randomised or mixed-case
// names multiplying the cache and the upstream traffic.
func TestNamesAreCanonicalisedForCaching(t *testing.T) {
	up := &fakeUpstream{reply: answerWith(300)}
	s := observe.NewSource([]observe.Exchanger{up}, observe.SourceOptions{})

	ctx := context.Background()
	for _, n := range []string{"Example.Test.", "example.test.", "EXAMPLE.TEST."} {
		if _, err := s.Lookup(ctx, n, dns.TypeA); err != nil {
			t.Fatalf("lookup %q: %v", n, err)
		}
	}
	if n := len(up.questions()); n != 1 {
		t.Fatalf("sent %d questions for one name in three casings, want 1", n)
	}
}

// TestTheSecondUpstreamIsTriedWhenTheFirstFails matches the resolver's own
// failover expectation, so switching validation on does not make an instance
// depend on one upstream being healthy.
func TestTheSecondUpstreamIsTriedWhenTheFirstFails(t *testing.T) {
	bad := &fakeUpstream{reply: func(*dns.Msg) (*dns.Msg, error) {
		return nil, errors.New("connection refused")
	}}
	good := &fakeUpstream{reply: answerWith(300)}
	s := observe.NewSource([]observe.Exchanger{bad, good}, observe.SourceOptions{})

	resp, err := s.Lookup(context.Background(), "example.test.", dns.TypeA)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answer records, want 1", len(resp.Answer))
	}
	if len(bad.questions()) != 1 || len(good.questions()) != 1 {
		t.Fatalf("failover did not happen: bad=%d good=%d", len(bad.questions()), len(good.questions()))
	}
}

// TestNoUpstreamsIsAnErrorRatherThanAPanic covers the wiring mistake of
// switching observation on with nothing to ask.
func TestNoUpstreamsIsAnErrorRatherThanAPanic(t *testing.T) {
	s := observe.NewSource(nil, observe.SourceOptions{})
	if _, err := s.Lookup(context.Background(), "example.test.", dns.TypeA); err == nil {
		t.Fatal("a Source with no upstreams returned success")
	}
}

// TestACancelledContextStopsTheSource checks the observation deadline reaches
// the network layer rather than only bounding the validator.
func TestACancelledContextStopsTheSource(t *testing.T) {
	up := &fakeUpstream{reply: answerWith(300)}
	s := observe.NewSource([]observe.Exchanger{up}, observe.SourceOptions{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Lookup(ctx, "example.test.", dns.TypeA); err == nil {
		t.Fatal("a cancelled context still produced a lookup")
	}
	if n := len(up.questions()); n != 0 {
		t.Fatalf("sent %d questions after cancellation, want 0", n)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// TestAnOperationalRcodeIsNotEvidence.
//
// An upstream that answers SERVFAIL or REFUSED is saying it could not answer.
// Passed through as a successful lookup it becomes, to the chain walk, a zone
// that published no DNSKEY or no DS — which is Bogus. An upstream outage or a
// rate limit would then be recorded as a security verdict and land in the
// disagreement table this whole milestone exists to fill.
//
// These queries set CD, so a validating upstream must not be failing them on
// validation grounds either: a SERVFAIL here is a broken upstream, not a
// broken zone.
func TestAnOperationalRcodeIsNotEvidence(t *testing.T) {
	for _, rcode := range []int{
		dns.RcodeServerFailure,
		dns.RcodeRefused,
		dns.RcodeNotImplemented,
		dns.RcodeFormatError,
	} {
		t.Run(dns.RcodeToString[rcode], func(t *testing.T) {
			up := &fakeUpstream{reply: func(m *dns.Msg) (*dns.Msg, error) {
				r := new(dns.Msg)
				r.SetReply(m)
				r.Rcode = rcode
				return r, nil
			}}
			s := observe.NewSource([]observe.Exchanger{up}, observe.SourceOptions{})

			if _, err := s.Lookup(context.Background(), "example.test.", dns.TypeDNSKEY); err == nil {
				t.Fatalf("%s was handed to the validator as a usable answer",
					dns.RcodeToString[rcode])
			}
		})
	}
}

// TestNXDOMAINIsEvidence is the other half, and the reason the check names two
// rcodes rather than one. A denial of existence *is* the answer for a NODATA
// or name-error proof, and rejecting it would make authenticated denial
// unobservable.
func TestNXDOMAINIsEvidence(t *testing.T) {
	up := &fakeUpstream{reply: func(m *dns.Msg) (*dns.Msg, error) {
		r := new(dns.Msg)
		r.SetReply(m)
		r.Rcode = dns.RcodeNameError
		r.Ns = []dns.RR{&dns.SOA{
			Hdr: dns.RR_Header{
				Name: "test.", Rrtype: dns.TypeSOA,
				Class: dns.ClassINET, Ttl: 300,
			},
			Ns: "ns.test.", Mbox: "hostmaster.test.",
		}}
		return r, nil
	}}
	s := observe.NewSource([]observe.Exchanger{up}, observe.SourceOptions{})

	resp, err := s.Lookup(context.Background(), "absent.test.", dns.TypeA)
	if err != nil {
		t.Fatalf("NXDOMAIN was rejected: %v", err)
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode %d survived as %d", dns.RcodeNameError, resp.Rcode)
	}
	if len(resp.Authority) != 1 {
		t.Fatalf("the denial proof was dropped: %d authority records", len(resp.Authority))
	}
}

// TestAFailingUpstreamFailsOverOnRcodeToo.
//
// The failover path already existed for transport errors. An rcode failure is
// the same kind of event and has to reach it, or an instance with a healthy
// second upstream would stop observing whenever the first one degraded.
func TestAFailingUpstreamFailsOverOnRcodeToo(t *testing.T) {
	bad := &fakeUpstream{reply: func(m *dns.Msg) (*dns.Msg, error) {
		r := new(dns.Msg)
		r.SetReply(m)
		r.Rcode = dns.RcodeServerFailure
		return r, nil
	}}
	good := &fakeUpstream{reply: answerWith(300)}
	s := observe.NewSource([]observe.Exchanger{bad, good}, observe.SourceOptions{})

	resp, err := s.Lookup(context.Background(), "example.test.", dns.TypeA)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answer records, want 1", len(resp.Answer))
	}
	if len(good.questions()) != 1 {
		t.Fatal("a SERVFAIL from the first upstream did not fail over to the second")
	}
}
