package dnssec_test

import (
	"context"
	"testing"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
)

// QTYPE=* is a query type, not a record type, and conflating the two was a
// false Secure.
//
// No record has type 255, so no NSEC or NSEC3 type bitmap ever lists it. A
// NODATA rule phrased as "the matching denial record must omit the queried
// type" is therefore satisfied by every bitmap in existence when the queried
// type is 255 — and a validator that reaches that rule for an ANY query
// authenticates an absence no zone ever asserted.
//
// The attack costs nothing. Take a real, correctly signed response to an ANY
// query, delete the answer section, and forward the zone's own genuine NSEC
// and SOA records untouched. Every signature still verifies, because every
// record is genuine. RFC 6840 §4.2 is what closes it.
func TestAnEmptyAnyAnswerIsNotAnAuthenticatedAbsence(t *testing.T) {
	h, err := lab.Standard()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	cfg, err := h.Config(lab.Now())
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	// www.example.dnsdaddylab. exists and has an A RRset. Its NSEC record
	// says so, in the very response used to "prove" the absence.
	src := &relayingSource{
		inner: h, name: lab.AnswerName, rrtype: dns.TypeANY,
		rewrite: func([]dns.RR) []dns.RR { return nil },
	}
	got := dnssec.New(src, cfg).Validate(context.Background(), lab.AnswerName, dns.TypeANY)

	if got.Status == dnssec.StatusSecure {
		t.Fatalf("an emptied ANY answer for a name that exists was reported Secure\n%s", got.Trace())
	}
	if got.Status != dnssec.StatusIndeterminate {
		t.Errorf("status = %s, want indeterminate: the zone has done nothing wrong, "+
			"this validator simply has no proof to check\n%s", got.Status, got.Trace())
	}
	if got.Reason != dnssec.ReasonAnyNotProvable {
		t.Errorf("reason = %s, want %s", got.Reason, dnssec.ReasonAnyNotProvable)
	}
}

// The other half of RFC 6840 §4.2: "all received RRsets that match QNAME and
// QCLASS MUST be validated."
//
// A validator that ignores the answer section of an ANY response — which is
// what filtering it by rrtype 255 amounts to, since nothing matches — never
// looks at the records it is being asked about. Whether they are genuine or
// forged makes no difference to its verdict, which is the definition of not
// validating them.
func TestAnAnyAnswerValidatesEveryRRsetItReceived(t *testing.T) {
	h, err := lab.Standard()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	cfg, err := h.Config(lab.Now())
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	real, err := h.Lookup(context.Background(), lab.AnswerName, dns.TypeA)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	t.Run("genuine records validate", func(t *testing.T) {
		src := &relayingSource{
			inner: h, name: lab.AnswerName, rrtype: dns.TypeANY,
			rewrite: func([]dns.RR) []dns.RR { return real.Answer },
		}
		got := dnssec.New(src, cfg).Validate(context.Background(), lab.AnswerName, dns.TypeANY)
		if got.Status != dnssec.StatusSecure {
			t.Fatalf("a genuine ANY answer was refused: %s (%s)\n%s", got.Status, got.Reason, got.Trace())
		}
	})

	t.Run("a tampered record is Bogus", func(t *testing.T) {
		tampered := make([]dns.RR, 0, len(real.Answer))
		for _, rr := range real.Answer {
			c := dns.Copy(rr)
			if a, ok := c.(*dns.A); ok {
				a.A = a.A.To4()
				a.A[3]++
			}
			tampered = append(tampered, c)
		}
		src := &relayingSource{
			inner: h, name: lab.AnswerName, rrtype: dns.TypeANY,
			rewrite: func([]dns.RR) []dns.RR { return tampered },
		}
		got := dnssec.New(src, cfg).Validate(context.Background(), lab.AnswerName, dns.TypeANY)
		if got.Status != dnssec.StatusBogus {
			t.Fatalf("a rewritten address inside an ANY answer was not Bogus: %s (%s)\n%s",
				got.Status, got.Reason, got.Trace())
		}
	})

	t.Run("one bad RRset among several is still Bogus", func(t *testing.T) {
		// §4.2: "If any of those RRsets fail validation, the answer is
		// considered Bogus." A per-type loop that stopped at the first
		// success, or that returned the last result, would pass the
		// subtests above and fail this one.
		mail, err := h.Lookup(context.Background(), lab.MailName, dns.TypeMX)
		if err != nil {
			t.Fatalf("lookup: %v", err)
		}
		mixed := make([]dns.RR, 0, len(mail.Answer)+len(real.Answer))
		for _, rr := range mail.Answer {
			mixed = append(mixed, dns.Copy(rr))
		}
		// A genuine A RRset from another name, relabelled onto this one:
		// unsigned for this owner, so it must fail while the MX passes.
		for _, rr := range real.Answer {
			c := dns.Copy(rr)
			c.Header().Name = lab.MailName
			mixed = append(mixed, c)
		}
		src := &relayingSource{
			inner: h, name: lab.MailName, rrtype: dns.TypeANY,
			rewrite: func([]dns.RR) []dns.RR { return mixed },
		}
		got := dnssec.New(src, cfg).Validate(context.Background(), lab.MailName, dns.TypeANY)
		if got.Status == dnssec.StatusSecure {
			t.Fatalf("an ANY answer containing an unauthenticated RRset was Secure\n%s", got.Trace())
		}
	})
}

// An ANY query for a name that does not exist is answerable, and must stay
// answerable: the NXDOMAIN proof shows the name has no records of any type,
// which is a complete answer to QTYPE=*. Refusing every ANY query would also
// close the false Secure above, so this is what stops the fix from being that.
func TestAnAnyQueryForAMissingNameIsStillSecure(t *testing.T) {
	h, err := lab.Standard()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	v, err := h.Validator(lab.Now())
	if err != nil {
		t.Fatalf("validator: %v", err)
	}
	got := v.Validate(context.Background(), lab.MissingName, dns.TypeANY)
	if got.Status != dnssec.StatusSecure {
		t.Fatalf("an authenticated NXDOMAIN for QTYPE=ANY was not Secure: %s (%s)\n%s",
			got.Status, got.Reason, got.Trace())
	}
}

// The verdict must not depend on the order the answer section arrived in.
// An attacker on the path reorders records for free, and §4.2's all-must-pass
// rule implemented with an early return leaks that ordering into the reported
// reason, which decides Bogus versus Indeterminate.
func TestAnAnyVerdictDoesNotDependOnAnswerOrder(t *testing.T) {
	h, err := lab.Standard()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	cfg, err := h.Config(lab.Now())
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	real, err := h.Lookup(context.Background(), lab.AnswerName, dns.TypeA)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	forwards := make([]dns.RR, 0, len(real.Answer))
	for _, rr := range real.Answer {
		forwards = append(forwards, dns.Copy(rr))
	}
	// An unsigned TXT alongside the signed A, so there is a failure and a
	// success to order against each other.
	forwards = append(forwards, &dns.TXT{
		Hdr: dns.RR_Header{Name: lab.AnswerName, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600},
		Txt: []string{"unsigned"},
	})
	backwards := make([]dns.RR, len(forwards))
	for i, rr := range forwards {
		backwards[len(forwards)-1-i] = rr
	}

	verdict := func(answer []dns.RR) dnssec.ValidationResult {
		src := &relayingSource{
			inner: h, name: lab.AnswerName, rrtype: dns.TypeANY,
			rewrite: func([]dns.RR) []dns.RR { return answer },
		}
		return dnssec.New(src, cfg).Validate(context.Background(), lab.AnswerName, dns.TypeANY)
	}

	a, b := verdict(forwards), verdict(backwards)
	if a.Status != b.Status || a.Reason != b.Reason {
		t.Fatalf("reordering the answer section changed the verdict:\n  %s (%s)\n  %s (%s)",
			a.Status, a.Reason, b.Status, b.Reason)
	}
	if a.Status == dnssec.StatusSecure {
		t.Fatalf("an ANY answer containing an unsigned RRset was Secure\n%s", a.Trace())
	}
}
