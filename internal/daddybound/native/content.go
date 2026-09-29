package native

import (
	"context"
	"fmt"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/recursive"
)

type recordSet struct {
	key  question
	data []dns.RR
	sigs []dns.RR
}

// groups preserves packet order while collecting RRsets. Only the Internet
// class is usable on the native public-DNS path.
func groups(records []dns.RR) []recordSet {
	var out []recordSet
	index := map[question]int{}
	for _, rr := range records {
		if rr.Header().Class != dns.ClassINET || rr.Header().Rrtype == dns.TypeOPT {
			continue
		}
		typ := rr.Header().Rrtype
		_, signature := rr.(*dns.RRSIG)
		if sig, ok := rr.(*dns.RRSIG); ok {
			typ = sig.TypeCovered
		}
		key := question{dns.CanonicalName(rr.Header().Name), typ}
		i, ok := index[key]
		if !ok {
			i = len(out)
			index[key] = i
			out = append(out, recordSet{key: key})
		}
		if signature {
			out[i].sigs = append(out[i].sigs, rr)
		} else {
			out[i].data = append(out[i].data, rr)
		}
	}
	return out
}

// clientContent removes unsolicited answer/authority/additional data before
// deciding what has to authenticate. A server being in bailiwick does not
// make an unrelated record relevant to a client's question.
func clientContent(res *recursive.Result, name string, rrtype uint16) (*dns.Msg, []dns.Question, map[question]question, error) {
	if res == nil || res.Msg == nil || res.Msg.Truncated {
		return nil, nil, nil, fmt.Errorf("native: no complete authoritative response")
	}
	out := res.Msg.Copy()
	answerRecords, authorityRecords := out.Answer, out.Ns
	out.Answer, out.Ns, out.Extra = nil, nil, nil
	allowed := map[question]bool{}
	synthetic := map[question]question{}
	for _, hop := range res.Chain {
		qname := dns.CanonicalName(hop.QName)
		allowed[question{qname, rrtype}] = true
		allowed[question{qname, dns.TypeCNAME}] = true
		var closest string
		if hop.Msg != nil {
			for _, rr := range hop.Msg.Answer {
				if rrtype == dns.TypeANY && dns.CanonicalName(rr.Header().Name) == qname {
					allowed[question{qname, rr.Header().Rrtype}] = true
				}
				if d, ok := rr.(*dns.DNAME); ok {
					owner := dns.CanonicalName(d.Hdr.Name)
					if owner != qname && dns.IsSubDomain(owner, qname) &&
						(closest == "" || dns.CountLabel(owner) > dns.CountLabel(closest)) {
						closest = owner
					}
				}
			}
		}
		if closest != "" {
			key := question{closest, dns.TypeDNAME}
			allowed[key] = true
			synthetic[question{qname, dns.TypeCNAME}] = key
		}
	}
	if len(res.Chain) == 0 {
		return nil, nil, nil, fmt.Errorf("native: response has no pinned provenance")
	}
	// Preserve wildcard denial records from earlier alias hops as well as
	// the terminal reply. They are filtered by exact authentication receipts
	// below, and a DO client needs them to verify an expanded alias itself.
	for _, hop := range res.Chain[:len(res.Chain)-1] {
		if hop.Msg == nil {
			continue
		}
		for _, rr := range hop.Msg.Ns {
			typ := rr.Header().Rrtype
			if sig, ok := rr.(*dns.RRSIG); ok {
				typ = sig.TypeCovered
			}
			if typ == dns.TypeNSEC || typ == dns.TypeNSEC3 {
				authorityRecords = append(authorityRecords, dns.Copy(rr))
			}
		}
	}
	authorityRecords = uniqueRecords(authorityRecords)
	for _, set := range groups(answerRecords) {
		if !allowed[set.key] || len(set.data) == 0 {
			continue
		}
		if (set.key.rrtype == dns.TypeCNAME || set.key.rrtype == dns.TypeDNAME) && len(set.data) != 1 {
			return nil, nil, nil, fmt.Errorf("native: ambiguous alias RRset at %s", set.key.name)
		}
		out.Answer = append(out.Answer, set.data...)
		out.Answer = append(out.Answer, set.sigs...)
	}
	for _, set := range groups(authorityRecords) {
		switch set.key.rrtype {
		case dns.TypeSOA, dns.TypeNSEC, dns.TypeNSEC3:
			out.Ns = append(out.Ns, set.data...)
			out.Ns = append(out.Ns, set.sigs...)
		}
	}
	// A DNAME synthesised CNAME answers a CNAME question without a signature
	// of its own. Authenticate the DNAME and retain the locally recomputed
	// CNAME; asking the validator to authenticate that CNAME as ordinary zone
	// data would manufacture a missing-signature failure.
	first := question{dns.CanonicalName(name), rrtype}
	if dname, ok := synthetic[first]; ok {
		first = dname
	}
	questions := []dns.Question{{Name: first.name, Qtype: first.rrtype, Qclass: dns.ClassINET}}
	seen := map[question]bool{first: true}
	add := func(key question) {
		if seen[key] {
			return
		}
		seen[key] = true
		questions = append(questions, dns.Question{Name: key.name, Qtype: key.rrtype, Qclass: dns.ClassINET})
	}
	for _, set := range groups(out.Answer) {
		if _, generated := synthetic[set.key]; !generated && len(set.data) != 0 {
			add(set.key)
		}
	}
	for _, set := range groups(out.Ns) {
		if set.key.rrtype == dns.TypeSOA && len(set.data) != 0 {
			add(set.key)
		}
	}
	return out, questions, synthetic, nil
}

// validateContent combines the question's denial/alias verdict with the
// verdict of every returned data RRset. In particular an insecure first
// alias does not exempt a signed terminal RRset from verification.
func validateContent(ctx context.Context, p *pin, cfg dnssec.Config, msg *dns.Msg, questions []dns.Question, synthetic map[question]question) dnssec.ValidationResult {
	results := dnssec.New(p, cfg).ValidateQuestions(ctx, questions)
	combined := dnssec.ValidationResult{Status: dnssec.StatusSecure, Reason: dnssec.ReasonVerified}
	for _, result := range results {
		if combined.At.IsZero() {
			combined.At = result.At
		}
		combined.Steps = append(combined.Steps, result.Steps...)
		combined.Authenticated = append(combined.Authenticated, result.Authenticated...)
		if statusRank(result.Status) > statusRank(combined.Status) {
			combined.Status, combined.Reason = result.Status, result.Reason
		}
	}
	if len(results) != len(questions) {
		combined.Status, combined.Reason = dnssec.StatusIndeterminate, dnssec.ReasonResourceLimit
	}
	if !combined.Secure() && !combined.Insecure() {
		return combined
	}
	// Receipts cover exact canonical bytes; a success in a different reply's
	// textual trace is not permission to include this packet's data.
	for _, set := range groups(msg.Answer) {
		if len(set.data) == 0 {
			continue
		}
		if _, generated := synthetic[set.key]; generated {
			continue
		}
		if ttl, ok := authenticatedTTL(set.data, combined.Authenticated); ok {
			capTTL(set, ttl)
		} else if combined.Secure() {
			combined.Status, combined.Reason = dnssec.StatusIndeterminate, dnssec.ReasonUnknown
			return combined
		}
	}
	// Negative proof collectors can correctly ignore an unauthenticated
	// extra NSEC. Do not pass that ignored record on under our AD bit.
	var authority []dns.RR
	for _, set := range groups(msg.Ns) {
		if len(set.data) == 0 {
			continue
		}
		ttl, verified := authenticatedTTL(set.data, combined.Authenticated)
		if !verified {
			if set.key.rrtype != dns.TypeSOA || combined.Secure() {
				continue
			}
		} else {
			capTTL(set, ttl)
		}
		authority = append(authority, set.data...)
		authority = append(authority, set.sigs...)
	}
	msg.Ns = authority
	// A synthesised CNAME has the DNAME's maximum lifetime, including the
	// signature expiry that just constrained the DNAME's records.
	all := groups(msg.Answer)
	for _, set := range all {
		if dname, ok := synthetic[set.key]; ok {
			for _, parent := range all {
				if parent.key == dname && len(parent.data) != 0 {
					capTTL(set, parent.data[0].Header().Ttl)
				}
			}
		}
	}
	return combined
}

func authenticatedTTL(records []dns.RR, receipts []dnssec.AuthenticatedRRset) (uint32, bool) {
	var ttl uint32
	ok := false
	for _, receipt := range receipts {
		if receipt.Covers(records) && (!ok || receipt.TTL() < ttl) {
			ttl, ok = receipt.TTL(), true
		}
	}
	return ttl, ok
}

func capTTL(set recordSet, ttl uint32) {
	for _, records := range [][]dns.RR{set.data, set.sigs} {
		for _, rr := range records {
			if rr.Header().Ttl > ttl {
				rr.Header().Ttl = ttl
			}
		}
	}
}

func statusRank(status dnssec.ValidationStatus) int {
	switch status {
	case dnssec.StatusSecure:
		return 0
	case dnssec.StatusInsecure:
		return 1
	case dnssec.StatusBogus:
		return 3
	default:
		return 2
	}
}

// pinSets makes every RRset sent to a client available at its own question.
// The complete original question responses remain pinned first; these
// additional entries serve only the explicit RRset checks above.
func (p *pin) pinSets(res *recursive.Result) {
	for _, hop := range res.Chain {
		if hop.Msg == nil {
			continue
		}
		for _, records := range [][]dns.RR{hop.Msg.Answer, hop.Msg.Ns} {
			for _, set := range groups(records) {
				if len(set.data) == 0 {
					continue
				}
				if _, exists := p.answers[set.key]; exists {
					continue
				}
				p.answers[set.key] = dnssec.Response{
					Rcode:     dns.RcodeSuccess,
					Answer:    append(append([]dns.RR{}, set.data...), set.sigs...),
					Authority: hop.Msg.Ns,
				}
			}
		}
	}
}

func uniqueRecords(records []dns.RR) []dns.RR {
	seen := map[string]dns.RR{}
	out := make([]dns.RR, 0, len(records))
	for _, rr := range records {
		identity := dns.Copy(rr)
		identity.Header().Name = dns.CanonicalName(identity.Header().Name)
		identity.Header().Ttl = 0
		key := identity.String()
		if previous, exists := seen[key]; exists {
			if rr.Header().Ttl < previous.Header().Ttl {
				previous.Header().Ttl = rr.Header().Ttl
			}
			continue
		}
		seen[key] = rr
		out = append(out, rr)
	}
	return out
}
