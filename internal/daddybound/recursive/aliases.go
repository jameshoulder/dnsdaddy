package recursive

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// PrepareAliasResponse projects one alias step and recomputes a DNAME's
// unsigned CNAME. Forwarded local validation shares these rules with iterative
// resolution so a transport choice cannot change the alias being authenticated.
func PrepareAliasResponse(msg *dns.Msg, qname string, rrtype uint16) (*dns.Msg, string, error) {
	return prepareAlias(msg, qname, rrtype)
}

// FirstAliasRecords returns only the alias step being followed, including its
// signatures. Bundled target data is obtained and pinned separately.
func FirstAliasRecords(msg *dns.Msg, qname string) []dns.RR {
	return firstAlias(msg, qname)
}

// prepareAlias chooses the next link and repairs a DNAME's unsigned CNAME
// from the DNAME itself. A server-supplied CNAME must never redirect the
// native resolver somewhere different from the redirection the validator
// authenticates (RFC 6672 section 5.3.1).
func prepareAlias(msg *dns.Msg, qname string, rrtype uint16) (*dns.Msg, string, error) {
	if (msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError) || rrtype == dns.TypeANY {
		return msg, "", nil
	}
	qname = dns.CanonicalName(qname)
	var dname *dns.DNAME
	for _, rr := range msg.Answer {
		d, ok := rr.(*dns.DNAME)
		if !ok || !strictlyBelow(dns.CanonicalName(d.Hdr.Name), qname) {
			continue
		}
		if dname == nil || dns.CountLabel(d.Hdr.Name) > dns.CountLabel(dname.Hdr.Name) {
			dname = d
		} else if dns.CanonicalName(d.Hdr.Name) == dns.CanonicalName(dname.Hdr.Name) {
			return nil, "", fmt.Errorf("%w: multiple DNAMEs at %s", ErrLame, d.Hdr.Name)
		}
	}
	if dname != nil {
		owner, target := dns.CanonicalName(dname.Hdr.Name), dns.CanonicalName(dname.Target)
		prefix := strings.TrimSuffix(qname, owner)
		if target == "." {
			target = prefix
		} else {
			target = prefix + target
		}
		if _, ok := dns.IsDomainName(target); !ok {
			return nil, "", fmt.Errorf("%w: DNAME target exceeds the DNS name limit", ErrLimit)
		}
		out := msg.Copy()
		out.Answer = out.Answer[:0]
		for _, rr := range msg.Answer {
			if _, isCNAME := rr.(*dns.CNAME); isCNAME && dns.CanonicalName(rr.Header().Name) == qname {
				continue
			}
			out.Answer = append(out.Answer, dns.Copy(rr))
		}
		out.Answer = append(out.Answer, &dns.CNAME{
			Hdr:    dns.RR_Header{Name: qname, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: dname.Hdr.Ttl},
			Target: target,
		})
		if rrtype == dns.TypeCNAME {
			return out, "", nil
		}
		return out, target, nil
	}
	if rrtype == dns.TypeCNAME {
		return msg, "", nil
	}
	var alias *dns.CNAME
	for _, rr := range msg.Answer {
		if rr.Header().Rrtype == rrtype && dns.CanonicalName(rr.Header().Name) == qname {
			return msg, "", nil
		}
		if c, ok := rr.(*dns.CNAME); ok && dns.CanonicalName(c.Hdr.Name) == qname {
			if alias != nil {
				return nil, "", fmt.Errorf("%w: multiple CNAMEs at %s", ErrLame, qname)
			}
			alias = c
		}
	}
	if alias == nil {
		return msg, "", nil
	}
	// Resolve the next name even when this message happens to carry records
	// for it. The returned terminal RRset then has its own pinned reply and
	// cannot be replaced by a second fetch performed only by the validator.
	return msg, dns.CanonicalName(alias.Target), nil
}

// firstAlias carries only the link followed by this recursive step. Copying
// the rest of a bundled alias chain would duplicate or contradict the next
// authoritative reply, whose records are what will actually be validated.
func firstAlias(msg *dns.Msg, qname string) []dns.RR {
	qname = dns.CanonicalName(qname)
	owners := map[string]uint16{qname: dns.TypeCNAME}
	var best string
	for _, rr := range msg.Answer {
		if d, ok := rr.(*dns.DNAME); ok {
			owner := dns.CanonicalName(d.Hdr.Name)
			if strictlyBelow(owner, qname) && (best == "" || dns.CountLabel(owner) > dns.CountLabel(best)) {
				best = owner
			}
		}
	}
	if best != "" {
		owners[best] = dns.TypeDNAME
	}
	var out []dns.RR
	for _, rr := range msg.Answer {
		owner, typ := dns.CanonicalName(rr.Header().Name), rr.Header().Rrtype
		if sig, ok := rr.(*dns.RRSIG); ok {
			typ = sig.TypeCovered
		}
		if owners[owner] == typ {
			out = append(out, dns.Copy(rr))
		}
	}
	return out
}
