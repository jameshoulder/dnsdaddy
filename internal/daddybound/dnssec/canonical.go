package dnssec

import (
	"bytes"
	"errors"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// This file is Daddybound's trusted computing base.
//
// Every verdict this package produces is ultimately a statement about the
// bytes constructed here. If these bytes are wrong, each downstream check
// still runs, still looks correct, and answers a question nobody asked — and
// it answers it with a confident Secure or a confident Bogus. There is no
// self-check further down that catches an error at this level, which is why
// the tests for this file assert byte sequences against the RFC's rules
// rather than asserting that a library was called.

// maxRRsetSize bounds how many records one RRset may contribute to signed
// data. An RRset arrives from the network, and canonicalisation sorts it, so
// an unbounded set is unbounded work on attacker-chosen input. The limit is
// far above any legitimate RRset and exists to make the failure a refusal
// rather than a stall.
const maxRRsetSize = 1024

// canonicalSignedData builds the exact byte sequence an RRSIG signs.
//
// RFC 4034 §3.1.8.1 (R-CANON-01):
//
//	signature = sign(RRSIG_RDATA | RR(1) | RR(2)... )
//
// where RRSIG_RDATA is the RRSIG's RDATA with the Signature field omitted,
// and each RR is in canonical form per §6.2.
//
// The RRset is not required to be sorted or deduplicated on the way in; this
// function does both, because §6.3 defines the signed order and a caller that
// had to sort first would be a caller that could forget to.
func canonicalSignedData(sig *dns.RRSIG, rrset []dns.RR) ([]byte, error) {
	if len(rrset) == 0 {
		return nil, errors.New("dnssec: cannot build signed data for an empty RRset")
	}
	if len(rrset) > maxRRsetSize {
		return nil, errors.New("dnssec: RRset exceeds the canonicalisation limit")
	}

	wires, err := canonicalRRs(sig, rrset)
	if err != nil {
		return nil, err
	}

	header, err := canonicalRRSIGRDATA(sig)
	if err != nil {
		return nil, err
	}

	total := len(header)
	for _, w := range wires {
		total += len(w)
	}
	out := make([]byte, 0, total)
	out = append(out, header...)
	for _, w := range wires {
		out = append(out, w...)
	}
	return out, nil
}

// canonicalRRSIGRDATA packs the RRSIG RDATA up to but not including the
// signature.
//
// Field order and widths are RFC 4034 §3.1: Type Covered (2), Algorithm (1),
// Labels (1), Original TTL (4), Signature Expiration (4), Signature Inception
// (4), Key Tag (2), Signer's Name (variable). The signer's name is packed
// uncompressed and down-cased, being a domain name in the RDATA of an RRSIG
// (R-CANON-04).
//
// It is built by packing a copy of the RRSIG with an empty Signature field
// and taking the RDATA, rather than by writing the eight fields out by hand.
// Hand-writing them duplicates a wire format that already has one correct
// implementation in this binary, and a duplicate is a place for the two to
// disagree.
func canonicalRRSIGRDATA(sig *dns.RRSIG) ([]byte, error) {
	stripped := *sig
	stripped.Signature = ""
	stripped.Hdr.Name = dns.CanonicalName(sig.Hdr.Name)
	stripped.SignerName = dns.CanonicalName(sig.SignerName)

	wire, err := packCanonical(&stripped)
	if err != nil {
		return nil, err
	}
	rdata, err := rdataOf(wire, &stripped)
	if err != nil {
		return nil, err
	}
	return rdata, nil
}

// canonicalRRs returns the canonical wire form of each record in the RRset,
// sorted per RFC 4034 §6.3 and with exact duplicates removed.
//
// Duplicates are removed because a signer signs an RRset, and an RRset is a
// set: RFC 2181 §5 defines it by (owner, class, type) membership, not by
// arrival count. An RRset that arrives with a record repeated must produce
// the same signed data as one that does not, or an attacker could invalidate
// a correctly signed answer simply by duplicating a record in transit.
func canonicalRRs(sig *dns.RRSIG, rrset []dns.RR) ([][]byte, error) {
	wires := make([][]byte, 0, len(rrset))
	for _, rr := range rrset {
		wire, err := canonicalRR(sig, rr)
		if err != nil {
			return nil, err
		}
		wires = append(wires, wire)
	}

	// §6.3: "RRs with identical owner, class, and type sort by treating
	// RDATA as unsigned octet sequences." The owner, class and type are
	// identical across the set by construction — rrsetOf enforces it — so
	// comparing whole canonical records is equivalent to comparing RDATA and
	// avoids having to locate the RDATA offset for every record.
	sort.SliceStable(wires, func(i, j int) bool {
		return bytes.Compare(wires[i], wires[j]) < 0
	})

	deduped := wires[:0]
	for i, w := range wires {
		if i > 0 && bytes.Equal(w, wires[i-1]) {
			continue
		}
		deduped = append(deduped, w)
	}
	return deduped, nil
}

// canonicalRR returns one record in canonical form per RFC 4034 §6.2.
func canonicalRR(sig *dns.RRSIG, rr dns.RR) ([]byte, error) {
	c := dns.Copy(rr)
	h := c.Header()

	// §6.2 (2) — the owner name is down-cased (R-CANON-03), and §6.2 (4) —
	// a wildcard owner appears unexpanded (R-CANON-06).
	//
	// The wildcard rule is expressed through the RRSIG's Labels field rather
	// than by looking for a "*" label, because by the time an answer reaches
	// a validator the wildcard has already been substituted: the record says
	// www.example.test and only the Labels count reveals that the signer
	// signed *.example.test. RFC 4034 §3.1.3 defines Labels as excluding the
	// root label and the wildcard label, so an owner with more labels than
	// the field says was produced by wildcard expansion.
	name := dns.CanonicalName(h.Name)
	labels := dns.SplitDomainName(name)

	// R-SIG-04 is checked before an RRSIG becomes eligible, so a Labels
	// field larger than the owner name should be impossible here. It is
	// re-checked anyway because this is the trusted computing base: the
	// alternative to an explicit refusal is a negative slice index, and a
	// panic inside signed-data construction is a worse failure than a
	// refusal to construct it.
	if int(sig.Labels) > len(labels) {
		return nil, errors.New("dnssec: RRSIG labels field exceeds the owner name")
	}
	if len(labels) > int(sig.Labels) {
		name = "*." + strings.Join(labels[len(labels)-int(sig.Labels):], ".") + "."
	}
	h.Name = name

	// §6.2 (5) — the TTL is the covering RRSIG's Original TTL (R-CANON-02).
	//
	// This is the substitution that makes signature verification independent
	// of how long the record sat in a cache. Using the received TTL instead
	// produces an implementation that verifies at the moment of signing and
	// fails a second later, which presents as intermittent network trouble
	// rather than as a bug.
	h.Ttl = sig.OrigTtl

	// §6.2 (3) — domain names inside the RDATA of the enumerated types are
	// down-cased (R-CANON-04).
	downcaseRDATANames(c)

	// §6.2 (1) — fully expanded, uncompressed. packCanonical passes a nil
	// compression map and compress=false.
	return packCanonical(c)
}

// downcaseRDATANames down-cases the domain names inside the RDATA of exactly
// the record types the standards say to, and no others.
//
// The list is RFC 4034 §6.2 item 3 as corrected by RFC 6840 §5.1, which makes
// two changes worth stating explicitly because both are easy to get wrong by
// reading only RFC 4034:
//
//   - HINFO is removed. RFC 4034 lists it, twice, and RFC 6840 §5.1 says:
//     "Section 6.2 of [RFC4034] also erroneously lists HINFO as a record that
//     needs conversion to lowercase, and twice at that. Since HINFO records
//     contain no domain names, they are not subject to case conversion."
//
//   - NSEC is removed. RFC 6840 §5.1: "DNS names in the RDATA section of NSEC
//     resource records are not converted to lowercase. DNS names in the RDATA
//     section of RRSIG resource records are converted to lowercase." RFC 4034
//     said to down-case both and RFC 3755 said to down-case neither; the
//     correction follows deployed practice, and a validator that follows
//     RFC 4034 literally here declares correctly signed zones Bogus.
//
// The list is closed. Types defined after RFC 4034 are not added to it even
// when their RDATA contains something name-shaped — SVCB and HTTPS being the
// obvious modern examples — because the standard enumerates types rather than
// describing a property, and inventing membership would produce signed data
// no signer ever signed.
func downcaseRDATANames(rr dns.RR) {
	switch x := rr.(type) {
	case *dns.NS:
		x.Ns = dns.CanonicalName(x.Ns)
	case *dns.MD:
		x.Md = dns.CanonicalName(x.Md)
	case *dns.MF:
		x.Mf = dns.CanonicalName(x.Mf)
	case *dns.CNAME:
		x.Target = dns.CanonicalName(x.Target)
	case *dns.SOA:
		x.Ns = dns.CanonicalName(x.Ns)
		x.Mbox = dns.CanonicalName(x.Mbox)
	case *dns.MB:
		x.Mb = dns.CanonicalName(x.Mb)
	case *dns.MG:
		x.Mg = dns.CanonicalName(x.Mg)
	case *dns.MR:
		x.Mr = dns.CanonicalName(x.Mr)
	case *dns.PTR:
		x.Ptr = dns.CanonicalName(x.Ptr)
	case *dns.MINFO:
		x.Rmail = dns.CanonicalName(x.Rmail)
		x.Email = dns.CanonicalName(x.Email)
	case *dns.MX:
		x.Mx = dns.CanonicalName(x.Mx)
	case *dns.RP:
		x.Mbox = dns.CanonicalName(x.Mbox)
		x.Txt = dns.CanonicalName(x.Txt)
	case *dns.AFSDB:
		x.Hostname = dns.CanonicalName(x.Hostname)
	case *dns.RT:
		x.Host = dns.CanonicalName(x.Host)
	case *dns.SIG:
		x.SignerName = dns.CanonicalName(x.SignerName)
	case *dns.PX:
		x.Map822 = dns.CanonicalName(x.Map822)
		x.Mapx400 = dns.CanonicalName(x.Mapx400)
	case *dns.NXT:
		x.NextDomain = dns.CanonicalName(x.NextDomain)
	case *dns.NAPTR:
		x.Replacement = dns.CanonicalName(x.Replacement)
	case *dns.KX:
		x.Exchanger = dns.CanonicalName(x.Exchanger)
	case *dns.SRV:
		x.Target = dns.CanonicalName(x.Target)
	case *dns.DNAME:
		x.Target = dns.CanonicalName(x.Target)
	case *dns.RRSIG:
		x.SignerName = dns.CanonicalName(x.SignerName)
	}
	// A6 is in RFC 4034's list and has no type in this library, having been
	// moved to Historic by RFC 6563. A zone serving one cannot be validated
	// here, which surfaces as a packing failure rather than as a silent pass.
}

// packCanonical serialises a record with no compression, which is §6.2 (1).
//
// The two-step length probe is deliberate: dns.Len reports the packed size,
// and PackRR reports how much it actually wrote. Slicing to the second value
// rather than trusting the first means a library whose estimate is generous
// cannot leave uninitialised trailing bytes inside signed data.
func packCanonical(rr dns.RR) ([]byte, error) {
	buf := make([]byte, dns.Len(rr)+1)
	n, err := dns.PackRR(rr, buf, 0, nil, false)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// rdataOf returns the RDATA portion of a packed record by re-deriving where
// the fixed header ends: owner name, then type (2), class (2), TTL (4) and
// RDLENGTH (2).
func rdataOf(wire []byte, rr dns.RR) ([]byte, error) {
	_, off, err := dns.UnpackDomainName(wire, 0)
	if err != nil {
		return nil, err
	}
	const fixedHeader = 2 + 2 + 4 + 2 // type, class, ttl, rdlength
	if off+fixedHeader > len(wire) {
		return nil, errors.New("dnssec: packed record is shorter than its header")
	}
	return wire[off+fixedHeader:], nil
}
