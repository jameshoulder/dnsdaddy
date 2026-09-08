package lab

import (
	"context"
	"crypto"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
)

// ZoneSpec describes one zone to build.
type ZoneSpec struct {
	// Name is the zone apex, for example "example.dnsdaddylab.".
	Name string
	// Algorithm signs this zone. Ed25519 is the default because it signs
	// deterministically, so a scenario produces byte-identical signatures on
	// every run and can be kept in a regression corpus.
	Algorithm dnssec.Algorithm
	// DigestType is used for the DS this zone's parent publishes.
	DigestType dnssec.DigestType
	// Records is the zone's unsigned data, excluding DNSKEY, DS and NSEC,
	// which are generated. Owner names must be at or below Name.
	Records []dns.RR

	// Parent names the delegating zone. Empty means the zone listed
	// immediately before this one, which keeps a simple chain simple.
	//
	// Naming it is what allows siblings — two zones delegated from the same
	// parent — and siblings are needed as soon as one delegation is secure
	// and another is not, which is the whole point of testing Insecure.
	Parent string

	// Insecure delegates this zone from its parent with NS but no DS, so the
	// parent proves that no DS exists. That authenticated absence is the
	// only honest route to RFC 4033's Insecure.
	Insecure bool

	// NoDenial suppresses this zone's denial records entirely. A signed zone
	// that publishes none cannot prove any absence, and a validator must say
	// so rather than accept the server's word for it.
	NoDenial bool

	// NSEC3 signs this zone with NSEC3 rather than NSEC.
	NSEC3 bool
	// NSEC3Salt is the salt in hexadecimal, empty for none. RFC 9276 §3.1
	// recommends an empty salt, so that is the default.
	NSEC3Salt string
	// NSEC3Iterations is the extra iteration count. RFC 9276 §3.1: "an
	// iterations count of 0 MUST be used", so that is the default, and a
	// non-zero value here is testing what a validator does with a zone that
	// ignores the recommendation.
	NSEC3Iterations uint16
	// NSEC3OptOut excludes unsigned delegations from the chain and sets the
	// Opt-Out flag on the records that span them.
	NSEC3OptOut bool
}

// Spec describes a whole hierarchy.
type Spec struct {
	// Zones are listed parent first. The first is the trust anchor's zone.
	Zones []ZoneSpec
	// Inception and Expiration bound every signature. Both are fixed values
	// rather than offsets from now, so that a stored trace stays meaningful
	// and a test can sit exactly on either boundary.
	Inception  time.Time
	Expiration time.Time
	// Seed makes key derivation reproducible. Two hierarchies built from the
	// same Spec have the same keys.
	Seed string
}

// Shifted returns the same specification with every signature validity
// window moved by d.
//
// It exists so one set of logical scenarios can be built either against fixed
// instants — which keeps traces and signatures reproducible — or around a
// wall-clock moment, which is what a reference validator with no clock
// override needs. The zones, keys and mutations are identical either way;
// only the timestamps move, so a scenario means the same thing in both.
func (s Spec) Shifted(d time.Duration) Spec {
	out := s
	out.Inception = s.Inception.Add(d)
	out.Expiration = s.Expiration.Add(d)
	return out
}

// Zone is one built and signed zone.
type Zone struct {
	Name       string
	Key        *dns.DNSKEY
	Signer     crypto.Signer
	Algorithm  dnssec.Algorithm
	DigestType dnssec.DigestType

	// DS is the delegation record the parent publishes for this zone. Nil
	// for the top zone, which is vouched for by a trust anchor instead, and
	// nil for a child delegated insecurely.
	DS *dns.DS

	// delegations names the child zones delegated from here, secure or not.
	// A referral is served for anything at or below one of them.
	delegations map[string]bool

	// useNSEC generates an NSEC chain for this zone. Off means the zone is
	// signed but publishes no denial records, which is a real and broken
	// configuration worth being able to construct.
	useNSEC bool

	// useNSEC3 and its parameters replace the NSEC chain with an NSEC3 one.
	// A zone publishes one mechanism or the other, never both.
	useNSEC3 bool
	n3alg    uint8
	n3iter   uint16
	n3salt   string
	n3optOut bool

	sets map[setKey][]dns.RR
}

// maxDNSLabels is the most labels a encodable DNS name can have: RFC 1035
// §2.3.4 caps a name at 255 octets and each label costs at least two (a
// length octet and a character), leaving 127 plus the root.
const maxDNSLabels = 127

type setKey struct {
	name   string
	rrtype uint16
}

// Hierarchy is a complete signed tree held in memory.
//
// It is both a dnssec.Source, so Daddybound can validate against it directly,
// and a set of records an authoritative DNS server can serve, so a reference
// validator can be pointed at the same data. Serving one hierarchy to both is
// the whole point: a differential comparison is only evidence if both sides
// saw the same bytes.
type Hierarchy struct {
	Zones  []*Zone
	Anchor dnssec.TrustAnchor

	byName map[string]*Zone
	sets   map[setKey][]dns.RR
	spec   Spec

	// overrides rewrite the response to specific questions, for scenarios
	// where the zone is correct and the response is not. See
	// responseOverride.
	overrides map[setKey]*responseOverride
}

// Build constructs and signs a hierarchy.
func Build(spec Spec) (*Hierarchy, error) {
	if len(spec.Zones) == 0 {
		return nil, fmt.Errorf("lab: a hierarchy needs at least one zone")
	}
	if !spec.Expiration.After(spec.Inception) {
		return nil, fmt.Errorf("lab: expiration %s is not after inception %s", spec.Expiration, spec.Inception)
	}

	h := &Hierarchy{
		byName: make(map[string]*Zone),
		sets:   make(map[setKey][]dns.RR),
		spec:   spec,
	}

	for i := range spec.Zones {
		zone, err := buildZone(spec, i)
		if err != nil {
			return nil, err
		}
		h.Zones = append(h.Zones, zone)
		h.byName[zone.Name] = zone
	}

	// The parent delegates to each child. Built after all zones exist
	// because a DS is a statement about a key created with the child.
	//
	// The NS RRset is added unsigned: delegation NS records sit on the
	// parent side of a cut and are not authoritative data there, so no
	// signer signs them. A validator that demanded a signature would reject
	// every real delegation.
	for i := 1; i < len(h.Zones); i++ {
		child := h.Zones[i]

		parentName := dns.CanonicalName(spec.Zones[i].Parent)
		if spec.Zones[i].Parent == "" {
			parentName = h.Zones[i-1].Name
		}
		parent := h.byName[parentName]
		if parent == nil {
			return nil, fmt.Errorf("lab: %s names parent %s, which is not in this hierarchy", child.Name, parentName)
		}
		// A delegation only exists between a zone and a name inside it.
		// Without this check a specification can describe a hierarchy no
		// resolver could ever walk, and the resulting failures look like
		// validator bugs.
		if parent.Name == child.Name || !dns.IsSubDomain(parent.Name, child.Name) {
			return nil, fmt.Errorf("lab: %s cannot delegate %s; it is not inside that zone", parent.Name, child.Name)
		}
		parent.delegations[child.Name] = true

		parent.sets[setKey{name: child.Name, rrtype: dns.TypeNS}] = []dns.RR{
			ns(child.Name, "ns."+MiddleZone),
		}

		if spec.Zones[i].Insecure {
			// No DS. The parent's NSEC chain shows NS set and DS clear at
			// this name, which is the authenticated proof of an insecure
			// delegation.
			continue
		}
		ds, err := makeDS(child)
		if err != nil {
			return nil, err
		}
		child.DS = ds
		if err := parent.addSigned(spec, []dns.RR{ds}); err != nil {
			return nil, err
		}
	}

	// NSEC chains last: the type bitmaps describe what is present, and a
	// bitmap computed before the DS records existed would omit them and
	// prove the opposite of the truth.
	for _, zone := range h.Zones {
		if err := zone.buildNSECChain(spec); err != nil {
			return nil, err
		}
		if err := zone.buildNSEC3Chain(spec); err != nil {
			return nil, err
		}
	}

	top := h.Zones[0]
	digest, err := hex.DecodeString(mustDS(top).Digest)
	if err != nil {
		return nil, err
	}
	h.Anchor = dnssec.TrustAnchor{
		Name:       top.Name,
		KeyTag:     top.Key.KeyTag(),
		Algorithm:  top.Algorithm,
		DigestType: top.DigestType,
		Digest:     digest,
	}

	h.reindex()
	return h, nil
}

// buildZone creates one zone's key and signs its records.
func buildZone(spec Spec, i int) (*Zone, error) {
	zs := spec.Zones[i]
	name := dns.CanonicalName(zs.Name)

	alg := zs.Algorithm
	if alg == 0 {
		alg = dnssec.AlgED25519
	}
	digest := zs.DigestType
	if digest == 0 {
		digest = dnssec.DigestSHA256
	}

	signer, err := deriveKey(alg, spec.Seed+"|"+name)
	if err != nil {
		return nil, err
	}

	key := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name: name, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600,
		},
		// Both the zone bit and the SEP bit are set because this lab signs
		// each zone with a single key. That is a legal configuration and a
		// deliberate choice: a validator that quietly assumes the KSK/ZSK
		// split — signing the DNSKEY RRset with a SEP key and everything
		// else with a non-SEP key — passes against a two-key lab and fails
		// against real single-key zones. This setup catches that assumption
		// on the first run.
		Flags:     257,
		Protocol:  3,
		Algorithm: uint8(alg),
	}
	if err := setPublicKey(key, signer); err != nil {
		return nil, err
	}

	zone := &Zone{
		Name: name, Key: key, Signer: signer,
		Algorithm: alg, DigestType: digest,
		delegations: map[string]bool{},
		useNSEC:     !zs.NoDenial && !zs.NSEC3,
		useNSEC3:    !zs.NoDenial && zs.NSEC3,
		n3alg:       dns.SHA1,
		n3iter:      zs.NSEC3Iterations,
		n3salt:      zs.NSEC3Salt,
		n3optOut:    zs.NSEC3OptOut,
		sets:        make(map[setKey][]dns.RR),
	}

	// The apex DNSKEY RRset signs itself, which is what a DS or trust anchor
	// then authenticates.
	if err := zone.addSigned(spec, []dns.RR{key}); err != nil {
		return nil, err
	}

	for _, group := range groupRRsets(zs.Records) {
		if err := zone.addSigned(spec, group); err != nil {
			return nil, err
		}
	}
	return zone, nil
}

// addSigned signs one RRset with the zone's key and stores it alongside its
// signature.
//
// Signing goes through github.com/miekg/dns rather than through Daddybound's
// own canonicalisation, deliberately. Signing with the code under test would
// make every signature verify by construction: a canonicalisation bug would
// cancel out and the tests would pass while producing signatures no other
// implementation accepts. Using an independent implementation to sign means
// Daddybound's verifier is checked against someone else's reading of
// RFC 4034 §6 on every run.
func (z *Zone) addSigned(spec Spec, rrset []dns.RR) error {
	if len(rrset) == 0 {
		return nil
	}
	h := rrset[0].Header()

	// RFC 4034 §3.1.3 gives the Labels field one octet. A DNS name cannot
	// carry more than 127 labels — RFC 1035 §2.3.4 caps a name at 255 octets
	// and every label costs at least two — so the conversion below cannot
	// overflow for any name that could be encoded at all. The bound is
	// checked rather than asserted in a comment, because this signs the
	// fixtures every other test depends on and a silently truncated Labels
	// field would produce signatures that fail for a reason pointing
	// somewhere else entirely.
	labels := dns.CountLabel(h.Name)
	if strings.HasPrefix(dns.CanonicalName(h.Name), "*.") {
		// RFC 4034 §3.1.3: the Labels field is "the number of labels in the
		// original RRSIG RR owner name ... not counting the null root label
		// and not counting any leading asterisk label".
		//
		// Without the subtraction a wildcard RRset is signed claiming one
		// label more than it has, and a validator reconstructing the signed
		// name from the Labels field (RFC 4035 §5.3.2) rebuilds the wrong
		// name and rejects the signature. The failure looks like a
		// cryptographic one, which is exactly the wrong place to go looking.
		labels--
	}
	if labels < 0 || labels > maxDNSLabels {
		return fmt.Errorf("lab: %s has %d labels, which cannot be expressed in an RRSIG Labels field", h.Name, labels)
	}

	sig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name: dns.CanonicalName(h.Name), Rrtype: dns.TypeRRSIG,
			Class: h.Class, Ttl: h.Ttl,
		},
		TypeCovered: h.Rrtype,
		Algorithm:   uint8(z.Algorithm),
		Labels:      uint8(labels),
		OrigTtl:     h.Ttl,
		// The 32-bit wrapping conversion RFC 4034 §3.1.5 specifies, shared
		// with the validator so the lab and the engine cannot disagree about
		// what a timestamp means.
		Inception:  dnssec.DNSSECTime(spec.Inception),
		Expiration: dnssec.DNSSECTime(spec.Expiration),
		KeyTag:     z.Key.KeyTag(),
		SignerName: z.Name,
	}
	if err := sig.Sign(z.Signer, rrset); err != nil {
		return fmt.Errorf("lab: signing %s %s: %w", h.Name, dns.TypeToString[h.Rrtype], err)
	}

	k := setKey{name: dns.CanonicalName(h.Name), rrtype: h.Rrtype}
	z.sets[k] = append(append([]dns.RR{}, rrset...), sig)
	return nil
}

// makeDS builds the delegation record a parent publishes for a child.
//
// The digest is computed by github.com/miekg/dns for the same reason
// signatures are: Daddybound recomputes it in dsDigest, and a lab that used
// Daddybound's own computation could not tell a correct implementation from
// a consistently wrong one.
func makeDS(child *Zone) (*dns.DS, error) {
	ds := child.Key.ToDS(uint8(child.DigestType))
	if ds == nil {
		return nil, fmt.Errorf("lab: cannot build a DS for %s with digest type %d", child.Name, child.DigestType)
	}
	ds.Hdr.Name = child.Name
	ds.Hdr.Ttl = 3600
	ds.Hdr.Class = dns.ClassINET
	return ds, nil
}

func mustDS(z *Zone) *dns.DS {
	if z.DS != nil {
		return z.DS
	}
	ds, err := makeDS(z)
	if err != nil {
		// Only reachable with a digest type the library cannot compute,
		// which Build has already rejected for every other zone.
		panic(err)
	}
	return ds
}

// groupRRsets partitions records into RRsets by owner name, class and type,
// in a deterministic order so that two builds produce the same hierarchy.
func groupRRsets(records []dns.RR) [][]dns.RR {
	index := make(map[setKey][]dns.RR)
	var order []setKey
	for _, rr := range records {
		h := rr.Header()
		k := setKey{name: dns.CanonicalName(h.Name), rrtype: h.Rrtype}
		if _, seen := index[k]; !seen {
			order = append(order, k)
		}
		index[k] = append(index[k], rr)
	}
	sort.Slice(order, func(i, j int) bool {
		if order[i].name != order[j].name {
			return order[i].name < order[j].name
		}
		return order[i].rrtype < order[j].rrtype
	})

	out := make([][]dns.RR, 0, len(order))
	for _, k := range order {
		out = append(out, index[k])
	}
	return out
}

// reindex rebuilds the flat lookup table from the zones. Called after any
// mutation so that a scenario's changes are visible to both the Source and
// the authoritative server.
func (h *Hierarchy) reindex() {
	h.sets = make(map[setKey][]dns.RR)
	for _, z := range h.Zones {
		for k, v := range z.sets {
			h.sets[k] = v
		}
	}
}

// Zone returns a zone by name, or nil.
func (h *Hierarchy) Zone(name string) *Zone { return h.byName[dns.CanonicalName(name)] }

// Lookup implements dnssec.Source.
//
// It answers from memory and never blocks, so a validation against the lab
// exercises only the validation logic. The context is honoured anyway: code
// that ignores cancellation in the easy case tends to ignore it in the hard
// one too.
//
// The answer and authority sections are built by the same routine the
// authoritative server uses, so a validator reading the hierarchy directly
// and a validator reading it over DNS see the same records — which is what
// makes a differential comparison against those two paths meaningful.
func (h *Hierarchy) Lookup(ctx context.Context, name string, rrtype uint16) (dnssec.Response, error) {
	if err := ctx.Err(); err != nil {
		return dnssec.Response{}, err
	}
	return h.respond(name, rrtype, true), nil
}

// respond assembles the answer and authority sections for one question.
//
// wantDNSSEC mirrors the DO bit: without it the signatures and denial records
// are withheld, which is what an unaware client would see.
func (h *Hierarchy) respond(name string, rrtype uint16, wantDNSSEC bool) dnssec.Response {
	qname := dns.CanonicalName(name)
	out := h.chaseAliases(qname, rrtype, wantDNSSEC)

	// Applied last, to the finished response, because that is where an
	// on-path attacker sits: after the server has decided what to send and
	// before the validator sees it.
	if o := h.overrides[setKey{name: qname, rrtype: rrtype}]; o != nil {
		if o.rcode != nil {
			out.Rcode = *o.rcode
		}
		if o.set {
			out.Authority = o.authority
		}
	}
	return out
}

// chaseAliases builds a response the way an authoritative server does, by
// following a CNAME within the zones it serves.
//
// RFC 1034 §4.3.2 step 3a: when a query for (QNAME, QTYPE) finds a CNAME, the
// server puts the CNAME in the answer section, restarts the query at the
// target, and — where it is authoritative for the target too — appends what it
// finds. A resolver receives the whole chain in one message.
//
// The lab has to do this or the oracle comparison stops being a comparison.
// delv validates a message rather than resolving a chain, so a server that
// returned only the alias would have delv authenticate one CNAME, call the
// answer fully validated and never see the tampered link two hops along. It
// would agree with nothing, and the disagreement would be about the harness.
//
// Bounded, because the zones it walks can contain a loop and this is a server
// rather than a resolver: it stops and returns what it has, which is what a
// real one does.
func (h *Hierarchy) chaseAliases(qname string, rrtype uint16, wantDNSSEC bool) dnssec.Response {
	out := h.assemble(qname, rrtype, wantDNSSEC)
	if rrtype == dns.TypeCNAME {
		return out
	}

	seen := map[string]bool{qname: true}
	for hop := 0; hop < maxServerAliasHops; hop++ {
		alias := lastCNAME(out.Answer)
		if alias == nil {
			return out
		}
		target := dns.CanonicalName(alias.Target)
		if seen[target] {
			// A loop in the zone data. The records so far are genuine and
			// the chain does not terminate; a server sends what it has.
			return out
		}
		seen[target] = true

		next := h.assemble(target, rrtype, wantDNSSEC)
		out.Rcode = next.Rcode
		out.Answer = append(out.Answer, next.Answer...)
		// Every hop's authority section is kept, not just the last.
		//
		// This was wrong the first time and the failure was instructive. A
		// wildcard-expanded CNAME carries its own justification — RFC 4035
		// §3.1.3 makes the server include the NSEC or NSEC3 proving the
		// expansion was legitimate — and that proof belongs to the hop that
		// was expanded, not to the end of the chain. Overwriting the
		// authority section on the next hop deleted it, and the validator
		// then correctly refused an answer whose wildcard nobody had
		// justified. The verdict was right; the message was not one an
		// authoritative server would have sent.
		//
		// Keeping the earlier proofs is also what a real server does: BIND
		// accumulates the DNSSEC records for each expansion it performs
		// while following the chain, and sends them alongside whatever
		// explains the end of it.
		out.Authority = appendUnseen(out.Authority, next.Authority)
		if len(next.Answer) == 0 {
			return out
		}
	}
	return out
}

// maxServerAliasHops bounds the lab server's own chase. Deliberately larger
// than the validator's default hop budget, so a scenario testing the
// validator's limit is testing the validator's limit.
const maxServerAliasHops = 24

// lastCNAME returns the final CNAME in an answer section, which is the one
// whose target has not yet been followed.
func lastCNAME(answer []dns.RR) *dns.CNAME {
	for i := len(answer) - 1; i >= 0; i-- {
		if c, ok := answer[i].(*dns.CNAME); ok {
			return c
		}
	}
	return nil
}

// assemble builds the response an honest authoritative server would send.
func (h *Hierarchy) assemble(qname string, rrtype uint16, wantDNSSEC bool) dnssec.Response {
	out := dnssec.Response{Rcode: dns.RcodeSuccess}

	zone := h.authoritativeZone(qname, rrtype)
	if zone == nil {
		out.Rcode = dns.RcodeNameError
		return out
	}

	// Below a delegation this zone does not answer for: it refers, and the
	// referral carries either the DS or the proof that none exists.
	if child := h.delegationCovering(zone, qname); child != "" && !(qname == child && rrtype == dns.TypeDS) {
		out.Authority = append(out.Authority, h.referral(zone, child, wantDNSSEC)...)
		return out
	}

	// QTYPE=* is a query type and matches no set, so it is answered by
	// gathering the sets rather than by looking one up. RFC 1034 §6.2.2 lets
	// a server return a subset; this returns everything, which is the harder
	// case for a validator — RFC 6840 §4.2 makes it check every RRset it
	// receives, so more records mean more that must verify.
	if rrtype == dns.TypeANY {
		if answer := zone.everythingAt(qname, wantDNSSEC); len(answer) > 0 {
			out.Answer = answer
			return out
		}
	} else if records := zone.sets[setKey{name: qname, rrtype: rrtype}]; len(records) > 0 {
		out.Answer = filterSignatures(records, wantDNSSEC)
		return out
	}

	// No records of the queried type at this name. RFC 1034 §3.6.2 makes a
	// CNAME the answer to a query for any other type at the same name, so a
	// server checks for one before deciding the type is absent.
	if rrtype != dns.TypeCNAME {
		if alias := zone.sets[setKey{name: qname, rrtype: dns.TypeCNAME}]; len(alias) > 0 {
			out.Answer = filterSignatures(alias, wantDNSSEC)
			return out
		}
	}

	// A DNAME at an ancestor redirects everything beneath it (RFC 6672
	// §2.2). The server answers with the signed DNAME and a CNAME it
	// synthesises for the queried name — and RFC 6672 §5.3.1 requires that
	// synthesised CNAME to be *unsigned*, which is exactly what makes this
	// worth building rather than approximating. A lab that signed it would
	// let a validator pass by treating it as an ordinary alias, and the real
	// DNS would then reject that validator on the first DNAME it met.
	if owner := zone.dnameCovering(qname); owner != "" {
		out.Answer = append(out.Answer,
			filterSignatures(zone.sets[setKey{name: owner, rrtype: dns.TypeDNAME}], wantDNSSEC)...)
		if syn := zone.synthesiseCNAME(qname, owner); syn != nil {
			out.Answer = append(out.Answer, syn)
		}
		return out
	}

	// Nothing at the name itself. Before deciding it is missing, the server
	// does what RFC 4592 requires and looks for a wildcard that covers it.
	if !zone.nameExists(qname) {
		// A wildcard CNAME answers a query for any type, exactly as a
		// non-wildcard one does, so the type tried second is CNAME.
		answer, source := zone.synthesise(qname, rrtype)
		if len(answer) == 0 && rrtype != dns.TypeCNAME {
			answer, source = zone.synthesise(qname, dns.TypeCNAME)
		}
		if len(answer) > 0 {
			out.Answer = filterSignatures(answer, wantDNSSEC)
			if wantDNSSEC {
				// The expansion has to be justified: the name the wildcard
				// stood in for must be shown not to exist, or the same
				// signed wildcard answer works for every name under the
				// encloser.
				out.Authority = append(out.Authority, zone.wildcardJustification(qname, source)...)
			}
			return out
		}
	}

	// No data of that type. Everything from here is the server explaining
	// itself, and a validator is entitled to disbelieve all of it until the
	// signatures check out.
	if !zone.nameExists(qname) {
		out.Rcode = dns.RcodeNameError
	}
	if soa := zone.sets[setKey{name: zone.Name, rrtype: dns.TypeSOA}]; len(soa) > 0 {
		out.Authority = append(out.Authority, filterSignatures(soa, wantDNSSEC)...)
	}
	if wantDNSSEC {
		out.Authority = append(out.Authority, h.denialFor(zone, qname, rrtype, out.Rcode)...)
	}
	return out
}

// authoritativeZone picks the zone that answers a question.
//
// This is the zone-cut reasoning, and it has two cases that a naive "deepest
// zone containing the name" gets wrong — both of which matter for denial:
//
//   - A DS RRset lives in the *parent*. Asking the child would ask a zone
//     that never publishes its own DS, and the answer would be a spurious
//     NODATA rather than the delegation record.
//   - A zone apex name exists in two zones at once: as the child's apex and
//     as the parent's delegation point. They publish different NSEC records
//     at that name — the parent's carries NS with DS clear or set, the
//     child's carries SOA — and RFC 6840 §4.1 exists precisely because
//     confusing the two lets an ancestor's NSEC deny things inside the
//     child.
//
// The lab therefore keeps records per zone rather than in one flat index, so
// the two NSECs at a delegation name both survive and the right one is
// served.
func (h *Hierarchy) authoritativeZone(qname string, rrtype uint16) *Zone {
	if rrtype == dns.TypeDS {
		// The parent side of the cut, if this name is a delegation point.
		for _, z := range h.Zones {
			if z.delegations[qname] {
				return z
			}
		}
	}

	var best *Zone
	for _, z := range h.Zones {
		if !dns.IsSubDomain(z.Name, qname) {
			continue
		}
		if best == nil || dns.CountLabel(z.Name) > dns.CountLabel(best.Name) {
			best = z
		}
	}
	return best
}

// nameExists reports whether name is a name in this zone.
//
// A name exists if it owns records, and also if anything below it does: that
// second case is an empty non-terminal (RFC 5155 §1.3, "a domain name that
// owns no resource records, but has one or more subdomains that do"). An
// authoritative server answers NOERROR/NODATA at such a name, not NXDOMAIN,
// and a lab that got this wrong would be teaching a validator to accept a
// name error for a name that exists.
func (z *Zone) nameExists(name string) bool {
	name = dns.CanonicalName(name)
	for k := range z.sets {
		if k.name == name {
			return true
		}
		if k.name != name && dns.IsSubDomain(name, k.name) {
			return true
		}
	}
	return false
}

// Records returns every record in the hierarchy, for an authoritative server
// to serve. Sorted, so the server's behaviour does not depend on map order.
func (h *Hierarchy) Records() []dns.RR {
	keys := make([]setKey, 0, len(h.sets))
	for k := range h.sets {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].name != keys[j].name {
			return keys[i].name < keys[j].name
		}
		return keys[i].rrtype < keys[j].rrtype
	})

	var out []dns.RR
	for _, k := range keys {
		out = append(out, h.sets[k]...)
	}
	return out
}

// setPublicKey fills a DNSKEY's public key field from a signer.
//
// The DNSKEY wire formats are RFC 3110 for RSA, RFC 6605 for ECDSA and
// RFC 8080 for Ed25519. This is the encoding side of what dnssec.verify.go
// decodes, and the two are written from the same RFCs rather than from each
// other — a round trip that only agreed with itself would prove nothing.
func setPublicKey(key *dns.DNSKEY, signer crypto.Signer) error {
	priv, ok := signer.(interface{ Public() crypto.PublicKey })
	if !ok {
		return fmt.Errorf("lab: signer for %s exposes no public key", key.Hdr.Name)
	}
	encoded, err := encodePublicKey(priv.Public())
	if err != nil {
		return fmt.Errorf("lab: %s: %w", key.Hdr.Name, err)
	}
	key.PublicKey = encoded
	return nil
}

// Description renders the hierarchy for a human, one zone per line. Used by
// the CLI and by test failure output.
func (h *Hierarchy) Description() string {
	var b strings.Builder
	for i, z := range h.Zones {
		fmt.Fprintf(&b, "%s%s  alg=%s keytag=%d", strings.Repeat("  ", i), z.Name, z.Algorithm.Name(), z.Key.KeyTag())
		if z.DS != nil {
			fmt.Fprintf(&b, " ds=%s", z.DigestType.Name())
		} else {
			fmt.Fprintf(&b, " (trust anchor)")
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// appendUnseen appends records not already present, compared on their full
// text.
//
// Two hops of one chain routinely need the same record — the zone's apex SOA
// most obviously — and sending it twice would be a message no server
// produces. The comparison is on the rendered record rather than on the owner
// name and type, because two different NSECs can share both.
func appendUnseen(dst, src []dns.RR) []dns.RR {
	seen := make(map[string]bool, len(dst))
	for _, rr := range dst {
		seen[rr.String()] = true
	}
	for _, rr := range src {
		if k := rr.String(); !seen[k] {
			seen[k] = true
			dst = append(dst, rr)
		}
	}
	return dst
}

// everythingAt returns every RRset the zone holds at one name, for a QTYPE=*
// query.
//
// Ordered by type so that the message is a function of the zone rather than
// of Go's map iteration. That is not cosmetic here: the differential suite
// compares two validators on the same response, and a response that differs
// between runs turns a disagreement into a coin toss.
func (z *Zone) everythingAt(name string, wantDNSSEC bool) []dns.RR {
	name = dns.CanonicalName(name)
	types := make([]uint16, 0, 8)
	for k := range z.sets {
		if k.name == name && k.rrtype != dns.TypeRRSIG {
			types = append(types, k.rrtype)
		}
	}
	sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })

	var out []dns.RR
	for _, rrtype := range types {
		out = append(out, filterSignatures(z.sets[setKey{name: name, rrtype: rrtype}], wantDNSSEC)...)
	}
	return out
}

// dnameCovering returns the owner of the DNAME that redirects qname, or "".
//
// The deepest one wins, matching RFC 1034 §4.3.2's label-by-label descent,
// and the owner itself is never redirected (RFC 6672 §2.3).
func (z *Zone) dnameCovering(qname string) string {
	qname = dns.CanonicalName(qname)
	best, bestLabels := "", -1
	for k := range z.sets {
		if k.rrtype != dns.TypeDNAME || k.name == qname {
			continue
		}
		if !dns.IsSubDomain(k.name, qname) {
			continue
		}
		if n := dns.CountLabel(k.name); n > bestLabels {
			best, bestLabels = k.name, n
		}
	}
	return best
}

// synthesiseCNAME builds the unsigned CNAME a server puts in a DNAME
// response, per RFC 6672 §3.1.
//
// Unsigned deliberately, and its TTL taken from the DNAME. A validator must
// derive the redirection from the DNAME rather than from this record; the lab
// sends it because a real server does, so that a validator which reads it
// instead is caught here rather than in production.
func (z *Zone) synthesiseCNAME(qname, owner string) dns.RR {
	qname = dns.CanonicalName(qname)
	records := z.sets[setKey{name: owner, rrtype: dns.TypeDNAME}]
	for _, rr := range records {
		d, ok := rr.(*dns.DNAME)
		if !ok {
			continue
		}
		prefix := qname[:len(qname)-len(owner)]
		return &dns.CNAME{
			Hdr:    dns.RR_Header{Name: qname, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: d.Hdr.Ttl},
			Target: prefix + dns.CanonicalName(d.Target),
		}
	}
	return nil
}
