package dnssec

import (
	"context"
	"errors"
	"time"

	"github.com/miekg/dns"
)

// Response is what a Source returns for one question.
//
// The authority section is not decoration. Authenticated denial of existence
// — the proof that a name or a type does not exist — is carried there and
// nowhere else, so a Source that returned only answers could never support
// anything but positive validation. That was the shape of the earlier
// interface, and it is why Insecure was unreachable.
type Response struct {
	// Rcode is the response code. NXDOMAIN and NOERROR are the two that
	// carry different denial obligations, and a validator must not take
	// either on trust: the rcode says what the server claims, and the
	// authority section is where it has to prove it.
	Rcode int

	// Answer holds the records that answer the question, with their RRSIGs.
	Answer []dns.RR

	// Authority holds the records that justify the absence of an answer —
	// NSEC, NSEC3, SOA, and the NS RRset of a delegation — with their
	// RRSIGs.
	Authority []dns.RR
}

// Source supplies the records a chain walk needs.
//
// It is the seam between validation and retrieval, and it exists so that the
// engine can validate a complete, deterministic hierarchy offline while the
// same validation code later runs against a real resolver. Nothing above this
// interface knows or cares where records came from.
//
// Returning an empty Response and no error means "I have nothing for this
// question" — which, crucially, is not a proof that nothing exists. A proof
// is a signed denial record in the authority section, and the difference
// between the two is the difference between Insecure and Indeterminate.
type Source interface {
	Lookup(ctx context.Context, name string, rrtype uint16) (Response, error)
}

// Limits bound the work one validation may do.
//
// Every input to a validator arrives from the network, so every loop over it
// is a loop an adversary chooses the length of. These bounds exist so that
// hostile input produces a refusal with a reason rather than a validator that
// stops answering. Hitting one is never a verdict: it produces Indeterminate
// with ReasonResourceLimit, because "I stopped early" is not evidence about
// the data.
type Limits struct {
	// MaxZones bounds chain depth. A DNS name has at most 127 labels, so
	// this is an operational bound rather than a protocol one.
	MaxZones int
	// MaxLookups bounds calls to the Source across one validation.
	MaxLookups int
	// MaxSignatures bounds RRSIGs considered for a single RRset. Each one
	// costs a canonicalisation and possibly a public-key operation.
	MaxSignatures int
	// MaxKeys bounds DNSKEYs considered in one zone's apex RRset.
	MaxKeys int
}

// DefaultLimits are generous enough that no correctly operated zone meets
// them and small enough that meeting one is cheap.
func DefaultLimits() Limits {
	return Limits{MaxZones: 24, MaxLookups: 64, MaxSignatures: 16, MaxKeys: 16}
}

// Config is everything a Validator needs besides its Source.
type Config struct {
	Anchors  TrustAnchors
	Policy   Policy
	Clock    Clock
	Verifier SignatureVerifier
	Limits   Limits
}

// Validator walks chains of trust and reports what it found.
//
// A Validator is immutable after construction and safe for concurrent use, so
// long as its Source is. It holds no cache: v0.1 deliberately has no cache,
// because a cache is a second place for a verdict to live and the first
// version of this engine should have exactly one.
type Validator struct {
	src Source
	cfg Config
}

// New returns a Validator. Zero-valued Config fields are filled with the
// defaults that fail safe: the standard verifier, the system clock, the
// default policy and the default limits. Anchors are not defaulted — a
// validator with no anchors returns Indeterminate, which is correct, and
// inventing one would be the single worst thing this package could do.
func New(src Source, cfg Config) *Validator {
	if cfg.Clock == nil {
		cfg.Clock = SystemClock{}
	}
	if cfg.Verifier == nil {
		cfg.Verifier = StdVerifier()
	}
	// Only an unconfigured policy takes the defaults. An explicitly empty
	// one means "permit nothing" and is honoured — see Policy.Configured.
	if !cfg.Policy.Configured() {
		cfg.Policy = DefaultPolicy()
	}
	if cfg.Limits.MaxZones == 0 {
		cfg.Limits = DefaultLimits()
	}
	return &Validator{src: src, cfg: cfg}
}

// walk carries the state of one validation. It exists so the step recorder,
// the lookup budget and the context travel together rather than being
// threaded through every function as three more parameters.
type walk struct {
	v       *Validator
	ctx     context.Context
	rec     *recorder
	now     time.Time
	lookups int
}

// Validate walks the chain of trust for one RRset and returns the verdict
// with its full trace.
//
// The result's Status is the only thing a caller should act on, and
// Indeterminate is a real answer meaning "this validator could not tell" —
// not a soft yes and not a soft no.
func (v *Validator) Validate(ctx context.Context, name string, rrtype uint16) ValidationResult {
	qname := dns.CanonicalName(name)
	now := v.cfg.Clock.Now()
	w := &walk{v: v, ctx: ctx, rec: newRecorder(qname, rrtype, now), now: now}

	anchorName, anchors := v.cfg.Anchors.deepestFor(qname)
	if len(anchors) == 0 {
		return w.rec.indeterminate(w.rec.skip(
			ValidationStep{Kind: StepTrustAnchor, Zone: qname},
			ReasonNoTrustAnchor,
		))
	}

	// The anchor zone is established first: its apex DNSKEY RRset has to be
	// authenticated by a configured anchor before anything it signs means
	// anything.
	zone, res, ok := w.establishAnchorZone(anchorName, anchors)
	if !ok {
		return res
	}

	// Then descend one delegation at a time.
	candidates, truncated := zoneCandidates(anchorName, qname, rrtype, v.cfg.Limits.MaxZones)
	if truncated {
		// The chain is deeper than the depth budget allows. Continuing with
		// the names that fit would validate the answer against whichever
		// zone the walk happened to stop in, which is not the zone that
		// contains it — and the resulting failure would be reported as
		// Bogus, turning "this validator gave up early" into an accusation
		// against the data. Stopping here says the true thing instead.
		return w.rec.indeterminate(w.rec.fail(
			ValidationStep{Kind: StepLimit, Zone: anchorName, Name: qname, RRType: rrtype,
				Note: "the chain is deeper than the configured zone limit"},
			ReasonResourceLimit,
		))
	}
	for _, child := range candidates {
		next, res, done := w.descend(zone, child)
		if done {
			return res
		}
		if next != nil {
			zone = next
		}
	}

	return w.validateAnswer(zone, qname, rrtype)
}

// establishAnchorZone authenticates a zone's apex DNSKEY RRset against
// configured trust anchors.
func (w *walk) establishAnchorZone(zoneName string, anchors []TrustAnchor) (*zoneState, ValidationResult, bool) {
	resp, reason := w.lookup(zoneName, dns.TypeDNSKEY)
	if reason != ReasonNone {
		return nil, w.rec.indeterminate(w.rec.fail(
			ValidationStep{Kind: StepDNSKEY, Zone: zoneName}, reason,
		)), false
	}
	records := resp.Answer

	keys := dnskeysOf(records)
	if len(keys) == 0 {
		// No apex DNSKEY where an anchor says there should be one. The
		// anchor is a standing claim that this zone is signed, so failing to
		// find a key is a broken chain rather than an absence of one:
		// Bogus, not Indeterminate.
		return nil, w.rec.verdict(w.rec.fail(
			ValidationStep{Kind: StepDNSKEY, Zone: zoneName}, ReasonMissingDNSKEY,
		)), false
	}
	if len(keys) > w.v.cfg.Limits.MaxKeys {
		return nil, w.rec.indeterminate(w.rec.fail(
			ValidationStep{Kind: StepDNSKEY, Zone: zoneName}, ReasonResourceLimit,
		)), false
	}

	// Which keys does an anchor vouch for?
	var trusted []*dns.DNSKEY
	worst := ReasonTrustAnchorMismatch
	for _, k := range keys {
		if reason := keyUsable(k); reason != ReasonNone {
			w.rec.fail(keyStep(StepDNSKEY, zoneName, k), reason)
			continue
		}
		for _, a := range anchors {
			reason := a.matchesKey(w.v.cfg.Policy, k)
			if reason == ReasonNone {
				step := keyStep(StepTrustAnchor, zoneName, k)
				step.DigestType = uint8(a.DigestType)
				w.rec.ok(step)
				trusted = append(trusted, k)
				break
			}
			// Same reasoning as for DS records below: a configured anchor
			// set is a set, and combining by rank rather than by position
			// keeps the reported reason — and therefore the verdict —
			// independent of the order anchors happen to be listed in.
			worst = worseReason(worst, reason)
		}
	}
	if len(trusted) == 0 {
		return nil, w.rec.verdict(w.rec.fail(
			ValidationStep{Kind: StepTrustAnchor, Zone: zoneName}, worst,
		)), false
	}

	return w.authenticateDNSKEYRRset(zoneName, records, keys, trusted)
}

// authenticateDNSKEYRRset checks that the apex DNSKEY RRset is signed by one
// of the keys already vouched for, which is what turns a set of observed keys
// into a set of trusted ones.
//
// RFC 4035 §5.2 requires exactly this and no less: a DS (or anchor)
// authenticates one key, and that key's signature over the apex DNSKEY RRset
// is what extends trust to the rest of the set. Skipping the signature step
// and trusting every key in a set because one of them matched a DS is the
// mistake that lets an attacker append their own key to a legitimate zone's
// DNSKEY RRset and sign whatever they like with it.
func (w *walk) authenticateDNSKEYRRset(zoneName string, records []dns.RR, all, trusted []*dns.DNSKEY) (*zoneState, ValidationResult, bool) {
	keyRRs := make([]dns.RR, 0, len(all))
	for _, k := range all {
		keyRRs = append(keyRRs, k)
	}
	set, reason := NewRRset(keyRRs)
	if reason != ReasonNone {
		return nil, w.rec.verdict(w.rec.fail(
			ValidationStep{Kind: StepRRset, Zone: zoneName, RRType: dns.TypeDNSKEY}, reason,
		)), false
	}

	_, sigs := SplitSignatures(records, dns.TypeDNSKEY)
	if reason := w.authenticate(set, sigs, zoneName, trusted); reason != ReasonNone {
		return nil, w.rec.verdict(reason), false
	}

	w.rec.ok(ValidationStep{Kind: StepRRset, Zone: zoneName, RRType: dns.TypeDNSKEY})
	return &zoneState{name: zoneName, keys: all}, ValidationResult{}, true
}

// descend crosses one delegation, from the established zone to child.
//
// It returns the new zone when a secure delegation was crossed, a terminal
// result when the walk must stop, and done=true in that case.
func (w *walk) descend(zone *zoneState, child string) (*zoneState, ValidationResult, bool) {
	resp, reason := w.lookup(child, dns.TypeDS)
	if reason != ReasonNone {
		return nil, w.rec.indeterminate(w.rec.fail(
			ValidationStep{Kind: StepDS, Zone: child}, reason,
		)), true
	}
	records := resp.Answer

	dsRecords := dsOf(records)
	if len(dsRecords) == 0 {
		// No DS was returned, and two different situations produce that:
		//
		//   - child is not a zone cut at all, which is true of nearly every
		//     name a query is ever asked about;
		//   - child is a zone cut with no DS — an insecure delegation — and
		//     everything below it is legitimately unsigned.
		//
		// Telling them apart needs a signed proof that no DS exists, which
		// is NSEC or NSEC3, and v0.1 implements neither. So the walk assumes
		// the first reading and continues in the same zone, recording where
		// it did so.
		//
		// That assumption is deliberately biased. If it is wrong — if this
		// really was an insecure delegation — the data below it is unsigned,
		// the walk finds no signature from a zone it trusts, and the answer
		// is reported Bogus where a complete validator would report Insecure.
		// That is a false Bogus: it refuses data that was genuinely fine.
		//
		// The bias cannot run the other way. Concluding Secure would require
		// a signature over the answer made by a key in an apex DNSKEY RRset
		// this walk has already authenticated, and no attacker below an
		// insecure delegation has that key. So the cost of the assumption is
		// paid in refusals, never in false Secures, which is the direction
		// this engine is willing to be wrong in.
		//
		// The earlier design carried this ambiguity to the end of the walk
		// and downgraded any final failure to Indeterminate. That was worse
		// in exactly the way that matters: because almost no answer name is
		// a zone cut, it turned every genuinely tampered answer into "cannot
		// tell", and an enforcing resolver reading Indeterminate as "allow"
		// would have accepted forged data.
		w.rec.skip(ValidationStep{
			Kind: StepDS, Zone: child,
			Note: "no DS; treated as not a zone cut, which v0.1 cannot prove without NSEC or NSEC3",
		}, ReasonDenialNotImplemented)
		return nil, ValidationResult{}, false
	}

	// A DS RRset exists, so it is data in the parent zone and must itself be
	// authenticated by the parent's keys before it can authenticate anything.
	set, reason := NewRRset(toRRs(dsRecords))
	if reason != ReasonNone {
		return nil, w.rec.verdict(w.rec.fail(
			ValidationStep{Kind: StepRRset, Zone: zone.name, Name: child, RRType: dns.TypeDS}, reason,
		)), true
	}
	_, sigs := SplitSignatures(records, dns.TypeDS)
	if reason := w.authenticate(set, sigs, zone.name, zone.keys); reason != ReasonNone {
		return nil, w.rec.verdict(reason), true
	}
	w.rec.ok(ValidationStep{Kind: StepRRset, Zone: zone.name, Name: child, RRType: dns.TypeDS})

	return w.crossDelegation(child, dsRecords)
}

// crossDelegation authenticates the child zone's apex DNSKEY RRset against an
// authenticated DS RRset.
func (w *walk) crossDelegation(child string, dsRecords []*dns.DS) (*zoneState, ValidationResult, bool) {
	resp, reason := w.lookup(child, dns.TypeDNSKEY)
	if reason != ReasonNone {
		return nil, w.rec.indeterminate(w.rec.fail(
			ValidationStep{Kind: StepDNSKEY, Zone: child}, reason,
		)), true
	}
	records := resp.Answer

	keys := dnskeysOf(records)
	if len(keys) == 0 {
		// A DS is the parent's signed statement that this zone is signed, so
		// an absent DNSKEY here is a broken chain and not an unsigned zone.
		return nil, w.rec.verdict(w.rec.fail(
			ValidationStep{Kind: StepDNSKEY, Zone: child}, ReasonMissingDNSKEY,
		)), true
	}
	if len(keys) > w.v.cfg.Limits.MaxKeys {
		return nil, w.rec.indeterminate(w.rec.fail(
			ValidationStep{Kind: StepDNSKEY, Zone: child}, ReasonResourceLimit,
		)), true
	}

	// RFC 6840 §5.2 (R-DS-04) fixes the shape of what follows: DS records
	// with a digest type this validator cannot use are filtered out *before*
	// anything is concluded from the RRset, and only "if none are left" is
	// the zone treated as unsigned.
	//
	//	DS records using unknown or unsupported message digest algorithms
	//	MUST be treated the same way as DS records referring to DNSKEY RRs of
	//	unknown or unsupported public key algorithms. ... If none are left,
	//	the zone is treated as if it were unsigned.
	//
	// Filtering first is what makes the outcome a property of the set rather
	// than of the order it arrived in. Evaluating the RRset as one list and
	// keeping the last failure seen — which is what this did before review —
	// lets a DS with an unusable digest displace a definitive digest
	// mismatch from a usable one, turning Bogus into Indeterminate. A DS
	// RRset is unordered and reaches us over the network, so that handed an
	// attacker both the ordering and the verdict.
	usable, unusableReason := w.usableDS(child, dsRecords)
	if len(usable) == 0 {
		// Nothing evaluable is left. A complete validator reports Insecure
		// here; v0.1 has no denial proofs, so it reports Indeterminate with
		// the specific reason. unusableReason is derived from the whole set,
		// not from whichever record came last.
		if unusableReason == ReasonNone {
			unusableReason = ReasonMissingDS
		}
		return nil, w.rec.verdict(w.rec.fail(
			ValidationStep{Kind: StepDS, Zone: child}, unusableReason,
		)), true
	}

	var trusted []*dns.DNSKEY
	worst := ReasonNoDSMatchedKey
	for _, k := range keys {
		if reason := keyUsable(k); reason != ReasonNone {
			w.rec.fail(keyStep(StepDNSKEY, child, k), reason)
			continue
		}
		for _, ds := range usable {
			reason := dsMatchesKey(w.v.cfg.Policy, ds, k)
			if reason == ReasonNone {
				step := keyStep(StepDS, child, k)
				step.DigestType = ds.DigestType
				w.rec.ok(step)
				trusted = append(trusted, k)
				break
			}
			// A digest mismatch is more informative than "no DS referred to
			// this key": the first says the parent published a digest for
			// this exact key and it did not match, the second says the
			// parent never mentioned it. worseReason picks by rank rather
			// than by position, so which of the two is reported does not
			// depend on the order the records were iterated in.
			worst = worseReason(worst, reason)
		}
	}
	if len(trusted) == 0 {
		return nil, w.rec.verdict(w.rec.fail(
			ValidationStep{Kind: StepDS, Zone: child}, worst,
		)), true
	}

	zone, res, ok := w.authenticateDNSKEYRRset(child, records, keys, trusted)
	if !ok {
		return nil, res, true
	}
	return zone, ValidationResult{}, false
}

// usableDS partitions a DS RRset into the records this validator may act on
// and a single reason describing why the rest were set aside.
//
// The reason is combined with worseReason, so it is determined by the set of
// unusable records rather than by their order.
func (w *walk) usableDS(child string, dsRecords []*dns.DS) ([]*dns.DS, Reason) {
	usable := make([]*dns.DS, 0, len(dsRecords))
	unusable := ReasonNone

	for _, ds := range dsRecords {
		reason := w.v.cfg.Policy.CheckDigest(DigestType(ds.DigestType))
		if reason == ReasonNone {
			usable = append(usable, ds)
			continue
		}
		step := ValidationStep{
			Kind: StepDS, Zone: child,
			DigestType: ds.DigestType, Algorithm: ds.Algorithm, KeyTag: ds.KeyTag,
			Note: "digest type set aside per RFC 6840 §5.2 before evaluating the RRset",
		}
		w.rec.skip(step, reason)
		unusable = worseReason(unusable, reason)
	}
	return usable, unusable
}

// validateAnswer authenticates the RRset the caller actually asked about.
func (w *walk) validateAnswer(zone *zoneState, qname string, rrtype uint16) ValidationResult {
	resp, reason := w.lookup(qname, rrtype)
	if reason != ReasonNone {
		return w.rec.indeterminate(w.rec.fail(
			ValidationStep{Kind: StepRRset, Zone: zone.name, Name: qname, RRType: rrtype}, reason,
		))
	}

	data, sigs := SplitSignatures(resp.Answer, rrtype)
	if len(data) == 0 {
		// Nothing to validate. Establishing whether that absence is
		// legitimate is a denial-of-existence question, which v0.1 does not
		// answer, so it says so rather than guessing NXDOMAIN or NODATA.
		return w.rec.indeterminate(w.rec.skip(
			ValidationStep{Kind: StepRRset, Zone: zone.name, Name: qname, RRType: rrtype},
			ReasonDenialNotImplemented,
		))
	}

	set, reason := NewRRset(data)
	if reason != ReasonNone {
		return w.rec.verdict(w.rec.fail(
			ValidationStep{Kind: StepRRset, Zone: zone.name, Name: qname, RRType: rrtype}, reason,
		))
	}

	if reason := w.authenticate(set, sigs, zone.name, zone.keys); reason != ReasonNone {
		// Bogus is an accusation, and RFC 4033 §5 licenses it only where
		// there is "a trust anchor and a secure delegation indicating that
		// subsidiary data is signed". Reaching this line means both hold:
		// the walk started at a configured anchor and every delegation it
		// crossed was authenticated by a DS, so this zone's apex DNSKEY
		// RRset is trusted and its data is supposed to be signed by it.
		//
		// verdict still declines to say Bogus for reasons that describe this
		// validator rather than the data — an unsupported algorithm, a
		// digest policy refuses, a limit reached.
		return w.rec.verdict(reason)
	}

	w.rec.ok(ValidationStep{Kind: StepRRset, Zone: zone.name, Name: qname, RRType: rrtype})
	return w.rec.secure()
}

// zoneState is a zone whose apex DNSKEY RRset has been authenticated.
type zoneState struct {
	name string
	keys []*dns.DNSKEY
}

// lookup calls the Source, enforcing the lookup budget and the caller's
// context.
func (w *walk) lookup(name string, rrtype uint16) (Response, Reason) {
	if err := w.ctx.Err(); err != nil {
		return Response{}, ReasonCancelled
	}
	if w.lookups >= w.v.cfg.Limits.MaxLookups {
		return Response{}, ReasonResourceLimit
	}
	w.lookups++

	resp, err := w.v.src.Lookup(w.ctx, name, rrtype)
	if err != nil {
		// A cancelled context reaching us as an error is still a
		// cancellation, not a statement about the data.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return Response{}, ReasonCancelled
		}
		// A source that cannot answer leaves the validator unable to tell,
		// which is Indeterminate territory and never a verdict. The
		// underlying error text is deliberately not carried into a Reason:
		// reasons are typed, and an error string from a network library is
		// not a category.
		return Response{}, ReasonUnknown
	}
	return resp, ReasonNone
}

func toRRs[T dns.RR](in []T) []dns.RR {
	out := make([]dns.RR, 0, len(in))
	for _, rr := range in {
		out = append(out, rr)
	}
	return out
}

// zoneCandidates lists the names between an anchor and a query name that
// could be zone cuts, shallowest first.
//
// The DS type gets its own treatment because a DS record lives in the parent
// zone, not the zone it delegates to: validating example.test DS means
// authenticating data in test, and descending into example.test first would
// look for the DS under the very keys the DS is supposed to authenticate.
// The second return value reports that the chain was longer than maxZones.
// It is a separate value rather than a short list because a truncated list is
// indistinguishable from a complete one, and a caller that cannot tell the
// difference will quietly validate against the wrong zone.
func zoneCandidates(anchor, qname string, rrtype uint16, maxZones int) (names []string, truncated bool) {
	target := qname
	if rrtype == dns.TypeDS {
		// The parent of qname. A DS at the anchor itself has no parent to
		// descend from, which leaves the list empty and the walk validating
		// the DS in the anchor zone — which is correct.
		if idx := dns.Split(qname); len(idx) > 1 {
			target = qname[idx[1]:]
		} else {
			target = "."
		}
	}

	if !dns.IsSubDomain(anchor, target) {
		return nil, false
	}

	anchorLabels := dns.CountLabel(anchor)
	labels := dns.SplitDomainName(target)

	out := make([]string, 0, len(labels))
	for i := len(labels) - anchorLabels - 1; i >= 0; i-- {
		if len(out) >= maxZones {
			return out, true
		}
		out = append(out, dns.CanonicalName(joinLabels(labels[i:])))
	}
	return out, false
}

func joinLabels(labels []string) string {
	out := ""
	for _, l := range labels {
		out += l + "."
	}
	if out == "" {
		return "."
	}
	return out
}
