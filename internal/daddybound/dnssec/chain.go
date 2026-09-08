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

	// MaxNSEC3Iterations is the highest NSEC3 iteration count this
	// validator will compute. A record above it is set aside with
	// ReasonResourceLimit, which is Indeterminate — never Insecure.
	//
	// RFC 9276 §3.1 tells zones to publish 0, and §3.2 offers validators two
	// permissions for anything larger: report insecure, or refuse. Taking
	// the first would let an attacker downgrade a signed zone by publishing
	// an expensive NSEC3, and RFC 9276 §3.2 says so itself — "treating a
	// high iterations count as insecure leaves zones subject to attack" — so
	// this validator takes the second.
	MaxNSEC3Iterations int

	// MaxAliasHops bounds how many CNAMEs one resolution may follow.
	//
	// A chain arrives from the network and each hop costs a full walk from
	// the trust anchor. RFC 1034 sets no limit and real resolvers pick one;
	// this is generous next to any legitimate chain and small enough that
	// reaching it is cheap. Reaching it is Indeterminate, never Bogus: a
	// deeply aliased zone is unusual, not forged.
	MaxAliasHops int

	// MaxAnyRRsets bounds how many distinct types one QTYPE=* answer may
	// carry. RFC 6840 §4.2 requires every one of them to be validated, so
	// the number of public-key operations an ANY query costs is chosen by
	// whoever sends the response.
	MaxAnyRRsets int

	// MaxDenialRecords bounds how many denial RRsets one response may have
	// authenticated.
	//
	// Each one costs a canonicalisation and, usually, a public-key
	// operation, and the number of them is chosen by whoever sent the
	// response. A correct proof needs at most a handful — RFC 4035 §5.4 and
	// RFC 5155 §7.2 both describe proofs of three or four records — so a
	// response carrying hundreds is not a proof, it is a bill.
	//
	// Stopping early is recorded rather than hidden: a proof that then fails
	// is reported as a limit rather than as a fault in the data, because a
	// validator that stopped reading has no business accusing anyone.
	MaxDenialRecords int

	// MaxNSEC3Hashes bounds the total hash computations one validation may
	// perform.
	//
	// Separate from the iteration ceiling because the cost is the product of
	// two attacker-chosen numbers. Bounding iterations alone leaves them free
	// to send many records; bounding records alone leaves them free to make
	// each one expensive.
	MaxNSEC3Hashes int
}

// DefaultLimits are generous enough that no correctly operated zone meets
// them and small enough that meeting one is cheap.
func DefaultLimits() Limits {
	return Limits{
		MaxZones: 24, MaxLookups: 64, MaxSignatures: 16, MaxKeys: 16,
		// 100 is not a round number chosen for looking sensible. RFC 9276
		// Appendix A reports it as the measured point at which an upper
		// limit "is interoperable without significant problems", and the
		// same appendix notes that even this "still enables CPU-exhausting
		// DoS attacks" — which is why the total-hash budget exists as well.
		MaxNSEC3Iterations: 100,
		MaxAliasHops:       12,
		// More distinct types at one name than any real name carries, and
		// far fewer than the 65535 an answer section could name.
		MaxAnyRRsets: 32,
		// Eight times what the largest correct proof in this suite needs,
		// and small enough that reaching it is free.
		MaxDenialRecords: 32,
		// Enough for a deep name's full closest-encloser walk at the
		// iteration ceiling, and nowhere near enough to be a lever: at 100
		// iterations this is a few thousand SHA-1 computations, bounded per
		// validation rather than per record.
		MaxNSEC3Hashes: 4096,
	}
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
	// The NSEC3 bounds were added after the others, so a caller with a
	// hand-built Limits from before them would otherwise get zero — which
	// would refuse every NSEC3 record in existence, including the iteration
	// count of 0 that RFC 9276 tells zones to publish. A zero here means
	// "not set", not "permit nothing"; the policy layer is where an explicit
	// deny-all belongs, and it says so with its own flag.
	if cfg.Limits.MaxNSEC3Iterations == 0 {
		cfg.Limits.MaxNSEC3Iterations = DefaultLimits().MaxNSEC3Iterations
	}
	if cfg.Limits.MaxNSEC3Hashes == 0 {
		cfg.Limits.MaxNSEC3Hashes = DefaultLimits().MaxNSEC3Hashes
	}
	if cfg.Limits.MaxDenialRecords == 0 {
		cfg.Limits.MaxDenialRecords = DefaultLimits().MaxDenialRecords
	}
	if cfg.Limits.MaxAliasHops == 0 {
		cfg.Limits.MaxAliasHops = DefaultLimits().MaxAliasHops
	}
	if cfg.Limits.MaxAnyRRsets == 0 {
		cfg.Limits.MaxAnyRRsets = DefaultLimits().MaxAnyRRsets
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
	return w.chase(qname, rrtype)
}

// chase resolves a name, following CNAMEs, and combines what it finds.
//
// The loop is bounded three ways, because every one of its inputs comes from
// the network. Hops are capped; a name seen twice is a loop and stops; and the
// lookup budget is shared with everything else this walk does rather than
// reset per hop, so a chain cannot buy itself more work by being long.
//
// The verdict is the weakest of the hops — see weakest, which explains why
// that ordering and not another. It is accumulated as the loop goes rather
// than at the end, so a chain that later hits a limit still carries the
// verdict of the links it did check.
func (w *walk) chase(qname string, rrtype uint16) ValidationResult {
	visited := map[string]bool{}
	status := StatusSecure
	reason := ReasonVerified

	for hop := 0; ; hop++ {
		if hop >= w.v.cfg.Limits.MaxAliasHops {
			// Not a verdict about the data: this validator stopped walking.
			// Reporting Bogus would accuse a zone of forgery for being
			// deeply aliased, which plenty of real ones are.
			return w.rec.indeterminate(w.rec.fail(
				ValidationStep{Kind: StepLimit, Name: qname, RRType: rrtype,
					Note: "the alias chain is longer than the configured hop limit"},
				ReasonResourceLimit,
			))
		}
		if visited[qname] {
			// The zone signed a chain that returns to a name it already
			// passed through. Every record in it may be authentic; it simply
			// does not resolve, which is a statement about the data's shape
			// rather than about its authenticity, so it is not Bogus.
			return w.rec.indeterminate(w.rec.fail(
				ValidationStep{Kind: StepRRset, Name: qname, RRType: dns.TypeCNAME,
					Note: "the alias chain returns to a name it has already visited"},
				ReasonAliasLoop,
			))
		}
		visited[qname] = true

		outcome := w.resolveOnce(qname, rrtype)
		// Status and reason move together, and only when this hop is
		// strictly weaker than what the chain has so far.
		//
		// Updating them separately was wrong in a way that would have shown
		// up as an operator chasing the wrong hop: a chain whose first link
		// was Indeterminate and whose second was Insecure came out
		// Indeterminate — correct — carrying the *Insecure* link's reason,
		// because the second assignment was conditioned on "not Secure"
		// rather than on having decided anything. The verdict and the
		// sentence explaining it have to come from the same link.
		//
		// Equal ranks leave both alone, so the earliest hop at the deciding
		// rank is the one reported. That is a function of the chain's own
		// order rather than of anything a server controls: the order is
		// CNAME target following CNAME target, and a server that reorders
		// its answer section does not change it.
		if next := weakest(status, outcome.result.Status); next != status {
			status, reason = next, outcome.result.Reason
		}

		if outcome.followTo == "" {
			// The end of the chain, for good or ill. The accumulated status
			// is what the whole answer is worth.
			return w.rec.result(status, reason)
		}
		if status == StatusBogus {
			// A link failed to authenticate. Following the target would only
			// add steps to a trace whose conclusion is already fixed, and
			// would spend lookups on a chain nobody should act on.
			return w.rec.result(status, reason)
		}
		qname = outcome.followTo
	}
}

// resolveOnce walks the chain of trust to one name and validates its answer.
//
// Split out of Validate so that a CNAME target can be resolved the same way
// the original name was, from the trust anchor down. A target can sit in a
// different zone, under a different anchor, or below a delegation the first
// name never crossed, so reusing the first name's zone would be validating
// the second name's data against the wrong keys.
func (w *walk) resolveOnce(qname string, rrtype uint16) aliasOutcome {
	anchorName, anchors := w.v.cfg.Anchors.deepestFor(qname)
	if len(anchors) == 0 {
		return aliasOutcome{result: w.rec.indeterminate(w.rec.skip(
			ValidationStep{Kind: StepTrustAnchor, Zone: qname},
			ReasonNoTrustAnchor,
		))}
	}

	// The anchor zone is established first: its apex DNSKEY RRset has to be
	// authenticated by a configured anchor before anything it signs means
	// anything.
	zone, res, ok := w.establishAnchorZone(anchorName, anchors)
	if !ok {
		return aliasOutcome{result: res}
	}

	// Then descend one delegation at a time.
	candidates, truncated := zoneCandidates(anchorName, qname, rrtype, w.v.cfg.Limits.MaxZones)
	if truncated {
		// The chain is deeper than the depth budget allows. Continuing with
		// the names that fit would validate the answer against whichever
		// zone the walk happened to stop in, which is not the zone that
		// contains it — and the resulting failure would be reported as
		// Bogus, turning "this validator gave up early" into an accusation
		// against the data. Stopping here says the true thing instead.
		return aliasOutcome{result: w.rec.indeterminate(w.rec.fail(
			ValidationStep{Kind: StepLimit, Zone: anchorName, Name: qname, RRType: rrtype,
				Note: "the chain is deeper than the configured zone limit"},
			ReasonResourceLimit,
		))}
	}
	for _, child := range candidates {
		next, res, done := w.descend(zone, child)
		if done {
			return aliasOutcome{result: res}
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

	keys := dnskeysAt(records, zoneName)
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

	_, sigs := SplitSignaturesAt(records, zoneName, dns.TypeDNSKEY)
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

	dsRecords := dsAt(records, child)
	if len(dsRecords) == 0 {
		return w.noDSAtDelegation(zone, child, resp)
	}

	// A DS RRset exists, so it is data in the parent zone and must itself be
	// authenticated by the parent's keys before it can authenticate anything.
	set, reason := NewRRset(toRRs(dsRecords))
	if reason != ReasonNone {
		return nil, w.rec.verdict(w.rec.fail(
			ValidationStep{Kind: StepRRset, Zone: zone.name, Name: child, RRType: dns.TypeDS}, reason,
		)), true
	}
	_, sigs := SplitSignaturesAt(records, child, dns.TypeDS)
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

	keys := dnskeysAt(records, child)
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

// validateAnswer authenticates the RRset the caller actually asked about, or
// reports the alias that stands where it would have been.
func (w *walk) validateAnswer(zone *zoneState, qname string, rrtype uint16) aliasOutcome {
	resp, reason := w.lookup(qname, rrtype)
	if reason != ReasonNone {
		return aliasOutcome{result: w.rec.indeterminate(w.rec.fail(
			ValidationStep{Kind: StepRRset, Zone: zone.name, Name: qname, RRType: rrtype}, reason,
		))}
	}

	// QTYPE=* has its own rule and cannot share this one. See any.go: type
	// 255 matches no record and appears in no type bitmap, so both the
	// answer filter below and the NODATA proof it falls through to are
	// vacuous for it — together, a Secure verdict on an absence nobody
	// proved.
	if rrtype == dns.TypeANY {
		return w.validateAny(zone, qname, resp)
	}

	// Restricted to the queried owner name. See SplitSignaturesAt: an answer
	// section legitimately carries records for other names, and taking them
	// as the answer is a false Secure that needs no forgery at all.
	data, sigs := SplitSignaturesAt(resp.Answer, qname, rrtype)
	if len(data) == 0 {
		// No records of the queried type. Before deciding the answer is an
		// absence, look for the alias that would explain it.
		//
		// The order matters: a name that has both a CNAME and the queried
		// type violates RFC 2181 §10.1, and answering from the direct
		// records — which the branch above already did — is what every
		// resolver does with such a zone. Only where the type is genuinely
		// absent does the alias become the answer.
		//
		// DNAME is tried before CNAME and that order is the point. A DNAME
		// response carries a server-synthesised CNAME at the queried name
		// which RFC 6672 §5.3.1 says "will never be signed", so reaching
		// the alias path first finds an unsigned RRset and reports Bogus
		// for every DNAME-using name there is. See dname.go: the DNAME is
		// authenticated and the redirection recomputed from it, and the
		// synthesised CNAME is never read.
		if out, isDname := w.validateDname(zone, qname, resp); isDname {
			return out
		}
		if rrtype != dns.TypeCNAME {
			if alias, _ := SplitSignaturesAt(resp.Answer, qname, dns.TypeCNAME); len(alias) > 0 {
				return w.validateAlias(zone, qname, rrtype, resp)
			}
		}
		// Nothing in the answer section. Whether that absence is legitimate
		// is exactly the denial-of-existence question, and the response has
		// to prove its own claim rather than be taken at its word.
		return aliasOutcome{result: w.validateDenial(zone, qname, rrtype, resp)}
	}

	set, reason := NewRRset(data)
	if reason != ReasonNone {
		return aliasOutcome{result: w.rec.verdict(w.rec.fail(
			ValidationStep{Kind: StepRRset, Zone: zone.name, Name: qname, RRType: rrtype}, reason,
		))}
	}

	accepted, reason := w.authenticateSigned(set, sigs, zone.name, zone.keys)
	if reason != ReasonNone {
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
		return aliasOutcome{result: w.rec.verdict(reason)}
	}

	w.rec.ok(ValidationStep{Kind: StepRRset, Zone: zone.name, Name: qname, RRType: rrtype})

	// A verified signature is not the end of the story for an answer the
	// server synthesised from a wildcard. See wildcardProof.
	if res, done := w.wildcardProof(zone, qname, rrtype, accepted, resp); done {
		return aliasOutcome{result: res}
	}
	return aliasOutcome{result: w.rec.secure()}
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
