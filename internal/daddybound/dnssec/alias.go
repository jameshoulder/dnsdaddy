package dnssec

import "github.com/miekg/dns"

// Following a CNAME, and what the verdict means once a chain crosses zones.
//
// A CNAME answer is not one RRset to check. It is a sequence: the alias at the
// queried name, then whatever the target resolves to, possibly through more
// aliases and possibly through zones with different security status. Each link
// has its own chain of trust, its own zone cuts and its own verdict, and the
// answer a caller receives is only as good as the weakest of them.
//
// Getting the combination wrong is the whole risk here. Reporting the terminal
// RRset's verdict ignores an alias that failed to authenticate; reporting the
// first hop's ignores everything the alias pointed at. Either would let an
// attacker place a forged link in a chain and have the answer come back
// Secure.

// aliasOutcome is what one name's answer step produced.
//
// followTo carries a CNAME target when the answer was an alias, and is empty
// otherwise. It is a separate field rather than something to dig back out of
// the result because a verdict and a next step are different things: a hop can
// be Secure and still not be the answer.
type aliasOutcome struct {
	result   ValidationResult
	followTo string
}

// weakest returns the less confident of two chain verdicts, which is the one
// an answer assembled from both is entitled to.
//
// The order is Bogus, then Indeterminate, then Insecure, then Secure, and each
// step of it is a decision worth stating:
//
//   - **Bogus outranks everything.** One link that should have validated and
//     did not means the answer contains data somebody tampered with or broke.
//     That the rest of the chain was fine is not mitigation.
//   - **Indeterminate outranks Insecure.** Both fall short of Secure, and they
//     say different things. Insecure is a claim — the data was proved to be
//     unsigned — while Indeterminate admits the validator could not tell.
//     Reporting Insecure for a chain containing a link nobody could evaluate
//     would assert a proof that was never offered.
//   - **Insecure outranks Secure.** A chain that passes through an
//     authenticated unsigned zone cannot be called authenticated, however
//     well-signed the links either side of it are: anyone can rewrite the
//     unsigned part.
//
// The rule is the same one libunbound and BIND apply to a chain, and it is
// checked against both in the differential suite rather than assumed.
func weakest(a, b ValidationStatus) ValidationStatus {
	if chainRank(a) >= chainRank(b) {
		return a
	}
	return b
}

func chainRank(s ValidationStatus) int {
	switch s {
	case StatusBogus:
		return 3
	case StatusIndeterminate:
		return 2
	case StatusInsecure:
		return 1
	default: // StatusSecure
		return 0
	}
}

// validateAlias authenticates a CNAME RRset and reports where it points.
//
// The alias is data in its zone like any other, so it is checked the same way:
// one RRset, an admissible signature from a key this walk has authenticated,
// and — because a CNAME can be synthesised from a wildcard as readily as an
// address can — the wildcard proof RFC 4035 §5.3.4 demands when the owner has
// more labels than the signature claims to cover.
func (w *walk) validateAlias(zone *zoneState, qname string, rrtype uint16, resp Response) aliasOutcome {
	step := ValidationStep{Kind: StepRRset, Zone: zone.name, Name: qname, RRType: dns.TypeCNAME}

	data, sigs := SplitSignaturesAt(resp.Answer, qname, dns.TypeCNAME)

	// RFC 2181 §10.1: "a CNAME record is not allowed to coexist with any
	// other data", which also means there is at most one of them at a name.
	// Two would leave a validator choosing a target, and the choice would be
	// made from a response an attacker ordered — the same defect class that
	// duplicate denial records had. Refusing is the only answer that does not
	// hand them the decision.
	if len(data) != 1 {
		return aliasOutcome{result: w.rec.verdict(w.rec.fail(step, ReasonAliasAmbiguous))}
	}
	alias, ok := data[0].(*dns.CNAME)
	if !ok {
		return aliasOutcome{result: w.rec.verdict(w.rec.fail(step, ReasonMalformedRecord))}
	}

	set, reason := NewRRset(data)
	if reason != ReasonNone {
		return aliasOutcome{result: w.rec.verdict(w.rec.fail(step, reason))}
	}

	accepted, reason := w.authenticateSigned(set, sigs, zone.name, zone.keys)
	if reason != ReasonNone {
		return aliasOutcome{result: w.rec.verdict(reason)}
	}

	// The wildcard proof is asked for against the alias's own type. A
	// wildcard-expanded CNAME is exactly as replayable over sibling names as
	// a wildcard-expanded address, and the signature is just as genuine.
	if res, done := w.wildcardProof(zone, qname, dns.TypeCNAME, accepted, resp); done {
		return aliasOutcome{result: res}
	}

	target := dns.CanonicalName(alias.Target)
	step.Note = "alias to " + target
	w.rec.ok(step)

	// Secure so far, and not yet an answer: the caller follows the target and
	// combines what it finds with this.
	return aliasOutcome{result: w.rec.secure(), followTo: target}
}
