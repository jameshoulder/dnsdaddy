package dnssec

import "sort"

// Policy says which algorithms and digest types an operator is willing to
// rely on. It is the second of the two questions the standards ask, and it is
// deliberately not the same question as whether this build can do the
// arithmetic.
//
// The distinction is forced by RFC 9905 §2, which places both obligations on
// RSASHA1 at once:
//
//	Validating resolver implementations ... MUST continue to support
//	validation using these algorithms ... Operators of validating resolvers
//	MUST treat DNSSEC signing algorithms RSASHA1 and RSASHA1-NSEC3-SHA1 as
//	unsupported ...
//
// So the implementation keeps the capability and the default policy refuses
// to use it. An implementation with one boolean per algorithm has to violate
// one of those two MUSTs.
//
// A Policy is a value and is not mutated after construction. Changing what an
// operator relies on is a configuration change, reviewed as one; nothing here
// is fetched at runtime.
type Policy struct {
	algorithms map[Algorithm]bool
	digests    map[DigestType]bool
}

// DefaultPolicy is what Daddybound relies on unless told otherwise.
//
// Permitted signature algorithms are the ones the registry marks as current
// for zone signing and that this build can verify: RSASHA256, RSASHA512,
// ECDSAP256SHA256, ECDSAP384SHA384 and Ed25519.
//
// RSASHA1 (5) and RSASHA1-NSEC3-SHA1 (7) are verifiable by this build and are
// *not* permitted, which is precisely the operator obligation quoted above.
//
// Permitted DS digest types are SHA-1, SHA-256 and SHA-384. SHA-1 is included
// deliberately and is not an oversight: RFC 9905 deprecates SHA-1 for
// *creating* delegations while the IANA registry keeps "Use for DNSSEC
// Validation: RECOMMENDED" and "Implement for DNSSEC Validation: MUST" for
// digest type 1. Refusing it would break validation of zones whose parents
// still publish SHA-1 DS records, which the RFC explicitly does not ask for.
// The deprecated thing is algorithm 5 and 7 in the DS Algorithm field, which
// the algorithm policy above already refuses.
func DefaultPolicy() Policy {
	return Policy{
		algorithms: map[Algorithm]bool{
			AlgRSASHA256:       true,
			AlgRSASHA512:       true,
			AlgECDSAP256SHA256: true,
			AlgECDSAP384SHA384: true,
			AlgED25519:         true,
		},
		digests: map[DigestType]bool{
			DigestSHA1:   true,
			DigestSHA256: true,
			DigestSHA384: true,
		},
	}
}

// NewPolicy builds a policy permitting exactly the given algorithms and
// digest types.
//
// An entry this build cannot verify is accepted here rather than rejected,
// because permitting something unsupported is not a contradiction: it says
// the operator would rely on it if the capability existed. The two conditions
// stay separately reportable, which is the whole point — AllowedAndSupported
// is where they are combined, and it names which of the two failed.
func NewPolicy(algs []Algorithm, digestTypes []DigestType) Policy {
	p := Policy{
		algorithms: make(map[Algorithm]bool, len(algs)),
		digests:    make(map[DigestType]bool, len(digestTypes)),
	}
	for _, a := range algs {
		p.algorithms[a] = true
	}
	for _, d := range digestTypes {
		p.digests[d] = true
	}
	return p
}

// AllowsAlgorithm reports whether policy permits relying on a.
func (p Policy) AllowsAlgorithm(a Algorithm) bool { return p.algorithms[a] }

// AllowsDigest reports whether policy permits relying on d.
func (p Policy) AllowsDigest(d DigestType) bool { return p.digests[d] }

// CheckAlgorithm combines capability and permission and returns the reason
// the algorithm may not be used, or ReasonNone if it may.
//
// The order matters. Capability is reported first because it is a fact about
// this binary that an operator cannot configure away, and telling someone
// their policy is wrong when the real problem is a missing verifier sends
// them to the wrong file.
func (p Policy) CheckAlgorithm(a Algorithm) Reason {
	if !a.Supported() {
		return ReasonUnsupportedAlgorithm
	}
	if !p.AllowsAlgorithm(a) {
		return ReasonDisallowedAlgorithm
	}
	return ReasonNone
}

// CheckDigest is CheckAlgorithm for DS digest types.
func (p Policy) CheckDigest(d DigestType) Reason {
	if !d.Supported() {
		return ReasonUnsupportedDigest
	}
	if !p.AllowsDigest(d) {
		return ReasonDisallowedDigest
	}
	return ReasonNone
}

// Algorithms returns the permitted algorithm numbers in ascending order.
// Sorted because it is rendered into traces and documentation, and a listing
// that reorders between runs is a listing nobody can diff.
func (p Policy) Algorithms() []Algorithm {
	out := make([]Algorithm, 0, len(p.algorithms))
	for a, ok := range p.algorithms {
		if ok {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Digests returns the permitted digest types in ascending order.
func (p Policy) Digests() []DigestType {
	out := make([]DigestType, 0, len(p.digests))
	for d, ok := range p.digests {
		if ok {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
