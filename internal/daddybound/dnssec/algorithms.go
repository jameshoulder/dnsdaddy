package dnssec

import "crypto"

// Algorithm is a DNSSEC security algorithm number from the IANA "DNS Security
// Algorithm Numbers" registry. The registry snapshot this file agrees with is
// reproduced in docs/daddybound/standards.md §6.1, and a test compares the two.
type Algorithm uint8

// The algorithm numbers this package names. Numbers absent here are not
// "invalid"; they are numbers this build has no verifier for, which is a
// different thing and produces a different reason. See Supported.
const (
	AlgRSAMD5           Algorithm = 1
	AlgDSA              Algorithm = 3
	AlgRSASHA1          Algorithm = 5
	AlgDSANSEC3SHA1     Algorithm = 6
	AlgRSASHA1NSEC3SHA1 Algorithm = 7
	AlgRSASHA256        Algorithm = 8
	AlgRSASHA512        Algorithm = 10
	AlgECCGOST          Algorithm = 12
	AlgECDSAP256SHA256  Algorithm = 13
	AlgECDSAP384SHA384  Algorithm = 14
	AlgED25519          Algorithm = 15
	AlgED448            Algorithm = 16
	AlgSM2SM3           Algorithm = 17
	AlgECCGOST12        Algorithm = 23
	AlgPrivateDNS       Algorithm = 253
	AlgPrivateOID       Algorithm = 254
)

// algorithmInfo is what this package knows about one registry entry.
type algorithmInfo struct {
	Mnemonic string
	// ZoneSigning mirrors the registry's "Zone Signing" column. An algorithm
	// marked N there may not sign zone data at all, whatever else is true of
	// it.
	ZoneSigning bool
	// Hash is the digest a signature over this algorithm is computed with.
	// Zero for algorithms whose signature scheme has no separate hash step
	// (Ed25519 signs the message).
	Hash crypto.Hash
	// Supported reports whether this build has a verifier. Deliberately a
	// property of the algorithm table rather than of policy: see Policy.
	Supported bool
}

// algorithms is the registry as this build understands it.
//
// Entries exist for algorithms with no verifier so that the reason for
// refusing them is "this build cannot verify that" rather than "unknown
// number" — the operator is better served by a name than by an integer, and
// the two failures are genuinely different.
var algorithms = map[Algorithm]algorithmInfo{
	AlgRSAMD5:           {Mnemonic: "RSAMD5", ZoneSigning: false, Supported: false},
	AlgDSA:              {Mnemonic: "DSA", ZoneSigning: true, Supported: false},
	AlgRSASHA1:          {Mnemonic: "RSASHA1", ZoneSigning: true, Hash: crypto.SHA1, Supported: true},
	AlgDSANSEC3SHA1:     {Mnemonic: "DSA-NSEC3-SHA1", ZoneSigning: true, Supported: false},
	AlgRSASHA1NSEC3SHA1: {Mnemonic: "RSASHA1-NSEC3-SHA1", ZoneSigning: true, Hash: crypto.SHA1, Supported: true},
	AlgRSASHA256:        {Mnemonic: "RSASHA256", ZoneSigning: true, Hash: crypto.SHA256, Supported: true},
	AlgRSASHA512:        {Mnemonic: "RSASHA512", ZoneSigning: true, Hash: crypto.SHA512, Supported: true},
	AlgECCGOST:          {Mnemonic: "ECC-GOST", ZoneSigning: true, Supported: false},
	AlgECDSAP256SHA256:  {Mnemonic: "ECDSAP256SHA256", ZoneSigning: true, Hash: crypto.SHA256, Supported: true},
	AlgECDSAP384SHA384:  {Mnemonic: "ECDSAP384SHA384", ZoneSigning: true, Hash: crypto.SHA384, Supported: true},
	AlgED25519:          {Mnemonic: "ED25519", ZoneSigning: true, Supported: true},
	AlgED448:            {Mnemonic: "ED448", ZoneSigning: true, Supported: false},
	AlgSM2SM3:           {Mnemonic: "SM2SM3", ZoneSigning: true, Supported: false},
	AlgECCGOST12:        {Mnemonic: "ECC-GOST12", ZoneSigning: true, Supported: false},
	AlgPrivateDNS:       {Mnemonic: "PRIVATEDNS", ZoneSigning: true, Supported: false},
	AlgPrivateOID:       {Mnemonic: "PRIVATEOID", ZoneSigning: true, Supported: false},
}

// Name returns the registry mnemonic, or ALGnnn for a number this build does
// not name. Never used to decide anything.
func (a Algorithm) Name() string {
	if info, ok := algorithms[a]; ok {
		return info.Mnemonic
	}
	return "ALG" + itoa(uint(a))
}

// Supported reports whether this build can verify signatures made with a.
//
// This is a statement about Daddybound's capabilities and nothing else. It is
// deliberately separate from whether an operator is willing to rely on the
// algorithm, because RFC 9905 §2 imposes both obligations at once for
// RSASHA1: implementations "MUST continue to support validation using these
// algorithms", while operators "MUST treat [them] as unsupported". A single
// boolean cannot satisfy both. Policy.Allows answers the other question.
func (a Algorithm) Supported() bool {
	info, ok := algorithms[a]
	return ok && info.Supported
}

// ZoneSigning reports whether the registry permits a to sign zone data.
func (a Algorithm) ZoneSigning() bool {
	info, ok := algorithms[a]
	return ok && info.ZoneSigning
}

// hash returns the digest used with a, and whether a is one this build knows
// how to verify at all.
func (a Algorithm) hash() (crypto.Hash, bool) {
	info, ok := algorithms[a]
	if !ok || !info.Supported {
		return 0, false
	}
	return info.Hash, true
}

// DigestType is a DS digest algorithm number from the IANA "Digest
// Algorithms" registry for the DS RR. Snapshot in
// docs/daddybound/standards.md §6.2.
type DigestType uint8

const (
	DigestSHA1     DigestType = 1
	DigestSHA256   DigestType = 2
	DigestGOST94   DigestType = 3
	DigestSHA384   DigestType = 4
	DigestGOST2012 DigestType = 5
	DigestSM3      DigestType = 6
)

type digestInfo struct {
	Name      string
	Hash      crypto.Hash
	Supported bool
}

var digests = map[DigestType]digestInfo{
	DigestSHA1:     {Name: "SHA-1", Hash: crypto.SHA1, Supported: true},
	DigestSHA256:   {Name: "SHA-256", Hash: crypto.SHA256, Supported: true},
	DigestGOST94:   {Name: "GOST R 34.11-94", Supported: false},
	DigestSHA384:   {Name: "SHA-384", Hash: crypto.SHA384, Supported: true},
	DigestGOST2012: {Name: "GOST R 34.11-2012", Supported: false},
	DigestSM3:      {Name: "SM3", Supported: false},
}

// Name returns the registry description, or DIGESTnnn for an unnamed number.
func (d DigestType) Name() string {
	if info, ok := digests[d]; ok {
		return info.Name
	}
	return "DIGEST" + itoa(uint(d))
}

// Supported reports whether this build can compute digest type d.
func (d DigestType) Supported() bool {
	info, ok := digests[d]
	return ok && info.Supported && info.Hash.Available()
}

func (d DigestType) hash() (crypto.Hash, bool) {
	info, ok := digests[d]
	if !ok || !info.Supported {
		return 0, false
	}
	return info.Hash, true
}

// itoa formats an unsigned number without the allocation fmt.Sprintf would
// make on a path that runs inside trace rendering.
//
// The buffer is sized for the largest uint rather than for the two callers
// here, which only ever pass a registry number below 256. A buffer sized to
// the current callers is correct until someone reuses the helper, and then it
// is an out-of-range panic in trace rendering — which is to say, in the code
// that runs while something else is already going wrong.
func itoa(v uint) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
