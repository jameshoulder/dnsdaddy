package lab

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
)

// encodePublicKey renders a public key in DNSKEY wire format.
//
// This is the inverse of what internal/daddybound/dnssec decodes, and it is
// written here from the same RFCs rather than by calling into that package.
// A round trip through one shared implementation proves only that the
// implementation agrees with itself; two independent readings of RFC 3110,
// RFC 6605 and RFC 8080 that agree is weak evidence, and two that disagree is
// a finding.
func encodePublicKey(pub crypto.PublicKey) (string, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return encodeRSA(k)
	case *ecdsa.PublicKey:
		return encodeECDSA(k)
	case ed25519.PublicKey:
		// RFC 8080 §3: the 32-octet public key, unadorned.
		return base64.StdEncoding.EncodeToString(k), nil
	default:
		return "", fmt.Errorf("no DNSKEY encoding for %T", pub)
	}
}

// encodeRSA implements RFC 3110 §2: an exponent length of one octet, or a
// zero octet followed by two more when the exponent needs 256 octets or
// more, then the exponent, then the modulus.
func encodeRSA(k *rsa.PublicKey) (string, error) {
	exponent := big.NewInt(int64(k.E)).Bytes()
	modulus := k.N.Bytes()

	var out []byte
	switch {
	case len(exponent) == 0:
		return "", fmt.Errorf("RSA exponent is zero")
	case len(exponent) < 256:
		out = append(out, byte(len(exponent)))
	case len(exponent) < 65536:
		out = append(out, 0, byte(len(exponent)>>8), byte(len(exponent)))
	default:
		return "", fmt.Errorf("RSA exponent is too long for the DNSKEY encoding")
	}
	out = append(out, exponent...)
	out = append(out, modulus...)
	return base64.StdEncoding.EncodeToString(out), nil
}

// encodeECDSA implements RFC 6605 §4: the uncompressed point with the leading
// 0x04 octet removed, so X and Y each padded to the curve's field size.
//
// The padding is the part worth being careful about. big.Int.Bytes drops
// leading zeros, so a coordinate that happens to start with a zero octet
// would produce a key one octet short — which happens for roughly one key in
// 256 and would otherwise be a test that fails rarely and for no visible
// reason.
func encodeECDSA(k *ecdsa.PublicKey) (string, error) {
	size := (k.Curve.Params().BitSize + 7) / 8
	out := make([]byte, 2*size)
	k.X.FillBytes(out[:size])
	k.Y.FillBytes(out[size:])
	return base64.StdEncoding.EncodeToString(out), nil
}
