package dnssec

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"math/big"

	// Registers the digests named in the algorithm table. Blank imports
	// because nothing here calls them directly: crypto.Hash.New dispatches
	// through the registry, and an unregistered hash reports Available()
	// false, which would silently turn a supported algorithm into an
	// unsupported one.
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
)

// SignatureVerifier verifies one signature against one public key.
//
// It is an interface so that the boundary between trust logic and
// cryptography is a named seam rather than a habit. Everything above this
// interface decides *whether* a signature should be trusted; everything below
// it answers only *whether the arithmetic holds*, and is not permitted an
// opinion about anything else.
//
// A verifier answers exactly one question and answers it in one of three
// ways: verified, did not verify, or could not attempt. The third is not a
// failure of the data and must not be reported as one.
type SignatureVerifier interface {
	// Verify reports whether sig is a valid signature over signed, made with
	// the private key corresponding to keyData under algorithm alg.
	//
	// keyData is the raw DNSKEY public key material, already base64-decoded,
	// in the wire format the algorithm's RFC defines.
	//
	// The returned Reason is ReasonNone on success and otherwise says which
	// of the three outcomes occurred: ReasonSignatureCryptoFailed for a
	// signature that did not verify, ReasonUnsupportedAlgorithm for one this
	// verifier cannot attempt, ReasonKeyMalformed for key material that could
	// not be decoded.
	Verify(alg Algorithm, keyData, signed, sig []byte) Reason
}

// stdVerifier verifies using Go's standard library.
//
// Daddybound implements the DNS trust logic itself and does not implement
// cryptographic mathematics itself. What this type does implement is the
// DNSSEC-specific *encoding* of keys and signatures — RFC 3110 for RSA,
// RFC 6605 for ECDSA, RFC 8080 for Ed25519 — because those are wire formats,
// and getting them wrong is a protocol bug rather than a numerical one.
type stdVerifier struct{}

// StdVerifier returns the verifier backed by crypto/rsa, crypto/ecdsa and
// crypto/ed25519.
func StdVerifier() SignatureVerifier { return stdVerifier{} }

func (stdVerifier) Verify(alg Algorithm, keyData, signed, sig []byte) Reason {
	switch alg {
	case AlgRSASHA1, AlgRSASHA1NSEC3SHA1, AlgRSASHA256, AlgRSASHA512:
		return verifyRSA(alg, keyData, signed, sig)
	case AlgECDSAP256SHA256:
		return verifyECDSA(alg, elliptic.P256(), 32, keyData, signed, sig)
	case AlgECDSAP384SHA384:
		return verifyECDSA(alg, elliptic.P384(), 48, keyData, signed, sig)
	case AlgED25519:
		return verifyEd25519(keyData, signed, sig)
	default:
		return ReasonUnsupportedAlgorithm
	}
}

func verifyRSA(alg Algorithm, keyData, signed, sig []byte) Reason {
	pub, err := parseRSAPublicKey(keyData)
	if err != nil {
		return ReasonKeyMalformed
	}
	h, ok := alg.hash()
	if !ok || !h.Available() {
		return ReasonUnsupportedAlgorithm
	}
	digest := hashOf(h, signed)

	// PKCS#1 v1.5, per RFC 3110 §3 for SHA-1 and RFC 5702 §3 for SHA-2.
	// RSASSA-PSS is not used by any DNSSEC algorithm in the registry.
	if err := rsa.VerifyPKCS1v15(pub, h, digest, sig); err != nil {
		return ReasonSignatureCryptoFailed
	}
	return ReasonNone
}

// parseRSAPublicKey decodes DNSKEY RSA key material per RFC 3110 §2.
//
//	"The structure of the algorithm specific portion of the RDATA part of
//	 such RRs is as shown below.
//	        Field             Size
//	        -----             ----
//	        exponent length   1 or 3 octets (see text)
//	        exponent          as specified by length field
//	        modulus           remaining space"
//
// A leading zero octet means the length is in the two octets that follow, so
// exponents of 255 octets or more remain expressible.
func parseRSAPublicKey(b []byte) (*rsa.PublicKey, error) {
	if len(b) < 1 {
		return nil, errors.New("dnssec: RSA key material is empty")
	}

	var expLen int
	var off int
	if b[0] == 0 {
		if len(b) < 3 {
			return nil, errors.New("dnssec: RSA key material truncated in the three-octet exponent length")
		}
		expLen = int(b[1])<<8 | int(b[2])
		off = 3
		// A three-octet form encoding a length that fits in one octet is not
		// a length this parser should accept as equivalent: it is a second
		// encoding of the same key, and a key with two encodings has two key
		// tags, which is a way to smuggle a key past a tag-based check.
		if expLen < 256 {
			return nil, errors.New("dnssec: RSA exponent length uses the long form for a short value")
		}
	} else {
		expLen = int(b[0])
		off = 1
	}
	if expLen == 0 {
		return nil, errors.New("dnssec: RSA exponent length is zero")
	}
	if len(b) < off+expLen+1 {
		return nil, errors.New("dnssec: RSA key material truncated")
	}

	exponent := new(big.Int).SetBytes(b[off : off+expLen])
	modulus := new(big.Int).SetBytes(b[off+expLen:])

	// crypto/rsa carries the exponent as an int, so an exponent that does not
	// fit is rejected here rather than being silently truncated into a
	// different key.
	if !exponent.IsInt64() || exponent.Int64() > (1<<31)-1 || exponent.Int64() < 3 {
		return nil, errors.New("dnssec: RSA exponent is out of range")
	}
	if modulus.BitLen() == 0 {
		return nil, errors.New("dnssec: RSA modulus is empty")
	}

	pub := &rsa.PublicKey{N: modulus, E: int(exponent.Int64())}
	return pub, nil
}

// verifyECDSA implements RFC 6605 §4: the public key is the uncompressed
// point with the leading 0x04 octet removed, and the signature is the fixed
// width concatenation of r and s. Neither is ASN.1, which is the mistake this
// function exists to avoid.
func verifyECDSA(alg Algorithm, curve elliptic.Curve, size int, keyData, signed, sig []byte) Reason {
	if len(keyData) != 2*size {
		return ReasonKeyMalformed
	}
	// ParseUncompressedPublicKey checks the point is on the curve, which
	// matters: an off-curve point is not a key, and treating one as a key is
	// how a verifier ends up answering a question nobody asked.
	uncompressed := make([]byte, 0, 1+2*size)
	uncompressed = append(uncompressed, 0x04)
	uncompressed = append(uncompressed, keyData...)
	pub, err := ecdsa.ParseUncompressedPublicKey(curve, uncompressed)
	if err != nil {
		return ReasonKeyMalformed
	}

	if len(sig) != 2*size {
		return ReasonSignatureCryptoFailed
	}
	r := new(big.Int).SetBytes(sig[:size])
	s := new(big.Int).SetBytes(sig[size:])

	h, ok := alg.hash()
	if !ok || !h.Available() {
		return ReasonUnsupportedAlgorithm
	}
	if !ecdsa.Verify(pub, hashOf(h, signed), r, s) {
		return ReasonSignatureCryptoFailed
	}
	return ReasonNone
}

// verifyEd25519 implements RFC 8080 §3: a 32-octet public key and a 64-octet
// signature over the message itself. Ed25519 hashes internally, so there is
// no separate digest step and no hash to choose.
func verifyEd25519(keyData, signed, sig []byte) Reason {
	if len(keyData) != ed25519.PublicKeySize {
		return ReasonKeyMalformed
	}
	if len(sig) != ed25519.SignatureSize {
		return ReasonSignatureCryptoFailed
	}
	if !ed25519.Verify(ed25519.PublicKey(keyData), signed, sig) {
		return ReasonSignatureCryptoFailed
	}
	return ReasonNone
}

func hashOf(h crypto.Hash, b []byte) []byte {
	hasher := h.New()
	hasher.Write(b)
	return hasher.Sum(nil)
}
