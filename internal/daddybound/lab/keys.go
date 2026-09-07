// Package lab builds complete, signed DNS hierarchies in memory so that
// DNSSEC validation can be exercised without touching the Internet.
//
// Everything here is test and demonstration infrastructure. It generates
// private keys and signs zones, so it has no business anywhere near a
// resolver that answers real queries — nothing in the DNS Daddy resolver
// imports this package, and a test enforces that.
//
// The lab is deterministic by default: the same seed produces the same keys,
// and with Ed25519 (which signs deterministically) the same signatures, so a
// failing case can be reproduced exactly and kept in a regression corpus.
package lab

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
)

// deriveKey produces a signing key for an algorithm from a seed string.
//
// Deterministic key generation is worth some trouble here. A lab that
// generates fresh keys on every run cannot have a regression corpus of signed
// messages, and a failure that reproduces only sometimes is a failure nobody
// fixes.
//
// crypto/ecdsa and crypto/ed25519 both offer a way in from raw bytes.
// crypto/rsa does not: ecdsa.GenerateKey and rsa.GenerateKey deliberately
// consume a random amount of entropy so that callers cannot depend on their
// output being a function of the reader, which is the right decision for
// production and an obstacle here. RSA is therefore served from a fixed
// embedded key, which is a test key and is documented as one.
func deriveKey(alg dnssec.Algorithm, seed string) (crypto.Signer, error) {
	switch alg {
	case dnssec.AlgED25519:
		return ed25519.NewKeyFromSeed(expand(seed, ed25519.SeedSize)), nil
	case dnssec.AlgECDSAP256SHA256:
		return deriveECDSA(elliptic.P256(), seed)
	case dnssec.AlgECDSAP384SHA384:
		return deriveECDSA(elliptic.P384(), seed)
	case dnssec.AlgRSASHA256, dnssec.AlgRSASHA512, dnssec.AlgRSASHA1:
		return embeddedRSAKey()
	default:
		return nil, fmt.Errorf("lab: no key derivation for algorithm %d (%s)", alg, alg.Name())
	}
}

// deriveECDSA builds a private key from a seed by hashing it into a scalar
// and retrying until the scalar is in range.
//
// ecdsa.ParseRawPrivateKey rejects a scalar of zero or one at or above the
// curve order, so the counter is incremented and the hash retried rather than
// reducing modulo the order — reduction biases the low end of the range, and
// while that does not matter for a test key, writing biased key derivation
// anywhere invites it being copied somewhere it does matter.
func deriveECDSA(curve elliptic.Curve, seed string) (crypto.Signer, error) {
	size := (curve.Params().BitSize + 7) / 8
	for counter := uint32(0); counter < 256; counter++ {
		raw := expandCounter(seed, counter, size)
		if new(big.Int).SetBytes(raw).Sign() == 0 {
			continue
		}
		key, err := ecdsa.ParseRawPrivateKey(curve, raw)
		if err != nil {
			continue
		}
		return key, nil
	}
	return nil, fmt.Errorf("lab: could not derive an ECDSA key for seed %q", seed)
}

// expand stretches a seed to n octets with counter-mode SHA-256.
func expand(seed string, n int) []byte {
	out := make([]byte, 0, n+sha256.Size)
	for counter := uint32(0); len(out) < n; counter++ {
		out = append(out, blockOf(seed, counter)...)
	}
	return out[:n]
}

// expandCounter is expand with an extra domain separator, used so that
// retrying an out-of-range ECDSA scalar produces unrelated bytes rather than
// a shift of the same stream.
func expandCounter(seed string, salt uint32, n int) []byte {
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], salt)
	return expand(string(prefix[:])+seed, n)
}

func blockOf(seed string, counter uint32) []byte {
	h := sha256.New()
	var c [4]byte
	binary.BigEndian.PutUint32(c[:], counter)
	h.Write(c[:])
	h.Write([]byte(seed))
	sum := h.Sum(nil)
	return sum
}

// labRSAKey is a 2048-bit RSA private key generated once, for this lab, and
// committed so that RSA scenarios are reproducible.
//
// It is a test key. It signs zones under .dnsdaddylab, a name that exists
// nowhere, in a hierarchy that never leaves memory. Publishing it costs
// nothing because it protects nothing, and the alternative — generating RSA
// keys at test time — costs a second of CPU per run and gives up
// reproducibility.
// The PEM says TESTING KEY where a real one would say PRIVATE KEY, and
// testingKey puts the word back at load time. That is the convention Go's
// own standard library uses for committed test keys, and it exists so that
// credential scanners — the ones in this repository's CI included — do not
// have to decide whether this particular private key is the dangerous kind.
const labRSAKeyPEM = `-----BEGIN RSA TESTING KEY-----
MIIEpAIBAAKCAQEAt83dYFAaqibzGeK7EbGiP2vyuVzadmvCTOlhQjAPvRN/4d1j
D06/EacPaYXeYCYn3e9HICSx7CZ19PTsVmF6rZ6A4qtPksGfXYUJS/u98+pBUw5n
RWDAaonXm4hrRivLlcEkeQy1xoMtxnQBOdeGYj92Dq4mBKB5uGPtzkkzXhBb1RW1
nHKJO3gJvv6AOZKa3sJkCftiuYED+DGDzzf8jIlKEDLIIQLghPhbGih/3It2uM2S
uxnxqL6IAODAwvZIfOqTuPCcti4HR4P8YGNPJXcTp+RrEhNkxA1lIDQOlPgo3NNl
VyWwDLS17WTVT7oxq0PkwHluTt4rZUTSFqJg2QIDAQABAoIBAA4EbyuXMFFlowiI
WAfjaiI4E0y7nhWF5k2DRt2LWMfsosYQ4isasEuiV/SONwVSI5wzUVNMOR1vWXOS
8issR/TRr7aZpfnlNkgliy32RuhBJzY0VP/ffw0g8gZ0gunZES+ciTGKHJrFCkqm
Mim9HAyGFnTMJy4XJvE+/bXLs1Uq/RYiQPog+LRT0gtnn6ZTtMtZlS100958qZRt
2upHutVHaGUOfqmwfOLjOK3dT1Aw3KZw8Ax0qvdpXdga/miWPr7RI+lCLNS2xhtV
Y8i4QWr8Yh7Jvigko+xs+NT3XKP+YNO199fNAj8ClyYK4GFm4ojlDkm7L/f/oftO
lJKwYuECgYEA45SOuMcIsMRYpP9oM4JsZXAiX4O3dwnyax7qXvOs7nelcaQQl+CR
0+213JkBjFR6CDGfkF4fi74Tm/v84f5JFRB8uQo1xbIFHWZ8LX3Se5SXgSMlb7Zy
ojPBPQUDtV3GcsxjIKDRXHS3tonPRO/v0cJ/01yDsrzfrAQpqhWIEh0CgYEAzsHX
cwfrZAadlO9xrJpLPCOedDv+zrrmlydd62Ga+pDvBzbRlPEX5WNREB60+gLIjZp1
sV0LOmAMR2xqPxWSSwhz3GdS9c4xlDudNlhEtKrnTRsi6nYEVEhWio4eIlcahHps
mneXhoGCxwOYg1mUSf+HXL8ow3/8JHdOlnkdTO0CgYBueN2zGoLAc/9n0Md/QY9m
ykEVRnYXpc90amRwxS6r745zFKYtY4jGbHy8YdWbjiJSuevwA5CioBkavf6qoWpO
fFte43LozZqoA+jBmHNFJANLX4k7qkAJNsBV44pCTwwXC9oOq6IVlF7dkBX6K9Kp
axXrvtv7Nq4I7VhgROVxjQKBgQCPJ/YGRqh8RHxdgADkMpz/EeaHsna2KwC4DeDg
tl85OJrYEuPATcJu6HpbP/es17qHGTh+St8YVyKJXY6fCU+Wtk6Kf9wYJ+F6MmCj
HTDNKzwlzjE5x+cteDy7iLVir47DxYRm24FF92xWYa363E5pggz2ccFGw9oQYa8/
TrKz7QKBgQDSGMZ8grov5GH+F0t+LSuevCxDolf9zZQGC6J28B2Pu15VfqWLe+2S
n3ys9O4t8Kn3DIr/iQTAjixj5hbtijlWE28HvlEXM0yHVuTdcJKI7pv8zI5NkUcZ
LmBaCMF2S53D2Gv3kNWgYZ+gDywcHHIFC6u+oBCSPl5IlRy6KS7eDw==
-----END RSA TESTING KEY-----`

func testingKey(s string) string { return strings.ReplaceAll(s, "TESTING KEY", "PRIVATE KEY") }

var cachedRSAKey *rsa.PrivateKey

func embeddedRSAKey() (crypto.Signer, error) {
	if cachedRSAKey != nil {
		return cachedRSAKey, nil
	}
	block, _ := pem.Decode([]byte(testingKey(labRSAKeyPEM)))
	if block == nil {
		return nil, fmt.Errorf("lab: the embedded RSA test key could not be decoded")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("lab: the embedded RSA test key is not a PKCS#1 key: %w", err)
	}
	cachedRSAKey = key
	return key, nil
}
