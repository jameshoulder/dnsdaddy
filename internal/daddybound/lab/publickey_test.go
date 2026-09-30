package lab

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"testing"
)

func TestECDSAPublicKeyEncodingPreservesCoordinatePadding(t *testing.T) {
	// These fixed scalar multiples have a leading zero octet in Y. Their
	// expected RFC 6605 DNSKEY values include that octet but no SEC 1 prefix.
	for _, tc := range []struct {
		curve  elliptic.Curve
		size   int
		scalar byte
		want   string
	}{
		{elliptic.P256(), 32, 43, "mGriUG8f8QTQQjCGHY9LSY9LxMbQCbMPdUTcEpuC0o0APMzApkYOCuMopNl9PHth2G/GKJwYnyUlEQxEG7B+lw=="},
		{elliptic.P384(), 48, 176, "0DqnSPX0jrPgxUtoPyXS4tfX4yASgqlbV6Wf+4+Uz0xDsRB8qUS5IRw1ERLeFu0YAAoIxgLcXgAx2tCIwZMF9rJSorw/JF96W4C0hMe5n2mBwyN0xxSnaDJV9TMfZrsG"},
	} {
		t.Run(tc.curve.Params().Name, func(t *testing.T) {
			raw := make([]byte, tc.size)
			raw[len(raw)-1] = tc.scalar
			key, err := ecdsa.ParseRawPrivateKey(tc.curve, raw)
			if err != nil {
				t.Fatal(err)
			}
			got, err := encodePublicKey(key.Public())
			if err != nil || got != tc.want {
				t.Fatalf("DNSKEY = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestECDSAPublicKeyEncodingRejectsInvalidOrUnsupportedKeys(t *testing.T) {
	raw := make([]byte, 32)
	raw[len(raw)-1] = 1
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), raw)
	if err != nil {
		t.Fatal(err)
	}
	invalid := key.Public().(*ecdsa.PublicKey)
	invalid.Curve = elliptic.P384() // The P-256 generator is not on P-384.
	for _, tc := range []struct {
		name string
		key  *ecdsa.PublicKey
	}{
		{"nil", nil},
		{"missing curve", &ecdsa.PublicKey{}},
		{"unsupported curve", &ecdsa.PublicKey{Curve: elliptic.P521()}},
		{"invalid point", invalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if encoded, err := encodeECDSA(tc.key); err == nil || encoded != "" {
				t.Fatalf("invalid key produced DNSKEY %q, %v", encoded, err)
			}
		})
	}
}

// RFC 3110 §2 gives the DNSKEY RSA exponent either a one-octet length or a
// zero octet followed by two more. The boundary between the two forms is at
// 256, and the two-octet form is a big-endian split of a 16-bit value into
// octets — a truncation that is the wire format rather than an overflow.
//
// This pins both, because the encoder here and the decoder in
// internal/daddybound/dnssec are written from the RFC independently, and a
// disagreement between them would look like a broken key rather than like a
// length-encoding bug.
func TestRSAExponentLengthRoundTrips(t *testing.T) {
	tests := []struct {
		name    string
		expLen  int
		wantErr bool
	}{
		{name: "the common exponent, one octet", expLen: 3},
		{name: "the last one-octet length", expLen: 255},
		{name: "the first two-octet length", expLen: 256},
		{name: "a length needing both octets", expLen: 0x0102},
		{name: "the largest expressible length", expLen: 0xFFFF},
		{name: "one octet too long", expLen: 0x10000, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// An exponent of the requested length, with a leading 1 so
			// big.Int keeps every octet.
			raw := make([]byte, tc.expLen)
			if tc.expLen > 0 {
				raw[0] = 1
			}
			key := &rsa.PublicKey{N: big.NewInt(0xC0FFEE)}

			encoded, err := encodeRSAWithExponent(key, raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error for a %d-octet exponent", tc.expLen)
				}
				return
			}
			if err != nil {
				t.Fatalf("encode: %v", err)
			}

			out, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}

			var gotLen, offset int
			if out[0] == 0 {
				gotLen = int(out[1])<<8 | int(out[2])
				offset = 3
				if tc.expLen < 256 {
					t.Errorf("a %d-octet exponent used the long form", tc.expLen)
				}
			} else {
				gotLen = int(out[0])
				offset = 1
				if tc.expLen >= 256 {
					t.Errorf("a %d-octet exponent used the short form", tc.expLen)
				}
			}

			if gotLen != tc.expLen {
				t.Errorf("length field = %d, want %d", gotLen, tc.expLen)
			}
			if got := out[offset : offset+gotLen]; string(got) != string(raw) {
				t.Errorf("exponent octets did not round-trip")
			}
		})
	}
}
