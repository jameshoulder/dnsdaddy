package lab

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"testing"
)

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
