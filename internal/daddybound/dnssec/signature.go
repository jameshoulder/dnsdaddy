package dnssec

import (
	"encoding/base64"
	"errors"

	"github.com/miekg/dns"
)

// decodeSignature returns an RRSIG's signature octets.
//
// Kept apart from the rest of the RRSIG handling because it is the one place
// that turns presentation format into bytes, and because an empty signature
// has to be rejected explicitly: base64 decoding "" succeeds and yields an
// empty slice, which some verifiers would then cheerfully compare against a
// digest.
func decodeSignature(sig *dns.RRSIG) ([]byte, error) {
	if sig.Signature == "" {
		return nil, errors.New("dnssec: RRSIG carries no signature")
	}
	raw, err := base64.StdEncoding.DecodeString(sig.Signature)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, errors.New("dnssec: RRSIG signature decoded to nothing")
	}
	return raw, nil
}
