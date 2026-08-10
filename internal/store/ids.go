package store

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"strings"
)

// NewID returns a short random identifier with the given prefix, e.g. "n_a1b2c3d4".
func NewID(prefix string) string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		panic("dnsdaddy: crypto/rand unavailable: " + err.Error())
	}
	return prefix + "_" + hex.EncodeToString(b)
}

var tokenEnc = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewToken returns a URL-safe random token used for per-network DoH paths and
// API credentials. base32 keeps it copy-pasteable and case-insensitive-safe in
// URLs, which matters when someone is typing it into a UniFi controller.
func NewToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("dnsdaddy: crypto/rand unavailable: " + err.Error())
	}
	return strings.ToLower(tokenEnc.EncodeToString(b))
}
