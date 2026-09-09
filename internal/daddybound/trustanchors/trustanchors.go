// Package trustanchors supplies the DNSSEC trust anchors Daddybound validates
// against at runtime.
//
// The root anchors are compiled in. That is a deliberate choice rather than a
// convenience: a validator that fetched its trust anchor over the network at
// startup would be trusting the network to tell it what to trust, which is the
// thing DNSSEC exists to stop needing. Every validating resolver ships these
// values the same way.
//
// They are public data, published by IANA and reproducible by anyone: take the
// root DNSKEY RRset, keep the keys with the SEP bit, and compute the SHA-256
// digest RFC 4034 §5.1.4 defines. The two below were derived that way from the
// IANA root anchors rather than transcribed, and a test recomputes them.
package trustanchors

import (
	"fmt"
	"os"
	"strings"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
)

// IANARootDS are the root zone's trust anchors in DS presentation form.
//
//   - 20326 is KSK-2017, the key that has signed the root since the 2018
//     rollover.
//   - 38696 is KSK-2024, published in advance of the next one.
//
// Both are listed so that the rollover between them does not need a new
// release: a validator holding both accepts whichever the root is currently
// signing with. That is the whole of DNS Daddy's trust-anchor lifecycle today
// — there is no RFC 5011 automatic rollover, and the limitation is documented
// rather than implied.
var IANARootDS = []string{
	". 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
	". 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
}

// Root returns the compiled-in root anchors.
func Root() (dnssec.TrustAnchors, error) { return parse(IANARootDS) }

// FromFile reads anchors from a file in DS presentation form, one per line.
//
// An escape hatch for the case the compiled-in set cannot cover: a root key
// rollover that happens before a release ships, or a deployment validating
// against something other than the public root. Comments start with ';' or
// '#', matching the format IANA and BIND both use, so an operator can point
// this at a file they already have.
//
// Anything unparseable is an error rather than a skipped line. A trust anchor
// file with a typo in it should stop a validator starting, not silently
// configure it to trust less than the operator wrote.
func FromFile(path string) (dnssec.TrustAnchors, error) {
	// #nosec G304 -- the path comes from the operator's own configuration file
	// and is read once at startup. There is no request-time input here: a
	// deployment that can set this can already set the upstreams and the
	// listeners.
	raw, err := os.ReadFile(path)
	if err != nil {
		return dnssec.TrustAnchors{}, fmt.Errorf("trust anchor file: %w", err)
	}
	var specs []string
	for i, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		// Tolerate the zone-file form "· IN DS 20326 8 2 …" as well as the
		// bare IANA form, because an operator will paste whichever they have.
		line = stripZoneFileTokens(line)
		if line == "" {
			return dnssec.TrustAnchors{}, fmt.Errorf("trust anchor file %s line %d: no DS record found", path, i+1)
		}
		specs = append(specs, line)
	}
	if len(specs) == 0 {
		return dnssec.TrustAnchors{}, fmt.Errorf("trust anchor file %s contains no anchors", path)
	}
	return parse(specs)
}

// stripZoneFileTokens removes an "IN DS" (or "DS") in the middle of a record,
// leaving the owner name and the four DS fields ParseTrustAnchorDS expects.
func stripZoneFileTokens(line string) string {
	fields := strings.Fields(line)
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		switch strings.ToUpper(f) {
		case "IN", "DS":
			continue
		}
		out = append(out, f)
	}
	if len(out) < 5 {
		return ""
	}
	return strings.Join(out, " ")
}

func parse(specs []string) (dnssec.TrustAnchors, error) {
	anchors := make([]dnssec.TrustAnchor, 0, len(specs))
	for _, s := range specs {
		a, err := dnssec.ParseTrustAnchorDS(s)
		if err != nil {
			return dnssec.TrustAnchors{}, fmt.Errorf("trust anchor %q: %w", s, err)
		}
		anchors = append(anchors, a)
	}
	return dnssec.NewTrustAnchors(anchors...)
}
