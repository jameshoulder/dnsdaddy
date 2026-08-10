package store

import "github.com/jameshoulder/dnsdaddy/internal/domainutil"

// NormalizeDomain canonicalises a domain for storage. It returns "" if the
// input cannot be used as a DNS name.
func NormalizeDomain(s string) string { return domainutil.Normalize(s) }
