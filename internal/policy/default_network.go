package policy

import "github.com/jameshoulder/dnsdaddy/internal/clientacl"

// preferDefaultNetwork runs only while building an unpublished snapshot.
// CIDR-less networks also carry roaming credentials. Choosing the catch-all
// alphabetically allowed adding "Alice's laptop" with Monitor policy to change
// the policy of unrelated unmatched clients. The seeded Default row is the
// explicit fallback whenever it is enabled and remains CIDR-less; its display
// name, access gate and the names of token profiles do not decide attribution.
//
// No row or access grant is changed here. An absent, disabled or CIDR-scoped
// Default retains the legacy fallback selection made by Reload.
func preferDefaultNetwork(s *snapshot) {
	for i := range s.networks {
		n := &s.networks[i]
		if n.id == clientacl.DefaultNetworkID && n.enabled && len(n.prefixes) == 0 {
			s.fallback = n
			return
		}
	}
}
