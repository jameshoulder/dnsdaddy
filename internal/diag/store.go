package diag

import "github.com/jameshoulder/dnsdaddy/internal/store"

// FromStoreNetworks adapts persisted networks to the analysis input.
//
// It lives apart from diag.go so the rules themselves stay free of the
// persistence layer and can be tested without a database.
func FromStoreNetworks(networks []store.Network, policyNames map[string]string) []Network {
	out := make([]Network, 0, len(networks))
	for _, n := range networks {
		out = append(out, Network{
			ID:            n.ID,
			Name:          n.Name,
			PolicyName:    policyNames[n.PolicyID],
			Enabled:       n.Enabled,
			AllowResolver: n.AllowResolver,
			CIDRs:         n.CIDRs,
		})
	}
	return out
}

// PolicyNames indexes policies by ID so a finding can name the policy an
// unreachable network was carrying.
func PolicyNames(policies []store.Policy) map[string]string {
	out := make(map[string]string, len(policies))
	for _, p := range policies {
		out[p.ID] = p.Name
	}
	return out
}
