package api

import (
	"net/netip"

	"github.com/jameshoulder/dnsdaddy/internal/clientacl"
	"github.com/jameshoulder/dnsdaddy/internal/dnsserver"
)

// ClientAccessActivity separates a permission decision from a DNS answer.
// This is a bounded source-address diagnostic, not an authenticated device list.
// The management route requires a session/token; no credentials are included.
type ClientAccessActivity struct {
	Enabled              bool                `json:"enabled"`
	WindowSeconds        int                 `json:"windowSeconds"`
	Capacity             int                 `json:"capacity"`
	Dropped              uint64              `json:"dropped"`
	Evicted              uint64              `json:"evicted"`
	ACLStale             bool                `json:"aclStale"`
	QueryLogging         bool                `json:"queryLogging"`
	ClientAddressLogging bool                `json:"clientAddressLogging"`
	Entries              []ClientAccessEntry `json:"entries"`
	Note                 string              `json:"note"`
}

type ClientAccessEntry struct {
	dnsserver.AccessEntry
	SourceAllowed bool   `json:"sourceAllowed"`
	CanAuthorize  bool   `json:"canAuthorize"`
	Public        bool   `json:"public"`
	NetworkID     string `json:"networkId"`
	NetworkName   string `json:"networkName"`
	PolicyID      string `json:"policyId"`
	PolicyName    string `json:"policyName"`
	Status        string `json:"status"`
	Reason        string `json:"reason"`
}

func (a *API) clientAccessActivity() ClientAccessActivity {
	samples := a.DNS.AccessActivity()
	out := ClientAccessActivity{Enabled: samples.Enabled, WindowSeconds: samples.WindowSeconds, Capacity: samples.Capacity, Dropped: samples.Dropped, Evicted: samples.Evicted, ACLStale: a.ClientACL.Stale(), QueryLogging: a.Config.Log.QueryLog, ClientAddressLogging: a.Config.Log.LogClientIP, Entries: []ClientAccessEntry{}, Note: "Recent source refusals and subsequent responses, in memory only. Addresses are observed, not authenticated identities. Counters may be sampled under load. Expired records are omitted and erased on the next read or observation."}
	if !samples.Enabled {
		out.Note = "Source diagnostics are disabled by query-log or client-address privacy settings. Anonymous DNS counters still work; no settings were changed."
		return out
	}
	if a.Engine == nil {
		return out
	}
	acl := a.ClientACL.Current()
	for _, sample := range samples.Entries {
		ip, err := netip.ParseAddr(sample.Address)
		if err != nil {
			continue
		}
		match := a.Engine.MatchClient(ip)
		if !a.Engine.PolicyLogsQueries(match.PolicyID) {
			continue
		}
		allowed := acl.Allows(ip)
		prefix := netip.PrefixFrom(ip, ip.BitLen())
		e := ClientAccessEntry{AccessEntry: sample, SourceAllowed: allowed, CanAuthorize: !ip.IsLinkLocalUnicast() && match.PolicyID != "", Public: clientacl.PrefixIsPublic(prefix), NetworkID: match.NetworkID, NetworkName: match.NetworkName, PolicyID: match.PolicyID, PolicyName: match.PolicyName, Status: "needs_permission", Reason: "The live source-address rules do not permit this address. Refused requests do not enter query history, threat feeds or learning."}
		if allowed {
			e.Status = "permitted_waiting"
			e.Reason = "Source access is now permitted. Waiting for a subsequent DNS answer from this source; saving permission is not a connection test."
			switch sample.LastOutcome {
			case "answered":
				e.Status, e.Reason = "answered", "A subsequent source-authorised query produced a DNS answer. This does not prove every query or the remote reply path succeeds."
			case "blocked":
				e.Status, e.Reason = "policy_blocked", "A subsequent source-authorised query was blocked by policy or local response protection, not client admission."
			case "error":
				e.Status, e.Reason = "resolution_error", "Source access passed, but subsequent resolution failed. Inspect the query reason; broadening client permissions will not fix it."
			}
		}
		out.Entries = append(out.Entries, e)
	}
	return out
}
