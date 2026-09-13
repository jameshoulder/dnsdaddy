package diag

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/jameshoulder/dnsdaddy/internal/rebind"
)

// RebindingInput is the configured DNS rebinding filter and the exemptions
// policies carry.
type RebindingInput struct {
	// Enabled is the resolved state, after the installation record has been
	// consulted — what would actually run, not what the file says.
	Enabled bool
	// Ranges and EmptyAction are the compiled filter, empty when disabled.
	Ranges      []netip.Prefix
	EmptyAction rebind.EmptyAction
	// Exemptions maps policy id to the ranges that policy accepts anyway.
	Exemptions map[string][]string
	// DefaultPolicyID is the policy unmatched clients receive. An exemption
	// there applies to everything the operator has not explicitly placed, so
	// a wide one is worth naming separately.
	DefaultPolicyID string
	// Dropped is how many stored exemptions would not parse and were ignored.
	// Should be zero.
	Dropped uint64
}

// wideExemption is the prefix length at or below which an exemption is
// reported as broad.
//
// /8 is the threshold because it is where the shipped filter list itself
// starts: exempting a whole /8 gives back the entirety of 10.0.0.0/8 or
// 127.0.0.0/8, which is most of what this control exists to withhold. It is a
// warning rather than a refusal — an operator whose site really does use a
// flat 10/8 is not doing anything wrong — but it should be visible.
const wideExemption = 8

// Rebinding reports whether a public name can still answer with a private
// address.
//
// The FAIL cases are the ones where the filter is reporting itself as on while
// protecting nothing, because that is worse than being off: an operator who
// turned it off knows they did.
func Rebinding(in RebindingInput) []Check {
	c := Check{Section: sectionClientAccess, Name: "DNS rebinding filter"}

	if !in.Enabled {
		c.Status = StatusWarn
		c.Summary = "Answers are returned as resolved. A public name may answer with a private, " +
			"loopback or link-local address."
		c.Evidence = []string{"dns.rebinding.enabled is false"}
		c.Action = "Set dns.rebinding.enabled: true. If a name on your network legitimately " +
			"resolves to a private address, exempt that range on the policy that needs it rather " +
			"than leaving the filter off for everybody."
		return []Check{c}
	}

	if len(in.Ranges) == 0 {
		c.Status = StatusFail
		c.Summary = "The rebinding filter is on and has no ranges, so it filters nothing."
		c.Evidence = []string{"dns.rebinding.filter_ranges is empty"}
		c.Action = "Remove dns.rebinding.filter_ranges to use the shipped defaults, or set " +
			"dns.rebinding.enabled: false so the status reflects what is happening."
		return []Check{c}
	}

	c.Status = StatusPass
	c.Summary = fmt.Sprintf(
		"%d address range(s) are withheld from answers; an answer left with no address becomes %s.",
		len(in.Ranges), in.EmptyAction)

	withExemptions := 0
	for _, ex := range in.Exemptions {
		if len(ex) > 0 {
			withExemptions++
		}
	}
	c.Evidence = []string{
		"filtered: " + strings.Join(prefixStrings(in.Ranges), ", "),
		fmt.Sprintf("%d polic(ies) carry an exemption", withExemptions),
	}

	out := []Check{c}

	// A default route exemption is reported as a failure rather than folded
	// into the summary. It cannot be written through the API, so one that is
	// present arrived another way and silently disables the filter for every
	// client on that policy.
	if fails := defaultRouteExemptions(in); len(fails) > 0 {
		out = append(out, Check{
			Section:  sectionClientAccess,
			Name:     "Rebinding exemption covers every address",
			Status:   StatusFail,
			Summary:  "A policy exempts the whole address space, so the rebinding filter does nothing for its clients.",
			Evidence: fails,
			Action: "Remove the 0.0.0.0/0 or ::/0 exemption and list the ranges that network " +
				"actually uses. The API refuses to write one, so this was set another way.",
		})
	}

	if wide := wideExemptions(in); len(wide) > 0 {
		out = append(out, Check{
			Section:  sectionClientAccess,
			Name:     "Broad rebinding exemption",
			Status:   StatusWarn,
			Summary:  "A policy exempts a range large enough to give back most of what the filter withholds.",
			Evidence: wide,
			Action: "Narrow the exemption to the addresses that are genuinely reachable by public " +
				"name. A whole /8 returns nearly all of the private address space to those clients.",
		})
	}

	if in.Dropped > 0 {
		out = append(out, Check{
			Section: sectionClientAccess,
			Name:    "Unreadable rebinding exemption",
			Status:  StatusFail,
			Summary: fmt.Sprintf("%d stored exemption(s) could not be parsed and are being ignored.", in.Dropped),
			Evidence: []string{
				"the affected policies are filtering a range their operator believes is exempt",
			},
			Action: "Re-save the exemptions on each policy. This should not be reachable — the " +
				"write path validates — so please report it.",
		})
	}
	return out
}

// defaultRouteExemptions names any policy exempting everything.
func defaultRouteExemptions(in RebindingInput) []string {
	var out []string
	for policyID, cidrs := range in.Exemptions {
		for _, raw := range cidrs {
			p, err := netip.ParsePrefix(strings.TrimSpace(raw))
			if err != nil || p.Bits() != 0 {
				continue
			}
			label := policyID
			if policyID == in.DefaultPolicyID {
				label += " (the default policy, so this covers every unmatched client)"
			}
			out = append(out, label+" exempts "+raw)
		}
	}
	sort.Strings(out)
	return out
}

// wideExemptions names exemptions broad enough to be worth a second look.
func wideExemptions(in RebindingInput) []string {
	var out []string
	for policyID, cidrs := range in.Exemptions {
		for _, raw := range cidrs {
			p, err := netip.ParsePrefix(strings.TrimSpace(raw))
			if err != nil || p.Bits() == 0 {
				continue
			}
			// Judged against the address family's own scale: a /8 of IPv4 is
			// broad, while a /8 of IPv6 is not a thing anybody writes and a
			// /32 of IPv6 is still enormous.
			limit := wideExemption
			if !p.Addr().Is4() {
				limit = 32
			}
			if p.Bits() <= limit {
				out = append(out, policyID+" exempts "+p.String())
			}
		}
	}
	sort.Strings(out)
	return out
}

func prefixStrings(ps []netip.Prefix) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.String())
	}
	return out
}
