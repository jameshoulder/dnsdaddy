package diag

import (
	"fmt"

	"github.com/jameshoulder/dnsdaddy/internal/firstseen"
)

// FirstSeenInput describes the configured first-seen index.
type FirstSeenInput struct {
	// Enabled is dns.first_seen.enabled.
	Enabled bool
	// Rows is how many domains are indexed, and MaxRows the ceiling.
	Rows    int64
	MaxRows int
	// MaxNewPerMinute is the new-row budget.
	MaxNewPerMinute int
	// Evictions is how many rows have been recycled since start.
	Evictions uint64
	// Dropped counts observations not recorded, by reason.
	Dropped map[string]uint64
	// Available reports whether the index could be constructed at all. False
	// means enabled was set but no index exists — a wiring fault rather than a
	// configuration choice.
	Available bool
}

// nearCapacity is the fraction of max_rows at which an index is reported as
// filling up. At 80% an operator still has room to raise the ceiling before
// eviction starts rewriting what "first seen" means.
const nearCapacity = 0.8

// FirstSeen reports whether novelty is being recorded and whether the answer
// can still be trusted.
//
// The distinction this check exists to draw is between an index that is
// working and one that is full. A full index still answers, but it answers
// "new to this table" rather than "new to this network", and nothing about the
// response says so unless somebody looks here.
func FirstSeen(in FirstSeenInput) []Check {
	c := Check{Section: SectionSystem, Name: "First-seen domain index"}

	if !in.Enabled {
		c.Status = StatusWarn
		c.Summary = "Domain novelty is not recorded. \"Has this network ever asked for this " +
			"domain?\" can only be answered as far back as the query log is kept."
		c.Evidence = []string{"dns.first_seen.enabled is false"}
		c.Action = "Set dns.first_seen.enabled: true. The index observes only — it cannot " +
			"change an answer, an RCODE, or a block decision."
		return []Check{c}
	}

	if !in.Available {
		c.Status = StatusFail
		c.Summary = "The first-seen index is enabled but was not built, so nothing is being recorded."
		c.Evidence = []string{"dns.first_seen.enabled is true and no index is running"}
		c.Action = "This is a wiring fault rather than a setting. Check the startup log for a " +
			"store error and please report it."
		return []Check{c}
	}

	c.Status = StatusPass
	c.Summary = fmt.Sprintf("%d of at most %d registered domains indexed; at most %d new domains "+
		"are recorded per minute.", in.Rows, in.MaxRows, in.MaxNewPerMinute)
	c.Evidence = []string{
		"this index is kept outside the query-log retention window, so novelty survives a prune",
		fmt.Sprintf("%d row(s) recycled to stay within the ceiling", in.Evictions),
	}
	if dropped := in.Dropped[firstseen.DropInvalid]; dropped > 0 {
		// Not a problem: it is the count of names with no registered domain,
		// which on a network with a search suffix is most of them. Reported so
		// an operator comparing query volume against index growth is not left
		// wondering where the difference went.
		c.Evidence = append(c.Evidence, fmt.Sprintf(
			"%d name(s) had no registered domain and were not indexed — single labels, "+
				"private namespaces like .local, and address literals", dropped))
	}

	out := []Check{c}

	if in.MaxRows > 0 && float64(in.Rows) >= float64(in.MaxRows)*nearCapacity {
		out = append(out, Check{
			Section: SectionSystem,
			Name:    "First-seen index near capacity",
			Status:  StatusWarn,
			Summary: fmt.Sprintf("The index holds %d of %d rows. Past the ceiling it evicts the "+
				"stalest domains, and \"first seen\" starts meaning \"first seen since the row "+
				"was recycled\".", in.Rows, in.MaxRows),
			Evidence: []string{fmt.Sprintf("%.0f%% of dns.first_seen.max_rows", float64(in.Rows)/float64(in.MaxRows)*100)},
			Action: "Raise dns.first_seen.max_rows if the network genuinely touches this many " +
				"domains. If it does not, something is generating names — check the DGA and " +
				"NXDOMAIN findings.",
		})
	}

	if budget := in.Dropped[firstseen.DropBudget]; budget > 0 {
		out = append(out, Check{
			Section: SectionSystem,
			Name:    "First-seen budget reached",
			Status:  StatusWarn,
			Summary: fmt.Sprintf("%d new domain(s) went unrecorded because the per-minute budget "+
				"was spent.", budget),
			Evidence: []string{fmt.Sprintf("dns.first_seen.max_new_per_minute is %d", in.MaxNewPerMinute)},
			Action: "A network discovering this many new registered domains a minute is either " +
				"much busier than the default assumes or is generating names. Raise the budget " +
				"only once you know which.",
		})
	}

	if full := in.Dropped[firstseen.DropFull]; full > 0 {
		out = append(out, Check{
			Section: SectionSystem,
			Name:    "First-seen observations dropped",
			Status:  StatusWarn,
			Summary: fmt.Sprintf("%d observation(s) were dropped because the index buffer was full.", full),
			Evidence: []string{
				"the index drops rather than making a lookup wait, so this cost coverage and not latency",
			},
			Action: "Expected under a burst. Sustained, it means the writer cannot keep up with " +
				"query volume and the index is undercounting.",
		})
	}

	return out
}
