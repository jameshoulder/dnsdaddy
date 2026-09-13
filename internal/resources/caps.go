package resources

// Caps is how much of each bounded thing DNS Daddy will hold at a given size.
//
// Every field here is a ceiling on state, never a switch on behaviour. Turning
// the same binary from the 1 GB size to the 4 GB size changes how much history
// and how many clients it remembers; it does not change what it blocks, what
// it answers, or which engines run. That separation is the reason an operator
// can change size without re-reading the security documentation.
//
// The numbers are measured rather than guessed. See TestTheMeasuredBudgetFits
// in this package, which builds each structure at its cap and reports the heap
// it costs, and docs/architecture.md, which publishes the resulting table.
type Caps struct {
	// AnswerCacheEntries bounds the answer cache. Measured at roughly 430
	// bytes per entry for a single-address answer, so this is the largest
	// thing on the list after the blocklist itself.
	AnswerCacheEntries int

	// RateLimitMaxClients bounds the per-client limiter's table, at roughly 96
	// bytes per tracked client.
	RateLimitMaxClients int

	// FirstSeenMaxRows and FirstSeenMaxNewPerMinute bound the first-seen
	// domain index. These are rows in the database rather than memory, so they
	// are a disk figure — but they are also the thing an attacker can drive by
	// asking for names nobody has heard of, which is why the smallest size
	// holds fewer of them and admits them more slowly.
	FirstSeenMaxRows         int
	FirstSeenMaxNewPerMinute int

	// QueryLogRetentionDays bounds the query log on disk. The reference
	// deployment has 25 GB, and query rows are the only table that grows with
	// traffic rather than with configuration.
	QueryLogRetentionDays int

	// DetectorTrackedNumerator and DetectorTrackedDenominator scale every
	// behavioural detector's table against the bounds documented in
	// internal/detect.
	//
	// A fraction rather than a float because these must be reproducible: a
	// detector bound that comes out at 4095 on one machine and 4096 on another
	// would make the published budget table a lie in the least useful way.
	//
	// Scaling the table is not scaling the detector. Windows, thresholds and
	// volume gates are untouched, so a finding means the same thing at every
	// size; what changes is how many distinct clients and domains can be
	// watched at once before the least recently seen are dropped.
	DetectorTrackedNumerator   int
	DetectorTrackedDenominator int

	// SQLiteCacheMB is the database's own page cache.
	//
	// Until this existed the driver's default applied, which is about 2 MB —
	// far too little for a 4 GB machine and, more to the point, never stated
	// anywhere an operator could find it.
	SQLiteCacheMB int
}

// capsByProfile is the whole table, in one place, so that the answer to "what
// does this size actually do?" is one screen of code rather than a search.
var capsByProfile = map[Profile]Caps{
	ProfileTiny: {
		AnswerCacheEntries:         10_000,
		RateLimitMaxClients:        8_192,
		FirstSeenMaxRows:           20_000,
		FirstSeenMaxNewPerMinute:   60,
		QueryLogRetentionDays:      3,
		DetectorTrackedNumerator:   1,
		DetectorTrackedDenominator: 4,
		SQLiteCacheMB:              16,
	},
	ProfileSmall: {
		AnswerCacheEntries:         50_000,
		RateLimitMaxClients:        65_536,
		FirstSeenMaxRows:           100_000,
		FirstSeenMaxNewPerMinute:   200,
		QueryLogRetentionDays:      7,
		DetectorTrackedNumerator:   1,
		DetectorTrackedDenominator: 1,
		SQLiteCacheMB:              32,
	},
	ProfileFull: {
		AnswerCacheEntries:         150_000,
		RateLimitMaxClients:        131_072,
		FirstSeenMaxRows:           250_000,
		FirstSeenMaxNewPerMinute:   400,
		QueryLogRetentionDays:      14,
		DetectorTrackedNumerator:   2,
		DetectorTrackedDenominator: 1,
		SQLiteCacheMB:              128,
	},
}

// CapsFor returns the ceilings for a size.
//
// An unrecognised size gets the smallest set. Nothing should reach here with
// one — configuration validation refuses it and Resolve only ever returns the
// three — but if something did, running small is the failure that costs memory
// rather than the failure that loses the machine.
func CapsFor(p Profile) Caps {
	if c, ok := capsByProfile[p]; ok {
		return c
	}
	return capsByProfile[ProfileTiny]
}

// DetectorTracked scales one detector's documented bound to this size, with a
// floor so that a fraction can never produce a detector that tracks nothing.
func (c Caps) DetectorTracked(documented int) int {
	den := c.DetectorTrackedDenominator
	if den <= 0 {
		den = 1
	}
	num := c.DetectorTrackedNumerator
	if num <= 0 {
		num = 1
	}
	scaled := documented * num / den
	const floor = 256
	if scaled < floor {
		return floor
	}
	return scaled
}

// ExpensiveModes are the features that a larger machine does NOT switch on.
//
// They are listed here rather than left implicit because the rule they encode
// is easy to erode one commit at a time. Decision history and local DNSSEC
// validation cost real memory, which is why the smallest size leaves them off
// — but they are also choices about what the software does, and about what is
// written down concerning the people using the network. Moving to a bigger
// machine is not consent to either. Both stay exactly where the operator and
// the first-run record left them, at every size.
//
// Nothing in this package reads this list. It exists so that the constraint
// has a name, a place, and a test.
var ExpensiveModes = []string{
	"decision history",
	"local DNSSEC validation (Learn)",
	"additional blocking categories",
}
