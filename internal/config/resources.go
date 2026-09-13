package config

import (
	"fmt"
	"strings"

	"github.com/jameshoulder/dnsdaddy/internal/resources"
)

// Resources is how large a machine DNS Daddy should size itself for.
//
// An operator who never opens this block is the success case. The default
// looks at the machine and picks; everything below exists for the cases where
// that guess is wrong, or where somebody is deliberately running DNS Daddy
// alongside other things and wants to say how much of the box it may have.
type Resources struct {
	// Profile is "auto", "tiny", "small" or "full".
	//
	// Stored as the machine-readable word so that configuration, the database
	// record and the API all agree on one spelling. Everything an operator
	// reads renders it through resources.Profile.Label, which turns these into
	// "Automatic (recommended)", "1 GB machine", "2 GB machine" and
	// "4 GB+ machine".
	Profile string `yaml:"profile"`

	// MemoryMB says how much memory DNS Daddy may assume it has, in megabytes,
	// instead of working it out. Zero means work it out.
	MemoryMB int `yaml:"memory_mb"`

	// ReservedMB is how much memory to leave for the operating system and
	// everything else on the machine. Zero means use the default, which is
	// larger inside a container that has no memory limit of its own.
	ReservedMB int `yaml:"reserved_mb"`
}

// SizeProfile is the configured size as a typed value.
func (r Resources) SizeProfile() resources.Profile {
	p := resources.Profile(strings.ToLower(strings.TrimSpace(r.Profile)))
	if p == "" {
		return resources.ProfileAuto
	}
	return p
}

// DetectOptions turns the configuration into a detection run.
func (r Resources) DetectOptions() resources.Options {
	return resources.Options{MemoryMB: r.MemoryMB, ReservedMB: r.ReservedMB}
}

// validateResources refuses a size nobody can act on.
//
// A misspelled size is an error rather than a fallback to automatic, because
// the two failures look identical afterwards — a machine running the smallest
// caps because it was told to and one running them because "smal" was not a
// word — and only one of them is something the operator wants to know about.
func validateResources(r Resources) error {
	if p := r.SizeProfile(); !p.Valid() {
		return fmt.Errorf("resources.profile: %q is not a size. Use auto (recommended), "+
			"tiny for a 1 GB machine, small for 2 GB, or full for 4 GB and above", r.Profile)
	}
	if r.MemoryMB < 0 {
		return fmt.Errorf("resources.memory_mb: %d cannot be negative", r.MemoryMB)
	}
	if r.MemoryMB > 0 && r.MemoryMB < 256 {
		return fmt.Errorf("resources.memory_mb: %d MB is not enough to run a resolver. "+
			"Leave it at 0 to work it out from the machine", r.MemoryMB)
	}
	if r.ReservedMB < 0 {
		return fmt.Errorf("resources.reserved_mb: %d cannot be negative", r.ReservedMB)
	}
	if r.MemoryMB > 0 && r.ReservedMB >= r.MemoryMB {
		return fmt.Errorf("resources.reserved_mb (%d) leaves nothing of resources.memory_mb (%d) "+
			"for DNS Daddy itself", r.ReservedMB, r.MemoryMB)
	}
	return nil
}

// operatorCeilings remembers which of the size-controlled ceilings the
// operator set themselves.
//
// It is captured once, at load, by comparing the loaded configuration against
// the defaults: a value that differs from the default is one somebody wrote,
// in the file or in the environment. That is not a perfect test — writing the
// default value explicitly is indistinguishable from not writing it — but it
// is exactly right in the case that matters, and wrong only where being wrong
// changes nothing.
//
// Without it, applying a size would silently discard a deliberate setting. An
// operator who lowered first_seen.max_rows because their disk is nearly full
// would find it raised again by a VPS upgrade, which is precisely the kind of
// surprise this whole feature exists to avoid.
type operatorCeilings struct {
	answerCache      bool
	rateLimitClients bool
	firstSeenRows    bool
	firstSeenNew     bool
	retentionDays    bool
}

// captureOperatorCeilings records which ceilings differ from the defaults.
// Called by Load once the file and the environment have both been read.
func captureOperatorCeilings(c *Config) {
	d := Default()
	c.ceilings = operatorCeilings{
		answerCache:      c.Cache.MaxEntries != d.Cache.MaxEntries,
		rateLimitClients: c.DNS.RateLimit.MaxClients != d.DNS.RateLimit.MaxClients,
		firstSeenRows:    c.DNS.FirstSeen.MaxRows != d.DNS.FirstSeen.MaxRows,
		firstSeenNew:     c.DNS.FirstSeen.MaxNewPerMinute != d.DNS.FirstSeen.MaxNewPerMinute,
		retentionDays:    c.Log.RetentionDays != d.Log.RetentionDays,
	}
}

// ApplySize lowers or raises the ceilings on state to suit a machine size, and
// reports in plain words what it changed.
//
// # What it touches
//
// Ceilings only: how many answers are cached, how many clients the rate
// limiter remembers, how many domains the first-seen index holds and how fast
// new ones are admitted, how long query rows are kept, how much the database
// may cache, and how many things each behavioural detector watches at once.
//
// # What it does not touch, ever
//
// Whether anything is switched on. The protection path — filtering, the client
// ACL, the rate limiter, the rebinding filter — runs identically at every
// size. Decision history and local DNSSEC validation stay wherever the
// operator and the first-run record left them: moving to a bigger machine is
// not consent to start recording what a network resolves, and moving to a
// smaller one is not a reason to stop filtering.
//
// It also leaves alone any ceiling the operator set themselves. See
// operatorCeilings for how that is decided and why.
func (c *Config) ApplySize(p resources.Profile) []string {
	caps := resources.CapsFor(p)
	var changed []string

	note := func(format string, args ...any) {
		changed = append(changed, fmt.Sprintf(format, args...))
	}

	if !c.ceilings.answerCache && c.Cache.MaxEntries != caps.AnswerCacheEntries {
		note("answers cached: %s", countChange(c.Cache.MaxEntries, caps.AnswerCacheEntries))
		c.Cache.MaxEntries = caps.AnswerCacheEntries
	}
	if !c.ceilings.rateLimitClients && c.DNS.RateLimit.MaxClients != caps.RateLimitMaxClients {
		note("clients the rate limiter remembers: %s",
			countChange(c.DNS.RateLimit.MaxClients, caps.RateLimitMaxClients))
		c.DNS.RateLimit.MaxClients = caps.RateLimitMaxClients
	}
	if !c.ceilings.firstSeenRows && c.DNS.FirstSeen.MaxRows != caps.FirstSeenMaxRows {
		note("domains remembered as seen before: %s",
			countChange(c.DNS.FirstSeen.MaxRows, caps.FirstSeenMaxRows))
		c.DNS.FirstSeen.MaxRows = caps.FirstSeenMaxRows
	}
	if !c.ceilings.firstSeenNew && c.DNS.FirstSeen.MaxNewPerMinute != caps.FirstSeenMaxNewPerMinute {
		note("new domains recorded per minute: %s",
			countChange(c.DNS.FirstSeen.MaxNewPerMinute, caps.FirstSeenMaxNewPerMinute))
		c.DNS.FirstSeen.MaxNewPerMinute = caps.FirstSeenMaxNewPerMinute
	}
	if !c.ceilings.retentionDays && c.Log.RetentionDays != caps.QueryLogRetentionDays {
		note("query history kept: %d days, was %d", caps.QueryLogRetentionDays, c.Log.RetentionDays)
		c.Log.RetentionDays = caps.QueryLogRetentionDays
	}
	// The database's page cache has no operator setting to preserve: it is
	// derived from the size and nothing else.
	if c.DatabaseCacheMB != caps.SQLiteCacheMB {
		note("database memory: %d MB, was %d MB", caps.SQLiteCacheMB, c.DatabaseCacheMB)
		c.DatabaseCacheMB = caps.SQLiteCacheMB
	}
	return changed
}

// KeptByOperator lists, in words, the ceilings a size left alone because the
// operator had set them. Shown under the doctor check so that "the size says
// 20,000 but this box holds 5,000" is explained rather than confusing.
func (c *Config) KeptByOperator() []string {
	var out []string
	if c.ceilings.answerCache {
		out = append(out, fmt.Sprintf("answers cached: %s, as you set it", thousands(c.Cache.MaxEntries)))
	}
	if c.ceilings.rateLimitClients {
		out = append(out, fmt.Sprintf("clients the rate limiter remembers: %s, as you set it",
			thousands(c.DNS.RateLimit.MaxClients)))
	}
	if c.ceilings.firstSeenRows {
		out = append(out, fmt.Sprintf("domains remembered as seen before: %s, as you set it",
			thousands(c.DNS.FirstSeen.MaxRows)))
	}
	if c.ceilings.firstSeenNew {
		out = append(out, fmt.Sprintf("new domains recorded per minute: %s, as you set it",
			thousands(c.DNS.FirstSeen.MaxNewPerMinute)))
	}
	if c.ceilings.retentionDays {
		out = append(out, fmt.Sprintf("query history kept: %d days, as you set it", c.Log.RetentionDays))
	}
	return out
}

// countChange renders one ceiling move the way an operator reads it.
func countChange(from, to int) string {
	return fmt.Sprintf("%s, was %s", thousands(to), thousands(from))
}

// thousands groups digits so a long number is readable at a glance.
func thousands(n int) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	for i, r := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// LimitsInForce describes, in words, the ceilings this configuration is
// running. One line each, for the block doctor prints under the machine size.
//
// Deliberately not a dump of settings. An operator reading a doctor report
// wants to know how much history they have and how many clients are watched,
// not which YAML key holds the number.
func (c *Config) LimitsInForce() []string {
	out := []string{
		fmt.Sprintf("answers cached: %s", thousands(c.Cache.MaxEntries)),
		fmt.Sprintf("query history kept: %d days", c.Log.RetentionDays),
		fmt.Sprintf("clients the rate limiter remembers: %s", thousands(c.DNS.RateLimit.MaxClients)),
		fmt.Sprintf("database memory: %d MB", c.DatabaseCacheMB),
	}
	if c.DNS.FirstSeen.Enabled {
		out = append(out, fmt.Sprintf("domains remembered as seen before: %s",
			thousands(c.DNS.FirstSeen.MaxRows)))
	} else {
		out = append(out, "domains remembered as seen before: off")
	}
	out = append(out, "decision history: "+onOff(c.Log.DecisionRecords))
	out = append(out, "local DNSSEC Learn: "+onOff(c.DNS.LocalDNSSECValidation == LocalDNSSECObserve))
	return out
}

// onOff renders a switch the way a person reads one.
func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}
