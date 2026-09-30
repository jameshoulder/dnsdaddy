package dnsserver

import (
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const activityWindowSeconds = 60

type activityOutcome string

const (
	activityAnswered    activityOutcome = "answered"
	activityBlocked     activityOutcome = "blocked"
	activityError       activityOutcome = "error"
	activityRefused     activityOutcome = "refused"
	activityRateLimited activityOutcome = "rate_limited"
	activityInvalid     activityOutcome = "invalid"
)

// ActivityCounts counts messages handled by the resolver, including requests
// rejected before query logging. Completed is the sum of the six outcomes;
// Cached is a subset of Answered. An answer includes NXDOMAIN, which is a
// successful DNS lookup of a name that does not exist.
type ActivityCounts struct {
	Received    uint64 `json:"received"`
	Completed   uint64 `json:"completed"`
	Answered    uint64 `json:"answered"`
	Blocked     uint64 `json:"blocked"`
	Cached      uint64 `json:"cached"`
	Errors      uint64 `json:"errors"`
	Refused     uint64 `json:"refused"`
	RateLimited uint64 `json:"rateLimited"`
	Invalid     uint64 `json:"invalid"`
}

func (c *ActivityCounts) add(other ActivityCounts) {
	c.Received += other.Received
	c.Completed += other.Completed
	c.Answered += other.Answered
	c.Blocked += other.Blocked
	c.Cached += other.Cached
	c.Errors += other.Errors
	c.Refused += other.Refused
	c.RateLimited += other.RateLimited
	c.Invalid += other.Invalid
}

func (c *ActivityCounts) finish(outcome activityOutcome, cached bool) {
	c.Completed++
	switch outcome {
	case activityAnswered:
		c.Answered++
		if cached {
			c.Cached++
		}
	case activityBlocked:
		c.Blocked++
	case activityRefused:
		c.Refused++
	case activityRateLimited:
		c.RateLimited++
	case activityInvalid:
		c.Invalid++
	default:
		c.Errors++
	}
}

// RecentActivity is a fixed, one-minute window with one-second resolution.
// Arrivals and completions are counted at their respective times, so a query
// that crosses the window boundary can complete without an arrival in it.
type RecentActivity struct {
	ActivityCounts
	WindowSeconds    int     `json:"windowSeconds"`
	QueriesPerSecond float64 `json:"queriesPerSecond"`
}

// LiveActivity is a bounded in-memory snapshot, independent of per-query logs,
// rollup flushing and privacy settings. It contains no names or client IPs.
// Completed means the handler produced a response, not that a remote client
// received it. Status describes observed traffic, not a connectivity probe.
type LiveActivity struct {
	Available      bool           `json:"available"`
	Status         string         `json:"status"`
	StartedAt      time.Time      `json:"startedAt"`
	MeasuredAt     time.Time      `json:"measuredAt"`
	LastQueryAt    *time.Time     `json:"lastQueryAt"`
	LastResponseAt *time.Time     `json:"lastResponseAt"`
	LastOutcome    string         `json:"lastOutcome"`
	LastRcode      string         `json:"lastRcode"`
	Inflight       uint64         `json:"inflight"`
	SinceStart     ActivityCounts `json:"sinceStart"`
	Recent         RecentActivity `json:"recent"`
}

type activityBucket struct {
	second int64
	counts ActivityCounts
}

// activityTracker keeps constant memory and does no I/O on the query path.
// The short critical sections make received/completed/inflight internally
// consistent even while several listeners are answering concurrently.
type activityTracker struct {
	mu             sync.Mutex
	startedAt      time.Time
	lastQueryAt    time.Time
	lastResponseAt time.Time
	lastOutcome    activityOutcome
	lastRcode      string
	inflight       uint64
	total          ActivityCounts
	buckets        [activityWindowSeconds]activityBucket
}

func (a *activityTracker) bucket(now time.Time) *ActivityCounts {
	second := now.Unix()
	index := (second%activityWindowSeconds + activityWindowSeconds) % activityWindowSeconds
	b := &a.buckets[index]
	if b.second != second {
		*b = activityBucket{second: second}
	}
	return &b.counts
}

func (a *activityTracker) begin(now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.startedAt.IsZero() {
		a.startedAt = now
	}
	// The caller samples time before taking the lock. A delayed goroutine
	// must not replace a later event's timestamp with an older one.
	if a.lastQueryAt.IsZero() || now.After(a.lastQueryAt) {
		a.lastQueryAt = now
	}
	a.inflight++
	a.total.Received++
	a.bucket(now).Received++
}

func (a *activityTracker) finish(now time.Time, outcome activityOutcome, cached bool, response *dns.Msg) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.inflight--
	if a.lastResponseAt.IsZero() || now.After(a.lastResponseAt) {
		a.lastResponseAt = now
		a.lastOutcome = outcome
		a.lastRcode = ""
		if response != nil {
			a.lastRcode = dns.RcodeToString[response.Rcode]
			if a.lastRcode == "" {
				a.lastRcode = "RCODE" + strconv.Itoa(response.Rcode)
			}
		}
	}
	a.total.finish(outcome, cached)
	a.bucket(now).finish(outcome, cached)
}

func activityTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

func (a *activityTracker) snapshot(now time.Time) LiveActivity {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := LiveActivity{
		Available: true, Status: "active", StartedAt: a.startedAt.UTC(), MeasuredAt: now.UTC(),
		LastQueryAt: activityTime(a.lastQueryAt), LastResponseAt: activityTime(a.lastResponseAt),
		LastOutcome: string(a.lastOutcome), LastRcode: a.lastRcode,
		Inflight: a.inflight, SinceStart: a.total,
		Recent: RecentActivity{WindowSeconds: activityWindowSeconds},
	}
	second := now.Unix()
	for _, b := range a.buckets {
		if age := second - b.second; age >= 0 && age < activityWindowSeconds {
			s.Recent.ActivityCounts.add(b.counts)
		}
	}
	s.Recent.QueriesPerSecond = float64(s.Recent.Received) / activityWindowSeconds
	good := s.Recent.Answered + s.Recent.Blocked
	bad := s.Recent.Errors + s.Recent.Refused + s.Recent.RateLimited + s.Recent.Invalid
	switch {
	case s.SinceStart.Received == 0:
		s.Status = "waiting"
	case s.Recent.Received == 0 && s.Recent.Completed == 0 && s.Inflight == 0:
		s.Status = "idle"
	case bad > 0 && good > 0:
		s.Status = "degraded"
	case bad > 0 && bad == s.Recent.Refused:
		s.Status = "refused"
	case bad > 0:
		s.Status = "failing"
	}
	return s
}

// LiveActivity returns only observed handler activity. Reading it performs no
// DNS lookup, requires no database query, and never enables query logging.
func (h *Handler) LiveActivity() LiveActivity {
	if h == nil {
		return LiveActivity{Status: "unavailable"}
	}
	return h.activity.snapshot(time.Now())
}
