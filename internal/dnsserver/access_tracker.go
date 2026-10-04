package dnsserver

import (
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const accessCapacity = 64
const accessWindow = 5 * time.Minute

// AccessEntry is short-lived operational evidence, never a DNS query log.
// No domain, token, request body or reverse-DNS lookup enters this structure.
// A source address is observed, not authenticated: UDP sources can be spoofed.
type AccessEntry struct {
	Address        string    `json:"address"`
	CIDR           string    `json:"cidr"`
	FirstRefusedAt time.Time `json:"firstRefusedAt"`
	LastRefusedAt  time.Time `json:"lastRefusedAt"`
	LastResponseAt time.Time `json:"lastResponseAt"`
	LastOutcome    string    `json:"lastOutcome"`
	Refused        uint64    `json:"refused"`
	Answered       uint64    `json:"answered"`
	Blocked        uint64    `json:"blocked"`
	Errors         uint64    `json:"errors"`
	Protocols      []string  `json:"protocols"`
}

type AccessSnapshot struct {
	Enabled       bool          `json:"enabled"`
	WindowSeconds int           `json:"windowSeconds"`
	Capacity      int           `json:"capacity"`
	Dropped       uint64        `json:"dropped"`
	Evicted       uint64        `json:"evicted"`
	Entries       []AccessEntry `json:"entries"`
}

type accessSlot struct {
	addr                               netip.Addr
	firstRefused                       time.Time
	lastRefused                        time.Time
	lastResponse                       time.Time
	outcome                            string
	protocols                          uint8
	refused, answered, blocked, errors uint64
}

// accessTracker has a fixed allocation and never waits on the DNS hot path.
// API reads may take the lock; contended observations are dropped and counted.
// Only a refusal creates an entry. Subsequent accepted answers to that same
// source establish recovery; ordinary allowed traffic creates no IP inventory.
// Entries expire relative to the last refusal, not ongoing successful traffic.
// Expired slots are erased on the next observation or read.
type accessTracker struct {
	mu      sync.Mutex
	slots   [accessCapacity]accessSlot
	active  atomic.Bool
	dropped atomic.Uint64
	evicted atomic.Uint64
}

func accessProtocol(s string) uint8 {
	switch s {
	case "udp":
		return 1
	case "tcp":
		return 2
	case "dot":
		return 4
	case "doh":
		return 8
	}
	return 16
}

func (a *accessTracker) record(now time.Time, addr netip.Addr, protocol, outcome string) {
	if outcome != "refused" && !a.active.Load() {
		return
	}
	addr = addr.Unmap().WithZone("")
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() {
		return
	}
	switch outcome {
	case "refused", "answered", "blocked", "error":
	default:
		return
	}
	if !a.mu.TryLock() {
		a.dropped.Add(1)
		return
	}
	defer a.mu.Unlock()
	slot, free, oldest := -1, -1, 0
	for i := range a.slots {
		s := &a.slots[i]
		if s.addr.IsValid() && !now.Before(s.lastRefused.Add(accessWindow)) {
			*s = accessSlot{}
		}
		if s.addr == addr {
			slot = i
		}
		if !s.addr.IsValid() {
			if free < 0 {
				free = i
			}
		} else if a.slots[oldest].lastRefused.After(s.lastRefused) {
			oldest = i
		}
	}
	if slot < 0 {
		if outcome != "refused" {
			return
		}
		slot = free
		if slot < 0 {
			slot = oldest
			a.evicted.Add(1)
		}
		a.slots[slot] = accessSlot{addr: addr, firstRefused: now, lastRefused: now}
		a.active.Store(true)
	}
	s := &a.slots[slot]
	s.protocols |= accessProtocol(protocol)
	if !now.Before(s.lastResponse) {
		s.lastResponse, s.outcome = now, outcome
	}
	switch outcome {
	case "refused":
		s.refused++
		if now.After(s.lastRefused) {
			s.lastRefused = now
		}
	case "answered":
		s.answered++
	case "blocked":
		s.blocked++
	case "error":
		s.errors++
	}
}

func (a *accessTracker) snapshot(now time.Time, enabled bool) AccessSnapshot {
	out := AccessSnapshot{Enabled: enabled, WindowSeconds: int(accessWindow / time.Second), Capacity: accessCapacity, Entries: []AccessEntry{}, Dropped: a.dropped.Load(), Evicted: a.evicted.Load()}
	a.mu.Lock()
	for i := range a.slots {
		s := &a.slots[i]
		if !enabled || s.addr.IsValid() && !now.Before(s.lastRefused.Add(accessWindow)) {
			*s = accessSlot{}
		}
		if !s.addr.IsValid() {
			continue
		}
		protocols := []string{}
		for j, name := range []string{"udp", "tcp", "dot", "doh", "other"} {
			if s.protocols&(1<<j) != 0 {
				protocols = append(protocols, name)
			}
		}
		out.Entries = append(out.Entries, AccessEntry{Address: s.addr.String(), CIDR: netip.PrefixFrom(s.addr, s.addr.BitLen()).String(), FirstRefusedAt: s.firstRefused.UTC(), LastRefusedAt: s.lastRefused.UTC(), LastResponseAt: s.lastResponse.UTC(), LastOutcome: s.outcome, Refused: s.refused, Answered: s.answered, Blocked: s.blocked, Errors: s.errors, Protocols: protocols})
	}
	a.active.Store(len(out.Entries) != 0)
	a.mu.Unlock()
	sort.Slice(out.Entries, func(i, j int) bool { return out.Entries[i].LastResponseAt.After(out.Entries[j].LastResponseAt) })
	return out
}
