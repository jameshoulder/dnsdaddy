package dnsserver

import (
	"sync/atomic"

	"github.com/jameshoulder/dnsdaddy/internal/rebind"
)

// rebindClassCounts counts withheld addresses by class.
//
// A fixed array rather than a map, indexed by the position of the class in
// rebind.Classes(). The label set on the metric this feeds has to be closed —
// it is derived from addresses an attacker chooses to publish — and a fixed
// array makes that structural rather than a convention somebody has to
// remember. A class that is not in the list is counted as "other" rather than
// creating a series.
type rebindClassCounts struct {
	n [8]atomic.Uint64
}

func classIndex(c rebind.Class) int {
	for i, known := range rebind.Classes() {
		if known == c {
			return i
		}
	}
	// Unreachable while classify only returns members of Classes(), and
	// harmless if it ever does not: the count lands on the last slot, which is
	// reported as "other".
	return len(rebind.Classes()) - 1
}

func (r *rebindClassCounts) observe(removed []rebind.Removed) {
	for _, rr := range removed {
		r.n[classIndex(rr.Class)].Add(1)
	}
}

// counts returns the per-class totals in the order rebind.Classes() gives,
// so a caller can emit every series including the ones sitting at zero.
func (r *rebindClassCounts) counts() map[rebind.Class]uint64 {
	out := make(map[rebind.Class]uint64, len(rebind.Classes()))
	for i, c := range rebind.Classes() {
		out[c] = r.n[i].Load()
	}
	return out
}
