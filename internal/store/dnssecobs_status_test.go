package store

import (
	"context"
	"testing"
	"time"
)

func TestDNSSECPopulationsAndSpan(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if _, _, n, err := st.DNSSECObservationSpan(ctx); err != nil || n != 0 {
		t.Fatalf("empty span: %d rows, %v", n, err)
	}
	row := func(id string, at time.Time, res string, cached bool, up, status, dis string) DNSSECObservation {
		return DNSSECObservation{ID: id, Time: at, Domain: "x.example", QType: "A", Cached: cached,
			Upstream: up, Status: status, Disagreement: dis, Resolution: res}
	}
	if err := st.InsertDNSSECObservations(ctx, []DNSSECObservation{
		row("a", now.Add(-2*time.Hour), "native", false, "validated", "secure", ""),
		row("b", now.Add(-time.Hour), "native", false, "validated", "bogus", "local_bogus_upstream_validated"),
		row("c", now.Add(-time.Hour), "native", true, "validated", "bogus", "local_bogus_upstream_validated"),
		row("d", now.Add(-48*time.Hour), "forwarded", false, "validated", "secure", ""),
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	cells, err := st.DNSSECPopulationsSince(ctx, now.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("DNSSECPopulationsSince: %v", err)
	}
	var total int64
	seen := map[string]int64{}
	for _, c := range cells {
		total += c.Count
		key := c.Resolution + "/" + map[bool]string{true: "cached", false: "live"}[c.Cached] + "/" + c.Status
		seen[key] += c.Count
	}
	if total != 3 {
		t.Errorf("window holds %d rows, want 3 (the forwarded one is older)", total)
	}
	if seen["native/live/bogus"] != 1 || seen["native/cached/bogus"] != 1 || seen["native/live/secure"] != 1 {
		t.Errorf("cells = %v", seen)
	}

	first, last, n, err := st.DNSSECObservationSpan(ctx)
	if err != nil || n != 4 {
		t.Fatalf("span: %d rows, %v", n, err)
	}
	if !first.Equal(now.Add(-48*time.Hour).Truncate(time.Millisecond)) || !last.Equal(now.Add(-time.Hour).Truncate(time.Millisecond)) {
		t.Errorf("span = %v → %v", first, last)
	}
}
