package store

import (
	"context"
	"testing"
	"time"
)

func TestObserveRegisteredDomainPreservesFirstSeen(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	t1 := t0.Add(48 * time.Hour)

	if err := st.ObserveRegisteredDomain(ctx, "Evil.Example", t0); err != nil {
		t.Fatal(err)
	}
	if err := st.ObserveRegisteredDomain(ctx, "evil.example", t1); err != nil {
		t.Fatal(err)
	}
	row, err := st.LookupRegisteredDomain(ctx, "evil.example")
	if err != nil {
		t.Fatal(err)
	}
	if !row.FirstSeen.Equal(t0) {
		t.Fatalf("firstSeen = %v, want %v", row.FirstSeen, t0)
	}
	if !row.LastSeen.Equal(t1) {
		t.Fatalf("lastSeen = %v, want %v", row.LastSeen, t1)
	}
	if row.QueryCount != 2 {
		t.Fatalf("queryCount = %d, want 2", row.QueryCount)
	}
}

func TestObserveRegisteredDomainKeepsEarlierFirstSeenOutOfOrder(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	earlier := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	later := earlier.Add(time.Minute)

	// Later observation arrives first (fast resolve finishing before a slow one).
	if err := st.ObserveRegisteredDomain(ctx, "example.com", later); err != nil {
		t.Fatal(err)
	}
	if err := st.ObserveRegisteredDomain(ctx, "example.com", earlier); err != nil {
		t.Fatal(err)
	}
	row, err := st.LookupRegisteredDomain(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !row.FirstSeen.Equal(earlier) {
		t.Fatalf("firstSeen = %v, want earlier %v", row.FirstSeen, earlier)
	}
	if !row.LastSeen.Equal(later) {
		t.Fatalf("lastSeen = %v, want later %v", row.LastSeen, later)
	}
}

func TestClientIdentityUnknownWithoutRow(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	c, err := st.ClientIdentity(ctx, "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	if c.Confidence != IdentityConfidenceUnknown || c.Name != "" {
		t.Fatalf("identity = %+v, want unknown with empty name", c)
	}
	if err := st.SetClientName(ctx, "192.0.2.10", "laptop"); err != nil {
		t.Fatal(err)
	}
	c, err = st.ClientIdentity(ctx, "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "laptop" || c.Confidence != IdentityConfidenceOperator || c.Source != IdentitySourceManual {
		t.Fatalf("identity = %+v", c)
	}
}
