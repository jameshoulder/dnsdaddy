package recursive_test

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// A server that recovers is used again.
//
// Penalties decay. Never retrying a failed server would strand a zone whose
// servers all failed once during an outage of ours, and would hand anyone who
// can drop packets to one server the power to pin all this resolver's traffic
// onto another.
func TestAPenalisedServerIsTriedAgainOnceItRecovers(t *testing.T) {
	r, h := hierarchy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := r.Resolve(ctx, "www.example.com.", dns.TypeA); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	before := len(h.QueriesTo("example.com."))
	if before == 0 {
		t.Fatal("the leaf zone was never asked anything")
	}

	// A second name, which must still reach the same zone. If a single
	// success or failure could take a server permanently out of rotation,
	// this would not resolve.
	if _, err := r.Resolve(ctx, "other.example.com.", dns.TypeA); err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if after := len(h.QueriesTo("example.com.")); after <= before {
		t.Error("the second query never reached the zone's servers")
	}
}
