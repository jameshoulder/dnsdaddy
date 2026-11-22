package firstseen

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/store"
)

func TestRecorderWritesRegisteredDomain(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	r := New(st, Options{QueueSize: 8})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	r.Record(Event{Time: at, Domain: "www.example.co.uk"})
	r.Record(Event{Time: at.Add(time.Minute), Domain: "printer.corp.local"}) // skipped

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, _, written, _, skipped := r.Stats()
		if written >= 1 && skipped >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done

	row, err := st.LookupRegisteredDomain(context.Background(), "example.co.uk")
	if err != nil {
		t.Fatal(err)
	}
	if row.RegisteredDomain != "example.co.uk" {
		t.Fatalf("got %+v", row)
	}
}
