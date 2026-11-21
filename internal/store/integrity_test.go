package store

import (
	"context"
	"strings"
	"testing"
)

func TestFeedRefreshPreservesLastGoodChecksumOnFailure(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	name, url := "Integrity feed", "https://example.org/intel.txt"
	f, err := st.CreateFeed(ctx, FeedInput{Name: &name, URL: &url})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RecordFeedRefresh(ctx, f.ID, FeedResult{
		Status: "ok", DomainCount: 4, ETag: `"v1"`, ContentSHA256: "goodhash",
		SourceURL: url, ParserAccepted: 4, ParserRejected: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordFeedRefresh(ctx, f.ID, FeedResult{
		Status: "error", Error: "HTTP 500", SourceURL: url,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetFeed(ctx, f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastGoodSHA256 != "goodhash" || got.ContentSHA256 != "goodhash" {
		t.Fatalf("last good lost on failure: %+v", got)
	}
	if got.ParserAccepted != 4 || got.ParserRejected != 1 {
		t.Fatalf("parser evidence lost: %+v", got)
	}
	if got.RefreshSourceURL != url {
		t.Fatalf("source url = %q", got.RefreshSourceURL)
	}
	if got.LastSuccess == nil || got.LastStatus != "error" {
		t.Fatalf("expected success time retained with error status: %+v", got)
	}
}

func TestJournalHashChainDetectsMutation(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	if err := st.EnsureAuditSchema(ctx); err != nil {
		t.Fatal(err)
	}
	id, err := st.BeginConfigChange(ctx, "session:admin", "patch", "policy/demo")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CompleteConfigChange(ctx, id, "complete", 200, []ConfigChange{{
		Resource: "policy:demo", Field: "name", Before: "a", After: "b",
	}}, ""); err != nil {
		t.Fatal(err)
	}
	ok, err := st.VerifyConfigHistory(ctx, "")
	if err != nil || !ok.OK || ok.Sealed != 1 {
		t.Fatalf("fresh chain: %+v %v", ok, err)
	}
	tip := ok.TipHash
	if _, err := st.DB().Exec(`UPDATE config_change_history SET changes='[{"resource":"policy:demo","field":"name","before":"a","after":"tampered"}]' WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	broken, err := st.VerifyConfigHistory(ctx, tip)
	if err != nil {
		t.Fatal(err)
	}
	// The stored tip digest can still match a checkpoint while the sealed
	// payload no longer hashes to that digest — that is the mutation case.
	if broken.OK {
		t.Fatalf("expected content failure: %+v", broken)
	}
	joined := strings.Join(broken.Breaks, ";")
	if !strings.Contains(joined, "entry_hash mismatch") {
		t.Fatalf("expected hash break, got %q", joined)
	}
}

func TestJournalHashChainLinksEntries(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	if err := st.EnsureAuditSchema(ctx); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		id, err := st.BeginConfigChange(ctx, "session:admin", "patch", "settings/demo")
		if err != nil {
			t.Fatal(err)
		}
		if err := st.CompleteConfigChange(ctx, id, "complete", 200, nil, ""); err != nil {
			t.Fatal(err)
		}
	}
	events, _, err := st.ListConfigChanges(ctx, 0, 10)
	if err != nil || len(events) != 3 {
		t.Fatalf("list: %v %d", err, len(events))
	}
	// Newest first: events[0] should chain from events[1].
	if events[0].PrevHash != events[1].EntryHash || events[1].PrevHash != events[2].EntryHash {
		t.Fatalf("chain links broken: %+v", events)
	}
	if events[2].PrevHash != JournalGenesisPrev {
		t.Fatalf("genesis prev = %q", events[2].PrevHash)
	}
	got, err := st.VerifyConfigHistory(ctx, events[0].EntryHash)
	if err != nil || !got.OK || got.TipMatches == nil || !*got.TipMatches {
		t.Fatalf("verify: %+v %v", got, err)
	}
}
