package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestStage5BCommittedWarningPreservesSuccessEvidence(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	ctx := context.Background()
	name, url, category, format := "synthetic", "https://fixture.example/list", "malware", "domains"
	f, e := s.CreateFeed(ctx, FeedInput{Name: &name, URL: &url, Category: &category, Format: &format})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.RecordFeedRefresh(ctx, f.ID, FeedResult{Committed: true, Status: "committed-warning", Error: "feed cache/index committed; durability unconfirmed", ETag: "synthetic-v1", DomainCount: 3}); e != nil {
		t.Fatal(e)
	}
	after, e := s.GetFeed(ctx, f.ID)
	if e != nil || after.LastSuccess == nil || after.LastError == "" || after.LastStatus != "committed-warning" || after.DomainCount != 3 || after.ETag != "synthetic-v1" {
		t.Fatal("warning lost committed history")
	}
	if e = s.RecordFeedRefresh(ctx, f.ID, FeedResult{Status: "error", Error: "feed import rejected"}); e != nil {
		t.Fatal(e)
	}
	failed, e := s.GetFeed(ctx, f.ID)
	if e != nil || failed.LastSuccess == nil || !failed.LastSuccess.Equal(*after.LastSuccess) || failed.DomainCount != 3 || failed.ETag != after.ETag {
		t.Fatal("precommit failure destroyed last successful history")
	}
}
