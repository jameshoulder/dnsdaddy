package blocklist

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/jameshoulder/dnsdaddy/internal/feedimport"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"
)

// Return a complete prefix first, then fail precisely as the array opener is read.
type rev01Reader struct {
	prefix  *strings.Reader
	failure error
}

func (r *rev01Reader) Read(p []byte) (int, error) {
	if r.prefix.Len() > 0 {
		return r.prefix.Read(p)
	}
	return 0, r.failure
}
func TestREV01ArrayOpenPreservesErrorIdentity(t *testing.T) {
	for _, failure := range []error{context.Canceled, context.DeadlineExceeded, feedimport.Limit("synthetic boundary")} {
		t.Run(failure.Error(), func(t *testing.T) {
			for _, prefix := range []string{`{"indicators":`, `{"source":"https://synthetic-user:synthetic-password@fixture.example/?token=synthetic-token","indicators":`} {
				_, e := parseObservatoryLimited(context.Background(), &rev01Reader{strings.NewReader(prefix), fmt.Errorf("synthetic reader: %w", failure)}, 10, nil)
				if !errors.Is(e, failure) && !(errors.Is(failure, feedimport.ErrLimit) && errors.Is(e, feedimport.ErrLimit)) {
					t.Fatalf("array opener lost error identity: %T", e)
				}
			}
		})
	}
}

// Force a legitimate short read before the byte limit expires on the next byte.
func TestREV01ArrayOpenPreservesCountedByteLimit(t *testing.T) {
	prefix := `{"indicators":`
	r := &countedReader{ctx: context.Background(), r: io.MultiReader(strings.NewReader(prefix), strings.NewReader("[]}")), left: int64(len(prefix))}
	_, e := parseObservatoryLimited(context.Background(), r, 10, nil)
	if !errors.Is(e, feedimport.ErrLimit) {
		t.Fatalf("counted byte limit lost at array opener: %T", e)
	}
}

type rev01Cache struct {
	cacheFilesystem
	failure error
	onOpen  func()
}

func (c *rev01Cache) OpenFile(name string, flags int, mode os.FileMode) (*os.File, error) {
	if c.onOpen != nil {
		c.onOpen()
	}
	return nil, fmt.Errorf("synthetic cache reader: %w", c.failure)
}
func TestREV01InitialCacheLoadPreservesFatalErrors(t *testing.T) {
	for _, failure := range []error{context.Canceled, context.DeadlineExceeded, feedimport.Limit("synthetic boundary")} {
		t.Run(failure.Error(), func(t *testing.T) {
			h := newManagerHarness(t)
			h.addFeed(t, "synthetic", "https://fixture.example/feed", "malware", "observatory")
			h.mgr.cacheRoot = &rev01Cache{cacheFilesystem: h.mgr.cacheRoot, failure: failure}
			var logs bytes.Buffer
			h.mgr.log = slog.New(slog.NewTextHandler(&logs, nil))
			before := h.holder.Load()
			gen := h.holder.Generation()
			e := h.mgr.LoadFromCache(context.Background())
			if !errors.Is(e, failure) {
				t.Fatalf("fatal cache failure downgraded: %T", e)
			}
			if h.holder.Load() != before || h.holder.Generation() != gen {
				t.Fatal("failed initial load published a partial candidate")
			}
			if logs.Len() != 0 {
				t.Fatal("fatal cache failure entered skip/warning path")
			}
		})
	}
}
func TestREV01ExpiredInitialCacheDeadlineIsFatal(t *testing.T) {
	h := newManagerHarness(t)
	h.addFeed(t, "synthetic", "https://fixture.example/feed", "malware", "observatory")
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	before := h.holder.Load()
	gen := h.holder.Generation()
	if e := h.mgr.LoadFromCache(ctx); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatalf("initial deadline not preserved: %T", e)
	}
	if h.holder.Load() != before || h.holder.Generation() != gen {
		t.Fatal("expired initial load published an index")
	}
}

func TestREV01ParentCancellationCannotHideBehindCacheError(t *testing.T) {
	h := newManagerHarness(t)
	h.addFeed(t, "synthetic", "https://fixture.example/feed", "malware", "observatory")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.mgr.cacheRoot = &rev01Cache{cacheFilesystem: h.mgr.cacheRoot, failure: errors.New("synthetic parse/read failure"), onOpen: cancel}
	before := h.holder.Load()
	gen := h.holder.Generation()
	if e := h.mgr.LoadFromCache(ctx); !errors.Is(e, context.Canceled) {
		t.Fatalf("parent cancellation replaced by nonfatal cache error: %T", e)
	}
	if h.holder.Load() != before || h.holder.Generation() != gen {
		t.Fatal("canceled initial load published an index")
	}
}
