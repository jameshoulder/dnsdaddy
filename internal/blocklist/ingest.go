package blocklist

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/jameshoulder/dnsdaddy/internal/catalog"
	"github.com/jameshoulder/dnsdaddy/internal/feedimport"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// Implemented by the pinned os.Root. The narrow interface permits synthetic
// commit-failure tests without changing permissions or filling a real disk.
type cacheFilesystem interface {
	Open(string) (*os.File, error)
	OpenFile(string, int, os.FileMode) (*os.File, error)
	Lstat(string) (os.FileInfo, error)
	Rename(string, string) error
	Remove(string) error
	Close() error
}

// beginOperation keeps roots open until cancellation cleanup has completed.
func (m *Manager) beginOperation(ctx context.Context) (context.Context, func(), error) {
	m.lifecycle.RLock()
	if m.closing.Load() {
		m.lifecycle.RUnlock()
		return nil, nil, errors.New("feed manager closed")
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(m.lifecycleCtx, cancel)
	return ctx, func() { stop(); cancel(); m.lifecycle.RUnlock() }, nil
}

// Close cancels and joins manager operations before closing pinned roots. A
// kernel-stalled regular-file read can still delay Close; no goroutine is abandoned.
func (m *Manager) Close() error {
	m.closing.Store(true)
	m.lifecycleCancel()
	m.lifecycle.Lock()
	defer m.lifecycle.Unlock()
	m.localMu.Lock()
	defer m.localMu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	if m.localRoot != nil {
		m.localRoot.Close()
		m.localRoot = nil
	}
	m.client.CloseIdleConnections()
	return m.cacheRoot.Close()
}

func ownedByService(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid()
}

func regular(f *os.File, max int64) (os.FileInfo, error) {
	st, err := f.Stat()
	if err != nil {
		return nil, errors.New("cannot inspect feed descriptor")
	}
	return validateFeedInfo(st, max)
}

func validateFeedInfo(st os.FileInfo, max int64) (os.FileInfo, error) {
	if !st.Mode().IsRegular() {
		return nil, errors.New("feed must be a regular file")
	}
	raw, ok := st.Sys().(*syscall.Stat_t)
	if !ok || raw.Nlink != 1 {
		return nil, errors.New("feed must have exactly one filesystem link")
	}
	if st.Size() < 0 || st.Size() > max {
		return nil, feedimport.Limit("feed bytes")
	}
	return st, nil
}

func (m *Manager) openLocal(raw string) (*os.File, error) {
	name, err := feedimport.LocalName(m.cfg.LocalFeedDir, raw)
	if err != nil {
		return nil, err
	}
	m.localMu.Lock()
	defer m.localMu.Unlock()
	if m.closed {
		return nil, errors.New("feed manager closed")
	}
	if m.localRoot == nil {
		m.localRoot, err = os.OpenRoot(m.cfg.LocalFeedDir)
		if err != nil {
			return nil, errors.New("cannot open configured local feed root")
		}
	}
	f, err := m.localRoot.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, errors.New("cannot open confined local feed")
	}
	if _, err = regular(f, m.maxBytes); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func (m *Manager) copyLocal(ctx context.Context, f store.Feed) store.FeedResult {
	ctx, cancel := context.WithTimeout(ctx, m.localTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return failedImport(err)
	}
	src, err := m.openLocal(f.URL)
	if err != nil {
		return failedImport(err)
	}
	defer src.Close()
	return m.snapshot(ctx, f, src, src, "")
}
func failedImport(err error) store.FeedResult {
	reason := "feed content or cache operation failed"
	if errors.Is(err, feedimport.ErrLimit) {
		reason = "feed import resource limit exceeded; inspect configured byte, record, index and temporary-storage budgets"
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		reason = "feed import canceled or timed out; previous cache retained"
	}
	return store.FeedResult{Status: "error", Error: reason}
}

// Copy loops with a fixed buffer and actual-byte accounting. Regular filesystem
// reads can still block in the kernel: cancellation is cooperative, not a
// promise to interrupt stalled NFS/FUSE I/O. No abandoned worker goroutine.
func copyBounded(ctx context.Context, dst io.Writer, src io.Reader, max int64) (int64, error) {
	var n int64
	buf := make([]byte, 32<<10)
	for {
		if err := ctx.Err(); err != nil {
			return n, err
		}
		want := int64(len(buf))
		if want > max-n+1 {
			want = max - n + 1
		}
		nr, er := src.Read(buf[:int(want)])
		if nr > 0 {
			if int64(nr) > max-n {
				return n, feedimport.Limit("snapshot bytes")
			}
			nw, ew := dst.Write(buf[:nr])
			n += int64(nw)
			if ew != nil {
				return n, ew
			}
			if nw != nr {
				return n, io.ErrShortWrite
			}
		}
		if er == io.EOF {
			return n, ctx.Err()
		}
		if er != nil {
			return n, er
		}
		if nr == 0 {
			return n, io.ErrNoProgress
		}
	}
}

// Crash leftovers are NOT swept: only their creator can safely establish the
// lifecycle. Count them against the finite staging quota and require operator
// cleanup when that quota is exhausted. Directory scanning is also bounded.
func (m *Manager) tempAvailable() (int64, error) {
	d, err := m.cacheRoot.Open(".")
	if err != nil {
		return 0, err
	}
	defer d.Close()
	remaining := m.limits.TempBytes
	count := 0
	for {
		entries, e := d.ReadDir(128)
		for _, entry := range entries {
			count++
			if count > 16384 {
				return 0, feedimport.Limit("cache directory entries")
			}
			if !strings.HasPrefix(entry.Name(), ".download-") {
				continue
			}
			info, e := m.cacheRoot.Lstat(entry.Name())
			if e != nil {
				return 0, e
			}
			if !info.Mode().IsRegular() || info.Size() < 0 {
				return 0, errors.New("unsafe staging artifact; operator review required")
			}
			if info.Size() > remaining {
				return 0, feedimport.Limit("temporary storage")
			}
			remaining -= info.Size()
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return 0, e
		}
	}
	return remaining, nil
}
func (m *Manager) snapshot(ctx context.Context, f store.Feed, src io.Reader, local *os.File, etag string) store.FeedResult {
	var before os.FileInfo
	var err error
	if local != nil {
		before, err = regular(local, m.maxBytes)
		if err != nil {
			return failedImport(err)
		}
	}
	available, err := m.tempAvailable()
	if err != nil {
		return failedImport(err)
	}
	max := m.maxBytes
	if available < max {
		max = available
	}
	name := fmt.Sprintf(".download-%x", rand.Text())
	tmp, err := m.cacheRoot.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return failedImport(err)
	}
	tempIdentity, e := tmp.Stat()
	if e != nil {
		tmp.Close()
		_ = m.cacheRoot.Remove(name)
		return failedImport(e)
	}
	defer func() {
		tmp.Close()
		if current, e := m.cacheRoot.Lstat(name); e == nil && os.SameFile(tempIdentity, current) {
			if err := m.cacheRoot.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
				m.log.Warn("feed staging cleanup failed; artifact counts against temporary-storage budget")
			}
		}
	}()
	n, err := copyBounded(ctx, tmp, src, max)
	if err != nil {
		return failedImport(err)
	}
	if n == 0 {
		return failedImport(errors.New("empty feed"))
	}
	if local != nil {
		after, e := regular(local, m.maxBytes)
		if e != nil {
			return failedImport(e)
		}
		if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || n != after.Size() {
			return failedImport(errors.New("local source changed during import"))
		}
	}
	// Validate even if the feed was disabled while its bytes were being copied.
	budget := m.newBudget()
	recordLimit := m.limits.Records
	if local != nil {
		left := m.limits.LocalRecords - m.localRecords
		if left <= 0 {
			return failedImport(feedimport.Limit("local records per refresh"))
		}
		if left < recordLimit {
			recordLimit = left
		}
	}
	_, records, err := m.parseFile(ctx, tmp, f, budget, recordLimit)
	if local != nil {
		left := m.limits.LocalRecords - m.localRecords
		if records > left {
			records = left
		}
		m.localRecords += records
	}
	if err != nil {
		return failedImport(err)
	}
	// Do not keep the validation contribution live during candidate construction.
	budget = nil
	m.mu.Lock()
	defer m.mu.Unlock()
	ix, loads, err := m.candidate(ctx, f.ID, tmp, true)
	if err != nil {
		return failedImport(err)
	}
	if err = ctx.Err(); err != nil {
		return failedImport(err)
	}
	st, err := tmp.Stat()
	if err != nil {
		return failedImport(err)
	}
	linked, err := m.cacheRoot.Lstat(name)
	if err != nil || !os.SameFile(st, linked) {
		return failedImport(errors.New("staging identity changed"))
	}
	if err = tmp.Sync(); err != nil {
		return failedImport(err)
	}
	if err = tmp.Close(); err != nil {
		return failedImport(err)
	}
	if err = ctx.Err(); err != nil {
		return failedImport(err)
	}
	if err = m.cacheRoot.Rename(name, filepath.Base(m.cachePath(f.ID))); err != nil {
		return failedImport(err)
	}
	// Rename is the commit point. Complete publication even if cancellation now
	// arrives; never pretend the filesystem/SQLite/Holder form one transaction.
	m.holder.Store(ix)
	m.loads.Store(&loads)
	d, e := m.cacheRoot.Open(".")
	if e == nil {
		e = d.Sync()
		d.Close()
	}
	if e != nil {
		return store.FeedResult{Committed: true, Status: "committed-warning", DomainCount: ix.CountsByFeed()[f.ID], ETag: etag, Error: "feed cache/index committed; directory durability could not be confirmed"}
	}
	return store.FeedResult{Committed: true, Status: "ok", ETag: etag, DomainCount: ix.CountsByFeed()[f.ID]}
}

type importBudget struct {
	used   int64
	claims int
	limit  int64
}

func indexCharge(ix *Index) int64 {
	n := int64(0)
	for d, e := range ix.domains {
		n += claimCharge(d, e)
		for _, extra := range ix.extra[d] {
			n += claimCharge(d, extra)
		}
	}
	return n
}
func claimCharge(d string, e Entry) int64 {
	return 512 + int64(len(d)+len(e.Category)+len(e.FeedID)+len(e.FeedName))
}

// indexCapacity is a deterministic publication envelope, not an RSS quota.
// The fixed reserve covers an old index, candidate and transient per-feed part.
func (m *Manager) indexCapacity() int64 { return (m.limits.MemoryBytes - (32 << 20)) / 3 }

func (m *Manager) newBudget() *importBudget {
	// Reserve one share even on a cold start: an accepted index must fit
	// beside its replacement and one feed's parsing contribution on refresh.
	reserve := m.indexCapacity()
	if old := indexCharge(m.holder.Load()); old > reserve {
		reserve = old
	}
	return &importBudget{used: (32 << 20) + reserve, limit: m.limits.MemoryBytes}
}
func (m *Manager) addBounded(b *Builder, budget *importBudget, d string, e Entry) error {
	prev, exists := b.ix.domains[d]
	if exists && (prev.Category == e.Category || b.hasClaim(d, e.Category)) {
		return nil
	}
	if !exists && len(b.ix.domains) >= m.limits.Domains {
		return feedimport.Limit("index domains")
	}
	if budget.claims >= m.limits.Claims {
		return feedimport.Limit("index claims")
	}
	charge := claimCharge(d, e)
	if charge > budget.limit-budget.used {
		return feedimport.Limit("index memory accounting")
	}
	budget.used += charge
	budget.claims++
	b.Add(d, e)
	return nil
}
func (m *Manager) parseFile(ctx context.Context, file *os.File, f store.Feed, budget *importBudget, recordLimit int) (*Builder, int, error) {
	if _, err := regular(file, m.maxBytes); err != nil {
		return nil, 0, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, 0, err
	}
	if budget.used >= budget.limit {
		return nil, 0, feedimport.Limit("index memory accounting")
	}
	b := NewBuilder(1024)
	records := 0
	r := &countedReader{ctx: ctx, r: file, left: m.maxBytes}
	emit := func(d string, cat string) error {
		return m.addBounded(b, budget, d, Entry{Category: cat, FeedID: f.ID, FeedName: f.Name})
	}
	if Format(f.Format) == FormatObservatory {
		fallback := f.Category
		if !catalog.ValidCategory(fallback) {
			fallback = "malware"
		}
		res, err := parseObservatoryLimited(ctx, r, recordLimit, func(rec ObservatoryRecord) error {
			cats := rec.Categories
			if len(cats) == 0 {
				cats = []string{fallback}
			}
			for _, cat := range cats {
				if e := emit(rec.Domain, cat); e != nil {
					return e
				}
			}
			return nil
		})
		records = res.Accepted + res.Skipped
		if err != nil {
			return nil, records, err
		}
		if res.Skipped > 0 {
			m.log.Debug("observatory feed had unusable indicators", "feed", f.ID, "accepted", res.Accepted, "skipped", res.Skipped)
		}
		m.log.Info("observatory feed indexed", "feed", f.ID, "indicators", res.Accepted, "domains", b.ix.Len(), "generated_at", res.GeneratedAt, "source_present", res.Source != "", "publication", "candidate")
	} else {
		// Count every processed line, including comments, junk and duplicates.
		lr := &lineCounter{r: r}
		_, _, err := parseLines(ctx, lr, Format(f.Format), recordLimit, func(d string) error { return emit(d, f.Category) })
		records = lr.lines
		if lr.last {
			records++
		}
		if err != nil {
			return nil, records, err
		}
	}
	return b, records, ctx.Err()
}

type countedReader struct {
	ctx  context.Context
	r    io.Reader
	left int64
}

func (r *countedReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if int64(len(p)) > r.left+1 {
		p = p[:r.left+1]
	}
	n, e := r.r.Read(p)
	r.left -= int64(n)
	if r.left < 0 {
		return 0, feedimport.Limit("cached feed bytes")
	}
	return n, e
}

type lineCounter struct {
	r     io.Reader
	lines int
	last  bool
}

func (r *lineCounter) Read(p []byte) (int, error) {
	n, e := r.r.Read(p)
	for _, b := range p[:n] {
		if b == '\n' {
			r.lines++
		}
	}
	if n > 0 {
		r.last = p[n-1] != '\n'
	}
	return n, e
}

func (m *Manager) candidate(ctx context.Context, override string, staged *os.File, retainPublished bool) (*Index, map[string]FeedLoad, error) {
	feeds, err := m.store.ListFeeds(ctx)
	if err != nil {
		return nil, nil, err
	}
	sortByCategoryPriority(feeds)
	b := NewBuilder(1024)
	budget := m.newBudget()
	loads := make(map[string]FeedLoad)
	localRecords := 0
	for _, f := range feeds {
		if !f.Enabled {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		file := staged
		own := false
		if f.ID != override || file == nil {
			file, err = m.cacheRoot.OpenFile(filepath.Base(m.cachePath(f.ID)), os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
			own = true
		} else {
			err = nil
		}
		beforeUsed, beforeClaims := budget.used, budget.claims
		var part *Builder
		records := 0
		if err == nil {
			part, records, err = m.parseFile(ctx, file, f, budget, m.limits.Records)
			if own {
				file.Close()
			}
		}
		if err != nil {
			budget.used, budget.claims = beforeUsed, beforeClaims
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, nil, ctxErr
			}
			if f.ID == override || (retainPublished && m.FeedLoads()[f.ID].Loaded) || errors.Is(err, feedimport.ErrLimit) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, nil, err
			}
			loads[f.ID] = FeedLoad{Error: describeLoadError(err)}
			m.log.Warn("skipping feed with no usable cached copy", "feed", f.ID, "error", describeLoadError(err))
			continue
		}
		if strings.HasPrefix(f.URL, "file:") {
			if records > m.limits.LocalRecords-localRecords {
				return nil, nil, feedimport.Limit("aggregate local records")
			}
			localRecords += records
		}
		// The staging contribution and global candidate coexist. Charge both until
		// the merge completes, then release the staging accounting reservation.
		stageCharge := budget.used - beforeUsed
		budget.claims = beforeClaims
		for d, e := range part.ix.domains {
			if err = m.addBounded(b, budget, d, e); err != nil {
				return nil, nil, err
			}
			for _, extra := range part.ix.extra[d] {
				if err = m.addBounded(b, budget, d, extra); err != nil {
					return nil, nil, err
				}
			}
		}
		budget.used -= stageCharge
		loads[f.ID] = FeedLoad{Loaded: true}
	}
	if indexCharge(b.ix) > m.indexCapacity() {
		return nil, nil, feedimport.Limit("published index capacity; reserve required for safe refresh")
	}
	return b.Build(), loads, ctx.Err()
}
