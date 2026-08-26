package store

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/catalog"
)

// ListFeeds returns every configured threat-intelligence feed.
func (s *Store) ListFeeds(ctx context.Context) ([]Feed, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, url, category, format, enabled, builtin, domain_count,
		       last_refreshed_at, last_status, last_error, etag, created_at, updated_at
		FROM feeds ORDER BY category, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Feed
	for rows.Next() {
		var (
			f                Feed
			enabled, builtin int
			refreshed        *int64
			created, updated int64
		)
		if err := rows.Scan(&f.ID, &f.Name, &f.URL, &f.Category, &f.Format, &enabled, &builtin,
			&f.DomainCount, &refreshed, &f.LastStatus, &f.LastError, &f.ETag, &created, &updated); err != nil {
			return nil, err
		}
		f.Enabled = enabled == 1
		f.Builtin = builtin == 1
		if refreshed != nil {
			t := fromUnixMilli(*refreshed)
			f.LastRefresh = &t
		}
		f.CreatedAt = fromUnixMilli(created)
		f.UpdatedAt = fromUnixMilli(updated)
		out = append(out, f)
	}
	return out, rows.Err()
}

// FeedInput carries the mutable fields of a feed.
type FeedInput struct {
	Name     *string
	URL      *string
	Category *string
	Format   *string
	Enabled  *bool
}

// CreateFeed adds an operator-supplied feed.
func (s *Store) CreateFeed(ctx context.Context, in FeedInput) (Feed, error) {
	if in.Name == nil || strings.TrimSpace(*in.Name) == "" {
		return Feed{}, fmt.Errorf("feed name is required")
	}
	if in.URL == nil {
		return Feed{}, fmt.Errorf("feed url is required")
	}
	if err := s.validateFeedURL(*in.URL); err != nil {
		return Feed{}, err
	}
	category := "malware"
	if in.Category != nil {
		category = *in.Category
	}
	if !catalog.ValidCategory(category) {
		return Feed{}, fmt.Errorf("unknown category %q", category)
	}
	format := "auto"
	if in.Format != nil && *in.Format != "" {
		format = *in.Format
	}
	if err := validateFeedFormat(format); err != nil {
		return Feed{}, err
	}

	id := NewID("f")
	now := unixMilli(time.Now())
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO feeds (id, name, url, category, format, enabled, builtin, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)`,
		id, strings.TrimSpace(*in.Name), strings.TrimSpace(*in.URL), category, format,
		boolToInt(derefBoolDefault(in.Enabled, true)), now, now)
	if err != nil {
		return Feed{}, err
	}
	return s.GetFeed(ctx, id)
}

// GetFeed returns one feed by ID.
func (s *Store) GetFeed(ctx context.Context, id string) (Feed, error) {
	all, err := s.ListFeeds(ctx)
	if err != nil {
		return Feed{}, err
	}
	for _, f := range all {
		if f.ID == id {
			return f, nil
		}
	}
	return Feed{}, ErrNotFound
}

// UpdateFeed applies a partial update. Built-in feeds may be enabled or
// disabled but their source URL is managed by the shipped catalog.
func (s *Store) UpdateFeed(ctx context.Context, id string, in FeedInput) (Feed, error) {
	existing, err := s.GetFeed(ctx, id)
	if err != nil {
		return Feed{}, err
	}
	if existing.Builtin && (in.URL != nil || in.Category != nil || in.Format != nil) {
		return Feed{}, fmt.Errorf("built-in feeds can only be enabled or disabled; add a custom feed instead")
	}

	sets := []string{"updated_at = ?"}
	args := []any{unixMilli(time.Now())}
	if in.Name != nil && strings.TrimSpace(*in.Name) != "" {
		sets = append(sets, "name = ?")
		args = append(args, strings.TrimSpace(*in.Name))
	}
	if in.URL != nil {
		if err := s.validateFeedURL(*in.URL); err != nil {
			return Feed{}, err
		}
		// A changed source invalidates the cached ETag and counts.
		sets = append(sets, "url = ?", "etag = ''", "domain_count = 0")
		args = append(args, strings.TrimSpace(*in.URL))
	}
	if in.Category != nil {
		if !catalog.ValidCategory(*in.Category) {
			return Feed{}, fmt.Errorf("unknown category %q", *in.Category)
		}
		sets = append(sets, "category = ?")
		args = append(args, *in.Category)
	}
	if in.Format != nil {
		if err := validateFeedFormat(*in.Format); err != nil {
			return Feed{}, err
		}
		sets = append(sets, "format = ?")
		args = append(args, *in.Format)
	}
	if in.Enabled != nil {
		sets = append(sets, "enabled = ?")
		args = append(args, boolToInt(*in.Enabled))
	}
	args = append(args, id)

	// #nosec G202 -- sets holds only hardcoded column fragments ("name = ?");
	// every value is bound as a parameter. Never build a fragment from input.
	if _, err := s.db.ExecContext(ctx, "UPDATE feeds SET "+strings.Join(sets, ", ")+" WHERE id = ?", args...); err != nil {
		return Feed{}, err
	}
	return s.GetFeed(ctx, id)
}

// DeleteFeed removes a custom feed. Built-in feeds are disabled, not deleted,
// so that an upgrade can keep the catalog consistent.
func (s *Store) DeleteFeed(ctx context.Context, id string) error {
	f, err := s.GetFeed(ctx, id)
	if err != nil {
		return err
	}
	if f.Builtin {
		return fmt.Errorf("built-in feeds cannot be deleted; disable it instead")
	}
	_, err = s.db.ExecContext(ctx, "DELETE FROM feeds WHERE id = ?", id)
	return err
}

// FeedResult records the outcome of a refresh attempt.
type FeedResult struct {
	DomainCount int
	Status      string
	Error       string
	ETag        string
}

// RecordFeedRefresh stores the outcome of a feed fetch.
func (s *Store) RecordFeedRefresh(ctx context.Context, id string, r FeedResult) error {
	now := unixMilli(time.Now())
	// A "not modified" response leaves the previous domain count intact.
	if r.Status == "not-modified" {
		_, err := s.db.ExecContext(ctx,
			"UPDATE feeds SET last_refreshed_at = ?, last_status = ?, last_error = '', updated_at = ? WHERE id = ?",
			now, r.Status, now, id)
		return err
	}
	if r.Error != "" {
		_, err := s.db.ExecContext(ctx,
			"UPDATE feeds SET last_refreshed_at = ?, last_status = ?, last_error = ?, updated_at = ? WHERE id = ?",
			now, r.Status, truncate(r.Error, 500), now, id)
		return err
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE feeds SET domain_count = ?, last_refreshed_at = ?, last_status = ?,
		                 last_error = '', etag = ?, updated_at = ? WHERE id = ?`,
		r.DomainCount, now, r.Status, r.ETag, now, id)
	return err
}

// SetFeedDomainCount records how many domains a feed contributed to the index
// after de-duplication against higher-priority feeds.
//
// This is deliberately separate from RecordFeedRefresh: the count is only known
// once the index has been rebuilt, and by then the ETag and status recorded at
// download time must not be disturbed. Writing them again from a stale read
// would clobber the ETag and make every refresh re-download the full body.
func (s *Store) SetFeedDomainCount(ctx context.Context, id string, n int) error {
	_, err := s.db.ExecContext(ctx,
		"UPDATE feeds SET domain_count = ?, updated_at = ? WHERE id = ?",
		n, unixMilli(time.Now()), id)
	return err
}

func (s *Store) validateFeedURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("invalid feed URL: %w", err)
	}
	switch u.Scheme {
	case "http", "https":
		if u.Host == "" {
			return fmt.Errorf("feed URL is missing a host")
		}
		return nil
	case "file":
		// Rejected here as well as at download time so the operator gets the
		// error while they are still looking at the form, not silently in a
		// refresh log twelve hours later.
		_, err := LocalFeedPath(s.localFeedDir, raw)
		return err
	default:
		return fmt.Errorf("feed URL must be http, https, or file, got %q", u.Scheme)
	}
}

func validateFeedFormat(f string) error {
	switch f {
	case "auto", "hosts", "domains", "adblock", "observatory":
		return nil
	}
	return fmt.Errorf("feed format must be auto, hosts, domains, adblock, or observatory, got %q", f)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// LastFeedRefresh returns the most recent successful refresh across all feeds,
// or the zero time if none has ever completed.
//
// The feed manager tracks this in memory too, but that counter resets on
// restart. Reading it back from the database means the dashboard says "4 hours
// ago" after a reboot rather than "never", which is the difference between an
// operator ignoring the figure and trusting it.
func (s *Store) LastFeedRefresh(ctx context.Context) (time.Time, error) {
	var ms *int64
	err := s.db.QueryRowContext(ctx,
		"SELECT MAX(last_refreshed_at) FROM feeds WHERE enabled = 1 AND last_status != 'error'").Scan(&ms)
	if err != nil || ms == nil {
		return time.Time{}, err
	}
	return fromUnixMilli(*ms), nil
}
