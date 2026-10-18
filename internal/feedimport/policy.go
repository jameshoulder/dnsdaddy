// Package feedimport defines finite, shared feed ingestion budgets.
package feedimport

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

var ErrLimit = errors.New("feed import resource limit exceeded")

// Limits are application accounting limits, not an operating-system heap quota.
// Zero selects a finite default; negative and excessively large values fail closed.
type Limits struct {
	Records      int    `yaml:"records_per_feed"`
	LocalRecords int    `yaml:"local_records_per_refresh"`
	Domains      int    `yaml:"index_domains"`
	Claims       int    `yaml:"index_claims"`
	MemoryBytes  int64  `yaml:"memory_bytes"`
	TempBytes    int64  `yaml:"temporary_bytes"`
	Timeout      string `yaml:"local_import_timeout"`
}

func (l Limits) Normalize(maxBytes int64) (Limits, int64, time.Duration, error) {
	if maxBytes == 0 {
		maxBytes = 128 << 20
	}
	if maxBytes < 1 || maxBytes > 1<<30 {
		return l, 0, 0, errors.New("feeds.max_feed_bytes must be between 1 and 1073741824")
	}
	for _, v := range []struct {
		p      *int
		d, max int
	}{{&l.Records, 1000000, 5000000}, {&l.LocalRecords, 2000000, 10000000}, {&l.Domains, 2000000, 5000000}, {&l.Claims, 5000000, 10000000}} {
		if *v.p == 0 {
			*v.p = v.d
		}
		if *v.p < 1 || *v.p > v.max {
			return l, 0, 0, errors.New("invalid feed import record or index limit")
		}
	}
	if l.MemoryBytes == 0 {
		l.MemoryBytes = 256 << 20
	}
	if l.TempBytes == 0 {
		l.TempBytes = 256 << 20
	}
	if l.MemoryBytes < 64<<20 || l.MemoryBytes > 2<<30 || l.TempBytes < 1 || l.TempBytes > 2<<30 {
		return l, 0, 0, errors.New("invalid feed import memory or temporary-storage limit")
	}
	if l.Timeout == "" {
		l.Timeout = "90s"
	}
	timeout, err := time.ParseDuration(l.Timeout)
	if err != nil || timeout <= 0 || timeout > 10*time.Minute {
		return l, 0, 0, errors.New("local_import_timeout must be positive and at most 10m")
	}
	return l, maxBytes, timeout, nil
}

// LocalName is syntax/lexical validation only. Reads MUST use os.Root, not the
// absolute path returned by concatenating this name. URL decoding happens once.
func LocalName(dir, raw string) (string, error) {
	fail := func() (string, error) { return "", errors.New("invalid or unconfined local feed URL") }
	if strings.TrimSpace(dir) == "" {
		return "", errors.New("file feeds disabled; configure feeds.local_feed_dir")
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fail()
	}
	if u.Scheme != "file" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") || strings.ContainsRune(u.Path, 0) || !filepath.IsAbs(u.Path) || (u.Host != "" && !strings.EqualFold(u.Host, "localhost")) {
		return fail()
	}
	root, err := filepath.Abs(dir)
	if err != nil {
		return fail()
	}
	rel, err := filepath.Rel(root, filepath.Clean(u.Path))
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return fail()
	}
	return rel, nil
}

func Limit(reason string) error { return fmt.Errorf("%w: %s", ErrLimit, reason) }
