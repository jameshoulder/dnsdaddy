package store

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// LocalFeedPath converts a file:// feed URL into a filesystem path, refusing
// anything that resolves outside dir.
//
// A feed URL is operator-supplied, but it arrives over the management API —
// which means a stolen session or an over-broad API token could otherwise point
// a "feed" at /etc/shadow and read it back through the dashboard's feed
// preview. Confining file:// feeds to one directory turns that from arbitrary
// file disclosure into nothing.
//
// An empty dir disables file:// feeds entirely, which is the default. Local
// feeds are a niche convenience (a corporate blocklist dropped on disk by
// configuration management); most deployments should never turn them on.
func LocalFeedPath(dir, rawURL string) (string, error) {
	if strings.TrimSpace(dir) == "" {
		return "", fmt.Errorf("file:// feeds are disabled; set feeds.local_feed_dir to the directory holding them")
	}

	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", fmt.Errorf("invalid file URL: %w", err)
	}
	// file://somehost/path is a remote share, not a local file. Only an empty
	// or "localhost" authority names this machine.
	if u.Host != "" && !strings.EqualFold(u.Host, "localhost") {
		return "", fmt.Errorf("file:// feed URL must not name a host, got %q", u.Host)
	}
	if u.Path == "" {
		return "", fmt.Errorf("file:// feed URL has no path")
	}

	root, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("resolve feeds.local_feed_dir: %w", err)
	}
	// Clean collapses any "..", so a path that climbs out of root lexically is
	// caught here rather than being opened.
	path := filepath.Clean(u.Path)
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, path)
	}
	if !within(root, path) {
		return "", fmt.Errorf("file:// feed %q is outside feeds.local_feed_dir (%s)", u.Path, root)
	}

	// The lexical check above is defeated by a symlink inside the directory
	// pointing out of it, so re-check against the resolved target. A path that
	// does not exist yet cannot be a symlink escape; let the later open report
	// it as missing.
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("resolve feeds.local_feed_dir: %w", err)
	}
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		if os.IsNotExist(err) {
			return path, nil
		}
		return "", err
	}
	if !within(realRoot, realPath) {
		return "", fmt.Errorf("file:// feed %q resolves outside feeds.local_feed_dir (%s)", u.Path, root)
	}
	return realPath, nil
}

// within reports whether path is root itself or sits underneath it.
func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
