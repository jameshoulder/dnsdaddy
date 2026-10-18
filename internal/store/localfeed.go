package store

import (
	"os"
	"path/filepath"

	"github.com/jameshoulder/dnsdaddy/internal/feedimport"
)

// LocalFeedPath is an admission hint only. Importers must open relative to a
// pinned os.Root and validate the actual descriptor, never open this string.
func LocalFeedPath(dir, raw string) (string, error) {
	name, err := feedimport.LocalName(dir, raw)
	if err != nil {
		return "", err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", err
	}
	defer root.Close()
	if _, err = root.Stat(name); err != nil && !os.IsNotExist(err) {
		return "", err
	}
	return filepath.Join(dir, name), nil
}
