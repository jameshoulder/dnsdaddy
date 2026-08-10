// Package version carries build metadata stamped in at link time.
package version

import "runtime/debug"

// Version is overridden with -ldflags "-X .../version.Version=v1.2.3".
var Version = "dev"

// Commit is overridden at build time; otherwise it is read from the embedded
// VCS stamp Go adds to binaries built inside a git checkout.
var Commit = ""

// String returns a human-readable build identifier.
func String() string {
	v := Version
	if c := commit(); c != "" {
		v += "+" + c
	}
	return v
}

func commit() string {
	if Commit != "" {
		return short(Commit)
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" {
			return short(s.Value)
		}
	}
	return ""
}

func short(s string) string {
	if len(s) > 7 {
		return s[:7]
	}
	return s
}
