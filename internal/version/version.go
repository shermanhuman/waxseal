// Package version holds build identification for the waxseal binary.
package version

import "runtime/debug"

// Build information. Version is bumped by scripts/release; all three can be
// overridden at build time via -ldflags "-X".
var (
	Version   = "0.5.0"
	Commit    = ""
	BuildDate = ""
)

func init() {
	// Fall back to Go's embedded VCS info for local builds.
	// Goreleaser ldflags take priority when set.
	if Commit != "" && BuildDate != "" {
		return
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			if Commit == "" && len(s.Value) >= 7 {
				Commit = s.Value[:7]
			}
		case "vcs.time":
			if BuildDate == "" {
				BuildDate = s.Value
			}
		case "vcs.modified":
			if s.Value == "true" && Commit != "" {
				Commit += "-dirty"
			}
		}
	}
}

// String renders the multi-line text shown by --version.
func String() string {
	s := "waxseal " + Version + "\n"
	if Commit != "" {
		s += "Commit: " + Commit + "\n"
	}
	if BuildDate != "" {
		s += "Built:  " + BuildDate + "\n"
	}
	return s
}
