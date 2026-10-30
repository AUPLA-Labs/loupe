// Package version says which Loupe this binary is.
package version

import "runtime/debug"

// Version is the release this binary was built as; scripts/release.sh sets
// it with -ldflags. "" for a build from source.
var Version = ""

// String is Version, or for a build from source "dev" with the commit it was
// built from (and "+modified" for uncommitted changes) when Go recorded it.
func String() string {
	if Version != "" {
		return Version
	}
	s := "dev"
	if bi, ok := debug.ReadBuildInfo(); ok {
		rev, mod := "", false
		for _, st := range bi.Settings {
			switch st.Key {
			case "vcs.revision":
				rev = st.Value
			case "vcs.modified":
				mod = st.Value == "true"
			}
		}
		if len(rev) >= 12 {
			s += " " + rev[:12]
			if mod {
				s += "+modified"
			}
		}
	}
	return s
}
