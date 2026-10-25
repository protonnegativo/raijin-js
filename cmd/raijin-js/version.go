package main

import (
	"runtime/debug"
	"sort"
	"strings"

	"github.com/protonnegativo/raijin-js/internal/katana"
)

// version is the release the binary was installed from (go install ...@v0.1.3 or @latest), or "dev"
// for a local build, with the commit and "+dirty" when the build settings carry them.
var version = buildVersion(debug.ReadBuildInfo())

func buildVersion(info *debug.BuildInfo, ok bool) string {
	if !ok {
		return "dev"
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	v := "dev"
	var rev string
	var dirty bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev != "" {
		if len(rev) > 12 {
			rev = rev[:12]
		}
		v += "-" + rev
	}
	if dirty {
		v += "+dirty"
	}
	return v
}

// versionLine is what --version prints: "raijin-js v0.1.3 (tested with katana 1.8.0)".
func versionLine() string {
	line := "raijin-js " + version
	engines, err := katana.Engines()
	if err != nil || len(engines) == 0 {
		return line
	}
	var tested []string
	for name, e := range engines {
		tested = append(tested, name+" "+e.Version)
	}
	sort.Strings(tested)
	return line + " (tested with " + strings.Join(tested, ", ") + ")"
}
