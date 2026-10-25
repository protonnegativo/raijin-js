package main

import (
	"bytes"
	"runtime/debug"
	"testing"

	"github.com/protonnegativo/raijin-js/internal/katana"
)

func TestBuildVersion(t *testing.T) {
	settings := []debug.BuildSetting{{Key: "vcs.revision", Value: "0123456789abcdef0123"}, {Key: "vcs.modified", Value: "true"}}
	for _, c := range []struct {
		info *debug.BuildInfo
		ok   bool
		want string
	}{
		{&debug.BuildInfo{Main: debug.Module{Version: "v0.1.3"}}, true, "v0.1.3"},
		{&debug.BuildInfo{Main: debug.Module{Version: "(devel)"}, Settings: settings}, true, "dev-0123456789ab+dirty"},
		{&debug.BuildInfo{Main: debug.Module{Version: "(devel)"}, Settings: settings[:1]}, true, "dev-0123456789ab"},
		{&debug.BuildInfo{}, true, "dev"},
		{nil, false, "dev"},
	} {
		if got := buildVersion(c.info, c.ok); got != c.want {
			t.Errorf("buildVersion = %q, want %q", got, c.want)
		}
	}
}

func TestVersionLine(t *testing.T) {
	engines, err := katana.Engines()
	if err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"--version"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	want := "raijin-js " + version + " (tested with katana " + engines["katana"].Version + ")\n"
	if out.String() != want {
		t.Errorf("--version = %q, want %q", out.String(), want)
	}
}
