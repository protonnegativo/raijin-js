package katana

import (
	"strings"
	"testing"
)

func TestEnginesHasKatana(t *testing.T) {
	m, err := Engines()
	if err != nil {
		t.Fatal(err)
	}
	e, ok := m["katana"]
	if !ok {
		t.Fatalf("engines.json has no katana entry: %v", m)
	}
	if _, ok := ParseVersion(e.Version); !ok || e.Go == "" {
		t.Errorf("katana entry = %+v, want a X.Y.Z version and a go module", e)
	}
	if got := e.Install("katana", "1.1.2"); got != "go install "+e.Go+"@v1.1.2" {
		t.Errorf("install = %q", got)
	}
}

func TestParseVersion(t *testing.T) {
	for out, want := range map[string][3]int{
		// katana -version (stderr), with and without color
		"\n   __        __\n\t\tprojectdiscovery.io\n\n[\x1b[34mINF\x1b[0m] Current version: v1.1.2\n": {1, 1, 2},
		"[INF] Current version: v1.2.0\n": {1, 2, 0},
		"1.10.3":                          {1, 10, 3},
	} {
		if got, ok := ParseVersion(out); !ok || got != want {
			t.Errorf("ParseVersion(%q) = %v %v, want %v", out, got, ok, want)
		}
	}
	if _, ok := ParseVersion("[FTL] flag provided but not defined: -version"); ok {
		t.Error("no version in the output should not parse")
	}
}

func TestUntested(t *testing.T) {
	tested := [3]int{1, 1, 2}
	for v, want := range map[[3]int]bool{
		{1, 1, 2}: false,
		{1, 1, 3}: false, // newer patch: the drift job covers it
		{1, 4, 0}: false,
		{1, 1, 1}: true, // older
		{1, 0, 9}: true,
		{2, 0, 0}: true, // another major
		{0, 9, 9}: true,
	} {
		if got := Untested(v, tested); got != want {
			t.Errorf("Untested(%v) = %v, want %v", v, got, want)
		}
	}
}

func TestFormatRenamedField(t *testing.T) {
	good := `{"request":{"endpoint":"http://h.test/app.js"},"response":{"status_code":200,"body":"x"}}
{"request":{"endpoint":"http://h.test/again.js"},"response":{"headers":{}}}
{"request":{"endpoint":"http://h.test/slow.js"},"error":"context deadline exceeded"}
`
	events, st, _ := Parse(strings.NewReader(good))
	if bad, total := Format(events, st); bad != 0 || total != 3 {
		t.Errorf("katana's own shapes: %d of %d bad", bad, total)
	}
	// status_code renamed to status, and one line that is not JSON
	renamed := `{"request":{"endpoint":"http://h.test/app.js"},"response":{"status":200,"body":"x"}}
{"request":{"endpoint":"http://h.test/b.js"},"response":{"status":404,"body":"not found"}}
{"request":{"endpoint":"http://h.test/again.js"},"response":{"headers":{}}}
<html>
`
	events, st, _ = Parse(strings.NewReader(renamed))
	if bad, total := Format(events, st); bad != 3 || total != 4 {
		t.Errorf("renamed field: %d of %d bad, want 3 of 4", bad, total)
	}
	if st.Unparsed != 1 {
		t.Errorf("the non-JSON line must be counted: %+v", st)
	}
}
