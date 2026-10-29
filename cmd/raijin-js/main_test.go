package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func scopeFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "scope.txt")
	if err := os.WriteFile(p, []byte("*.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNoBannerByDefault(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if errb.Len() != 0 {
		t.Errorf("stderr should be empty without --banner, got %q", errb.String())
	}
	var v map[string]any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("stdout is not JSON: %v", err)
	}
}

func TestBannerGoesToStderrOnly(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--banner", "--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(errb.String(), "TGT-LOCK") || !strings.Contains(errb.String(), "raijin-js v"+strings.TrimPrefix(version, "v")) {
		t.Errorf("banner missing or without the version: %q", errb.String())
	}
	if strings.Contains(out.String(), "TGT-LOCK") {
		t.Error("banner leaked into stdout")
	}
	var v map[string]any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("stdout is not JSON with --banner: %v", err)
	}
}

func TestCompactByDefault(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if n := strings.Count(out.String(), "\n"); n != 1 {
		t.Errorf("default JSON should be one line, got %d lines", n)
	}
	var pretty bytes.Buffer
	if code := run([]string{"--pretty", "--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl"}, &pretty, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(pretty.String(), "\n  \"tool\"") {
		t.Errorf("--pretty should indent: %q", pretty.String())
	}
	var a, b map[string]any
	if json.Unmarshal(out.Bytes(), &a) != nil || json.Unmarshal(pretty.Bytes(), &b) != nil || len(a) != len(b) {
		t.Error("compact and pretty should carry the same fields")
	}
}

func TestMissingEngineExitsTwoWithHint(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--scope", scopeFile(t), "-u", "https://a.example.com/", "--katana", "/nonexistent/katana"}, &out, &errb)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	var v struct {
		Errors []struct{ Kind, Hint string }
		Raw    string
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil || len(v.Errors) != 1 || v.Errors[0].Kind != "missing_engine" || !strings.Contains(v.Errors[0].Hint, "--katana") || v.Raw != "" {
		t.Errorf("stdout = %s", out.String())
	}
}

func TestUsageErrorsExitOne(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--input", "../../testdata/sample.jsonl"}, &out, &errb); code != 1 {
		t.Errorf("no --scope: exit %d, want 1", code)
	}
	if code := run([]string{"--scope", scopeFile(t), "-u", "https://out.of-scope.net/"}, &out, &errb); code != 1 {
		t.Errorf("no target in scope: exit %d, want 1", code)
	}
	if code := run([]string{"--scope", scopeFile(t), "--no-such-flag"}, &out, &errb); code != 1 {
		t.Errorf("unknown flag: exit %d, want 1", code)
	}
}

func TestSummaryAndRedaction(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	s := out.String()
	if !strings.Contains(s, `"summary":"6 JS files (1 libraries), 17 items: 10 findings (1 high, 6 medium, 3 low), 10 groups","origin":"https://app.example.com"`) {
		t.Errorf("summary: %s", s)
	}
	if !strings.Contains(s, `"value":"AKIA…MPLE","locations":["/static/app.js:1","/static/chunk-1.js:1"]`) || strings.Contains(s, "AKIA"+"IOSFODNN7EXAMPLE") {
		t.Errorf("a secret is redacted and keeps every file:line: %s", s)
	}
	if !strings.Contains(s, `"omitted":{"duplicates":1,"not_js":3,"out_of_scope":1}`) {
		t.Errorf("omitted: %s", s)
	}
	if strings.Contains(s, `\u0026`) || strings.Contains(s, `\u2026`) {
		t.Errorf("no HTML escaping: %s", s)
	}
}

func TestTableFormat(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--format", "table", "--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"HIGH     secret:aws-access-key AKIA…MPLE (2)", "MEDIUM   admin,auth /admin/settings 403 (1)", "group    js 200 (4 files)", "group    library jquery 3.7.1 200 (1 files)"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("table should contain %q:\n%s", want, out.String())
		}
	}
}

func TestStateMarksNewFindings(t *testing.T) {
	st := filepath.Join(t.TempDir(), "run.state.json")
	args := []string{"--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl", "--state", st}
	var first, second, errb bytes.Buffer
	run(args, &first, &errb)
	run(args, &second, &errb)
	if !strings.Contains(first.String(), ", 10 new\"") || !strings.Contains(second.String(), ", 0 new\"") || strings.Contains(second.String(), `"new":true`) {
		t.Errorf("first: %s\nsecond: %s", first.String(), second.String())
	}
}

func TestBudgetIsCountedAndPointsToRaw(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--max-bytes", "900", "--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if out.Len() > 901 {
		t.Errorf("output is %d bytes", out.Len())
	}
	var v struct {
		Omitted map[string]int
		Next    []string
		Budget  struct{ Truncated bool }
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil || !v.Budget.Truncated || v.Omitted["groups"] == 0 || len(v.Next) != 1 || !strings.Contains(v.Next[0], "sample.jsonl") {
		t.Errorf("stdout = %s", out.String())
	}
}

// With only --scope, every host the scope names is crawled and wildcards get a next step.
func TestScopeAloneCrawlsWhatTheScopeNames(t *testing.T) {
	dir := t.TempDir()
	scopePath := filepath.Join(dir, "scope.txt")
	if err := os.WriteFile(scopePath, []byte("example.com\n*.example.com\n10.0.0.0/30\n!10.0.0.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := filepath.Join(dir, "targets.txt")
	fake := filepath.Join(dir, "katana")
	script := "#!/bin/sh\nwhile [ $# -gt 0 ]; do [ \"$1\" = -list ] && [ ! -e " + got + " ] && cp \"$2\" " + got + "; shift; done\n"
	if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopePath, "--katana", fake, "--raw", filepath.Join(dir, "raw.jsonl")}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s %s", code, errb.String(), out.String())
	}
	b, err := os.ReadFile(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(strings.Fields(string(b)), ",") != "https://example.com,https://10.0.0.0,https://10.0.0.2,https://10.0.0.3" {
		t.Errorf("katana got targets %q", b)
	}
	var res struct{ Next []string }
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Next) != 1 || !strings.Contains(res.Next[0], "raijin-subs --scope "+scopePath+" -d example.com") {
		t.Errorf("next = %v", res.Next)
	}
}

// A scope with only a wildcard has nothing to crawl yet: exit 1 with the next step.
func TestScopeWithOnlyWildcardPointsToSubs(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t), "--katana", "/nonexistent/katana"}, &out, &errb); code != 1 {
		t.Fatalf("exit %d", code)
	}
	var res struct {
		Summary string
		Next    []string
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil || res.Summary != "the scope names no single host to scan" || len(res.Next) != 1 {
		t.Errorf("got %s", out.String())
	}
}

func TestRenamedFieldIsAnEngineFormatError(t *testing.T) {
	in := filepath.Join(t.TempDir(), "katana.jsonl")
	lines := `{"request":{"endpoint":"https://app.example.com/static/app.js"},"response":{"status":200,"body":"fetch(\"/api/x\")"}}
{"request":{"endpoint":"https://app.example.com/static/b.js"},"response":{"status_code":200,"body":"x"}}
not json
`
	if err := os.WriteFile(in, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t), "--input", in}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	var v struct {
		Omitted map[string]int
		Errors  []struct{ Kind, Hint string }
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Errors) != 1 || v.Errors[0].Kind != "engine_format" || !strings.HasPrefix(v.Errors[0].Hint, "2 of 3 katana results") || !strings.Contains(v.Errors[0].Hint, in) {
		t.Errorf("errors = %+v", v.Errors)
	}
	if v.Omitted["unparsed"] != 1 {
		t.Errorf("the line that is not JSON must be counted: %v", v.Omitted)
	}
}

func TestInvalidScopeIsAStructuredErrorAndNothingRuns(t *testing.T) {
	p := filepath.Join(t.TempDir(), "scope.txt")
	if err := os.WriteFile(p, []byte("example.com:443\n10.0.0.7/24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	// --katana points at a binary that does not exist: if the engine were started, the result would carry
	// a missing_engine error instead.
	code := run([]string{"--scope", p, "-u", "https://example.com/", "--katana", "/nonexistent/katana"}, &out, &errb)
	if code != 2 {
		t.Fatalf("exit %d for an invalid scope, want 2: %s", code, out.String())
	}
	if !strings.HasPrefix(out.String(), `{"schema_version":1,`) {
		t.Errorf("result should start with schema_version: %s", out.String())
	}
	var v struct {
		Summary string `json:"summary"`
		Errors  []struct{ Kind, Hint string }
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("stdout is not JSON: %v", err)
	}
	if len(v.Errors) != 2 {
		t.Fatalf("want one error per invalid line, got %+v", v.Errors)
	}
	for i, want := range []string{"port in rule", "CIDR has host bits set"} {
		if v.Errors[i].Kind != "scope" || !strings.Contains(v.Errors[i].Hint, want) {
			t.Errorf("error %d: %+v, want kind scope and %q", i, v.Errors[i], want)
		}
	}
}

func TestMissingScopeFileIsAStructuredError(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--scope", filepath.Join(t.TempDir(), "nope.txt"), "--input", "../../testdata/sample.jsonl"}, &out, &errb)
	if code != 2 || !strings.Contains(out.String(), `"kind":"scope"`) || !strings.HasPrefix(out.String(), `{"schema_version":1,`) {
		t.Errorf("exit %d, stdout %s", code, out.String())
	}
}
