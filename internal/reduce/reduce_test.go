package reduce

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/protonnegativo/raijin-js/internal/katana"
	"github.com/protonnegativo/raijin-js/internal/schema"
	"github.com/protonnegativo/raijin-js/internal/scope"
)

// awsKey is the example key from the AWS documentation, built so no scanner reads this file as a leak.
var awsKey = "AKIA" + "IOSFODNN7EXAMPLE"

func load(t *testing.T) []katana.Event {
	t.Helper()
	f, err := os.Open("../../testdata/sample.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	events, err := katana.Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	return events
}

func reduceSample(t *testing.T) Output {
	t.Helper()
	sc, _ := scope.Parse([]string{"*.example.com", "!evil.example.net"})
	opt := Defaults()
	opt.InScope = sc.Allowed
	return Reduce(load(t), opt)
}

// js is a JavaScript file katana fetched.
func js(url, body string) katana.Event {
	return katana.Event{
		Request:  katana.Request{Method: "GET", Endpoint: url, Tag: "script", Attribute: "src", Source: "http://h.test/"},
		Response: &katana.Response{StatusCode: 200, Headers: map[string]any{"content-type": "application/javascript"}, Body: body},
	}
}

func finding(out Output, value string) *schema.Finding {
	for i := range out.Findings {
		if out.Findings[i].Value == value {
			return &out.Findings[i]
		}
	}
	return nil
}

func groupWith(out Output, kind, variant string) *schema.Group {
	for i, g := range out.Groups {
		if g.Kind != kind {
			continue
		}
		for _, v := range g.Variants {
			if v == variant {
				return &out.Groups[i]
			}
		}
	}
	return nil
}

func TestReduce(t *testing.T) {
	out := reduceSample(t)
	if out.Origin != "https://app.example.com" {
		t.Errorf("origin = %q", out.Origin)
	}
	if out.Omitted["duplicates"] != 1 || out.Omitted["out_of_scope"] != 1 || out.Omitted["not_js"] != 3 {
		t.Errorf("omitted = %v", out.Omitted)
	}
	if out.Stats.Files != 6 || out.Stats.Libraries != 1 || out.Stats.Items != 17 {
		t.Errorf("stats = %+v", out.Stats)
	}
	var got []string
	for _, f := range out.Findings {
		got = append(got, f.Severity+" "+strings.Join(f.Tags, ",")+" "+f.Value)
	}
	want := []string{
		"high secret AKIA…MPLE",
		"medium sourcemap /static/app.js.map",
		"medium admin,auth /admin/settings",
		"medium admin,internal http://10.1.2.3:9000/metrics",
		"medium admin /internal/health",
		"medium secret eyJh…FrZQ",
		"medium bucket https://acme-docs.s3.amazonaws.com/x/",
		"low api /api/v1/users?page=1",
		"low api /api/v1/orders/{id}",
		"low api https://api.example.com/v2/items",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("findings:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if f := finding(out, "/static/app.js.map"); f == nil || f.Confidence != "verified" || f.Status != 200 {
		t.Errorf("a source map katana fetched is verified: %+v", f)
	}
}

// Lossless rule: every JavaScript file katana found is listed, in a js or a library group, with its
// status, including one katana recorded no response for.
func TestEveryFileIsListed(t *testing.T) {
	out := reduceSample(t)
	listed := map[string]int{}
	for _, g := range out.Groups {
		if g.Kind != "js" && g.Kind != "library" {
			continue
		}
		for _, l := range g.Locations {
			for _, u := range expand(l) {
				listed[u] = g.Status
			}
		}
	}
	for u, st := range map[string]int{"/static/app.js": 200, "/static/chunk-1.js": 200, "/static/chunk-2.js": 200, "/static/chunk-3.js": 200, "/static/lazy.js": 0, "/static/vendor/jquery-3.7.1.min.js": 200} {
		if s, ok := listed[u]; !ok || s != st {
			t.Errorf("%s: listed %v with status %d, want %d", u, ok, s, st)
		}
	}
	if len(listed) != 6 {
		t.Errorf("listed %d files, want 6: %v", len(listed), listed)
	}
}

// Lossless rule: an item found in many files is one entry that lists every file.
func TestItemsAreDedupedAcrossFiles(t *testing.T) {
	out := reduceSample(t)
	f := finding(out, "/api/v1/users?page=1")
	if f == nil || strings.Join(f.Locations, " ") != "/static/app.js /static/chunk-[1-3].js" || f.Files != 4 {
		t.Errorf("api route: %+v", f)
	}
	if g := groupWith(out, "endpoint", "/about"); g == nil || strings.Join(g.Locations, " ") != "/static/app.js /static/chunk-[1-3].js" || g.Status != 200 {
		t.Errorf("plain path: %+v", g)
	}
}

// Lossless rule: a secret is one finding per value, with every file:line it is on, and its value is
// never written in full.
func TestSecretsKeepEveryFileAndLine(t *testing.T) {
	events := []katana.Event{
		js("http://h.test/a.js", "x\nvar k = \""+awsKey+"\";\nvar again = \""+awsKey+"\";"),
		js("http://h.test/b.js", "var k = \""+awsKey+"\";"),
	}
	out := Reduce(events, Defaults())
	f := finding(out, "AKIA…MPLE")
	if f == nil || f.Rule != "aws-access-key" || strings.Join(f.Locations, " ") != "/a.js:[2-3] /b.js:1" || f.Files != 3 {
		t.Fatalf("secret: %+v", f)
	}
	b, _ := schema.Marshal(out.Findings)
	if strings.Contains(string(b), awsKey) {
		t.Errorf("the secret leaked in full: %s", b)
	}
}

// Lossless rule: an endpoint katana's jsluice found in a file and the same string literal are one item,
// and it keeps the status katana got for it.
func TestJsluiceResultsMergeWithLiterals(t *testing.T) {
	events := []katana.Event{
		js("http://h.test/app.js", `fetch("/api/v2/admin/settings")`),
		{Request: katana.Request{Endpoint: "http://h.test/api/v2/admin/settings", Tag: "js", Attribute: "jsluice-fetch", Source: "http://h.test/app.js"},
			Response: &katana.Response{StatusCode: 403}},
		{Request: katana.Request{Endpoint: "http://h.test/only-jsluice", Tag: "js", Attribute: "jsluice-stringLiteral", Source: "http://h.test/app.js"}},
	}
	out := Reduce(events, Defaults())
	if f := finding(out, "/api/v2/admin/settings"); f == nil || f.Status != 403 || strings.Join(f.Tags, ",") != "admin,api,auth" {
		t.Errorf("merged item: %+v", f)
	}
	if out.Stats.Items != 2 || groupWith(out, "endpoint", "/only-jsluice") == nil {
		t.Errorf("an endpoint only jsluice found is kept: %+v %+v", out.Stats, out.Groups)
	}
}

// Lossless rule: only exact repeats collapse, and they are counted; a result out of scope is dropped and
// counted.
func TestDuplicatesAndScopeAreCounted(t *testing.T) {
	sc, _ := scope.Parse([]string{"h.test"})
	opt := Defaults()
	opt.InScope = sc.Allowed
	events := []katana.Event{js("http://h.test/a.js", `"/x/y"`), js("http://h.test/a.js", `"/x/y"`), js("http://other.test/b.js", `"/z/z"`)}
	out := Reduce(events, opt)
	if out.Omitted["duplicates"] != 1 || out.Omitted["out_of_scope"] != 1 || out.Stats.Files != 1 {
		t.Errorf("omitted = %v, stats = %+v", out.Omitted, out.Stats)
	}
}

func TestClassify(t *testing.T) {
	sc, _ := scope.Parse([]string{"h.test", "*.h.test"})
	opt := Defaults()
	opt.InScope = sc.Allowed
	body := strings.Join([]string{
		`"/api/v1/users"`, `"/admin/"`, `"/backup/db.sql"`, `"/about/us"`, `"https://api.h.test/v1/x"`,
		`"https://cdn.other.test/api/v1/x"`, `"https://b.s3.amazonaws.com/k"`, `"http://192.168.1.10/"`, `"http://jenkins/job/x"`,
		`"https://db.corp.internal/"`, `"/gone/admin"`,
	}, ";")
	events := []katana.Event{js("http://h.test/app.js", body),
		{Request: katana.Request{Endpoint: "http://h.test/gone/admin", Tag: "js", Source: "http://h.test/app.js"}, Response: &katana.Response{StatusCode: 404}}}
	out := Reduce(events, opt)
	want := map[string]string{
		"/api/v1/users":                "low api",
		"/admin/":                      "medium admin",
		"/backup/db.sql":               "medium admin,file",
		"https://api.h.test/v1/x":      "low api",
		"https://b.s3.amazonaws.com/k": "medium bucket",
		"http://192.168.1.10/":         "medium internal",
		"http://jenkins/job/x":         "medium internal",
		"https://db.corp.internal/":    "medium internal",
	}
	for v, w := range want {
		f := finding(out, v)
		if f == nil || f.Severity+" "+strings.Join(f.Tags, ",") != w {
			t.Errorf("%s: %+v, want %s", v, f, w)
		}
	}
	if groupWith(out, "endpoint", "/about/us") == nil || groupWith(out, "external", "https://cdn.other.test/api/v1/x") == nil {
		t.Errorf("a plain path and a third-party URL are groups: %+v", out.Groups)
	}
	if f := finding(out, "/gone/admin"); f == nil || f.Status != 404 || f.Severity != "low" {
		t.Errorf("a finding that answered 404 is low: %+v", f)
	}
}

func TestLibrariesAreGroupedByName(t *testing.T) {
	events := []katana.Event{
		js("http://h.test/vendor/jquery-3.7.1.min.js", "x"),
		js("http://h.test/vendor/react.production.min.js", "/*! React v18.2.0 */"),
		js("http://h.test/node_modules/@scope/pkg/index.js", ""),
		js("http://h.test/app.js", ""),
	}
	out := Reduce(events, Defaults())
	var libs []string
	for _, g := range out.Groups {
		if g.Kind == "library" {
			libs = append(libs, g.Value)
		}
	}
	if strings.Join(libs, ",") != "@scope/pkg,jquery 3.7.1,react 18.2.0" || out.Stats.Libraries != 3 {
		t.Errorf("libraries = %v", libs)
	}
}

func TestSourceMaps(t *testing.T) {
	events := []katana.Event{
		js("http://h.test/js/a.js", "x\n//# sourceMappingURL=a.js.map"),
		js("http://h.test/js/b.js", "//# sourceMappingURL=../maps/b.js.map"),
		js("http://h.test/js/c.js", "//# sourceMappingURL=data:application/json;base64,eyJ9"),
		{Request: katana.Request{Endpoint: "http://h.test/maps/b.js.map"}, Response: &katana.Response{StatusCode: 404}},
	}
	if got := strings.Join(MapURLs(events, nil), " "); got != "http://h.test/js/a.js.map" {
		t.Errorf("MapURLs = %q (b is already requested, c is inline)", got)
	}
	out := Reduce(events, Defaults())
	if f := finding(out, "/js/a.js.map"); f == nil || f.Severity != "low" {
		t.Errorf("a map katana did not request is low: %+v", f)
	}
	if f := finding(out, "data:application/json;base64,…"); f == nil || f.Confidence != "verified" {
		t.Errorf("an inline map is verified: %+v", f)
	}
	if g := groupWith(out, "sourcemap", "/maps/b.js.map"); g == nil || g.Status != 404 {
		t.Errorf("a map that answered 404 is a group: %+v", g)
	}
}

func TestRankingIsStable(t *testing.T) {
	a := reduceSample(t)
	for i := 0; i < 5; i++ {
		b := reduceSample(t)
		x, _ := schema.Marshal(a.Findings)
		y, _ := schema.Marshal(b.Findings)
		g1, _ := schema.Marshal(a.Groups)
		g2, _ := schema.Marshal(b.Groups)
		if string(x) != string(y) || string(g1) != string(g2) {
			t.Fatal("the same input must give the same output")
		}
	}
	if a.Groups[0].Kind != "js" {
		t.Errorf("js files come first among groups: %+v", a.Groups[0])
	}
}

func TestMaxItemsIsCounted(t *testing.T) {
	sc, _ := scope.Parse([]string{"*.example.com"})
	opt := Defaults()
	opt.InScope = sc.Allowed
	opt.MaxItems = 3
	out := Reduce(load(t), opt)
	if len(out.Findings) != 3 || out.Omitted["findings"] != 7 {
		t.Errorf("findings %d, omitted %v", len(out.Findings), out.Omitted)
	}
}

func TestFitCutsLeastImportantFirstAndCounts(t *testing.T) {
	out := reduceSample(t)
	res := &schema.Result{Tool: "raijin-js", Findings: out.Findings, Groups: out.Groups, Omitted: map[string]int{}}
	full := size(res)
	Fit(res, full-200)
	if size(res) > full-200 || !res.Budget.Truncated {
		t.Fatalf("size %d, budget %+v", size(res), res.Budget)
	}
	if res.Omitted["locations"] == 0 || len(res.Findings) != len(out.Findings) {
		t.Errorf("group locations go first: omitted %v, %d findings", res.Omitted, len(res.Findings))
	}
	for _, g := range res.Groups {
		if g.Locations == nil && g.Count != g.Files {
			t.Errorf("a cut group keeps its count: %+v", g)
		}
	}
	Fit(res, 600)
	if size(res) > 600 || res.Omitted["groups"] == 0 || res.Omitted["findings"] == 0 {
		t.Errorf("size %d, omitted %v", size(res), res.Omitted)
	}
}

func TestCompress(t *testing.T) {
	var in []string
	for i := 1; i <= 40; i++ {
		in = append(in, fmt.Sprintf("/static/js/chunk-%d.js", i))
	}
	in = append(in, "/static/js/chunk-07.js", "/a.js:3", "/a.js:9", "/a.js:4")
	got := strings.Join(Compress(in), " ")
	if got != "/a.js:[3-4,9] /static/js/chunk-07.js /static/js/chunk-[1-40].js" {
		t.Errorf("Compress = %s", got)
	}
}

// expand undoes Compress for one range, as bench/verify.py does.
func expand(l string) []string {
	i, j := strings.Index(l, "["), strings.Index(l, "]")
	if i < 0 || j < i {
		return []string{l}
	}
	var out []string
	for _, part := range strings.Split(l[i+1:j], ",") {
		var a, b int
		if n, _ := fmt.Sscanf(part, "%d-%d", &a, &b); n < 2 {
			b = a
		}
		for n := a; n <= b; n++ {
			out = append(out, fmt.Sprintf("%s%d%s", l[:i], n, l[j+1:]))
		}
	}
	return out
}
