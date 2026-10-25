package schema

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDerivableFieldsAreLeftOut(t *testing.T) {
	res := Result{
		Tool:     "raijin-js",
		Findings: []Finding{{ID: "path-ab12cd34", Severity: "medium", Tags: []string{"admin"}, Value: "/internal/debug", Locations: []string{"/app.js"}, Files: 1, Fingerprint: "fp"}},
		Groups:   []Group{{ID: "js-ef56ab78", Kind: "js", Locations: []string{"/app.js"}, Files: 1}},
		Omitted:  map[string]int{},
		Errors:   []Error{},
		Next:     []string{},
		Budget:   Budget{MaxItems: 20, MaxBytes: 8000},
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"fingerprint", "count", "files", "confidence", "rule", "status", "variants", "new", "origin", "omitted", "errors", "next", "raw", "budget"} {
		if strings.Contains(string(b), `"`+k+`"`) {
			t.Errorf("%s should be left out: %s", k, b)
		}
	}
	if strings.Contains(string(b), "null") {
		t.Errorf("no null values: %s", b)
	}
	if !strings.Contains(string(b), `{"id":"js-ef56ab78","kind":"js","locations":["/app.js"]}`) {
		t.Errorf("group: %s", b)
	}
}

func TestSecretFinding(t *testing.T) {
	f := Finding{ID: "secret-x", Severity: "high", Tags: []string{"secret"}, Rule: "aws-access-key", Value: "AKIA…7XQZ", Locations: []string{"/app.js:3", "/vendor.js:3"}, Files: 2}
	b, _ := Marshal(f)
	want := `{"id":"secret-x","severity":"high","tags":["secret"],"rule":"aws-access-key","value":"AKIA…7XQZ","locations":["/app.js:3","/vendor.js:3"]}`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}
}

func TestCountAndBudgetAppearWhenSomethingIsCut(t *testing.T) {
	res := Result{
		Findings: []Finding{{ID: "path-x", Tags: []string{"api"}, Value: "/api/a?x=1&y=2", Locations: []string{"/a.js"}, Count: 7, Files: 7}},
		Groups:   []Group{{ID: "path-y", Kind: "path", Variants: []string{"/about"}, Count: 4, Files: 4}},
		Budget:   Budget{MaxItems: 20, MaxBytes: 8000, Truncated: true},
	}
	b, _ := json.Marshal(res)
	s := string(b)
	if !strings.Contains(s, `"locations":["/a.js"],"count":7`) || !strings.Contains(s, `{"id":"path-y","kind":"path","variants":["/about"],"count":4}`) {
		t.Errorf("count must be written when locations were cut: %s", s)
	}
	if !strings.Contains(s, `"budget":{"max_items":20,"max_bytes":8000,"truncated":true}`) || strings.Count(s, "budget") != 1 {
		t.Errorf("budget must be written once when something was cut: %s", s)
	}
	if strings.Contains(s, `&`) || strings.Contains(s, `…`) {
		t.Errorf("& and … must not be escaped: %s", s)
	}
}
