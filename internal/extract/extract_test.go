package extract

import (
	"sort"
	"strings"
	"testing"
)

// Fake keys in the shape of real ones, built at run time so no scanner reads this file as a leak.
var (
	awsKey    = "AKIA" + "IOSFODNN7EXAMPLE"
	googleKey = "AIza" + strings.Repeat("Ab1_", 8) + "xyz"
	ghToken   = "ghp" + "_" + strings.Repeat("aB3d", 9)
	slackTok  = "xox" + "b-1234567890-abcdefghij"
	stripeKey = "sk_" + "live_" + strings.Repeat("a1B2", 6)
	jwt       = "eyJ" + "hbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLWZha2U"
)

func TestLiteral(t *testing.T) {
	const file = "http://h.test/static/js/app.js"
	for lit, want := range map[string]string{
		`"/api/v1/users"`:                   "path /api/v1/users",
		`'/api/v1/users?page=1'`:            "path /api/v1/users?page=1",
		`"\/api\/v2\/x"`:                    "path /api/v2/x",
		"`${API_BASE}/api/v1/orders/${id}`": "path /api/v1/orders/{id}",
		"`/u/${a + b}/x`":                   "path /u/{}/x",
		`"./chunk-2.js"`:                    "path /static/js/chunk-2.js",
		`"../img/a.png"`:                    "path /static/img/a.png",
		`"http://h.test/api/x"`:             "path /api/x",
		`"https://cdn.other.test/lib.js"`:   "url https://cdn.other.test/lib.js",
		`"//cdn.other.test/a"`:              "url http://cdn.other.test/a",
		`"http://u:pw@build.internal/x"`:    "url http://build.internal/x",
		`"wss://h.other.test/socket"`:       "url wss://h.other.test/socket",
		`"/"`:                               " ",
		`"/a"`:                              " ",
		`"//comment"`:                       " ",
		`"application/json"`:                " ",
		`"/[a-z]+/g"`:                       " ",
		`"hello world"`:                     " ",
		`"/a b"`:                            " ",
	} {
		kind, v := Literal(lit, file)
		if got := kind + " " + v; got != want {
			t.Errorf("%s: got %q, want %q", lit, got, want)
		}
	}
}

func TestExtract(t *testing.T) {
	body := strings.Join([]string{
		`import a from "./a.js"; fetch("/api/x"); fetch("/api/x");`,
		`const k = "` + awsKey + `", ga = "https://www.google-analytics.com/analytics.js";`,
		`// don't break the next line`,
		`var cfg = {apiKey: "` + googleKey + `", password: "s3cr3t-pass"};`,
		`//# sourceMappingURL=app.js.map`,
	}, "\n")
	var got []string
	for _, h := range Extract(body, "http://h.test/js/app.js") {
		s := h.Kind + " " + h.Value
		if h.Kind == "secret" {
			s = strings.Join(strings.Fields(s+" "+h.Rule+" "+h.Severity+" "+h.Confidence), " ")
			s += " " + string(rune('0'+h.Line))
		}
		got = append(got, strings.TrimSpace(s))
	}
	sort.Strings(got)
	want := []string{
		"path /api/x",
		"path /js/a.js",
		"secret AIza…_xyz google-api-key high 4",
		"secret AKIA…MPLE aws-access-key high 2",
		`secret password: "s3…ss" generic-secret medium heuristic 4`,
		"sourcemap /js/app.js.map",
		"url https://www.google-analytics.com/analytics.js",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestSecretRules(t *testing.T) {
	for line, want := range map[string]string{
		`k="` + awsKey + `"`: "aws-access-key AKIA…MPLE",
		`aws_secret_access_key = "` + strings.Repeat("aB1/", 10) + `"`: "aws-secret-key aws_secret_access_key = \"aB1/…aB1/\"",
		`t="` + googleKey + `"`:                            "google-api-key AIza…_xyz",
		`t="` + ghToken + `"`:                              "github-token ghp_…aB3d",
		`t="` + slackTok + `"`:                             "slack-token xoxb…ghij",
		`t="` + stripeKey + `"`:                            "stripe-secret-key sk_l…a1B2",
		`k="-----BEGIN RSA PRIVATE KEY-----\nMII"`:         "private-key -----BEGIN RSA PRIVATE KEY-----",
		`u="https://deploy:hunter2hunter2@ci.acme.test/x"`: "url-credentials https://deploy:hu…r2@ci.acme.test",
		`s="` + jwt + `"`:                                  "jwt eyJh…ha2U",
		`client_secret: "abc123def456"`:                    `generic-secret client_secret: "ab…56"`,
		`token = 'abcdefghijkl'`:                           "",
		`csrf_token: "abc123def456"`:                       "",
	} {
		var got []string
		for _, h := range Secrets(line) {
			got = append(got, h.Rule+" "+h.Value)
		}
		if strings.Join(got, "|") != want {
			t.Errorf("%s: got %q, want %q", line, got, want)
		}
	}
}

func TestSpecificRuleWinsOverGeneric(t *testing.T) {
	hits := Secrets(`apiKey: "` + googleKey + `"`)
	if len(hits) != 1 || hits[0].Rule != "google-api-key" || hits[0].Full != googleKey {
		t.Errorf("hits = %+v", hits)
	}
}

func TestRedact(t *testing.T) {
	for in, want := range map[string]string{"AKIAIOSFODNN7EXAMPLE": "AKIA…MPLE", "abcdefgh": "ab…gh", "short": "…", "ñandú-ñandú-ñandú": "ñand…andú"} {
		if got := Redact(in); got != want {
			t.Errorf("Redact(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLibrary(t *testing.T) {
	for u, want := range map[string]string{
		"http://h.test/js/jquery-3.7.1.min.js":           "jquery 3.7.1",
		"http://h.test/js/jquery.min.js":                 "jquery 3.6.0",
		"http://h.test/js/react-dom.production.min.js":   "react-dom 3.6.0",
		"http://h.test/js/lodash@4.17.21.js?v=2":         "lodash 4.17.21",
		"http://h.test/node_modules/axios/dist/axios.js": "axios 3.6.0",
		"http://h.test/js/app.js":                        " ",
		"http://h.test/js/jquery-plugin-mine.js":         " ",
	} {
		name, v := Library(u, "/*! Some Lib v3.6.0 | MIT */")
		if got := name + " " + v; got != want {
			t.Errorf("%s: %q, want %q", u, got, want)
		}
	}
}

func TestHostAndOrigin(t *testing.T) {
	if Origin("http://u@h.test:80/x?y") != "http://u@h.test:80" || Host("http://u@H.test:80/x") != "h.test" || Host("http://[::1]:8/x") != "::1" || Host("/x") != "" {
		t.Error("Origin / Host")
	}
}
