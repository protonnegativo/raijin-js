package katana

import (
	"regexp"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	in := `[INF] Started standard crawling
{"request":{"method":"GET","endpoint":"http://h.test/static/app.js","tag":"script","attribute":"src","source":"http://h.test/"},"response":{"status_code":200,"headers":{"Content-Type":"application/javascript"},"body":"fetch(\"/api/x\")"}}
{"request":{"method":"GET","endpoint":"http://h.test/api/x","tag":"js","attribute":"jsluice-fetch","source":"http://h.test/static/app.js"},"response":{"headers":{}}}
{"request":{"method":"GET","endpoint":"http://h.test/slow.js"},"error":"context deadline exceeded"}
{"request":{}}
not json
`
	events, st, err := Parse(strings.NewReader(in))
	if err != nil || len(events) != 3 {
		t.Fatalf("got %d events, err %v", len(events), err)
	}
	if st.Lines != 6 || st.Unparsed != 3 {
		t.Errorf("stats = %+v, want 6 lines, 3 unparsed", st)
	}
	if e := events[0]; e.Status() != 200 || e.ContentType() != "application/javascript" || e.Body() != `fetch("/api/x")` {
		t.Errorf("first event = %+v", e)
	}
	if e := events[1]; e.Status() != 0 || e.Body() != "" || e.Request.Source != "http://h.test/static/app.js" {
		t.Errorf("an empty response has no status: %+v", e)
	}
	if e := events[2]; e.Status() != 0 || e.Error != "context deadline exceeded" || e.Body() != "" {
		t.Errorf("a failed request keeps its error: %+v", e)
	}
}

func TestArgs(t *testing.T) {
	args := strings.Join(Args("list.txt", Options{Depth: 3, Rate: 50, Hosts: []string{"http://localhost:19100/", "a.example.com"}, Extra: []string{"-H", "X: y"}}), " ")
	for _, want := range []string{"-list list.txt -jsonl -silent -nc -duc -or", "-jc -jsl", "-d 3", "-rl 50", "-H X: y"} {
		if !strings.Contains(args, want) {
			t.Errorf("args %q should contain %q", args, want)
		}
	}
	if strings.Contains(args, "-ob") {
		t.Errorf("the crawl must keep the bodies, raijin-js parses them: %q", args)
	}
	if !strings.Contains(args, `-cs ^https?://(localhost|a\.example\.com)(:[0-9]+)?([/?#]|$)`) {
		t.Errorf("crawl scope: %q", args)
	}
	maps := strings.Join(Args("maps.txt", Options{Depth: 3, Maps: true, Hosts: []string{"localhost"}}), " ")
	if !strings.Contains(maps, "-d 1 -em map -ob") || strings.Contains(maps, "-jc") || strings.Contains(maps, "-d 3") {
		t.Errorf("source map pass: %q", maps)
	}
}

func TestHostScopeStaysOnHost(t *testing.T) {
	re := regexp.MustCompile(HostScope([]string{"http://localhost:19100/"}))
	for u, want := range map[string]bool{
		"http://localhost:19100/x":      true,
		"https://localhost/":            true,
		"http://localhost":              true,
		"http://localhost.evil.test/":   false,
		"http://evil.test/?localhost":   false,
		"http://localhostx:19100/":      false,
		"http://user@localhost:19100/x": false,
		"http://127.0.0.1:19100/x":      false,
	} {
		if re.MatchString(u) != want {
			t.Errorf("%s: match %v, want %v", u, !want, want)
		}
	}
}
