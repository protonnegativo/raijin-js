// Package katana runs the ProjectDiscovery katana crawler to find JavaScript files, and parses its JSONL
// output.
package katana

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/protonnegativo/raijin-js/internal/scope"
)

// ErrNotFound is returned when the katana binary is not on PATH.
var ErrNotFound = errors.New("katana binary not found")

// Event is the subset of a katana JSONL result that Raijin uses: one request katana made (or found),
// and what came back.
type Event struct {
	Request  Request   `json:"request"`
	Response *Response `json:"response"`
	Error    string    `json:"error"`
}

// Request is the endpoint katana visited and where it found it.
type Request struct {
	Method   string `json:"method"`
	Endpoint string `json:"endpoint"`
	// Tag and Attribute say where the endpoint came from: "script"/"src", "js"/"jsluice-fetch",
	// "js"/"jsluice-stringLiteral" and so on. The crawl's start URL has neither.
	Tag       string `json:"tag"`
	Attribute string `json:"attribute"`
	// Source is the page or file the endpoint was found in.
	Source string `json:"source"`
}

// Response is what the endpoint answered. katana writes an empty response (no status, no body) when the
// body is identical to one it has already seen in the crawl.
type Response struct {
	StatusCode int            `json:"status_code"`
	Headers    map[string]any `json:"headers"`
	Body       string         `json:"body"`
}

// Status is the response status, or 0 when katana recorded no response.
func (e Event) Status() int {
	if e.Response == nil {
		return 0
	}
	return e.Response.StatusCode
}

// Body is the response body, or "".
func (e Event) Body() string {
	if e.Response == nil {
		return ""
	}
	return e.Response.Body
}

// ContentType is the Content-Type header as katana wrote it, or "".
func (e Event) ContentType() string {
	if e.Response == nil {
		return ""
	}
	for k, v := range e.Response.Headers {
		if strings.EqualFold(k, "content-type") {
			if l, ok := v.([]any); ok && len(l) > 0 {
				v = l[0]
			}
			return fmt.Sprint(v)
		}
	}
	return ""
}

// Options are the katana settings Raijin passes through.
type Options struct {
	Binary string
	// Depth is the maximum crawl depth (katana -d).
	Depth       int
	Duration    string
	Rate        int
	Timeout     int
	Concurrency int
	// Hosts are the target hosts; the crawl never follows a link to another host (katana -cs).
	Hosts []string
	Extra []string
	// RawPath, if set, receives katana's JSONL output unchanged.
	RawPath string
	// Maps fetches the given source map URLs and nothing else (-d 1 -em map), and appends to RawPath.
	Maps bool
}

// Run crawls the targets and returns every event, plus the last stderr lines if katana failed.
func Run(ctx context.Context, targets []string, opt Options) ([]Event, string, error) {
	bin := opt.Binary
	if bin == "" {
		bin = "katana"
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		return nil, "", ErrNotFound
	}

	list, err := os.CreateTemp("", "raijin-js-targets-*.txt")
	if err != nil {
		return nil, "", err
	}
	defer os.Remove(list.Name())
	if _, err := io.WriteString(list, strings.Join(targets, "\n")+"\n"); err != nil {
		list.Close()
		return nil, "", err
	}
	list.Close()

	// katana reads targets from stdin when stdin is not a terminal; Stdin stays nil (/dev/null) so a
	// caller's pipe is never read as a target list.
	cmd := exec.CommandContext(ctx, path, Args(list.Name(), opt)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, "", err
	}
	var r io.Reader = stdout
	if opt.RawPath != "" {
		flags := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
		if opt.Maps {
			flags = os.O_CREATE | os.O_WRONLY | os.O_APPEND
		}
		raw, err := os.OpenFile(opt.RawPath, flags, 0o600)
		if err != nil {
			return nil, "", err
		}
		defer raw.Close()
		r = io.TeeReader(stdout, raw)
	}
	if err := cmd.Start(); err != nil {
		return nil, "", err
	}
	events, parseErr := Parse(r)
	waitErr := cmd.Wait()
	if parseErr != nil {
		return events, tail(stderr.String(), 3), parseErr
	}
	if waitErr != nil {
		return events, tail(stderr.String(), 3), fmt.Errorf("katana exited: %w", waitErr)
	}
	return events, "", nil
}

// Args builds the katana command line. The crawl parses JavaScript (-jc, and -jsl: jsluice finds the
// fetch() calls, imports and string endpoints in each file). -or drops the raw request and response
// strings, which nothing reads; the body is kept, because it is what raijin-js parses. The source map
// pass fetches only the given URLs: katana leaves .map files out of its output unless -em map asks for
// them, and their bodies are not needed (-ob).
func Args(listFile string, opt Options) []string {
	args := []string{"-list", listFile, "-jsonl", "-silent", "-nc", "-duc", "-or"}
	if opt.Maps {
		args = append(args, "-d", "1", "-em", "map", "-ob")
	} else {
		args = append(args, "-jc", "-jsl")
		if opt.Depth > 0 {
			args = append(args, "-d", fmt.Sprint(opt.Depth))
		}
		if opt.Duration != "" {
			args = append(args, "-ct", opt.Duration)
		}
	}
	if opt.Rate > 0 {
		args = append(args, "-rl", fmt.Sprint(opt.Rate))
	}
	if opt.Timeout > 0 {
		args = append(args, "-timeout", fmt.Sprint(opt.Timeout))
	}
	if opt.Concurrency > 0 {
		args = append(args, "-c", fmt.Sprint(opt.Concurrency))
	}
	if re := HostScope(opt.Hosts); re != "" {
		args = append(args, "-cs", re)
	}
	return append(args, opt.Extra...)
}

// HostScope is the katana crawl scope (-cs) that keeps the crawl on the given hosts, any port.
func HostScope(hosts []string) string {
	seen := map[string]bool{}
	var alts []string
	for _, h := range hosts {
		h = scope.Hostname(h)
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		alts = append(alts, regexp.QuoteMeta(h))
	}
	if len(alts) == 0 {
		return ""
	}
	return `^https?://(` + strings.Join(alts, "|") + `)(:[0-9]+)?([/?#]|$)`
}

// Parse reads katana JSONL. Lines that are not JSON objects with an endpoint are skipped.
func Parse(r io.Reader) ([]Event, error) {
	var events []Event
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 64*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var ev Event
		if err := json.Unmarshal(line, &ev); err != nil {
			continue
		}
		if ev.Request.Endpoint == "" {
			continue
		}
		events = append(events, ev)
	}
	return events, sc.Err()
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}
