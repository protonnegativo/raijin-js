// Command raijin-js runs katana to find JavaScript files and returns the endpoints, API routes, source maps
// and secrets in them, deduplicated across files and ranked, for AI agents.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"

	"github.com/protonnegativo/raijin-js/internal/banner"
	"github.com/protonnegativo/raijin-js/internal/katana"
	"github.com/protonnegativo/raijin-js/internal/reduce"
	"github.com/protonnegativo/raijin-js/internal/schema"
	"github.com/protonnegativo/raijin-js/internal/scope"
	"github.com/protonnegativo/raijin-js/internal/state"
)

const version = "0.1.0"

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("raijin-js", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var targets multi
	fs.Var(&targets, "u", "start URL (repeatable; default: every host the scope names, as https://<host>)")
	list := fs.String("l", "", "file with one start URL per line")
	scopeFile := fs.String("scope", "", "scope file (required): domains, *.wildcards, IPs, CIDRs, !exclusions")
	depth := fs.Int("depth", 3, "maximum crawl depth (katana -d)")
	maps := fs.Bool("maps", true, "ask katana to fetch the source maps the files point to (katana -em map)")
	duration := fs.String("duration", "", "maximum crawl time per target, e.g. 2m (katana -ct)")
	rate := fs.Int("rate", 0, "requests per second (katana -rl)")
	timeout := fs.Int("timeout", 0, "request timeout in seconds")
	concurrency := fs.Int("concurrency", 0, "concurrent fetchers (katana -c)")
	maxItems := fs.Int("max-items", 0, "maximum findings in the output (0 keeps all)")
	maxBytes := fs.Int("max-bytes", reduce.Defaults().MaxBytes, "maximum size of the JSON output; cuts are counted in omitted")
	rawPath := fs.String("raw", "", "file for katana's full JSONL output (default: a new file in the temp dir)")
	statePath := fs.String("state", "", "state file; marks findings that are new since the last run")
	format := fs.String("format", "json", "output format: json or table")
	pretty := fs.Bool("pretty", false, "indent the JSON (compact by default, which costs fewer tokens)")
	input := fs.String("input", "", "read an existing katana JSONL file instead of running katana")
	bin := fs.String("katana", "katana", "path to the katana binary")
	showVersion := fs.Bool("version", false, "print the version")
	showBanner := fs.Bool("banner", false, "print the Raijin banner to stderr (off by default to keep output small)")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: raijin-js --scope scope.txt [-u url | -l urls.txt | --input katana.jsonl] [flags] [-- extra katana args]\n\nWith no targets it crawls every host the scope names (https://<host>).\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *showBanner {
		banner.Write(stderr, "raijin-js", version, useColor(stderr))
	}
	if *showVersion {
		fmt.Fprintln(stdout, "raijin-js", version)
		return 0
	}
	if *scopeFile == "" {
		fmt.Fprintln(stderr, "raijin-js: --scope is required")
		return 1
	}
	sc, err := scope.Load(*scopeFile)
	if err != nil {
		fmt.Fprintln(stderr, "raijin-js: scope:", err)
		return 1
	}

	res := schema.Result{
		Tool:     "raijin-js",
		Version:  version,
		Findings: []schema.Finding{},
		Groups:   []schema.Group{},
		Omitted:  map[string]int{},
		Errors:   []schema.Error{},
		Next:     []string{},
		Budget:   schema.Budget{MaxItems: *maxItems, MaxBytes: *maxBytes},
	}

	var events []katana.Event
	if *input != "" {
		f, err := os.Open(*input)
		if err != nil {
			fmt.Fprintln(stderr, "raijin-js:", err)
			return 1
		}
		events, err = katana.Parse(f)
		f.Close()
		if err != nil {
			fmt.Fprintln(stderr, "raijin-js:", err)
			return 1
		}
		res.Target = *input
	} else {
		if *list != "" {
			lines, err := readLines(*list)
			if err != nil {
				fmt.Fprintln(stderr, "raijin-js:", err)
				return 1
			}
			targets = append(targets, lines...)
		}
		var inScope []string
		if len(targets) == 0 {
			// no targets given: crawl what the scope names. katana needs URLs and does not crawl a
			// bare host, so each host starts at https://<host>.
			hosts, wildcards, ranges := sc.Targets()
			for _, h := range hosts {
				inScope = append(inScope, "https://"+h)
			}
			for _, w := range wildcards {
				res.Next = append(res.Next, "raijin-subs --scope "+*scopeFile+" -d "+strings.TrimPrefix(w, "*.")+", then raijin-js -l <live URLs> to cover "+w)
			}
			for _, r := range ranges {
				res.Next = append(res.Next, "raijin-ports --scope "+*scopeFile+" -host "+r+", then raijin-js -l <web URLs> to cover "+r)
			}
		} else {
			inScope = filter(targets, sc, res.Omitted)
		}
		if len(inScope) == 0 {
			if len(res.Next) > 0 {
				res.Summary = "the scope names no single host to scan"
				res.Target = *scopeFile
				write(stdout, &res, *format, *pretty)
				return 1
			}
			fmt.Fprintln(stderr, "raijin-js: no targets in scope")
			return 1
		}
		res.Target = targetSummary(inScope, res.Omitted["out_of_scope"])

		tempRaw := *rawPath == ""
		if tempRaw {
			f, err := os.CreateTemp("", "raijin-js-*.jsonl")
			if err != nil {
				fmt.Fprintln(stderr, "raijin-js:", err)
				return 1
			}
			f.Close()
			*rawPath = f.Name()
		}
		res.Raw = *rawPath

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		var stderrTail string
		kopt := katana.Options{
			Binary: *bin, Depth: *depth, Duration: *duration, Rate: *rate, Timeout: *timeout,
			Concurrency: *concurrency, Hosts: inScope, Extra: fs.Args(), RawPath: *rawPath,
		}
		events, stderrTail, err = katana.Run(ctx, inScope, kopt)
		switch {
		case errors.Is(err, katana.ErrNotFound):
			res.Errors = append(res.Errors, schema.Error{Kind: "missing_engine", Hint: "install katana (go install github.com/projectdiscovery/katana/cmd/katana@latest) or pass --katana <path>"})
			res.Summary = "katana not found, nothing crawled"
			res.Raw = ""
			if tempRaw {
				os.Remove(*rawPath)
			}
			write(stdout, &res, *format, *pretty)
			return 2
		case err != nil:
			res.Errors = append(res.Errors, engineError(err, stderrTail))
		}
		// A second, short katana run fetches the source maps the files point to, so an exposed map is
		// told apart from a dangling comment. The extra katana args (headers, proxy) apply to it too.
		if mapURLs := reduce.MapURLs(events, sc.Allowed); *maps && len(mapURLs) > 0 && ctx.Err() == nil {
			kopt.Maps = true
			more, tail, err := katana.Run(ctx, mapURLs, kopt)
			if err != nil {
				res.Errors = append(res.Errors, engineError(err, tail))
			}
			events = append(events, more...)
		}
	}

	opt := reduce.Defaults()
	opt.MaxItems = *maxItems
	opt.MaxBytes = *maxBytes
	opt.InScope = sc.Allowed
	out := reduce.Reduce(events, opt)
	res.Findings, res.Groups, res.Origin = out.Findings, out.Groups, out.Origin
	for k, v := range out.Omitted {
		res.Omitted[k] += v
	}

	newCount := -1
	if *statePath != "" {
		st, err := state.Load(*statePath)
		if err != nil {
			res.Errors = append(res.Errors, schema.Error{Kind: "state_error", Hint: err.Error()})
		} else {
			newCount = st.Mark(res.Findings, out.Locations)
			if err := st.Save(*statePath); err != nil {
				res.Errors = append(res.Errors, schema.Error{Kind: "state_error", Hint: err.Error()})
			}
		}
	}

	res.Summary = summary(res, out.Stats, newCount)
	if res.Omitted["findings"] > 0 {
		res.Budget.Truncated = true
	}
	reduce.Fit(&res, *maxBytes)
	if res.Budget.Truncated {
		hint := "raise --max-bytes"
		if src := res.Raw + *input; src != "" {
			hint += " or read " + src + " for what was cut"
		}
		res.Next = append(res.Next, hint)
		reduce.Fit(&res, *maxBytes) // the hint takes room too
	}
	write(stdout, &res, *format, *pretty)
	return 0
}

// useColor is true when w is a terminal and NO_COLOR is not set.
func useColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func filter(targets []string, sc *scope.Scope, omitted map[string]int) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		if !sc.Allowed(t) {
			omitted["out_of_scope"]++
			continue
		}
		out = append(out, t)
	}
	return out
}

func targetSummary(targets []string, skipped int) string {
	s := fmt.Sprintf("%d target(s)", len(targets))
	if len(targets) == 1 {
		s = targets[0]
	}
	if skipped > 0 {
		s += fmt.Sprintf(" (%d out of scope skipped)", skipped)
	}
	return s
}

// summary is written before the budget, so it stays true when Fit cuts.
func summary(res schema.Result, st reduce.Stats, newCount int) string {
	bySev := map[string]int{}
	for _, f := range res.Findings {
		bySev[f.Severity]++
	}
	var parts []string
	for _, sev := range []string{"critical", "high", "medium", "low", "info", "unknown"} {
		if n := bySev[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	s := fmt.Sprintf("%d JS files", st.Files)
	if st.Libraries > 0 {
		s += fmt.Sprintf(" (%d libraries)", st.Libraries)
	}
	s += fmt.Sprintf(", %d items: %d findings", st.Items, len(res.Findings))
	if len(parts) > 0 {
		s += " (" + strings.Join(parts, ", ") + ")"
	}
	s += fmt.Sprintf(", %d groups", len(res.Groups))
	if newCount >= 0 {
		s += fmt.Sprintf(", %d new", newCount)
	}
	return s
}

func write(w io.Writer, res *schema.Result, format string, pretty bool) {
	if format == "table" {
		fmt.Fprintln(w, res.Summary)
		if res.Origin != "" {
			fmt.Fprintln(w, "origin  ", res.Origin)
		}
		for _, f := range res.Findings {
			mark := ""
			if f.New {
				mark = " [new]"
			}
			what := strings.Join(f.Tags, ",")
			if f.Rule != "" {
				what += ":" + f.Rule
			}
			fmt.Fprintf(w, "%-8s %s %s%s (%d)%s\n", strings.ToUpper(f.Severity), what, f.Value, status(f.Status), f.Files, mark)
			for _, l := range f.Locations {
				fmt.Fprintf(w, "         %s\n", l)
			}
		}
		for _, g := range res.Groups {
			what := g.Value
			if len(g.Variants) > 0 {
				what = fmt.Sprintf("%d items", len(g.Variants))
			}
			fmt.Fprintf(w, "group    %s%s (%d files)\n", strings.Join(strings.Fields(g.Kind+" "+what), " "), status(g.Status), g.Files)
		}
		for _, e := range res.Errors {
			fmt.Fprintf(w, "error    %s: %s\n", e.Kind, e.Hint)
		}
		return
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if pretty {
		enc.SetIndent("", "  ")
	}
	_ = enc.Encode(res)
}

func status(s int) string {
	if s == 0 {
		return ""
	}
	return fmt.Sprint(" ", s)
}

func engineError(err error, stderrTail string) schema.Error {
	hint := err.Error()
	if stderrTail != "" {
		hint += ": " + stderrTail
	}
	return schema.Error{Kind: "engine_error", Hint: hint}
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out, sc.Err()
}
