// Package extract finds endpoints, URLs, source maps and secret-like strings in the body of a JavaScript
// file.
//
// It is lexical, not a parser: it reads every string literal ("...", '...' and `...`) and keeps the ones
// that are a URL or a path, reads the sourceMappingURL comments, and runs a small ruleset (rules.json)
// on every line for secrets. bench/verify.py ports these rules to Python to check the output, so a
// change here is a change there.
package extract

import (
	_ "embed"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

// Hit is one thing found in a file.
type Hit struct {
	// Kind is "path", "url", "sourcemap" or "secret".
	Kind string
	// Value is the path (resolved against the file and without the file's origin when it is on it), the
	// URL (without user:password), the source map, or the secret match with the secret redacted.
	Value string
	// Rule, Severity and Confidence are set for secrets.
	Rule       string
	Severity   string
	Confidence string
	// Full is the secret match, not redacted; it is only used as a key and never written.
	Full string
	// Line is the 1-based line of a secret.
	Line int
}

// Rule is one secret rule of rules.json.
type Rule struct {
	ID         string `json:"id"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	Pattern    string `json:"pattern"`
	// Secret is the group that holds the secret (0 is the whole match); it is what gets redacted.
	Secret int `json:"secret"`
	// Redact false writes the match as it is: a PEM header is not secret, the key after it is.
	Redact *bool `json:"redact"`
	// Require is a pattern the secret must also match (the generic rule wants a digit).
	Require string `json:"require"`

	re, require *regexp.Regexp
}

//go:embed rules.json
var rulesJSON []byte

// Rules are the secret rules, in the order they run. A match whose secret overlaps one found by an
// earlier rule on the same line is skipped, so the specific rules come first and the generic one last.
var Rules = loadRules()

func loadRules() []Rule {
	var rules []Rule
	if err := json.Unmarshal(rulesJSON, &rules); err != nil {
		panic("rules.json: " + err.Error())
	}
	for i := range rules {
		rules[i].re = regexp.MustCompile(rules[i].Pattern)
		if rules[i].Require != "" {
			rules[i].require = regexp.MustCompile(rules[i].Require)
		}
	}
	return rules
}

var (
	literal = regexp.MustCompile("\"(?:[^\"\\\\\\n]|\\\\.)*\"|'(?:[^'\\\\\\n]|\\\\.)*'|`(?:[^`\\\\]|\\\\.)*`")
	// placeholder is a ${...} in a template literal.
	placeholder = regexp.MustCompile(`\$\{([^}]*)\}`)
	ident       = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$.]*$`)
	// leadingVar is a template literal that starts with a variable and then a path: ${API_BASE}/users.
	leadingVar = regexp.MustCompile(`^\{[^}]*\}/`)
	urlRe      = regexp.MustCompile(`^(?:(?:https?|wss?):)?//(?:[^\s/?#@"'<>\\]+@)?([A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(?::[0-9]{1,5})?(?:[/?#][^\s"'<>\\]*)?$`)
	pathRe     = regexp.MustCompile(`^(?:\.\.?)?/[A-Za-z0-9_.~%{}@:+,;=!$/-]*[A-Za-z][A-Za-z0-9_.~%{}@:+,;=!$/-]*(?:[?#][^\s"'<>\\]*)?$`)
	mapRe      = regexp.MustCompile(`[/][/*][#@]\s*sourceMappingURL=([^\s*'"]+)`)
)

// Extract returns what the body of the JavaScript file at fileURL contains: every path and URL string
// literal, every source map comment and every secret rule match. A path or URL repeated in the file is
// one hit; a secret is one hit per line it is on.
func Extract(body, fileURL string) []Hit {
	var hits []Hit
	seen := map[string]bool{}
	add := func(h Hit) {
		k := h.Kind + "\x00" + h.Value + "\x00" + h.Rule + "\x00" + h.Full + "\x00" + strconv.Itoa(h.Line)
		if !seen[k] {
			seen[k] = true
			hits = append(hits, h)
		}
	}
	for _, lit := range literal.FindAllString(body, -1) {
		if kind, v := Literal(lit, fileURL); kind != "" {
			add(Hit{Kind: kind, Value: v})
		}
	}
	for _, m := range mapRe.FindAllStringSubmatch(body, -1) {
		v := m[1]
		if strings.HasPrefix(v, "data:") {
			if i := strings.Index(v, ","); i >= 0 {
				v = v[:i+1]
			}
			add(Hit{Kind: "sourcemap", Value: v + "…"})
			continue
		}
		if !strings.HasPrefix(v, "/") && !strings.Contains(v, "://") && !strings.HasPrefix(v, ".") {
			v = "./" + v // a source map URL is relative to its file
		}
		add(Hit{Kind: "sourcemap", Value: Resolve(v, fileURL)})
	}
	for i, line := range strings.Split(body, "\n") {
		for _, h := range Secrets(line) {
			h.Line = i + 1
			add(h)
		}
	}
	return hits
}

// Literal classifies one string literal, quotes included: ("url", value), ("path", value) or ("", "").
// "\/" is read as "/". In a template literal each ${name} is written {name} (other expressions {}), and
// a leading ${...} before a "/" is dropped: `${API}/users/${id}` is /users/{id}.
func Literal(lit, fileURL string) (string, string) {
	if len(lit) < 2 {
		return "", ""
	}
	v := strings.ReplaceAll(lit[1:len(lit)-1], `\/`, "/")
	if lit[0] == '`' {
		v = placeholder.ReplaceAllStringFunc(v, func(m string) string {
			name := strings.TrimSpace(m[2 : len(m)-1])
			if ident.MatchString(name) {
				return "{" + name + "}"
			}
			return "{}"
		})
		if loc := leadingVar.FindStringIndex(v); loc != nil {
			v = v[loc[1]-1:]
		}
	}
	if len(v) > 500 {
		return "", ""
	}
	if m := urlRe.FindStringSubmatch(v); m != nil {
		host := m[1]
		if strings.HasPrefix(v, "//") && !strings.Contains(host, ".") {
			return "", "" // "//comment", not a protocol-relative URL
		}
		r := Resolve(v, fileURL)
		if strings.HasPrefix(r, "/") && !strings.HasPrefix(r, "//") {
			return "path", r
		}
		return "url", r
	}
	if strings.HasPrefix(v, "//") || strings.HasPrefix(v, "/*") {
		return "", ""
	}
	if pathRe.MatchString(v) && len(strings.SplitN(strings.SplitN(v, "?", 2)[0], "#", 2)[0]) >= 3 {
		return "path", Resolve(v, fileURL)
	}
	return "", ""
}

// Resolve writes a path or URL found in the file at fileURL the way the output lists it:
//
//   - "./x" and "../x" are resolved against the file, as katana does;
//   - "//host/x" takes the file's scheme;
//   - user:password@ is dropped from a URL (the url-credentials rule reports it);
//   - a URL on the file's own origin is written as its path.
func Resolve(v, fileURL string) string {
	origin := Origin(fileURL)
	if strings.HasPrefix(v, "./") || strings.HasPrefix(v, "../") {
		dir := strings.TrimPrefix(fileURL, origin)
		if i := strings.IndexAny(dir, "?#"); i >= 0 {
			dir = dir[:i]
		}
		dir = dir[:strings.LastIndex(dir, "/")+1]
		if dir == "" {
			dir = "/"
		}
		rest := ""
		if i := strings.IndexAny(v, "?#"); i >= 0 {
			v, rest = v[:i], v[i:]
		}
		return removeDots(dir+v) + rest
	}
	if strings.HasPrefix(v, "//") {
		if i := strings.Index(origin, "://"); i >= 0 {
			v = origin[:i+1] + v
		}
	}
	i := strings.Index(v, "://")
	if i < 0 {
		return v
	}
	auth := v[i+3:]
	end := strings.IndexAny(auth, "/?#")
	if end < 0 {
		end = len(auth)
	}
	if at := strings.LastIndex(auth[:end], "@"); at >= 0 {
		v = v[:i+3] + auth[at+1:]
	}
	if o := Origin(v); origin != "" && strings.EqualFold(o, origin) {
		if p := v[len(o):]; strings.HasPrefix(p, "/") {
			return p
		} else {
			return "/" + p
		}
	}
	return v
}

// removeDots resolves the "." and ".." segments of an absolute path (RFC 3986, 5.2.4).
func removeDots(p string) string {
	segs := strings.Split(p, "/")
	out := []string{}
	for i, s := range segs {
		last := i == len(segs)-1
		switch s {
		case ".":
			if last {
				out = append(out, "")
			}
		case "..":
			if len(out) > 1 {
				out = out[:len(out)-1]
			}
			if last {
				out = append(out, "")
			}
		default:
			out = append(out, s)
		}
	}
	return strings.Join(out, "/")
}

// Secrets runs the secret rules on one line.
func Secrets(line string) []Hit {
	var hits []Hit
	var taken [][2]int
	for _, r := range Rules {
		for _, m := range r.re.FindAllStringSubmatchIndex(line, -1) {
			g := r.Secret
			a, b := m[2*g], m[2*g+1]
			if a < 0 {
				continue
			}
			secret := line[a:b]
			if r.require != nil && !r.require.MatchString(secret) {
				continue
			}
			overlap := false
			for _, t := range taken {
				if a < t[1] && t[0] < b {
					overlap = true
				}
			}
			if overlap {
				continue
			}
			taken = append(taken, [2]int{a, b})
			full := line[m[0]:m[1]]
			shown := full
			if r.Redact == nil || *r.Redact {
				shown = line[m[0]:a] + Redact(secret) + line[b:m[1]]
			}
			hits = append(hits, Hit{Kind: "secret", Value: shown, Rule: r.ID, Severity: r.Severity, Confidence: r.Confidence, Full: full})
		}
	}
	return hits
}

// Redact keeps the first and last 4 characters of a secret of 16 or more, the first and last 2 of one
// of 8 to 15, and none of a shorter one: "AKIA…7XQZ".
func Redact(s string) string {
	r := []rune(s)
	switch {
	case len(r) >= 16:
		return string(r[:4]) + "…" + string(r[len(r)-4:])
	case len(r) >= 8:
		return string(r[:2]) + "…" + string(r[len(r)-2:])
	}
	return "…"
}

// Origin is the scheme and host of a URL as written ("http://localhost:19100"), or "" when it has none.
func Origin(raw string) string {
	i := strings.Index(raw, "://")
	if i < 0 {
		return ""
	}
	rest := raw[i+3:]
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		return raw[:i+3+j]
	}
	return raw
}

// Host is the lowercase host of a URL without port or user, or "".
func Host(raw string) string {
	o := Origin(raw)
	if o == "" {
		return ""
	}
	h := o[strings.Index(o, "://")+3:]
	if at := strings.LastIndex(h, "@"); at >= 0 {
		h = h[at+1:]
	}
	if strings.HasPrefix(h, "[") {
		if j := strings.Index(h, "]"); j >= 0 {
			return strings.ToLower(h[1:j])
		}
	}
	if j := strings.LastIndex(h, ":"); j >= 0 {
		h = h[:j]
	}
	return strings.ToLower(h)
}

var (
	// libName is the file name of a well-known third-party library, with an optional version and the
	// usual build suffixes: jquery-3.7.1.min.js, react.production.min.js, lodash.min.js.
	libName = regexp.MustCompile(`(?i)^(jquery(?:-ui|-migrate)?|react(?:-dom)?|vue|angular(?:js)?|lodash|underscore|bootstrap|moment|axios|d3|chart|three|backbone|ember|polyfills?|core-js|modernizr|popper|select2|swiper|gsap|socket\.io|zone|tslib|highcharts|leaflet|handlebars|knockout|prototype|mootools|dojo|tinymce|ckeditor|codemirror|plotly|datatables|alpine|htmx|preact|svelte|dayjs|luxon|rxjs|hammer|sortable|dompurify|marked|crypto-js|require|jszip|pdf|qs|clipboard|slick|owl\.carousel|lazysizes|fancybox|mapbox-gl|vue-router|vuex|redux|immutable|regenerator-runtime)(?:[.@-]v?([0-9]+(?:\.[0-9]+)*))?(?:[.-](?:production|development|bundle|slim|umd|esm|cjs|min|global|prod|full|all))*\.m?js$`)
	// libBanner is the version in a library's license banner: "/*! jQuery v3.7.1 | ...".
	libBanner = regexp.MustCompile(`^\s*/\*[!*]?\s*[A-Za-z][\w.@/ -]{0,40}?\sv?([0-9]+\.[0-9]+\.[0-9]+)`)
)

// Library is the name and version of a third-party library file, known by its file name ("jquery",
// "3.7.1"), or a file under node_modules (the package name). The version comes from the name, or else
// from the license banner at the top of the body. name is "" for an application file.
func Library(fileURL, body string) (name, version string) {
	p := strings.TrimPrefix(fileURL, Origin(fileURL))
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	segs := strings.Split(p, "/")
	base := segs[len(segs)-1]
	if m := libName.FindStringSubmatch(base); m != nil {
		name, version = strings.ToLower(m[1]), m[2]
	} else {
		for i, s := range segs {
			if s == "node_modules" && i+1 < len(segs)-1 {
				name = segs[i+1]
				if strings.HasPrefix(name, "@") && i+2 < len(segs)-1 {
					name += "/" + segs[i+2]
				}
				break
			}
		}
	}
	if name != "" && version == "" {
		if m := libBanner.FindStringSubmatch(body); m != nil {
			version = m[1]
		}
	}
	return name, version
}
