// Package reduce turns raw katana events into a small, ranked Raijin result about JavaScript files.
//
// It is lossless for what an agent acts on: every JavaScript file katana found is listed, with its
// status, and every item extracted from the files (paths, URLs, source maps, secrets) or found in them by
// katana's jsluice is listed once, with every file it appeared in. Only exact duplicates are dropped. A
// byte budget can cut, but every cut is counted in omitted.
package reduce

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"

	"github.com/protonnegativo/raijin-js/internal/extract"
	"github.com/protonnegativo/raijin-js/internal/katana"
	"github.com/protonnegativo/raijin-js/internal/schema"
)

// Options control what the reducer keeps.
type Options struct {
	MaxItems int // 0 keeps every finding
	MaxBytes int
	// InScope drops out-of-scope results, and makes a URL on an in-scope host one of the target's own
	// endpoints instead of a third-party URL.
	InScope func(target string) bool
}

// Defaults keep every finding and cap the JSON at a size that fits comfortably in an agent's context.
func Defaults() Options {
	return Options{MaxBytes: 16000}
}

// Stats are the counts of the run, before any budget, for the summary.
type Stats struct {
	Files     int // distinct JavaScript files
	Libraries int // files of a known third-party library
	Items     int // distinct items extracted
}

// Output is what Reduce returns.
type Output struct {
	Findings []schema.Finding
	Groups   []schema.Group
	Omitted  map[string]int
	// Origin is the scheme and host every JavaScript file shares, or "" when there are several.
	Origin string
	// Locations are every location per finding fingerprint, before any budget, for --state.
	Locations map[string][]string
	Stats     Stats
}

// The rules that make a path or URL a finding. Each tag has a fixed severity, and a finding takes the
// highest. Secrets take the severity of their rule, source maps are medium when served and low when
// katana did not request them.
var tagSeverity = map[string]string{
	"admin":    "medium",
	"file":     "medium",
	"bucket":   "medium",
	"internal": "medium",
	"api":      "low",
	"auth":     "low",
}

var (
	// adminWords are path segments (without extension) of admin, debug, internal and config areas.
	adminWords = regexp.MustCompile(`^(admin\w*|administrator|wp-admin|_?debug\w*|internal|private|actuator|console|manage|management|manager|phpmyadmin|config|configuration|settings|backups?|setup|install|server-status|server-info|metrics|env|staff|dashboard|jmx|heapdump|trace|pprof|swagger|swagger-ui|api-docs|graphiql|_profiler|phpinfo|elmah|export)$`)
	// apiWords are path segments of an API.
	apiWords = regexp.MustCompile(`^(api|apis|graphql|gql|rest|rpc|jsonrpc|v[0-9]+|soap|odata)$`)
	// bucketHost is cloud storage: S3, GCS, Azure Blob, DigitalOcean Spaces, R2, Firebase.
	bucketHost = regexp.MustCompile(`(^|\.)(s3[.-]([a-z0-9-]+\.)?amazonaws\.com|storage\.googleapis\.com|storage\.cloud\.google\.com|blob\.core\.windows\.net|digitaloceanspaces\.com|r2\.cloudflarestorage\.com|firebaseio\.com|firebasestorage\.googleapis\.com|appspot\.com)$`)
	// internalHost is a name that only resolves inside a network.
	internalHost = regexp.MustCompile(`(^localhost$|^[a-z0-9-]+$|\.(internal|local|lan|corp|intranet|private|home|localdomain|intra)$|(^|\.)(internal|intranet|corp)\.)`)
)

// fileExt are extensions of backups, dumps, configs, archives, keys and logs.
var fileExt = set("bak", "old", "orig", "backup", "bkp", "swp", "save", "tmp", "sql", "db", "sqlite", "sqlite3",
	"dump", "mdb", "env", "ini", "conf", "cfg", "config", "yml", "yaml", "toml", "properties", "log", "zip", "tar",
	"gz", "tgz", "bz2", "xz", "7z", "rar", "war", "jar", "pem", "key", "p12", "pfx", "kdbx", "htpasswd")

// jsExt are the extensions of a JavaScript file.
var jsExt = set("js", "mjs", "cjs", "jsx")

type item struct {
	key        string
	kind       string // path, url, sourcemap or secret
	value      string
	rule       string
	severity   string
	confidence string
	own        bool                    // a path, or a URL on an in-scope host
	files      map[string]map[int]bool // file URL -> lines (secrets) or {0}
}

type jsFile struct {
	url    string
	status int
	body   string
	lib    string // "jquery 3.7.1", "" for an application file
}

// Reduce lists every JavaScript file and every item found in them: one finding per item worth a look,
// and groups for the rest.
func Reduce(events []katana.Event, opt Options) Output {
	out := Output{Omitted: map[string]int{}, Locations: map[string][]string{}}
	inScope := func(u string) bool { return opt.InScope == nil || opt.InScope(u) }

	var kept []katana.Event
	status := map[string]int{}
	for _, ev := range events {
		if !inScope(ev.Request.Endpoint) {
			out.Omitted["out_of_scope"]++
			continue
		}
		kept = append(kept, ev)
		if s := ev.Status(); s != 0 && status[ev.Request.Endpoint] == 0 {
			status[ev.Request.Endpoint] = s
		}
	}

	files := map[string]*jsFile{}
	var order []string
	for _, ev := range kept {
		u := ev.Request.Endpoint
		if !IsJS(u, ev.ContentType()) {
			continue
		}
		f, ok := files[u]
		if ok {
			out.Omitted["duplicates"]++
			if f.body == "" {
				f.body = ev.Body()
			}
			continue
		}
		files[u] = &jsFile{url: u, status: status[u], body: ev.Body()}
		order = append(order, u)
	}

	items := map[string]*item{}
	var keys []string
	add := func(h extract.Hit, file string) {
		key := h.Kind + "\x00" + h.Value
		if h.Kind == "secret" {
			key = h.Kind + "\x00" + h.Rule + "\x00" + h.Full
		}
		it, ok := items[key]
		if !ok {
			it = &item{key: key, kind: h.Kind, value: h.Value, rule: h.Rule, severity: h.Severity, confidence: h.Confidence, files: map[string]map[int]bool{}}
			it.own = h.Kind == "path" || (h.Kind == "url" && opt.InScope != nil && opt.InScope(h.Value))
			items[key] = it
			keys = append(keys, key)
		}
		if it.files[file] == nil {
			it.files[file] = map[int]bool{}
		}
		it.files[file][h.Line] = true
	}

	// katana's own results: an endpoint jsluice found in a JavaScript file is an item of that file.
	for _, ev := range kept {
		u := ev.Request.Endpoint
		_, isFile := files[u]
		if ev.Request.Tag == "js" && files[ev.Request.Source] != nil {
			v := extract.Resolve(u, ev.Request.Source)
			kind := "url"
			if strings.HasPrefix(v, "/") {
				kind = "path"
			}
			add(extract.Hit{Kind: kind, Value: v}, ev.Request.Source)
			continue
		}
		if !isFile {
			out.Omitted["not_js"]++ // pages, links and the source map responses: raijin-crawl's job, kept in raw
		}
	}
	for _, u := range order {
		f := files[u]
		name, version := extract.Library(u, f.body)
		if name != "" {
			f.lib = strings.TrimSpace(name + " " + version)
			out.Stats.Libraries++
		}
		for _, h := range extract.Extract(f.body, u) {
			add(h, u)
		}
	}
	out.Stats.Files = len(order)
	out.Stats.Items = len(keys)

	origins := map[string]bool{}
	for _, u := range order {
		origins[extract.Origin(u)] = true
	}
	if len(origins) == 1 {
		for o := range origins {
			out.Origin = o
		}
	}
	loc := func(u string) string {
		if out.Origin != "" {
			u = strings.TrimPrefix(u, out.Origin)
		}
		return escapeBrackets(u)
	}

	type groupAcc struct {
		g        schema.Group
		variants []string
	}
	groups := map[string]*groupAcc{}
	var gkeys []string
	addGroup := func(kind, value string, st int, locs []string, variant string, files int) {
		gk := strings.Join([]string{kind, value, fmt.Sprint(st), strings.Join(locs, "\x01")}, "\x00")
		acc, ok := groups[gk]
		if !ok {
			acc = &groupAcc{g: schema.Group{ID: kind + "-" + fingerprint(gk)[:8], Kind: kind, Value: value, Status: st, Locations: locs, Files: files}}
			groups[gk] = acc
			gkeys = append(gkeys, gk)
		}
		if variant != "" {
			acc.variants = append(acc.variants, variant)
		}
	}

	// Every JavaScript file is in one group: the application files by status, each library by name.
	byGroup := map[string][]string{}
	var fkeys []string
	for _, u := range order {
		f := files[u]
		kind := "js"
		if f.lib != "" {
			kind = "library"
		}
		k := kind + "\x00" + f.lib + "\x00" + fmt.Sprint(f.status)
		if byGroup[k] == nil {
			fkeys = append(fkeys, k)
		}
		byGroup[k] = append(byGroup[k], loc(u))
	}
	for _, k := range fkeys {
		p := strings.Split(k, "\x00")
		var st int
		fmt.Sscan(p[2], &st)
		addGroup(p[0], p[1], st, Compress(byGroup[k]), "", len(byGroup[k]))
	}

	for _, key := range keys {
		it := items[key]
		var locs []string
		var fileList []string
		for f, lines := range it.files {
			fileList = append(fileList, f)
			for l := range lines {
				if it.kind == "secret" {
					locs = append(locs, fmt.Sprintf("%s:%d", loc(f), l))
				} else {
					locs = append(locs, loc(f))
				}
			}
		}
		sort.Strings(fileList)
		n := len(locs)
		locs = Compress(locs)
		st := 0
		if it.kind == "path" || it.kind == "url" || it.kind == "sourcemap" {
			st = status[absolute(it.value, fileList[0])]
		}
		tags, sev, conf := classify(it, st)
		if len(tags) == 0 {
			kind := "endpoint"
			switch {
			case it.kind == "sourcemap":
				kind = "sourcemap"
			case !it.own:
				kind = "external"
			}
			addGroup(kind, "", st, locs, it.value, n)
			continue
		}
		prefix := it.kind
		if prefix == "sourcemap" {
			prefix = "map"
		}
		id := prefix + "-" + fingerprint(key)[:8]
		f := schema.Finding{ID: id, Severity: sev, Confidence: conf, Tags: tags, Rule: it.rule, Value: it.value, Status: st,
			Locations: locs, Files: n, Fingerprint: fingerprint(id)}
		out.Locations[f.Fingerprint] = locs
		out.Findings = append(out.Findings, f)
	}
	for _, gk := range gkeys {
		acc := groups[gk]
		sort.Strings(acc.variants)
		acc.g.Variants = acc.variants
		out.Groups = append(out.Groups, acc.g)
	}
	if out.Findings == nil {
		out.Findings = []schema.Finding{}
	}
	if out.Groups == nil {
		out.Groups = []schema.Group{}
	}

	sort.SliceStable(out.Findings, func(i, j int) bool {
		a, b := out.Findings[i], out.Findings[j]
		if schema.SeverityRank[a.Severity] != schema.SeverityRank[b.Severity] {
			return schema.SeverityRank[a.Severity] > schema.SeverityRank[b.Severity]
		}
		if schema.ConfidenceRank[a.Confidence] != schema.ConfidenceRank[b.Confidence] {
			return schema.ConfidenceRank[a.Confidence] > schema.ConfidenceRank[b.Confidence]
		}
		if len(a.Tags) != len(b.Tags) {
			return len(a.Tags) > len(b.Tags)
		}
		if a.Files != b.Files {
			return a.Files > b.Files
		}
		if a.Value != b.Value {
			return a.Value < b.Value
		}
		return a.ID < b.ID
	})
	sort.SliceStable(out.Groups, func(i, j int) bool {
		a, b := out.Groups[i], out.Groups[j]
		if groupRank[a.Kind] != groupRank[b.Kind] {
			return groupRank[a.Kind] < groupRank[b.Kind]
		}
		if wa, wb := a.Files*max(1, len(a.Variants)), b.Files*max(1, len(b.Variants)); wa != wb {
			return wa > wb
		}
		if ka, kb := groupKey(a), groupKey(b); ka != kb {
			return ka < kb
		}
		return a.ID < b.ID
	})

	if opt.MaxItems > 0 && len(out.Findings) > opt.MaxItems {
		out.Omitted["findings"] += len(out.Findings) - opt.MaxItems
		out.Findings = out.Findings[:opt.MaxItems]
	}
	return out
}

// groupRank orders the kinds of groups, most useful first; the budget cuts from the end.
var groupRank = map[string]int{"js": 0, "endpoint": 1, "library": 2, "external": 3, "sourcemap": 4}

func groupKey(g schema.Group) string {
	if len(g.Variants) > 0 {
		return g.Variants[0]
	}
	if g.Value != "" {
		return g.Value
	}
	if len(g.Locations) > 0 {
		return g.Locations[0]
	}
	return ""
}

// classify returns the tags, severity and confidence of an item. No tags means it goes to a group.
//
//	secret     a secret rule matched (severity and confidence of the rule)
//	sourcemap  a source map: medium and verified when katana got a 2xx for it or it is inlined as a
//	           data: URI, low when katana did not request it; one that answered 4xx or 5xx is a group
//	admin      an admin, debug, internal, private, config, metrics or export path segment
//	file       a backup, dump, config, archive, key or log extension
//	bucket     a URL on cloud storage (S3, GCS, Azure Blob, Spaces, R2, Firebase)
//	internal   a URL on an internal host: a private, loopback or link-local IP, a name without a dot, or
//	           a .internal, .local, .lan, .corp, .intranet name
//	api        an api, graphql, rest or vN path segment
//	auth       katana got 401, 403 or 407 for it
//
// The path rules (admin, file, api) apply to the target's own endpoints (paths, and URLs on an in-scope
// host) and to bucket and internal URLs, never to other third-party URLs. A finding that answered 404 or
// 410 is low: katana's GET found nothing, but the route may still take another method or base path.
func classify(it *item, status int) ([]string, string, string) {
	switch it.kind {
	case "secret":
		return []string{"secret"}, it.severity, it.confidence
	case "sourcemap":
		switch {
		case strings.HasPrefix(it.value, "data:"), status/100 == 2:
			return []string{"sourcemap"}, "medium", "verified"
		case status == 0:
			return []string{"sourcemap"}, "low", ""
		}
		return nil, "", ""
	}
	var tags []string
	add := func(t string, ok bool) {
		if ok {
			tags = append(tags, t)
		}
	}
	path := it.value
	bucket, internal := false, false
	if it.kind == "url" {
		host := extract.Host(it.value)
		bucket = bucketHost.MatchString(host)
		internal = !bucket && isInternal(host)
		o := extract.Origin(it.value)
		path = strings.TrimPrefix(it.value, o)
	}
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	segs := strings.Split(strings.Trim(strings.ToLower(path), "/"), "/")
	if it.own || bucket || internal {
		admin, file, api := false, false, false
		last := segs[len(segs)-1]
		file = fileExt[ext(last)]
		for _, s := range segs {
			word := strings.TrimSuffix(s, "."+ext(s))
			admin = admin || adminWords.MatchString(word)
			api = api || apiWords.MatchString(word)
		}
		add("admin", admin)
		add("file", file)
		add("bucket", bucket)
		add("internal", internal)
		add("api", api && (it.own || internal))
	}
	add("auth", status == 401 || status == 403 || status == 407)
	sev := ""
	for _, t := range tags {
		if s := tagSeverity[t]; schema.SeverityRank[s] > schema.SeverityRank[sev] {
			sev = s
		}
	}
	if sev != "" && (status == 404 || status == 410) {
		sev = "low" // katana's GET found nothing there; the route may still take another method or base
	}
	return tags, sev, ""
}

func isInternal(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
	}
	return internalHost.MatchString(host)
}

// IsJS is true for a URL with a JavaScript extension (.js .mjs .cjs .jsx) or a JavaScript content type.
func IsJS(u, contentType string) bool {
	p := strings.TrimPrefix(u, extract.Origin(u))
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	segs := strings.Split(p, "/")
	if jsExt[ext(segs[len(segs)-1])] {
		return true
	}
	ct := strings.ToLower(contentType)
	return strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript")
}

// absolute is the URL katana would have requested for an item found in file.
func absolute(v, file string) string {
	if strings.HasPrefix(v, "/") && !strings.HasPrefix(v, "//") {
		return extract.Origin(file) + v
	}
	return v
}

// escapeBrackets writes a URL's own [ and ] as %5B and %5D, so a bracket in a location is always a range.
func escapeBrackets(s string) string {
	return strings.NewReplacer("[", "%5B", "]", "%5D").Replace(s)
}

var digitRun = regexp.MustCompile(`[0-9]+`)

// Compress writes locations that differ in one number as one location with the numbers as ranges:
// "/js/chunk-1.js" ... "/js/chunk-40.js" is "/js/chunk-[1-40].js", and "/app.js:3", "/app.js:9" is
// "/app.js:[3,9]". It tries each position of a number (the first number, the second...) and keeps the one
// that gives the fewest locations. A number with a leading zero is never part of a range. The result is
// sorted.
func Compress(locs []string) []string {
	uniq := map[string]bool{}
	for _, u := range locs {
		uniq[u] = true
	}
	best := sorted(uniq)
	most := 0
	for _, u := range best {
		most = max(most, len(digitRun.FindAllStringIndex(u, -1)))
	}
	for pos := 0; pos < most; pos++ {
		if out := compressAt(best, pos); len(out) < len(best) {
			best = out
		}
	}
	return best
}

func compressAt(locs []string, pos int) []string {
	type run struct {
		prefix, suffix string
		nums           []int64
	}
	runs := map[string]*run{}
	var order []string
	var out []string
	for _, u := range locs {
		idx := digitRun.FindAllStringIndex(u, -1)
		if pos >= len(idx) {
			out = append(out, u)
			continue
		}
		a, b := idx[pos][0], idx[pos][1]
		digits := u[a:b]
		var n int64
		if len(digits) > 18 || (len(digits) > 1 && digits[0] == '0') {
			out = append(out, u)
			continue
		}
		fmt.Sscan(digits, &n)
		k := u[:a] + "\x00" + u[b:]
		r, ok := runs[k]
		if !ok {
			r = &run{prefix: u[:a], suffix: u[b:]}
			runs[k] = r
			order = append(order, k)
		}
		r.nums = append(r.nums, n)
	}
	for _, k := range order {
		r := runs[k]
		if len(r.nums) == 1 {
			out = append(out, fmt.Sprint(r.prefix, r.nums[0], r.suffix))
			continue
		}
		out = append(out, r.prefix+"["+ranges(r.nums)+"]"+r.suffix)
	}
	sort.Strings(out)
	return out
}

// ranges writes sorted numbers as "1-5,7,9-12".
func ranges(nums []int64) string {
	sort.Slice(nums, func(i, j int) bool { return nums[i] < nums[j] })
	var parts []string
	for i := 0; i < len(nums); {
		j := i
		for j+1 < len(nums) && nums[j+1] == nums[j]+1 {
			j++
		}
		if j > i {
			parts = append(parts, fmt.Sprintf("%d-%d", nums[i], nums[j]))
		} else {
			parts = append(parts, fmt.Sprint(nums[i]))
		}
		i = j + 1
	}
	return strings.Join(parts, ",")
}

// MapURLs are the source maps the files point to that katana has not requested yet, as absolute URLs:
// raijin-js asks katana to fetch them, to tell an exposed source map from a dangling comment.
func MapURLs(events []katana.Event, inScope func(string) bool) []string {
	requested := map[string]bool{}
	for _, ev := range events {
		requested[ev.Request.Endpoint] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, ev := range events {
		u := ev.Request.Endpoint
		if !IsJS(u, ev.ContentType()) || (inScope != nil && !inScope(u)) {
			continue
		}
		for _, h := range extract.Extract(ev.Body(), u) {
			if h.Kind != "sourcemap" || strings.HasPrefix(h.Value, "data:") {
				continue
			}
			abs := absolute(h.Value, u)
			if seen[abs] || requested[abs] || !strings.Contains(abs, "://") || (inScope != nil && !inScope(abs)) {
				continue
			}
			seen[abs] = true
			out = append(out, abs)
		}
	}
	return out
}

// Fit shrinks the result until its JSON is at most maxBytes. It cuts the least important data first:
// group locations, then groups, then the locations of the lowest-ranked findings (each keeps one, and
// its count), then the lowest-ranked findings. Every cut is counted in Omitted.
func Fit(res *schema.Result, maxBytes int) {
	if maxBytes <= 0 || size(res) <= maxBytes {
		return
	}
	res.Budget.Truncated = true
	if res.Omitted == nil {
		res.Omitted = map[string]int{}
	}
	total := size(res) // now includes the budget object
	for i := len(res.Groups) - 1; i >= 0 && total > maxBytes; i-- {
		g := &res.Groups[i]
		if len(g.Locations) == 0 {
			continue
		}
		before := size(g)
		res.Omitted["locations"] += len(g.Locations)
		g.Locations, g.Count = nil, g.Files
		total += size(g) - before
	}
	for total > maxBytes && len(res.Groups) > 0 {
		last := len(res.Groups) - 1
		total -= size(res.Groups[last]) + 1
		res.Groups = res.Groups[:last]
		res.Omitted["groups"]++
	}
	for i := len(res.Findings) - 1; i >= 0 && total > maxBytes; i-- {
		f := &res.Findings[i]
		if len(f.Locations) <= 1 {
			continue
		}
		before := size(f)
		res.Omitted["locations"] += len(f.Locations) - 1
		f.Locations, f.Count = f.Locations[:1], f.Files
		total += size(f) - before
	}
	for total > maxBytes && len(res.Findings) > 1 {
		last := len(res.Findings) - 1
		total -= size(res.Findings[last]) + 1
		res.Findings = res.Findings[:last]
		res.Omitted["findings"]++
	}
	// the estimate above ignores the omitted counters it adds; settle on the real size, groups first
	for size(res) > maxBytes && (len(res.Groups) > 0 || len(res.Findings) > 1) {
		if n := len(res.Groups); n > 0 {
			res.Groups = res.Groups[:n-1]
			res.Omitted["groups"]++
			continue
		}
		res.Findings = res.Findings[:len(res.Findings)-1]
		res.Omitted["findings"]++
	}
}

// ext is the lowercase extension of a path segment, or "".
func ext(seg string) string {
	i := strings.LastIndex(seg, ".")
	if i <= 0 || i == len(seg)-1 {
		if i == 0 {
			return strings.ToLower(seg[1:]) // a dotfile: ".env" has extension "env"
		}
		return ""
	}
	return strings.ToLower(seg[i+1:])
}

func size(v any) int {
	b, _ := schema.Marshal(v)
	return len(b)
}

func set(items ...string) map[string]bool {
	m := map[string]bool{}
	for _, s := range items {
		m[s] = true
	}
	return m
}

func sorted(set map[string]bool) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func fingerprint(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:8])
}
