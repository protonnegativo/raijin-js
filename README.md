# ⚡ Raijin JS

[![CI](https://github.com/protonnegativo/raijin-js/actions/workflows/ci.yml/badge.svg)](https://github.com/protonnegativo/raijin-js/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/protonnegativo/raijin-js)](https://github.com/protonnegativo/raijin-js/releases/latest)
[![License: MIT](https://img.shields.io/github/license/protonnegativo/raijin-js)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/protonnegativo/raijin-js.svg)](https://pkg.go.dev/github.com/protonnegativo/raijin-js)
[![Go Report Card](https://goreportcard.com/badge/github.com/protonnegativo/raijin-js)](https://goreportcard.com/report/github.com/protonnegativo/raijin-js)

**katana for AI agents, aimed at JavaScript: every JS file, every endpoint, API route, URL and source map in them, deduplicated across files, and secrets with their file and line, redacted, ranked first.**

`raijin-js` is a tool of **Raijin**, an arsenal of offensive security tools built for AI agents. It runs [katana](https://github.com/projectdiscovery/katana) underneath to find the JavaScript files of a site, parses their bodies itself, and returns the **Raijin Schema**: one compact JSON where an endpoint referenced by 40 chunks is one entry listing `/static/js/chunk-[1-40].js`, secrets (high), admin, debug and internal routes, cloud buckets, internal hosts and exposed source maps are ranked findings, plain paths, third-party URLs and library files are groups, and anything it had to cut is counted.

## Why not just run katana?

katana is built for people and pipelines. An agent pays for every byte it reads. Its JSONL output is one line per URL with the raw request, the raw response and the body, so a bundle split in 40 chunks is 40 copies of the same runtime, and the endpoints and keys are still buried in the bodies. The text output is one URL per line: it says where the JS files are, not what is in them, so the agent still has to fetch and read every file.

Here is the same crawl read by an agent (tokens, `o200k_base`):

```
Noisy crawl: 45 JS files (40 chunks, 5 libraries), 64 distinct items in 690 (item, file) pairs
  raijin-js               ▋                        2,518 tokens
  katana text             ▍                        1,242 tokens
  katana text + JS bodies ████                    15,793 tokens
  katana -jsonl -or       █████████▊              37,809 tokens
  katana -jsonl           ████████████████████    77,961 tokens

Findings crawl: 6 JS files, 24 findings (4 high, 14 medium, 6 low), 2 source maps fetched
  raijin-js               ███                      1,521 tokens
  katana text             ▋                          285 tokens
  katana text + JS bodies ██▍                      1,192 tokens
  katana -jsonl -or       █████████▉               4,882 tokens
  katana -jsonl           ████████████████████     9,895 tokens
```

raijin-js reads **31×** fewer tokens than `katana -jsonl` on the noisy crawl and **6.5×** fewer on the findings crawl. Against katana's JSONL without the raw request and response strings (`-or`, what raijin-js saves as `raw`) it is **15×** and **3.2×** smaller. Each crawl's bars are drawn to scale against `katana -jsonl`.

- **Nothing is lost.** Every JS file katana found is listed with its status, and every path, URL, source map and secret in them is listed with every file it is in. `bench/verify.py` parses the bodies again with a Python port of the rules and checked all 728 (item, file) pairs, 51 JS files, 64 jsluice endpoints and 2 source maps of both crawls: none were missing.
- **One entry per item, not per file.** `/api/v1/cart` in 40 chunks is one finding with one location, `/static/js/chunk-[1-40].js`. Six plain paths that every chunk has are one group.
- **Secrets are redacted and pinned.** `AKIA…Q0GF` in `/static/js/app.js:3` and `/static/js/vendor.js:3`: the rule, a short prefix and suffix, every file and line. The full value stays in the raw file.
- **The real targets come first.** Keys, credentials in a URL, a private key, an admin API that answered 403, `/debug/pprof/`, an S3 bucket, `jenkins.corp.internal` and a source map that answered 200 are findings, ranked by severity. Plain paths, third-party URLs and library files are groups.
- **Source maps are checked, not guessed.** raijin-js asks katana to fetch every `sourceMappingURL` the files point to: a map that answers 200 is a `verified` finding, one that answers 404 is a group.
- **Output is bounded.** On a huge site, `--max-bytes` cuts the least important data first and counts every cut.

Against katana's text output, raijin-js is **2.0× larger** on the noisy crawl and **5.3× larger** on the findings crawl: a bare list of 99 or 20 URLs is smaller than what is in the files. But the text has none of it: no endpoint, no key, no bucket, no status. The fair comparison for an agent that starts from the text is the text plus the JS bodies it lists, and raijin-js is **6.3× smaller** on the noisy crawl and **1.28× larger** on the findings crawl, where the lab's six files total 2.6 KB (real bundles are hundreds of KB, and the bodies grow with them while raijin-js grows with the items). Full method and numbers are in [BENCHMARK.md](BENCHMARK.md), and `bench/run.sh` reproduces them.

## Install

```bash
go install github.com/protonnegativo/raijin-js/cmd/raijin-js@latest
```

installs the latest release.

**Versions.** Releases are tagged automatically on every change and every passing engine update. `raijin-js --version` shows the release and the tested engine versions (`raijin-js v0.1.3 (tested with katana 1.8.0)`). `raijin-mcp update` updates every Raijin tool at once.

You also need ProjectDiscovery `katana` on `PATH`, or pass `--katana <path>`.

## Usage

```bash
raijin-js --scope scope.txt                                  # crawl every host the scope names
raijin-js --scope scope.txt -u https://app.example.com/
raijin-js --scope scope.txt -l start-urls.txt --depth 4 --duration 5m
raijin-js --scope scope.txt --input katana-results.jsonl     # reduce katana JSONL you already have (bodies needed)
raijin-js --scope scope.txt -u https://app.example.com/ --state run.json   # mark findings that are new since last run
raijin-js ... -- -H 'Cookie: session=...'                    # anything after -- goes to katana
```

`--scope` is required. One rule per line:

```
example.com
*.example.com
10.0.0.0/24
!admin.example.com
```

With no `-u`, `-l` or `--input`, raijin-js crawls what the scope names: every domain, every IP, and every address of ranges up to a /24, minus exclusions, each starting at `https://<host>` (katana needs a URL and does not crawl a bare host). A wildcard names no host and a larger range is too big to sweep blindly, so for each one `next` gives the command that enumerates it first (`raijin-subs` or `raijin-ports`).

Start URLs outside the scope are dropped before katana runs. The crawl stays on the hosts of the start URLs (katana `-cs`, any port), and katana results outside the scope (a JS file on a third-party CDN, for instance) are dropped from the output. Both are counted in `omitted.out_of_scope`. A URL on an in-scope host found in a file is one of the target's own endpoints; a URL on any other host is third-party.

What raijin-js asks katana for: depth 3 (`-d 3`), JavaScript parsing (`-jc -jsl`: jsluice finds the `fetch()` calls, imports and string endpoints, and katana requests them, so they get a status), `-or` (no raw request and response strings) and the bodies, which raijin-js parses. Then a second, short katana run fetches the source maps the files point to (`-d 1 -em map -ob`: katana leaves `.map` files out of its output otherwise); `--maps=false` skips it. Both outputs go to the same raw file.

## Output

```json
{
  "schema_version": 1,
  "tool": "raijin-js",
  "version": "v0.1.1",
  "target": "http://localhost:19101/",
  "summary": "6 JS files (1 libraries), 35 items: 24 findings (4 high, 14 medium, 6 low), 8 groups",
  "origin": "http://localhost:19101",
  "findings": [
    {
      "id": "secret-fa6ab0c1",
      "severity": "high",
      "tags": ["secret"],
      "rule": "aws-access-key",
      "value": "AKIA…Q0GF",
      "locations": ["/static/js/app.js:3", "/static/js/vendor.js:3"]
    },
    {
      "id": "secret-a10770e3",
      "severity": "high",
      "tags": ["secret"],
      "rule": "url-credentials",
      "value": "http://deploy:gM…ox@build.acme.internal",
      "locations": ["/static/js/app.js:15"]
    },
    {
      "id": "map-24902a34",
      "severity": "medium",
      "confidence": "verified",
      "tags": ["sourcemap"],
      "value": "/static/js/app.js.map",
      "status": 200,
      "locations": ["/static/js/app.js"]
    },
    {
      "id": "path-1273df0f",
      "severity": "medium",
      "tags": ["admin", "api", "auth"],
      "value": "/api/v1/admin/users/export",
      "status": 403,
      "locations": ["/static/js/chunk-lazy.js"]
    },
    {
      "id": "url-e50df7cf",
      "severity": "medium",
      "tags": ["admin", "internal"],
      "value": "http://10.0.3.7:8080/metrics",
      "locations": ["/static/js/app.js"]
    },
    {
      "id": "url-ec13b308",
      "severity": "medium",
      "tags": ["bucket"],
      "value": "https://acme-lab-uploads.s3.amazonaws.com/user-docs/",
      "locations": ["/static/js/app.js"]
    },
    {
      "id": "secret-aa77860b",
      "severity": "medium",
      "confidence": "heuristic",
      "tags": ["secret"],
      "rule": "generic-secret",
      "value": "client_secret: \"y2Kz…QRPA\"",
      "locations": ["/static/js/config.js:3"]
    },
    {
      "id": "path-f784e2a0",
      "severity": "low",
      "tags": ["api"],
      "value": "/api/v1/orders/{id}",
      "locations": ["/static/js/app.js"]
    }
  ],
  "groups": [
    {
      "id": "js-3bcdb36b",
      "kind": "js",
      "status": 200,
      "locations": ["/static/js/app.js", "/static/js/chunk-lazy.js", "/static/js/config.js", "/static/js/runtime.js", "/static/js/vendor.js"]
    },
    {
      "id": "endpoint-9c3d50ce",
      "kind": "endpoint",
      "status": 200,
      "variants": ["/about", "/pricing"],
      "locations": ["/static/js/app.js", "/static/js/runtime.js"]
    },
    {
      "id": "library-1d8a8019",
      "kind": "library",
      "value": "jquery 3.6.0",
      "status": 200,
      "locations": ["/static/js/lib/jquery-3.6.0.min.js"]
    },
    {
      "id": "external-e9a312e4",
      "kind": "external",
      "variants": ["https://cdn.jsdelivr.net/npm/", "https://o0.ingest.sentry.example/api/1/store/"],
      "locations": ["/static/js/vendor.js"]
    },
    {
      "id": "sourcemap-7cf2734e",
      "kind": "sourcemap",
      "status": 404,
      "variants": ["/static/js/vendor.js.map"],
      "locations": ["/static/js/vendor.js"]
    }
  ],
  "omitted": {"not_js": 5},
  "raw": "bench/fixtures/findings/raw.jsonl"
}
```

That is the real findings crawl from the benchmark, pretty-printed here. Three things are shortened: 16 of the 24 findings and 3 of the 8 groups are left out, short arrays are written on one line, and `raw` is relative to the repo. The tool writes it as one line. The noisy crawl's biggest entries are one line each:

```json
{"id":"path-9b58ec0e","severity":"low","tags":["api"],"value":"/api/v1/cart","status":200,"locations":["/static/js/chunk-[1-40].js"]}
{"id":"external-4218f9b0","kind":"external","variants":["https://cdn.shopify.example/assets/","https://fonts.googleapis.com/css2","https://www.facebook.com/tr","https://www.googletagmanager.com/gtag/js"],"locations":["/static/js/chunk-[1-40].js"]}
```

**Nothing raijin-js or katana found is dropped silently.** Every JS file is in exactly one `js` or `library` group, and every item is in exactly one finding or group, with all its files. Only exact repeats collapse, and katana's are counted in `omitted.duplicates`.

What raijin-js extracts from each JS body (`internal/extract`; it is lexical, not a JavaScript parser):

- **Paths and URLs** from every string literal (`"..."`, `'...'`, `` `...` ``) that is a whole URL (`http`, `https`, `ws`, `wss` or `//host`) or a path (`/x`, `./x`, `../x`, at least 3 characters, no spaces). `\/` is read as `/`. In a template literal `${id}` is written `{id}` (`{}` for an expression), and a leading `${API_BASE}` before a `/` is dropped: `` `${API_BASE}/api/v1/orders/${id}` `` is `/api/v1/orders/{id}`.
- `./x` and `../x` are resolved against the file, as katana does; `//host/x` takes the file's scheme; a URL on the file's own origin is written as its path; `user:password@` is removed from a URL (the `url-credentials` rule reports it).
- **Source maps** from `//# sourceMappingURL=` (and `//@`, `/*#`) comments, resolved against the file. An inline `data:` map is written `data:application/json;base64,…`.
- **Secrets** with the rules in [`internal/extract/rules.json`](internal/extract/rules.json), run on each line. The value is the match with the secret redacted: the first and last 4 characters of a secret of 16 or more, the first and last 2 of one of 8 to 15, nothing of a shorter one. A match whose secret overlaps one found by an earlier rule on the same line is skipped, so `apiKey: "AIza..."` is a `google-api-key`, not also a `generic-secret`.

  | Rule | Severity | Matches |
  |---|---|---|
  | `aws-access-key` | high | `AKIA`, `ASIA`, `AGPA`, `AIDA`, `AROA`, `ANPA`, `ANVA`, `AIPA` and 16 characters |
  | `aws-secret-key` | high | 40 base64 characters in quotes near `aws` and `secret` or `sk` |
  | `google-api-key` | high | `AIza` and 35 characters |
  | `github-token` | high | `ghp_ gho_ ghu_ ghs_ ghr_` and 36 characters, `github_pat_` |
  | `slack-token` | high | `xoxb- xoxa- xoxp- xoxr- xoxs-` |
  | `slack-webhook` | high | `https://hooks.slack.com/services/T.../B.../...` |
  | `stripe-secret-key` | high | `sk_live_`, `rk_live_` |
  | `sendgrid-key` | high | `SG.` and two dotted parts |
  | `private-key` | high | a `-----BEGIN ... PRIVATE KEY-----` header (written as it is: the header is not secret) |
  | `url-credentials` | high | `scheme://user:password@host` |
  | `jwt` | medium | three base64url parts, the first two starting with `eyJ` |
  | `generic-secret` | medium, `heuristic` | `api_key`, `apikey`, `secret`, `client_secret`, `secret_key`, `access_token`, `auth_token`, `token`, `password`, `passwd`, `pwd` assigned (`:` or `=`) a quoted value of 8 or more characters with a digit |

katana's own results count too: an endpoint jsluice found in a JS file (`tag: js`) is an item of that file, written the same way, so it merges with the same string literal.

What the reducer does with them:

- **One entry per item.** A path, URL or source map is one item, a secret is one item per rule and value. Its `locations` are every file it is in (`file:line` for a secret, one per line), without the shared `origin`, sorted, and files that differ in one number written as a range: `/static/js/chunk-[1-40].js`, `/static/js/app.js:[3,9]`. A file's own `[` and `]` are written `%5B` and `%5D`.
- **`status`** is what katana got when it requested the item (jsluice endpoints, other JS files, source maps), resolved against the item's first file. It is left out when katana did not request it, or recorded no response: katana writes an empty response for a body identical to one it has already seen.
- **Findings** are the items that match a rule. A finding takes the highest severity of its tags:

  | Tag | Severity | Rule |
  |---|---|---|
  | `secret` | the rule's | A secret rule matched. |
  | `sourcemap` | medium and `verified` when katana got a 2xx for it or it is inline; low when katana did not request it | A `sourceMappingURL`. A map that answered 4xx or 5xx is a `sourcemap` group. |
  | `admin` | medium | A path segment is an admin, debug, internal, private, config, metrics or export area: `admin*`, `debug*`, `internal`, `private`, `actuator`, `console`, `manage`, `config`, `settings`, `backup`, `server-status`, `metrics`, `env`, `pprof`, `swagger`, `api-docs`, `graphiql`, `phpinfo`, `export` and similar. |
  | `file` | medium | The last segment has a backup, dump, config, archive, key or log extension (`.bak .sql .env .yml .zip .pem .key .log ...`). |
  | `bucket` | medium | A URL on cloud storage: S3, GCS, Azure Blob, DigitalOcean Spaces, R2, Firebase, App Engine. |
  | `internal` | medium | A URL on an internal host: a private, loopback or link-local IP, a name without a dot, or a `.internal`, `.local`, `.lan`, `.corp`, `.intranet`, `.private`, `.home` name. |
  | `api` | low | An `api`, `graphql`, `gql`, `rest`, `rpc`, `soap`, `odata` or `v1`/`v2`... segment. |
  | `auth` | low | katana got 401, 403 or 407 for it. |

  The path rules (`admin`, `file`, `api`) apply to the target's own endpoints (paths, and URLs on an in-scope host) and to bucket and internal URLs, never to other third-party URLs. A finding that answered 404 or 410 is low: katana's GET found nothing there, but the route may take another method or base path.
- **Groups** collapse the rest. Every variant listed is in every location listed:
  - `js`: the application JS files, one group per status;
  - `library`: the files of one third-party library, by file name (`jquery-3.7.1.min.js`, `react.production.min.js`, a file under `node_modules/<pkg>/`), with the version from the name or the license banner (`/*! React v18.2.0`);
  - `endpoint`: the target's own paths and URLs no rule flagged, one group per status and set of files;
  - `external`: URLs on third-party hosts, one group per set of files;
  - `sourcemap`: source maps that answered 4xx or 5xx.
- **`omitted.not_js`** counts the katana results that are neither a JS file nor found in one: the pages, links and source map responses (each map's status is on its item). They are raijin-crawl's job and stay in `raw`.
- **Ranking:** findings by severity, then confidence, then the number of tags, then the number of locations, then value and `id`. Groups by kind (`js`, `endpoint`, `library`, `external`, `sourcemap`), then size (files × variants), then the first variant, and `id`. The same input always gives the same order.
- **`id`** is the kind (`secret`, `path`, `url`, `map`; a group's kind) and a short hash of the item (rule and full value for a secret) or of the group, so the same finding has the same `id` in the next run.
- **`raw`** is katana's full JSONL, saved to disk: the bodies (with the secrets in full), headers and the page each file was found on. Reading it costs no tokens until the agent opens it. `--raw <file>` picks the path.
- **Budget:** `--max-bytes` (16,000 by default) keeps the output bounded. It cuts in this order until the JSON fits:
  1. group locations (each keeps its `count` of files);
  2. groups;
  3. the locations of the lowest-ranked findings, each keeping one location plus its `count`;
  4. the lowest-ranked findings.

  Every cut is counted in `omitted`, `budget.truncated` is set, and `next` points to the raw file. `--max-items` caps the number of findings (0, the default, keeps all).
- **Errors** say what to try next. If katana is missing, the exit code is 2.
- **`schema_version`** is the first field (currently `1`) and changes only when the schema changes incompatibly.
- **Invalid scope:** a scope file with bad lines (or none) stops the run before katana starts, with one `{"kind":"scope"}` error per invalid line in `errors`, naming the line and why.
- **Exit codes:** `0` ok; `2` a structured error with the JSON on stdout (invalid scope, a scope that names no single host, katana missing): read `errors[].kind`; `1` wrong usage (bad flag, missing `--scope`, no target in scope), with the message on stderr.

Fields an agent can rebuild are left out to save tokens:

- `status` is left out when katana did not request the item or recorded no response.
- `rule`, `variants` and a group's `value` are left out when empty.
- `count` appears only when the budget cut `locations`.
- `confidence` appears only when it is not `matched`.
- `origin`, `omitted`, `errors` and `next` appear only when they are not empty.
- `budget` appears only when something was cut.

The JSON is compact (one line) by default because indentation costs 56% to 57% more tokens in the benchmark; `--pretty` indents it. `--format table` prints a short human view of the same result; it lists finding locations but only counts group items.

The Raijin banner is **off by default**, so normal runs stay small. `--banner` prints it to **stderr** (never stdout, so the JSON is untouched), with the version taken from the binary. Colors are disabled when `NO_COLOR` is set or stderr is not a terminal.

## Flags

| Flag | Default | |
|---|---|---|
| `--scope` | (required) | scope file |
| `-u` / `-l` / `--input` | every host the scope names | one start URL (repeatable) / start URL file / existing katana JSONL (with bodies) |
| `--depth` | 3 | maximum crawl depth (katana `-d`) |
| `--maps` | true | fetch the source maps the files point to (a second katana run, `-d 1 -em map`) |
| `--duration` | | maximum crawl time per target, e.g. `5m` (katana `-ct`) |
| `--rate`, `--timeout`, `--concurrency` | | katana `-rl` / `-timeout` / `-c` |
| `--max-items` | 0 | max findings (0 keeps all) |
| `--max-bytes` | 16000 | max JSON size; cuts are counted in `omitted` |
| `--raw` | temp file | where to save katana's full JSONL |
| `--state` | | state file for new-since-last-run |
| `--format` | json | `json` or `table` |
| `--pretty` | false | indent the JSON |
| `--katana` | katana | path to the binary |
| `--banner` | false | print the banner to stderr |

## Engine versions

The tested katana version is in `engines.json` (embedded in the binary): the one `bench/fixtures` was produced with. raijin-js warns in `errors`, without failing the run, when the installed katana is older than that or has another major version (`engine_version`), and when katana's results do not have the fields raijin-js reads (`engine_format`: its output format may have changed). A weekly GitHub Actions job runs the live benchmark with the latest katana, and when it passes with a newer katana it commits the bump and tags a release, or an issue when it breaks.

## Development

```bash
go test ./...
go vet ./...
bench/run.sh            # replay bench/fixtures and count tokens
LIVE=1 bench/run.sh     # start the local lab, crawl it again, refresh the fixtures
```

The only dependency besides the standard library is [raijin-core](https://github.com/protonnegativo/raijin-core) (scope, state and the schema envelope shared by the Raijin tools). katana runs as a subprocess with `-jsonl -silent -nc -duc -or -jc -jsl`, so the binary stays small and katana can be updated on its own. Its stdin is `/dev/null`, because katana reads targets from stdin when stdin is not a terminal. The secret rules are in `internal/extract/rules.json`, embedded in the binary and read by `bench/verify.py`.

## Responsible use

Only crawl what you are authorized to test. Treat every secret raijin-js reports, and the raw file that holds it in full, as sensitive; do not use a credential you find unless your authorization covers it.
