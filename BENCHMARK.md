# Token benchmark: katana vs raijin-js

How many tokens does an AI agent spend reading what is in a site's JavaScript, and does it lose anything? This benchmark crawls a local lab with katana, counts the tokens in each output shape, and checks that every JS file, every jsluice endpoint, every source map and every item in the JS bodies is in the raijin-js output.

Reproduce: `bench/run.sh` replays the saved crawls in `bench/fixtures`. `LIVE=1 bench/run.sh` starts the lab, crawls it again and refreshes the fixtures first (about two and a half minutes, most of it katana waiting at the end of each crawl; set `KATANA=<path>` if katana is not on `PATH`, and `PY=<python with tiktoken>`).

## Setup

- **Lab:** `bench/lab.py`, one Python process serving two sites on `127.0.0.1`, crawled as `http://localhost:19100/` and `http://localhost:19101/`. Every key in it is fake: random characters in the shape of a real key, from a fixed seed, never issued by a provider.
  - **noisy** (`shop`, port 19100): a storefront split in 40 webpack-style chunks. Every chunk repeats the same runtime, the same 6 API paths, the same 6 page paths and the same 4 third-party URLs, and has one route of its own (`/category/N`). Plus 5 vendor libraries (jQuery 3.7.1, React 18.2.0, lodash, Bootstrap, Moment) with the namespace and docs URLs libraries carry. 45 files, 49 KB of JavaScript.
  - **findings** (`app`, port 19101): an app whose bundles leak: an AWS access key ID (in two files), a Google API key, a JWT, a client secret, a password, an RSA private key header, credentials in a URL; admin, debug and internal routes (two answer 403, two answer 200, some 404); an S3 and a GCS bucket; an internal IP and two `.internal` hosts; a lazy chunk only JS points to; a source map that is served, one that is not (404) and one inlined as a `data:` URI; and a vendored jQuery. 6 files, 2.6 KB of JavaScript.
- **katana:** v1.1.2.
- **raijin-js:** runs katana itself (`-jsonl -silent -nc -duc -or -jc -jsl -d 3 -cs <host>`), then katana again on the source maps the files point to (`-d 1 -em map -ob`), and saves both outputs as `raw`: that file is the fixture (`raw.jsonl`). Defaults apply: no limit on findings, and `--max-bytes 16000`, which was not reached. All raijin-js rows replay `raw.jsonl` with `--input`, so they see the same crawl.
- **Baselines**, as an agent would run katana to collect JavaScript, with the same crawl options (`-d 3 -jc -jsl` and the same crawl scope):
  - `katana -jsonl -silent`: katana's default JSONL, with the raw request and response strings and the bodies. A separate live crawl, saved as `katana.jsonl`; it found the same number of results as raijin-js's first katana run.
  - `katana -jsonl -or`: the `raw` file (the source map pass adds 2 lines in the findings crawl).
  - Text: katana's default output, one URL per line, stdout and stderr (banner and log lines). A separate live crawl, saved as `text.txt` and `text_stderr.txt`.
  - Text plus the JS bodies: the text output, then the body of every `.js` file in `raw`. The text says where the files are, not what is in them; this is what an agent that starts from it still has to read.
- **Tokens:** counted with tiktoken (`o200k_base`). This is a **proxy**, because Claude's tokenizer is not public. `bench/count_tokens.py` also gives exact Claude counts if `ANTHROPIC_API_KEY` is set and the `anthropic` package is installed. `cl100k_base` gives the same ratios.

## Scenario 1: noisy

45 JS files and 99 katana results. raijin-js found 64 distinct items in 690 (item, file) pairs and returned 6 findings (the 6 API routes, `api`, low, each with one location, `/static/js/chunk-[1-40].js`) and 54 groups: the 40 chunks in one `js` group, the 6 page paths of every chunk in one `endpoint` group, the 40 `/category/N` routes (one group each, since each is in a different file), 5 `library` groups and 7 `external` groups.

| Output | Bytes | Tokens | vs. katana -jsonl |
|---|---:|---:|---:|
| katana `-jsonl` | 228,131 | 77,961 | 1× |
| katana `-jsonl -or` (raijin-js's raw) | 114,320 | 37,809 | 2.1× |
| katana text (stdout+stderr) | 4,166 | 1,242 | 63× |
| katana text + the JS bodies | 53,577 | 15,793 | 4.9× |
| **raijin-js JSON (default)** | 8,240 | **2,493** | **31×** |
| raijin-js `--pretty` | 13,204 | 3,905 | 20× |
| raijin-js `--format table` | 2,698 | 841 | 93× |

## Scenario 2: findings

6 JS files and 22 katana results (20 from the crawl, 2 source maps). raijin-js found 35 items and returned 24 findings and 8 groups.

- high: the AWS key (in `app.js:3` and `vendor.js:3`), the private key header, the Google API key, and `deploy:…@build.acme.internal`;
- medium: the source map that answered 200 and the inline one (both `verified`), the two admin APIs that answered 403, `http://10.0.3.7:8080/metrics`, `/debug/pprof/` and `/internal/debug` (200), the JWT, the two internal hosts, the two buckets, and the client secret and the password (`generic-secret`, `heuristic`);
- low: `/api/v1/users` (200), `/api/v1/orders/{id}` from a template literal, and `/account/settings`, `/api/v1/`, `/graphql` and `/server-status`, which answered 404.

| Output | Bytes | Tokens | vs. katana -jsonl |
|---|---:|---:|---:|
| katana `-jsonl` | 27,826 | 9,895 | 1× |
| katana `-jsonl -or` (raijin-js's raw) | 14,570 | 4,882 | 2.0× |
| katana text (stdout+stderr) | 980 | 285 | 35× |
| katana text + the JS bodies | 3,606 | 1,192 | 8.3× |
| **raijin-js JSON (default)** | 5,093 | **1,496** | **6.6×** |
| raijin-js `--pretty` | 8,013 | 2,339 | 4.2× |
| raijin-js `--format table` | 2,366 | 722 | 14× |

In a live run (not a replay) the raijin-js JSON also has `raw`, the path of katana's saved JSONL: about 17 tokens.

## Nothing is lost

For each scenario, `bench/verify.py` checks the raijin-js output against the `raw` JSONL. Identities:

- a **JS file** (a `.js .mjs .cjs .jsx` URL or a JavaScript content type) is its URL and status: it must be in a `js` or `library` group with that status;
- a **jsluice endpoint** (a katana line with tag `js` whose source is a JS file) is (endpoint, file), the endpoint written as raijin-js writes it: it must be in a finding or group that lists the file, with the status katana got;
- a **source map** katana fetched is its URL and status: it must be in a `sourcemap` finding or group;
- an **extracted item** is (item, file): verify.py parses each body again with a Python port of `internal/extract` and the same `rules.json`. A path, URL or source map must be in a finding or group that lists the file; a secret must be in a finding with the same rule and redacted value that lists `file:line`;
- every other katana line (pages, links) is counted, and the count must equal `omitted.not_js`.

Locations are expanded (`[1-40]`) and `origin` is prepended before the check.

- Scenario 1: 45 JS files, 51 jsluice endpoints, 0 source maps, 690 (item, file) pairs, 3 other results, **0 missing**.
- Scenario 2: 6 JS files, 13 jsluice endpoints, 2 source maps, 38 (item, file) pairs, 5 other results, **0 missing**.

The check fails when it should: with the range of `/api/v1/cart` cut to `chunk-[1-39].js`, it reports `/api/v1/cart` in `chunk-40.js` missing; with `/static/js/app.js:3` taken out of the AWS key's locations, it reports that secret at that line missing.

Since verify.py is a port of the extractor, it proves that the reducer drops nothing the extractor found; it does not prove the rules find every secret a site could hold. What the JSON leaves out stays in katana's JSONL, which raijin-js saves to disk and points to in `raw`: the bodies with the secrets in full, the headers, the page each file was found on and the timestamps.

## Reading the numbers

- **Against `katana -jsonl`**, the structured output an agent would parse, raijin-js uses **31× fewer tokens** on the noisy crawl and **6.6× fewer** on the findings crawl. Against the JSONL without the raw strings (`-or`) it is **15×** and **3.3×** smaller. The gap grows with repetition: an endpoint in 40 chunks costs one entry and one location.
- **Against katana's text output**, raijin-js is larger: **2.0×** on the noisy crawl (1,242 → 2,493) and **5.2×** on the findings crawl (285 → 1,496). A list of 99 or 20 URLs is smaller than what is in the files, but it holds none of it: no endpoint, no key, no bucket, no status.
- **Against the text plus the JS bodies**, what an agent that starts from the text still has to read:
  - noisy: **6.3× smaller** (15,793 → 2,493);
  - findings: **1.25× larger** (1,192 → 1,496).

  The findings lab is six files of 2.6 KB where almost every line is a finding, so there is little to cut, and each finding's id, tags, severity and location cost more than the line it came from. Real bundles are tens to hundreds of KB per file, mostly code with no endpoint or key in it: the bodies grow with the code, raijin-js grows with the items. The lab files are kept small so the fixtures stay small; this row is the one where that matters.
- **The output stays bounded.** On a site too big for `--max-bytes`, raijin-js cuts the least important data first: group locations, then groups, then extra locations of low-ranked findings, then low-ranked findings. Every cut is counted in `omitted`, and `next` points to the raw file. Raw katana output has no upper bound.

## katana behavior worth knowing

- **Empty responses.** katana writes an empty response (no status, no body) for a URL whose body is identical to one it already saw in the crawl. raijin-js keeps such a JS file in the `js` group without a status, and cannot parse a body katana did not keep. The lab gives every page and API answer a distinct body so the crawls are stable.
- **Source maps.** katana 1.1.2 leaves `.map` URLs out of its output, even when it is asked to crawl one directly, unless `-em map` is set. That is why the source map pass is a separate run.
- **jsluice requests what it finds.** With `-jsl`, katana requests the endpoints it finds in JS (as GET), so most items get a status. A template literal like `` `${API_BASE}/api/v1/orders/${id}` `` is found only by raijin-js, and gets none.
