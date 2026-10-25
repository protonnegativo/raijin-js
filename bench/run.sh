#!/usr/bin/env bash
# Reproducible token benchmark: katana output vs raijin-js output on the same crawl.
#
# usage: bench/run.sh [workdir]
#        LIVE=1 bench/run.sh [workdir]   start the local lab, crawl it again and refresh bench/fixtures first
# needs: go, python3 with tiktoken (pip install tiktoken); LIVE=1 also needs katana
# optional: ANTHROPIC_API_KEY + pip install anthropic for exact Claude token counts
# env: PY=<python with tiktoken>, KATANA=<path>
#
# Safety: LIVE=1 crawls only the lab it starts itself (bench/lab.py) on 127.0.0.1, ports 19100 and
# 19101, as http://localhost:<port>/, depth 3, with katana's crawl scope set to localhost. Every key in
# the lab is fake. It stops the lab when it exits. A live run takes about two and a half minutes.
set -euo pipefail

W=${1:-$(mktemp -d)}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
PY=${PY:-python3}
KATANA=${KATANA:-katana}
mkdir -p "$W"
echo "workdir: $W"

# Lab: one python process with two sites (see lab.py).
# noisy:    a storefront with 40 webpack-style chunks that repeat the same API paths, page paths and
#           third-party URLs, one route per chunk, and 5 vendor libraries.
# findings: an app whose bundles leak fake keys (AWS, Google, JWT, a client secret, a password, a
#           private key, credentials in a URL), admin, debug and internal routes, buckets, internal
#           hosts, a lazy chunk, and source maps (one served, one 404, one inline).
declare -A port=([noisy]=19100 [findings]=19101)
printf 'localhost\n' > "$W/scope.txt"

(cd "$ROOT" && go build -o "$W/raijin-js" ./cmd/raijin-js)

if [ "${LIVE:-}" = 1 ]; then
  for p in "${port[@]}"; do
    if ss -ltn | grep -q ":$p "; then echo "port $p is busy; free it first" >&2; exit 1; fi
  done
  python3 "$HERE/lab.py" "${port[noisy]}=shop" "${port[findings]}=app" > "$W/lab.log" 2>&1 &
  echo $! > "$W/pids"
  trap '[ -f "$W/pids" ] && xargs kill < "$W/pids" 2>/dev/null || true' EXIT
  sleep 1
  for name in noisy findings; do
    f=$HERE/fixtures/$name
    u=http://localhost:${port[$name]}/
    mkdir -p "$f"
    # raijin-js runs katana (-jsonl -or -jc -jsl -d 3 -cs <host>), then katana again on the source maps
    # the files point to (-d 1 -em map -ob), and saves both JSONL outputs as raw: that file is the fixture.
    "$W/raijin-js" --katana "$KATANA" --scope "$W/scope.txt" -u "$u" --raw "$f/raw.jsonl" > "$W/$name.live.json"
    # katana as an agent would run it to collect JavaScript, with the same crawl options: JSONL (raw
    # request and response included, katana's default) and text (one URL per line, banner on stderr).
    crawl=(-u "$u" -d 3 -jc -jsl -cs '^https?://localhost(:[0-9]+)?([/?#]|$)' -duc -nc)
    "$KATANA" "${crawl[@]}" -jsonl -silent < /dev/null > "$f/katana.jsonl"
    "$KATANA" "${crawl[@]}" < /dev/null > "$f/text.txt" 2> "$f/text_stderr.txt"
  done
fi

scenario() {
  local name=$1
  local f=$HERE/fixtures/$name o=$W/$name
  mkdir -p "$o"
  # What an agent reading katana's text output still has to read to find the endpoints and secrets: the
  # body of every JavaScript file it lists (taken from raw, so it is the same bytes).
  python3 -c 'import json,sys
for l in open(sys.argv[1]):
    e = json.loads(l)
    u = e["request"]["endpoint"].split("?")[0]
    b = (e.get("response") or {}).get("body") or ""
    if u.endswith((".js", ".mjs")) and b:
        sys.stdout.write(b)' "$f/raw.jsonl" > "$o/js_bodies.txt"
  # raijin-js replays raw with --input, so every row sees the same crawl.
  (cd "$ROOT" && "$W/raijin-js" --scope "$W/scope.txt" --input "bench/fixtures/$name/raw.jsonl") > "$o/raijin.json"
  (cd "$ROOT" && "$W/raijin-js" --scope "$W/scope.txt" --input "bench/fixtures/$name/raw.jsonl" --pretty) > "$o/raijin_pretty.json"
  (cd "$ROOT" && "$W/raijin-js" --scope "$W/scope.txt" --input "bench/fixtures/$name/raw.jsonl" --format table) > "$o/raijin_table.txt"
  echo; echo "## $name: $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["summary"])' "$o/raijin.json")"; echo
  python3 "$HERE/verify.py" "$f/raw.jsonl" "$o/raijin.json"
  echo "separate katana runs: -jsonl $(grep -c '^{' "$f/katana.jsonl") results, text $(grep -c '^http' "$f/text.txt") URLs"
  "$PY" "$HERE/count_tokens.py" \
    "katana -jsonl=$f/katana.jsonl" \
    "katana -jsonl (raijin-js's raw)=$f/raw.jsonl" \
    "katana text (stdout+stderr)=$f/text.txt+$f/text_stderr.txt" \
    "katana text + the JS bodies=$f/text.txt+$f/text_stderr.txt+$o/js_bodies.txt" \
    "raijin-js JSON (default)=$o/raijin.json" \
    "raijin-js --pretty=$o/raijin_pretty.json" \
    "raijin-js --format table=$o/raijin_table.txt"
}

scenario noisy
scenario findings
