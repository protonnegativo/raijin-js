"""Checks that every katana result and every extracted item is in a raijin-js result.

A katana JSONL line is one of:

- a JavaScript file (a .js .mjs .cjs .jsx URL, or a JavaScript content type): its identity is its URL and
  status. It is present when a "js" or "library" group lists it with that status.
- an endpoint jsluice found in a JavaScript file (tag "js", source a JavaScript file): its identity is
  (endpoint, file). The endpoint is written the way raijin-js writes it (on the file's origin: its path).
  It is present when a finding or group lists it with that file and the status katana got for it.
- a source map katana fetched: present when a "sourcemap" finding or group lists it with that status.
- anything else (pages, links): counted, and the count must equal omitted.not_js.

Then each JavaScript body is parsed again here, with a Python port of internal/extract (same rules.json),
and every (item, file) pair must be in the output: a path, URL or source map in a finding or group that
lists the file, a secret in a finding with the same rule and redacted value that lists "file:line".
Locations are expanded ("[1-40]" ranges) and "origin" is prepended when the output has one.

usage: python verify.py <katana.jsonl> <raijin.json>
"""
import json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
RULES = json.load(open(os.path.join(HERE, "..", "internal", "extract", "rules.json")))
for r in RULES:
    r["re"] = re.compile(r["pattern"])
    r["req"] = re.compile(r["require"]) if r.get("require") else None

raw, out = sys.argv[1], sys.argv[2]
o = json.load(open(out))
origin = o.get("origin", "")

LITERAL = re.compile(r'"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\'|`(?:[^`\\]|\\.)*`')
PLACEHOLDER = re.compile(r"\$\{([^}]*)\}")
IDENT = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$.]*$")
LEADING_VAR = re.compile(r"^\{[^}]*\}/")
URL_RE = re.compile(r"""^(?:(?:https?|wss?):)?//(?:[^\s/?#@"'<>\\]+@)?([A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(?::[0-9]{1,5})?(?:[/?#][^\s"'<>\\]*)?$""")
PATH_RE = re.compile(r"""^(?:\.\.?)?/[A-Za-z0-9_.~%{}@:+,;=!$/-]*[A-Za-z][A-Za-z0-9_.~%{}@:+,;=!$/-]*(?:[?#][^\s"'<>\\]*)?$""")
MAP_RE = re.compile(r"""[/][/*][#@]\s*sourceMappingURL=([^\s*'"]+)""")
JS_EXT = {"js", "mjs", "cjs", "jsx"}


def origin_of(u):
    i = u.find("://")
    if i < 0:
        return ""
    m = re.search(r"[/?#]", u[i + 3:])
    return u[: i + 3 + m.start()] if m else u


def remove_dots(p):
    segs = p.split("/")
    res = []
    for i, s in enumerate(segs):
        last = i == len(segs) - 1
        if s == ".":
            if last:
                res.append("")
        elif s == "..":
            if len(res) > 1:
                res.pop()
            if last:
                res.append("")
        else:
            res.append(s)
    return "/".join(res)


def resolve(v, file_url):
    org = origin_of(file_url)
    if v.startswith("./") or v.startswith("../"):
        d = file_url[len(org):] if file_url.startswith(org) else file_url
        d = re.split(r"[?#]", d, maxsplit=1)[0]
        d = d[: d.rfind("/") + 1] or "/"
        rest = ""
        m = re.search(r"[?#]", v)
        if m:
            v, rest = v[: m.start()], v[m.start():]
        return remove_dots(d + v) + rest
    if v.startswith("//"):
        i = org.find("://")
        if i >= 0:
            v = org[: i + 1] + v
    i = v.find("://")
    if i < 0:
        return v
    auth = v[i + 3:]
    m = re.search(r"[/?#]", auth)
    end = m.start() if m else len(auth)
    at = auth[:end].rfind("@")
    if at >= 0:
        v = v[: i + 3] + auth[at + 1:]
    ov = origin_of(v)
    if org and ov.lower() == org.lower():
        p = v[len(ov):]
        return p if p.startswith("/") else "/" + p
    return v


def literal(lit, file_url):
    if len(lit) < 2:
        return None
    v = lit[1:-1].replace("\\/", "/")
    if lit[0] == "`":
        def ph(m):
            name = m.group(1).strip()
            return "{" + name + "}" if IDENT.match(name) else "{}"
        v = PLACEHOLDER.sub(ph, v)
        m = LEADING_VAR.match(v)
        if m:
            v = v[m.end() - 1:]
    if len(v.encode()) > 500:
        return None
    m = URL_RE.match(v)
    if m:
        if v.startswith("//") and "." not in m.group(1):
            return None
        r = resolve(v, file_url)
        if r.startswith("/") and not r.startswith("//"):
            return ("path", r)
        return ("url", r)
    if v.startswith("//") or v.startswith("/*"):
        return None
    if PATH_RE.match(v) and len(v.split("?", 1)[0].split("#", 1)[0]) >= 3:
        return ("path", resolve(v, file_url))
    return None


def redact(s):
    if len(s) >= 16:
        return s[:4] + "…" + s[-4:]
    if len(s) >= 8:
        return s[:2] + "…" + s[-2:]
    return "…"


def secrets(line):
    hits, taken = [], []
    for r in RULES:
        for m in r["re"].finditer(line):
            g = r["secret"]
            a, b = m.span(g)
            if a < 0:
                continue
            sec = line[a:b]
            if r["req"] and not r["req"].search(sec):
                continue
            if any(a < t[1] and t[0] < b for t in taken):
                continue
            taken.append((a, b))
            shown = m.group(0)
            if r.get("redact", True):
                shown = line[m.start():a] + redact(sec) + line[b:m.end()]
            hits.append((r["id"], shown))
    return hits


def extract(body, file_url):
    hits = set()
    for lit in LITERAL.findall(body):
        h = literal(lit, file_url)
        if h:
            hits.add((h[0], h[1], None, 0))
    for m in MAP_RE.finditer(body):
        v = m.group(1)
        if v.startswith("data:"):
            if "," in v:
                v = v[: v.index(",") + 1]
            hits.add(("sourcemap", v + "…", None, 0))
            continue
        if not v.startswith("/") and "://" not in v and not v.startswith("."):
            v = "./" + v
        hits.add(("sourcemap", resolve(v, file_url), None, 0))
    for i, line in enumerate(body.split("\n")):
        for rule, shown in secrets(line):
            hits.add(("secret", shown, rule, i + 1))
    return hits


def is_js(u, ctype):
    p = re.split(r"[?#]", u[len(origin_of(u)):], maxsplit=1)[0]
    last = p.split("/")[-1]
    i = last.rfind(".")
    if 0 < i < len(last) - 1 and last[i + 1:].lower() in JS_EXT:
        return True
    ct = (ctype or "").lower()
    return "javascript" in ct or "ecmascript" in ct


def expand(loc):
    m = re.search(r"\[([0-9,\-]+)\]", loc)
    if not m:
        return [loc]
    res = []
    for part in m.group(1).split(","):
        a, _, b = part.partition("-")
        for n in range(int(a), int(b or a) + 1):
            res.append(loc[: m.start()] + str(n) + loc[m.end():])
    return res


def esc(u):
    return u.replace("[", "%5B").replace("]", "%5D")


# index the output
files_listed = set()      # (file, status)
items = {}                # value -> list of (entry, set of files)
secret_locs = {}          # (rule, value) -> set of "file:line"
for kind in ("findings", "groups"):
    for x in o[kind]:
        locs = set()
        for loc in x.get("locations", []):
            for u in expand(loc):
                locs.add(origin + u)
        if kind == "groups" and x["kind"] in ("js", "library"):
            for u in locs:
                files_listed.add((u, x.get("status", 0)))
            continue
        if "secret" in x.get("tags", []):
            secret_locs.setdefault((x["rule"], x["value"]), set()).update(locs)
            continue
        for v in x.get("variants", [x.get("value")]):
            items.setdefault(v, []).append((x, locs))


def present(value, file, status=None, sourcemap=False):
    for x, locs in items.get(value, []):
        if sourcemap != ("sourcemap" in x.get("tags", []) or x.get("kind") == "sourcemap"):
            continue
        if file is not None and esc(file) not in locs:
            continue
        if status is not None and x.get("status", 0) != status:
            continue
        return True
    return False


events = []
for line in open(raw):
    line = line.strip()
    if line.startswith("{"):
        e = json.loads(line)
        if (e.get("request") or {}).get("endpoint"):
            events.append(e)

status, ctypes = {}, {}
for e in events:
    u = e["request"]["endpoint"]
    resp = e.get("response") or {}
    s = resp.get("status_code") or 0
    if s and not status.get(u):
        status[u] = s
    headers = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
    ct = headers.get("content-type", "")
    ctypes[u] = (ct[0] if ct else "") if isinstance(ct, list) else str(ct)

js = {}
for e in events:
    u = e["request"]["endpoint"]
    if is_js(u, ctypes.get(u, "")) and (u not in js or not js[u]):
        js[u] = (e.get("response") or {}).get("body") or js.get(u, "")

miss, n_files, n_jsluice, n_maps, n_items, not_js = [], 0, 0, 0, 0, 0
for u in js:
    n_files += 1
    if (esc(u), status.get(u, 0)) not in files_listed:
        miss.append(("js file", u, status.get(u, 0)))
for e in events:
    req = e["request"]
    u = req["endpoint"]
    if req.get("tag") == "js" and req.get("source") in js:
        n_jsluice += 1
        v = resolve(u, req["source"])
        if not present(v, req["source"], status.get(u, 0)):
            miss.append(("jsluice", v, req["source"]))
        continue
    if u in js:
        continue
    not_js += 1
    if re.split(r"[?#]", u, maxsplit=1)[0].endswith(".map"):
        n_maps += 1
        v = resolve(u, u)
        if not present(v, None, status.get(u, 0), sourcemap=True):
            miss.append(("source map", v, status.get(u, 0)))
for u, body in js.items():
    for kind, value, rule, line in extract(body, u):
        n_items += 1
        if kind == "secret":
            if esc(u) + f":{line}" not in secret_locs.get((rule, value), set()):
                miss.append(("secret", rule, value, u, line))
        elif not present(value, u, None, kind == "sourcemap"):
            miss.append((kind, value, u))
if not_js != o.get("omitted", {}).get("not_js", 0):
    miss.append(("not_js count", not_js, o.get("omitted", {}).get("not_js", 0)))

print(f"{n_files} JS files, {n_jsluice} jsluice endpoints, {n_maps} source maps, {n_items} (item, file) pairs, {not_js} other katana results: {len(miss)} missing from output", "truncated" if o.get("budget") else "")
for m in miss[:5]:
    print("  MISSING", m)
sys.exit(1 if miss else 0)
