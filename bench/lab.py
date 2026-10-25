"""Local lab for the raijin-js benchmark: small websites on 127.0.0.1 that serve fake JS bundles, one process.

Every key in these files is fake: random characters in the shape of a real key, made from a fixed seed so
the lab serves the same bytes on every run. None of them was ever issued by a provider.

Each argument is port=kind:

  shop  a noisy storefront: 40 webpack-style chunks that repeat the same runtime, the same 12 API and page
        paths and the same 4 third-party URLs, one category route per chunk, and 5 vendor libraries
        (jQuery, React, lodash, Bootstrap, Moment) with the namespace and docs URLs libraries carry.
  app   a small app whose bundles leak: an AWS access key ID (in two files), a Google API key, a JWT, a
        client secret, a password, a private key, credentials in a URL, admin, debug and internal API
        routes (one answers 403), S3 and GCS buckets, internal hosts, a lazy chunk that only JS points
        to, a source map that is served, one that is not (404) and one inlined as a data: URI, and a
        vendored jQuery.

usage: python3 lab.py 19100=shop 19101=app      (LAB_LOG=1 logs each request to stderr)
"""
import os
import random
import string
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

rnd = random.Random(19100)


def fake(alphabet, n):
    return "".join(rnd.choice(alphabet) for _ in range(n))


UP = string.ascii_uppercase + string.digits
ALNUM = string.ascii_letters + string.digits
B64URL = ALNUM + "-_"

AWS_ID = "AKIA" + fake(UP, 16)
GOOGLE_KEY = "AIza" + fake(B64URL, 35)
JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + "eyJ" + fake(B64URL, 40) + "." + fake(B64URL, 43)
CLIENT_SECRET = fake(ALNUM, 32)
PASSWORD = "lab-" + fake(ALNUM, 12)
URL_PASS = fake(ALNUM, 14)
PRIVKEY = fake(ALNUM + "+/", 64)

PAGE = """<!DOCTYPE html>
<html><head><title>{title}</title>
{scripts}
</head>
<body><nav><a href="/">Home</a> <a href="/about">About</a></nav>
<h1>{title}</h1>
</body></html>
"""


def scripts(paths):
    return "\n".join(f'<script src="{p}"></script>' for p in paths)


# --- shop: the noisy site -------------------------------------------------------------------------

SHARED_PATHS = ["/api/v1/products", "/api/v1/cart", "/api/v1/cart/items", "/api/v1/search", "/api/v1/session",
                "/api/v1/recommendations", "/about", "/contact", "/help/shipping", "/help/returns", "/account",
                "/checkout"]
SHARED_EXTERNAL = ["https://www.googletagmanager.com/gtag/js", "https://fonts.googleapis.com/css2",
                   "https://cdn.shopify.example/assets/", "https://www.facebook.com/tr"]
CHUNKS = [f"/static/js/chunk-{i}.js" for i in range(1, 41)]
LIBS = {
    "/static/vendor/jquery-3.7.1.min.js": ("jQuery", "3.7.1", ["http://www.w3.org/2000/svg", "http://www.w3.org/1999/xhtml", "https://jquery.com/upgrade-guide/"]),
    "/static/vendor/react.production.min.js": ("React", "18.2.0", ["https://reactjs.org/docs/error-decoder.html", "http://www.w3.org/1998/Math/MathML", "http://www.w3.org/2000/svg"]),
    "/static/vendor/lodash.min.js": ("lodash", "4.17.21", ["https://lodash.com/license"]),
    "/static/vendor/bootstrap.bundle.min.js": ("Bootstrap", "5.3.2", ["https://getbootstrap.com/docs/5.3/", "http://www.w3.org/2000/svg"]),
    "/static/vendor/moment.min.js": ("Moment", "2.29.4", ["https://momentjs.com/guides/"]),
}


def chunk(i):
    lines = [f'(self.webpackChunkshop=self.webpackChunkshop||[]).push([[{i}],{{{i}:function(e,t,n){{"use strict";',
             'var r=n(1),o=n(2),a="application/json",c={"Content-Type":a,"Accept":a};']
    for k, p in enumerate(SHARED_PATHS):
        lines.append(f'function f{k}(q){{return fetch("{p}",{{headers:c,body:q}})}}')
    lines.append("var ext=[" + ",".join(f'"{u}"' for u in SHARED_EXTERNAL) + "];")
    lines.append(f'r.route("/category/{i}",function(){{return o.render("category",{{id:{i}}})}});')
    lines.append("}}]);")
    return "\n".join(lines) + "\n"


def library(name, version, urls):
    body = f"/*! {name} v{version} | (c) {name} contributors | fake lab copy */\n"
    body += "!function(e,t){\"use strict\";var n=[],r=Object.getPrototypeOf,i=n.slice;"
    body += "".join(f'var u{k}="{u}";' for k, u in enumerate(urls))
    body += 'function s(e){return"string"==typeof e&&e.indexOf("<")>-1}' * 3
    return body + "}(window);\n"


def shop(path):
    if path == "/":
        return 200, "text/html", PAGE.format(title="Shop", scripts=scripts(list(LIBS) + CHUNKS))
    if path.startswith("/api/v1/"):
        return 200, "application/json", '{"path":"%s","items":[]}\n' % path
    if path in SHARED_PATHS or path.startswith("/category/"):
        return 200, "text/html", PAGE.format(title=path.strip("/").title(), scripts=scripts(CHUNKS[:1]))
    if path in CHUNKS:
        return 200, "application/javascript", chunk(CHUNKS.index(path) + 1)
    if path in LIBS:
        return 200, "application/javascript", library(*LIBS[path])
    return 404, "text/html", PAGE.format(title="Not found: " + path, scripts="")


# --- app: the site with real findings -------------------------------------------------------------

APP_JS = f"""// app bundle (fake lab copy)
import {{ h }} from "./runtime.js";
const AWS_ACCESS_KEY_ID = "{AWS_ID}";
const firebaseConfig = {{ apiKey: "{GOOGLE_KEY}", authDomain: "acme-lab.firebaseapp.com" }};
export function users() {{ return fetch("/api/v1/users").then(r => r.json()); }}
export function saveSettings(s) {{ return fetch("/api/v2/admin/settings", {{ method: "POST", body: JSON.stringify(s) }}); }}
export const order = (id) => fetch(`${{API_BASE}}/api/v1/orders/${{id}}`);
const DEBUG_VARS = "/internal/debug";
const PPROF = '/debug/pprof/';
const GRAPHQL = "/graphql";
const UPLOADS = "https://acme-lab-uploads.s3.amazonaws.com/user-docs/";
const BACKUPS = "https://storage.googleapis.com/acme-lab-backups/db/";
const METRICS = "http://10.0.3.7:8080/metrics";
const JENKINS = "http://jenkins.corp.internal/job/deploy/";
const HOOK = "http://deploy:{URL_PASS}@build.acme.internal/hooks";
let session = "{JWT}";
const pages = ["/about", "/help/faq", "/pricing"];
const ga = "https://www.google-analytics.com/analytics.js";
const lazy = () => import("/static/js/chunk-lazy.js");
//# sourceMappingURL=app.js.map
"""

VENDOR_JS = f"""/* vendor bundle (fake lab copy) */
var cfg = {{ region: "us-east-1" }};
var s3key = "{AWS_ID}";
var sentry = "https://o0.ingest.sentry.example/api/1/store/";
var cdn = "https://cdn.jsdelivr.net/npm/";
//# sourceMappingURL=vendor.js.map
"""

CONFIG_JS = f"""window.APP_CONFIG = {{
  env: "staging",
  client_secret: "{CLIENT_SECRET}",
  signingKey: "-----BEGIN RSA PRIVATE KEY-----\\n{PRIVKEY}\\n-----END RSA PRIVATE KEY-----",
  api: "/api/v1/",
  status: "/server-status"
}};
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImNvbmZpZy50cyJdfQ==
"""

RUNTIME_JS = """export function h(tag, props) { return { tag, props }; }
export const routes = ["/about", "/pricing", "/account/settings"];
"""

LAZY_JS = f"""export async function exportUsers() {{
  return fetch("/api/v1/admin/users/export", {{ headers: {{ "X-Requested-With": "XMLHttpRequest" }} }});
}}
const ADMIN = {{ user: "admin", password: "{PASSWORD}" }};
"""

APP_MAP = '{"version":3,"file":"app.js","sources":["webpack://app/src/api.ts","webpack://app/src/config.ts"],"mappings":"AAAA"}\n'

APP_FILES = {
    "/static/js/app.js": APP_JS,
    "/static/js/vendor.js": VENDOR_JS,
    "/static/js/config.js": CONFIG_JS,
    "/static/js/runtime.js": RUNTIME_JS,
    "/static/js/chunk-lazy.js": LAZY_JS,
    "/static/js/lib/jquery-3.6.0.min.js": library("jQuery", "3.6.0", ["http://www.w3.org/2000/svg", "https://jquery.com/upgrade-guide/"]),
}


def app(path):
    if path == "/":
        return 200, "text/html", PAGE.format(title="App", scripts=scripts(["/static/js/lib/jquery-3.6.0.min.js", "/static/js/config.js", "/static/js/vendor.js", "/static/js/app.js"]))
    if path in APP_FILES:
        return 200, "application/javascript", APP_FILES[path]
    if path == "/static/js/app.js.map":
        return 200, "application/json", APP_MAP
    if path in ("/api/v1/users", "/api/v1/orders"):
        return 200, "application/json", '{"path":"%s","items":[]}\n' % path
    if path in ("/api/v2/admin/settings", "/api/v1/admin/users/export"):
        return 403, "application/json", '{"path":"%s","error":"forbidden"}\n' % path
    if path in ("/internal/debug", "/debug/pprof/"):
        return 200, "text/plain", f"{path}: goroutines 12, heap 3 MB\n"
    if path in ("/about", "/pricing", "/help/faq"):
        return 200, "text/html", PAGE.format(title=path.strip("/").title(), scripts="")
    return 404, "text/html", PAGE.format(title="Not found: " + path, scripts="")


SITES = {"shop": shop, "app": app}


def handler(kind):
    site = SITES[kind]

    class H(BaseHTTPRequestHandler):
        server_version = "lab"
        sys_version = ""

        def do_GET(self):
            status, ctype, body = site(urlsplit(self.path).path)
            data = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        do_POST = do_GET

        def log_message(self, fmt, *args):
            if os.environ.get("LAB_LOG"):
                sys.stderr.write(f"{kind} {fmt % args}\n")

    return H


def main():
    servers = []
    for arg in sys.argv[1:]:
        port, kind = arg.split("=", 1)
        srv = ThreadingHTTPServer(("127.0.0.1", int(port)), handler(kind))
        servers.append(srv)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        print(f"{kind} on 127.0.0.1:{port}", flush=True)
    threading.Event().wait()


if __name__ == "__main__":
    main()
