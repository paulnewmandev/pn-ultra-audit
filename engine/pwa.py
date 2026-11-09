"""Progressive Web App (PWA) audit: manifest, installability, service worker correctness, offline, security, install/update UX.
Static (reads manifests, HTML and service-worker sources) plus an optional live check of a deployed URL. Never executes anything."""
import json, os, re, urllib.parse

from .kb import KB

HTML_EXT = {"html", "htm", "php", "twig", "erb", "ejs", "hbs", "vue", "svelte", "jsx", "tsx", "astro", "njk", "blade"}
SRC_EXT = {"js", "mjs", "cjs", "ts", "tsx", "jsx", "vue", "svelte", "astro"}
SW_NAME = re.compile(r"(^|/)(sw|service-?worker|serviceworker|firebase-messaging-sw|ngsw-worker|workbox-[\w.-]*|sw\.[\w-]+)\.(js|ts|mjs)$", re.I)
MANIFEST_NAME = re.compile(r"(^|/)(manifest\.webmanifest|manifest\.json|site\.webmanifest|[\w-]+\.webmanifest)$", re.I)
PWA_DEPS = re.compile(r'"(vite-plugin-pwa|next-pwa|@ducanh2912/next-pwa|@serwist/\w+|serwist|workbox-[\w-]+|workbox-webpack-plugin|@angular/pwa|@angular/service-worker|sw-precache|register-service-worker|@vue/cli-plugin-pwa|gatsby-plugin-offline|@nuxtjs/pwa|@vite-pwa/\w+|@remix-pwa/\w+|react-scripts)"|\bworkbox\b', re.I)
REGISTER = re.compile(r"serviceWorker\s*\.\s*register\s*\(|registerSW\s*\(|register-service-worker|workbox-window|\bnew\s+Workbox\s*\(|navigator\.serviceWorker\b", re.I)


def _f(rule, title, family, typ, sev, file, line, ev, fix=None, effort=15, status="confirmed", priority=None, cwe=(), owasp=()):
    kb = KB[family]
    return dict(rule=rule, title=title, family=family, type=typ, severity=sev if status == "confirmed" else None, category="pwa", file=file, line=line, evidence=(ev or "")[:500],
                impact=kb["impact"], fix=fix or "; ".join(kb["steps"][:2]), effort_min=effort, cwe=list(cwe), owasp=list(owasp), status=status, priority=priority, why=None)


def _read(ab, cap=300_000):
    try:
        with open(ab, encoding="utf-8", errors="ignore") as fh: return fh.read(cap)
    except OSError: return ""


def _line_of(text, pat):
    m = re.search(pat, text)
    return text[:m.start()].count("\n") + 1 if m else 1


def detect(files, deps_text=""):
    """-> evidence list; non-empty means the project is (or aims to be) a PWA."""
    ev = []
    rels = [f[0] for f in files]
    if any(MANIFEST_NAME.search(r) and "node_modules" not in r for r in rels): ev.append("web app manifest")
    if any(SW_NAME.search(r) and "node_modules" not in r for r in rels): ev.append("service worker file")
    if PWA_DEPS.search(deps_text or ""): ev.append("PWA tooling (workbox/vite-plugin-pwa/next-pwa/angular)")
    return ev


def _sev(strict, basic_sev, std_sev, strict_sev):
    return {"basic": basic_sev, "standard": std_sev, "strict": strict_sev}[strict]


def analyze(root, files, level="standard"):
    """level: basic | standard | strict.  -> (findings, info)"""
    out, info = [], {}
    prod = [f for f in files if "node_modules" not in f[0]]
    manifests = [f for f in prod if MANIFEST_NAME.search(f[0])]
    sw_files = [f for f in prod if SW_NAME.search(f[0]) and not re.search(r"workbox-[\w.-]*\.js$", f[0], re.I)]
    pages = [f for f in prod if f[2] in HTML_EXT and f[3] < 600_000]
    srcs = [f for f in prod if f[2] in SRC_EXT and f[3] < 600_000]
    page_txt = {f[0]: _read(f[1]) for f in pages[:400]}
    src_txt = {f[0]: _read(f[1]) for f in srcs[:600]}
    all_txt = {**page_txt, **{k: v for k, v in src_txt.items() if k not in page_txt}}
    pkg = " ".join(_read(f[1], 60_000) for f in prod if os.path.basename(f[0]) in ("package.json", "composer.json", "pubspec.yaml") and f[0].count("/") <= 3)
    ev = detect(files, pkg)
    if not ev and not any(REGISTER.search(t) for t in all_txt.values()): return [], {}
    S = lambda b, s, st: _sev(level, b, s, st)

    # ---------- manifest ----------
    mf, mf_path = None, None
    for rel, ab, ext, sz in manifests:
        txt = _read(ab)
        try: j = json.loads(txt)
        except ValueError:
            out.append(_f("PWA-MANIFEST-INVALID", "Web app manifest is not valid JSON", "pwa-manifest", "bug", "high", rel, 1, txt[:120],
                          "Fix the JSON syntax (no comments or trailing commas); validate in DevTools > Application > Manifest", 10)); continue
        if isinstance(j, dict) and (mf is None or "icons" in j): mf, mf_path = j, rel
    link_re = re.compile(r"<link[^>]+rel=[\"']manifest[\"']", re.I)
    linked = any(link_re.search(t) for t in page_txt.values()) or any(re.search(r"\bmanifest\s*[:=]\s*[\"'`]|rel[\"']?\s*[:=]\s*[\"']manifest", t) for t in src_txt.values())
    if sw_files and not manifests and not re.search(r"vite-plugin-pwa|next-pwa|serwist|@angular/pwa|manifest", pkg, re.I):
        out.append(_f("PWA-NO-MANIFEST", "Service worker present but no web app manifest: the app cannot be installed", "pwa-manifest", "code_smell", S("low", "medium", "high"), sw_files[0][0], 1,
                      f"service worker {sw_files[0][0]}; no manifest.webmanifest / manifest.json", None, 20))
    if manifests and pages and not linked:
        out.append(_f("PWA-MANIFEST-NOT-LINKED", "Manifest exists but no page links to it (<link rel=\"manifest\">)", "pwa-manifest", "bug", S("low", "medium", "high"), manifests[0][0], 1,
                      "no <link rel=manifest> found in HTML/templates", "Add `<link rel=\"manifest\" href=\"/manifest.webmanifest\">` to the document head (or the layout template)", 5))
    checks = []  # (label, ok) for the Lighthouse-style checklist
    if mf is not None:
        miss = [k for k in ("name", "start_url", "icons") if not mf.get(k)]
        if not mf.get("name") and not mf.get("short_name"): pass
        if not (mf.get("short_name") or mf.get("name")): miss.append("short_name")
        if miss: out.append(_f("PWA-MANIFEST-FIELDS", f"Manifest is missing required fields: {', '.join(sorted(set(miss)))}", "pwa-manifest", "bug", S("medium", "high", "high"), mf_path, 1, json.dumps({k: mf.get(k) for k in ("name", "short_name", "start_url", "display", "icons")})[:300], None, 15))
        disp = mf.get("display")
        if disp not in ("standalone", "fullscreen", "minimal-ui") and not (disp == "browser" and level == "basic"):
            if True:
                out.append(_f("PWA-MANIFEST-DISPLAY", f"Manifest `display` is {disp!r}: the app will open in a normal browser tab", "pwa-manifest", "code_smell", S("low", "low", "medium"), mf_path, _line_of(_read(os.path.join(root, mf_path)), r'"display"'), f"display={disp}", "Set \"display\": \"standalone\" (optionally with display_override)", 5))
        icons = [i for i in (mf.get("icons") or []) if isinstance(i, dict)]
        sizes = " ".join(str(i.get("sizes", "")) for i in icons)
        has192, has512 = bool(re.search(r"\b192x192\b|\bany\b", sizes)), bool(re.search(r"\b512x512\b|\bany\b", sizes))
        maskable = any("maskable" in str(i.get("purpose", "")) for i in icons)
        if icons and not (has192 and has512):
            out.append(_f("PWA-ICONS-SIZES", "Manifest icons lack the 192x192 and 512x512 sizes required for installability", "pwa-manifest", "bug", S("low", "medium", "high"), mf_path, 1, f"sizes: {sizes or '-'}", "Add PNG icons at 192x192 and 512x512", 15))
        if icons and not maskable:
            out.append(_f("PWA-ICON-MASKABLE", "No maskable icon: Android will shrink the icon inside a white circle", "pwa-manifest", "code_smell", S(None, "low", "medium") if level != "basic" else "info", mf_path, 1, "no icon with purpose=maskable", "Add a 512x512 icon with \"purpose\": \"maskable\" (art inside the central 80%)", 20))
        for u, nm in ((mf.get("start_url"), "start_url"), (mf.get("scope"), "scope")):
            if isinstance(u, str) and re.match(r"https?://", u):
                if u.startswith("http://"): out.append(_f("PWA-HTTP-URL", f"Manifest {nm} uses plain http://", "pwa-security", "vulnerability", "high", mf_path, 1, u, "Use a relative URL or https://", 5, cwe=["CWE-319"], owasp=["A02:2021"]))
        sc, su = mf.get("scope"), mf.get("start_url")
        if isinstance(sc, str) and isinstance(su, str) and sc.startswith("/") and su.startswith("/") and not su.startswith(sc):
            out.append(_f("PWA-START-OUTSIDE-SCOPE", "start_url is outside the manifest scope: the installed app will open in the browser", "pwa-manifest", "bug", "high", mf_path, 1, f"scope={sc} start_url={su}", "Make start_url fall inside scope", 5))
        if not mf.get("theme_color") or not mf.get("background_color"):
            out.append(_f("PWA-MANIFEST-COLORS", "Manifest lacks theme_color / background_color (white splash screen, mismatched status bar)", "pwa-manifest", "code_smell", S(None, "low", "low") if level != "basic" else "info", mf_path, 1, "", "Add theme_color and background_color matching your brand", 5))
        if level == "strict":
            rich = [k for k in ("id", "description", "screenshots", "categories", "lang", "shortcuts") if not mf.get(k)]
            if rich: out.append(_f("PWA-MANIFEST-RICH", f"Manifest lacks fields for the rich install dialog: {', '.join(rich)}", "pwa-manifest", "code_smell", "low", mf_path, 1, "", "Add id, description, screenshots (wide + narrow), categories, lang and shortcuts", 40))
        checks += [("Manifest valid with name + start_url + icons", not miss), ("Icons 192 and 512", has192 and has512 if icons else False), ("Maskable icon", maskable), ("Display standalone/fullscreen", disp in ("standalone", "fullscreen", "minimal-ui")),
                   ("Theme + background color", bool(mf.get("theme_color") and mf.get("background_color")))]
        info["manifest"] = dict(path=mf_path, name=mf.get("name") or mf.get("short_name"), display=disp, theme_color=mf.get("theme_color"), background_color=mf.get("background_color"), icons=len(icons), lang=mf.get("lang"), shortcuts=len(mf.get("shortcuts") or []), screenshots=len(mf.get("screenshots") or []))
    else: checks.append(("Manifest found", False))

    # ---------- registration / service worker ----------
    registered = [(r, t) for r, t in all_txt.items() if re.search(r"serviceWorker\s*\.\s*register\s*\(|registerSW\s*\(|new\s+Workbox\s*\(|register-service-worker", t)]
    has_plugin = bool(re.search(r"vite-plugin-pwa|next-pwa|serwist|@angular/service-worker|@vite-pwa|workbox-webpack-plugin|gatsby-plugin-offline|@nuxtjs/pwa|@angular/pwa", pkg))
    if (manifests or ev) and not sw_files and not registered and not has_plugin:
        out.append(_f("PWA-NO-SW", "No service worker: the app has no offline support and loses the main PWA benefit", "pwa-sw", "code_smell", S("low", "medium", "medium"), (manifests[0][0] if manifests else "."), 1,
                      "manifest present, no service worker file, no register() call", "Add a service worker (Workbox / vite-plugin-pwa / next-pwa) with at least an offline fallback", 90))
    if sw_files and not registered and not has_plugin:
        out.append(_f("PWA-SW-NOT-REGISTERED", "Service worker file exists but nothing registers it", "pwa-sw", "bug", S("low", "medium", "high"), sw_files[0][0], 1, "no navigator.serviceWorker.register(...) found", "Register it from your app entry point after the `load` event", 10))
    sw_info = []
    for rel, ab, ext, sz in sw_files[:6]:
        t = _read(ab)
        fetch_h = bool(re.search(r"addEventListener\s*\(\s*[\"']fetch[\"']|\.on\(\s*[\"']fetch|registerRoute\(|self\.__WB_MANIFEST|workbox\.routing|NavigationRoute|precacheAndRoute", t))
        if not fetch_h:
            out.append(_f("PWA-SW-NO-FETCH", "Service worker has no fetch handler: nothing works offline", "pwa-sw", "code_smell", S("low", "medium", "medium"), rel, 1, "no fetch event listener / workbox routing", "Handle `fetch` (network-first for pages, cache-first for hashed assets, offline fallback)", 45))
        uses_cache = bool(re.search(r"caches\.open|precache|workbox", t))
        if uses_cache and not re.search(r"caches\.(keys|delete)|cleanupOutdatedCaches|deleteCacheEntries|ExpirationPlugin", t) and not re.search(r"workbox|serwist|precacheAndRoute", t):
            out.append(_f("PWA-SW-CACHE-CLEANUP", "Service worker never deletes old caches: users keep stale files and storage grows", "pwa-sw", "bug", S("low", "medium", "medium"), rel, _line_of(t, r"caches\.open"), "no caches.delete / cleanupOutdatedCaches", "In `activate`, delete every cache whose name is not the current version", 20))
        if re.search(r"caches\.open\(\s*[\"'][^\"'\d]*[\"']\s*\)", t) and not re.search(r"v\d|VERSION|CACHE_NAME\s*=\s*[`\"'][^`\"']*\d", t, re.I) and level != "basic":
            out.append(_f("PWA-SW-CACHE-VERSION", "Cache name is not versioned: updated assets will never replace cached ones", "pwa-sw", "bug", "medium", rel, _line_of(t, r"caches\.open"), "caches.open('<static name>')", "Use a versioned cache name (`app-v42`) or Workbox precaching with revisions", 15))
        if fetch_h and not re.search(r"offline|fallback|setCatchHandler|NavigationRoute|navigateFallback|catch\s*\(", t, re.I):
            out.append(_f("PWA-SW-NO-OFFLINE-FALLBACK", "No offline fallback page for failed navigations", "pwa-sw", "code_smell", S(None, "low", "medium") if level != "basic" else "info", rel, 1, "no offline.html / catch handler", "Precache /offline.html and return it when a navigation fails", 20))
        if re.search(r"\bskipWaiting\s*\(", t) and not re.search(r"SKIP_WAITING|[\"']skipWaiting[\"']|skip[_-]waiting", t, re.I):
            out.append(_f("PWA-SW-SKIPWAITING", "skipWaiting() is called unconditionally: open tabs may run old pages against a new worker", "pwa-sw", "security_hotspot", None, rel, _line_of(t, r"skipWaiting"), "self.skipWaiting() without user-driven update", "Prompt the user and trigger skipWaiting from a message", 20, status="needs_validation", priority="low"))
        m = re.search(r"importScripts\s*\(([^)]*https?://[^)]*)\)", t)
        if m: out.append(_f("PWA-SW-IMPORT-REMOTE", "Service worker imports a script from another origin (supply-chain risk on your origin)", "pwa-security", "vulnerability", S("medium", "high", "high"), rel, _line_of(t, r"importScripts"), m.group(0)[:200], "Bundle the dependency (workbox-*) and serve it from your own origin", 25, cwe=["CWE-829"], owasp=["A08:2021"]))
        if re.search(r"\.put\(\s*\w+(\.request)?\s*,|cache\.add\(|\.addAll\(", t) and re.search(r"/api/|/auth|/account|/me\b|authorization|set-cookie", t, re.I) and not re.search(r"(startsWith|includes|test)\([^)]*[\"']/api|no-store|NetworkOnly|Authorization", t) and not re.search(r"if\s*\([^)]*(/api|auth)[^)]*\)\s*return", t):
            out.append(_f("PWA-SW-CACHE-PRIVATE", "Service worker may cache authenticated / API responses", "pwa-security", "security_hotspot", None, rel, _line_of(t, r"\.put\(|cache\.add\("), "cache.put(...) with /api or auth URLs and no exclusion", "Skip /api/ and credentialed requests (NetworkOnly) or key the cache per user and clear it on logout", 30, status="needs_validation", priority="high", cwe=["CWE-524", "CWE-200"], owasp=["A04:2021"]))
        if re.search(r"addEventListener\s*\(\s*[\"']message[\"']", t) and not re.search(r"\b(event|e|evt|ev)\.(origin|source)[^;\n]*(===|!==|==|startsWith|includes|instanceof)|origin\s*(===|!==)", t):
            out.append(_f("PWA-SW-MESSAGE-ORIGIN", "Service worker `message` handler does not validate the sender", "pwa-security", "security_hotspot", None, rel, _line_of(t, r"[\"']message[\"']"), "message listener without event.source/origin check", "Check event.source (a client of your origin) and an allowlist of message types", 15, status="needs_validation", priority="medium", cwe=["CWE-346"], owasp=["A01:2021"]))
        n_pre = len(re.findall(r"[\"'](/[^\"']*\.[a-z0-9]{2,5}|/)[\"']", re.search(r"addAll\(\s*\[([^\]]*)\]", t, re.S).group(1))) if re.search(r"addAll\(\s*\[([^\]]*)\]", t, re.S) else 0
        if n_pre > 60: out.append(_f("PWA-SW-PRECACHE-LARGE", f"Service worker precaches {n_pre} URLs at install (slow first visit, storage heavy)", "pwa-sw", "performance", "low", rel, _line_of(t, r"addAll"), "", "Precache only the app shell; cache the rest at runtime with expiration", 30))
        if uses_cache and fetch_h and level == "strict" and not re.search(r"ExpirationPlugin|maxEntries|maxAgeSeconds|expiration|trim|keys\(\)\.then[^;]*length", t):
            out.append(_f("PWA-SW-UNBOUNDED-CACHE", "Runtime cache has no size/age limit", "pwa-sw", "performance", "medium", rel, 1, "no maxEntries / maxAgeSeconds / trim", "Add Workbox ExpirationPlugin (maxEntries, maxAgeSeconds) or trim manually", 25))
        if level == "strict" and fetch_h and not re.search(r"navigationPreload|NavigationPreload", t):
            out.append(_f("PWA-SW-NAV-PRELOAD", "navigationPreload is not enabled (service-worker boot delays navigations)", "pwa-sw", "performance", "low", rel, 1, "", "Call self.registration.navigationPreload.enable() in activate and use event.preloadResponse", 15))
        sw_info.append(dict(path=rel, fetch=fetch_h, caches=uses_cache))
    # client-side checks
    ctext = "\n".join(all_txt.values())
    update_flow = bool(re.search(r"updatefound|controllerchange|onNeedRefresh|waiting\b|registration\.update|workbox-window|registerType\s*:\s*[\"']prompt", ctext))
    if (sw_files or registered or has_plugin) and not update_flow and level != "basic":
        out.append(_f("PWA-NO-UPDATE-FLOW", "No update flow: users can stay on an old version indefinitely", "pwa-ux", "code_smell", S(None, "low", "medium"), (registered[0][0] if registered else sw_files[0][0] if sw_files else "."), 1, "no updatefound / controllerchange / onNeedRefresh handling", "Show an 'Update available - reload' prompt when a new worker is waiting", 40))
    if level == "strict" and (manifests or sw_files) and not re.search(r"beforeinstallprompt", ctext):
        out.append(_f("PWA-NO-INSTALL-PROMPT", "No custom install prompt (beforeinstallprompt) - install rate depends on the browser's mini-infobar", "pwa-ux", "code_smell", "low", ".", 1, "", "Capture beforeinstallprompt and offer an Install button", 30))
    m = re.search(r"(Notification\.requestPermission\s*\(|pushManager\.subscribe\s*\()", ctext)
    if m:
        for r, t in all_txt.items():
            mm = re.search(r"Notification\.requestPermission\s*\(|pushManager\.subscribe\s*\(", t)
            if mm:
                before = t[max(0, mm.start() - 900):mm.start()]
                if not re.search(r"click|onClick|onclick|press|tap|button|submit|gesture", before, re.I):
                    out.append(_f("PWA-PUSH-PROMPT-ON-LOAD", "Notification permission is requested without a user gesture (browsers punish this and users deny it)", "pwa-ux", "code_smell", S("low", "medium", "medium"), r, t[:mm.start()].count("\n") + 1, mm.group(0), "Ask after a click, explain the benefit first and show an in-app pre-prompt", 20))
                break
    for r, t in all_txt.items():
        mm = re.search(r"setVapidDetails\s*\([^)]*[\"'][A-Za-z0-9_-]{40,}[\"']|VAPID_PRIVATE_KEY\s*[:=]\s*[\"'][A-Za-z0-9_-]{30,}[\"']|vapid[_-]?private[^\n]{0,20}[:=]\s*[\"'][A-Za-z0-9_-]{30,}[\"']", t, re.I)
        if mm:
            out.append(_f("PWA-VAPID-PRIVATE", "VAPID private key hard-coded in source", "pwa-security", "vulnerability", "high", r, t[:mm.start()].count("\n") + 1, "VAPID private key literal (redacted)", "Rotate the VAPID key pair; load the private key from the environment/secret manager (public key only on the client)", 30, cwe=["CWE-798"], owasp=["A02:2021", "A07:2021"])); break
    # HTML head checks
    if pages and (manifests or sw_files):
        head = "\n".join(page_txt.values())
        if not re.search(r"<meta[^>]+name=[\"']viewport[\"']", head, re.I) and not re.search(r"viewport", head, re.I):
            out.append(_f("PWA-NO-VIEWPORT", "No viewport meta tag: the installed app renders as a zoomed-out desktop page on phones", "pwa-ux", "bug", S("low", "medium", "medium"), next(iter(page_txt)), 1, "", "Add <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">", 5))
        if not re.search(r"name=[\"']theme-color[\"']", head, re.I) and level != "basic":
            out.append(_f("PWA-NO-THEME-META", "No <meta name=\"theme-color\">: the browser toolbar keeps the default color", "pwa-ux", "code_smell", "low", next(iter(page_txt)), 1, "", "Add <meta name=\"theme-color\" content=\"#...\">", 5))
        if not re.search(r"apple-touch-icon", head, re.I) and level != "basic":
            out.append(_f("PWA-NO-APPLE-ICON", "No apple-touch-icon: iOS 'Add to Home Screen' uses a screenshot as the icon", "pwa-ux", "code_smell", S(None, "low", "low"), next(iter(page_txt)), 1, "", "Add <link rel=\"apple-touch-icon\" href=\"/icons/180.png\"> (180x180)", 10))
        checks += [("Viewport meta", bool(re.search(r"viewport", head, re.I))), ("theme-color meta", bool(re.search(r"theme-color", head, re.I))), ("apple-touch-icon", bool(re.search(r"apple-touch-icon", head, re.I)))]
        if re.search(r"<link[^>]+rel=[\"'](manifest|apple-touch-icon)[\"'][^>]+href=[\"']http://", head, re.I) or re.search(r"serviceWorker\s*\.\s*register\(\s*[\"']http://", ctext):
            out.append(_f("PWA-HTTP-URL", "PWA assets / service worker referenced over plain http:// (service workers require HTTPS)", "pwa-security", "vulnerability", "high", next(iter(page_txt)), 1, "http:// URL for manifest/icon/service worker", "Serve everything over HTTPS and use relative or https URLs", 10, cwe=["CWE-319"], owasp=["A02:2021"]))
    # SW served from a sub-directory limits its scope
    for r, t in registered:
        mm = re.search(r"register\(\s*[\"'`](/?[^\"'`]*/[^\"'`/]+\.js)", t)
        if mm and not re.search(r"scope\s*:", t) and mm.group(1).count("/") >= 2 and not mm.group(1).startswith(("/sw", "/service")):
            out.append(_f("PWA-SW-SCOPE", f"Service worker is served from {mm.group(1)}: its scope is limited to that folder", "pwa-sw", "bug", S("low", "medium", "medium"), r, t[:mm.start()].count("\n") + 1, mm.group(0), "Serve the worker from the site root (/sw.js) or send the Service-Worker-Allowed header", 15)); break
    # sw.js caching headers
    cfg = [f for f in prod if os.path.basename(f[0]) in ("vercel.json", "netlify.toml", "_headers", "firebase.json", "nginx.conf", ".htaccess", "staticwebapp.config.json")]
    if sw_files and cfg and level != "basic":
        ctxt = "\n".join(_read(f[1], 100_000) for f in cfg)
        if not re.search(r"sw\.js|service-?worker", ctxt, re.I):
            out.append(_f("PWA-SW-HEADERS", "Server config does not set `Cache-Control: no-cache` for the service worker file (CDN may serve a stale worker)", "pwa-sw", "security_hotspot", None, cfg[0][0], 1, f"config files: {', '.join(f[0] for f in cfg[:3])}", "Add a rule: /sw.js -> Cache-Control: no-cache, max-age=0", 10, status="needs_validation", priority="low"))
    ok_n = sum(1 for _, ok in checks if ok)
    score = round(100 * ok_n / len(checks)) if checks else None
    sev_pen = {"critical": 25, "high": 12, "medium": 6, "low": 2, "info": 0}
    if score is not None: score = max(0, score - sum(sev_pen.get(f["severity"] or "", 0) for f in out if f["status"] == "confirmed") // 2)
    info.update(detected=ev, level=level, service_workers=sw_info, registered=bool(registered or has_plugin), checklist=[dict(item=a, ok=b) for a, b in checks], score=score, tooling=bool(has_plugin))
    return out, info


# ---------------- live check ----------------
def live(url, get):
    """Check a deployed site. `get(url)` -> dict(status, headers, body). -> (findings, info)"""
    out, info = [], {}
    u = urllib.parse.urlparse(url)
    if u.scheme != "https": out.append(_f("PWA-LIVE-NOT-HTTPS", "Site is not served over HTTPS: service workers and installs are disabled", "pwa-security", "vulnerability", "high", url, 1, u.scheme, "Serve the site over HTTPS (and redirect http -> https)", 30, cwe=["CWE-319"], owasp=["A02:2021"]))
    r = get(url)
    if r.get("status") != 200: return out, {"error": f"HTTP {r.get('status')}"}
    html = r["body"].decode("utf-8", "ignore") if isinstance(r["body"], bytes) else str(r["body"])
    m = re.search(r"<link[^>]+rel=[\"']manifest[\"'][^>]*href=[\"']([^\"']+)", html, re.I) or re.search(r"<link[^>]+href=[\"']([^\"']+)[\"'][^>]*rel=[\"']manifest[\"']", html, re.I)
    if not m:
        out.append(_f("PWA-LIVE-NO-MANIFEST", "Deployed page does not link a web app manifest", "pwa-manifest", "bug", "medium", url, 1, "", "Add <link rel=manifest> to the page head", 10)); return out, info
    murl = urllib.parse.urljoin(url, m.group(1)); mr = get(murl)
    info["manifest_url"] = murl
    if mr.get("status") != 200: out.append(_f("PWA-LIVE-MANIFEST-404", f"Manifest URL returns HTTP {mr.get('status')}", "pwa-manifest", "bug", "high", murl, 1, "", None, 10)); return out, info
    ct = (mr.get("headers") or {}).get("content-type", "")
    if "json" not in ct: out.append(_f("PWA-LIVE-MANIFEST-TYPE", f"Manifest served as `{ct or 'unknown'}` instead of application/manifest+json", "pwa-manifest", "code_smell", "low", murl, 1, ct, "Serve .webmanifest as application/manifest+json", 5))
    try: mj = json.loads(mr["body"].decode("utf-8", "ignore"))
    except ValueError:
        out.append(_f("PWA-LIVE-MANIFEST-INVALID", "Deployed manifest is not valid JSON", "pwa-manifest", "bug", "high", murl, 1, "", None, 10)); return out, info
    broken = []
    for ic in (mj.get("icons") or [])[:6]:
        iu = urllib.parse.urljoin(murl, ic.get("src", "")); ir = get(iu)
        if ir.get("status") != 200: broken.append(f"{ic.get('src')} -> {ir.get('status')}")
    if broken: out.append(_f("PWA-LIVE-ICON-404", "Manifest icons do not load", "pwa-manifest", "bug", "high", murl, 1, "; ".join(broken)[:300], "Fix the icon paths (they resolve relative to the manifest URL)", 10))
    sm = re.search(r"serviceWorker\s*\.\s*register\(\s*[\"'`]([^\"'`]+)", html)
    swu = urllib.parse.urljoin(url, sm.group(1)) if sm else urllib.parse.urljoin(url, "/sw.js")
    sr = get(swu)
    info["service_worker_url"] = swu if sr.get("status") == 200 else None
    if sr.get("status") == 200:
        h = sr.get("headers") or {}; cc = h.get("cache-control", ""); jt = h.get("content-type", "")
        if "javascript" not in jt and jt: out.append(_f("PWA-LIVE-SW-TYPE", f"Service worker served as `{jt}` (must be a JavaScript MIME type)", "pwa-sw", "bug", "high", swu, 1, jt, None, 5))
        mx = re.search(r"max-age=(\d+)", cc)
        if mx and int(mx.group(1)) > 86400: out.append(_f("PWA-LIVE-SW-CACHED", f"Service worker is cached for {mx.group(1)}s ({cc}); updates will be delayed", "pwa-sw", "bug", "medium", swu, 1, cc, "Serve the worker with Cache-Control: no-cache", 10))
    elif sm: out.append(_f("PWA-LIVE-SW-404", f"The registered service worker URL returns HTTP {sr.get('status')}", "pwa-sw", "bug", "high", swu, 1, "", None, 10))
    return out, info
