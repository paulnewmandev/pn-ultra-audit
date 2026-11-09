"""Vercel audit: static (vercel.json, next.config, API routes, crons, env names), live (headers, source maps, exposed files) and optional
project-settings audit through the read-only Vercel REST API (VERCEL_TOKEN from the environment; only names/types/settings are read, never secret values).
Vercel is serverless: there is no server to SSH into, so the configuration is the attack surface."""
import json, os, re, urllib.error, urllib.parse, urllib.request

from .kb import KB

SECRET_WORD = re.compile(r"(SECRET|PRIVATE|PASSWORD|PASSWD|TOKEN|CREDENTIAL|SERVICE_ROLE|SIGNING|WEBHOOK_SECRET)", re.I)
KEY_END = re.compile(r"(^|_)(API_?KEY|ACCESS_?KEY|AUTH_?KEY|SECRET_?KEY|ENCRYPTION_?KEY)$", re.I)
SAFE_PUBLIC = re.compile(r"(PUBLISHABLE|ANON|SITE_?KEY|CLIENT_?ID|MEASUREMENT|PUBLIC_?KEY|MAPS|ANALYTICS|RECAPTCHA|PROJECT_?ID|APP_?ID|DSN|SENTRY|POSTHOG|MIXPANEL|GA_|GTM|ALGOLIA_SEARCH|SEARCH_ONLY|TURNSTILE|HCAPTCHA|STRIPE_PK|PUBLIC_API_URL)", re.I)
PUBLIC_PREFIX = re.compile(r"^(NEXT_PUBLIC_|VITE_|REACT_APP_|PUBLIC_|EXPO_PUBLIC_|NUXT_PUBLIC_|GATSBY_|VUE_APP_|SVELTEKIT_PUBLIC_|REMIX_PUBLIC_)")
SEC_HEADERS = {"content-security-policy": "Content-Security-Policy", "x-content-type-options": "X-Content-Type-Options", "referrer-policy": "Referrer-Policy",
               "permissions-policy": "Permissions-Policy", "x-frame-options": "X-Frame-Options (or CSP frame-ancestors)", "strict-transport-security": "Strict-Transport-Security"}
NODE_EOL = {"14", "16", "18"}
AUTH_HINT = re.compile(r"getServerSession|getSession|auth\(\)|getAuth|currentUser|clerk|getToken|jwt\.verify|jwtVerify|verifyToken|verifyIdToken|supabase\.auth|createRouteHandlerClient|createServerClient|authorization|Authorization|CRON_SECRET|x-api-key|apiKey|session|cookies\(\)|withAuth|requireAuth|isAuthenticated|auth0|lucia|better-auth|next-auth|NextAuth|kinde|stytch|workos", re.I)
MUTATING = re.compile(r"export\s+(async\s+)?function\s+(POST|PUT|PATCH|DELETE)\b|export\s+const\s+(POST|PUT|PATCH|DELETE)\b|req(uest)?\.method\s*(===|==)\s*['\"](POST|PUT|PATCH|DELETE)['\"]|case\s+['\"](POST|PUT|PATCH|DELETE)['\"]")


def _f(rule, title, family, typ, sev, cat, file, line, ev, fix=None, effort=20, cwe=(), owasp=(), status="confirmed", priority=None):
    kb = KB[family]
    return dict(rule=rule, title=title, family=family, type=typ, severity=sev if status == "confirmed" else None, category=cat, file=file, line=line, evidence=(ev or "")[:400],
                impact=kb["impact"], fix=fix or "; ".join(kb["steps"][:2]), effort_min=effort, cwe=list(cwe), owasp=list(owasp), status=status, priority=priority, why=None)


def _read(ab, cap=300_000):
    try:
        with open(ab, encoding="utf-8", errors="ignore") as fh: return fh.read(cap)
    except OSError: return ""


def _line_of(text, pat):
    m = re.search(pat, text)
    return text[:m.start()].count("\n") + 1 if m else 1


def secret_like_public(name):
    """True when a browser-bundled variable name looks like a secret (not an obviously public key)."""
    if not PUBLIC_PREFIX.match(name or ""): return False
    rest = PUBLIC_PREFIX.sub("", name)
    if SAFE_PUBLIC.search(rest): return False
    return bool(SECRET_WORD.search(rest) or KEY_END.search(rest))


def detect(files, deps_text=""):
    rels = [f[0] for f in files]; ev = []
    if any(os.path.basename(r) in ("vercel.json", ".vercelignore", "now.json") for r in rels) or any(r.startswith(".vercel/") for r in rels): ev.append("vercel.json / .vercel")
    if re.search(r'"(vercel|@vercel/[\w-]+)"', deps_text or ""): ev.append("Vercel packages (@vercel/*)")
    if re.search(r"\bvercel\s+(deploy|--prod|pull|env)", deps_text or ""): ev.append("vercel CLI scripts")
    return ev


def _vj(text):
    try: return json.loads(text)
    except ValueError: return None


def _next_vulnerable(ver):
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", ver or "")
    if not m: return None
    a, b, c = (int(x) for x in m.groups())
    fixed = {12: (12, 3, 5), 13: (13, 5, 9), 14: (14, 2, 25), 15: (15, 2, 3)}
    if a in fixed: return (a, b, c) < fixed[a]
    return a < 12


def analyze(root, files, level="standard"):
    """-> (findings, info). Static review of a Vercel project."""
    out, info = [], {}
    prod = [f for f in files if "node_modules" not in f[0]]
    paths = {rel: ab for rel, ab, ext, sz in prod}
    pkg_txt = " ".join(_read(ab, 80_000) for rel, ab in paths.items() if os.path.basename(rel) == "package.json" and rel.count("/") <= 3)
    ev = detect(files, pkg_txt)
    if not ev: return [], {}
    info["detected"] = ev
    vj_path = next((r for r in paths if os.path.basename(r) == "vercel.json" and r.count("/") <= 2), None)
    vj_txt = _read(paths[vj_path]) if vj_path else ""
    vj = _vj(vj_txt) if vj_txt else None
    nc_path = next((r for r in paths if re.match(r"(^|.*/)next\.config\.(js|mjs|cjs|ts)$", r) and r.count("/") <= 2), None)
    nc = _read(paths[nc_path]) if nc_path else ""
    info.update(vercel_json=bool(vj_path), next_config=bool(nc_path), framework="next" if (nc_path or re.search(r'"next"\s*:', pkg_txt)) else None)

    # --- vercel.json
    if vj_path and vj is None: out.append(_f("VERCEL-JSON-INVALID", "vercel.json is not valid JSON (Vercel ignores or rejects it)", "vercel-config", "bug", "medium", "config", vj_path, 1, vj_txt[:100], "Fix the JSON syntax (no comments/trailing commas)", 10))
    if isinstance(vj, dict):
        if vj.get("public") is True: out.append(_f("VERCEL-PUBLIC-SOURCE", "vercel.json sets `public: true` (source files are served at /_src)", "vercel-config", "vulnerability", "high", "exposure", vj_path, _line_of(vj_txt, r'"public"'), '"public": true', "Remove it", 5, cwe=["CWE-540"], owasp=["A05:2021"]))
        envs = {}
        for k in ("env", "build"):
            sec = vj.get(k)
            if k == "build" and isinstance(sec, dict): sec = sec.get("env")
            if isinstance(sec, dict): envs.update(sec)
        lits = [n for n, v in envs.items() if isinstance(v, str) and not v.startswith("@") and (SECRET_WORD.search(n) or KEY_END.search(n)) and len(v) >= 6]
        if lits: out.append(_f("VERCEL-SECRET-IN-CONFIG", f"vercel.json contains literal secret value(s): {', '.join(lits[:4])}", "vercel-config", "vulnerability", "high", "secrets", vj_path, _line_of(vj_txt, re.escape(lits[0])), "names only; values not copied", "Remove them from the file, rotate the secrets and define them in Project > Settings > Environment Variables (Sensitive)", 25, cwe=["CWE-798"], owasp=["A07:2021"]))
        hdr_keys = {str(h.get("key", "")).lower() for blk in (vj.get("headers") or []) if isinstance(blk, dict) for h in (blk.get("headers") or []) if isinstance(h, dict)}
        nc_hdr = {m.lower() for m in re.findall(r"key\s*:\s*['\"]([\w-]+)['\"]", nc)} if re.search(r"headers\s*\(", nc) else set()
        have = hdr_keys | nc_hdr
        if info["framework"] or paths and any(r.endswith((".html", ".tsx", ".jsx", ".vue", ".svelte")) for r in paths):
            missing = [label for k, label in SEC_HEADERS.items() if k not in have and not (k == "x-frame-options" and "content-security-policy" in have and "frame-ancestors" in nc + vj_txt)]
            need = missing if level != "basic" else [m for m in missing if m.startswith(("Content-Security", "X-Content-Type"))]
            if len(need) >= (2 if level == "basic" else 3):
                out.append(_f("VERCEL-NO-SEC-HEADERS", f"No browser security headers configured ({len(need)} missing: {', '.join(need[:5])})", "vercel-config", "code_smell", "medium" if level == "strict" else "low", "hardening", vj_path or nc_path or ".", 1,
                              "headers in vercel.json / next.config: " + (", ".join(sorted(have)) or "none"), "Add them via `headers` in vercel.json or `headers()` in next.config", 20, cwe=["CWE-693", "CWE-1021"], owasp=["A05:2021"]))
        for blk in (vj.get("redirects") or []) + (vj.get("rewrites") or []):
            if isinstance(blk, dict) and re.match(r"https?://", str(blk.get("destination", ""))) and re.search(r":\w+\*?", str(blk.get("destination", ""))):
                out.append(_f("VERCEL-REDIRECT-EXTERNAL", "redirect/rewrite forwards path parameters to an external host", "vercel-config", "security_hotspot", None, "config", vj_path, _line_of(vj_txt, re.escape(str(blk.get("destination", ""))[:20])), f"{blk.get('source')} -> {blk.get('destination')}",
                              "Pin the destination host; never build external URLs from user-controlled path segments (open redirect / SSRF proxy)", 15, status="needs_validation", priority="medium", cwe=["CWE-601"], owasp=["A01:2021"])); break
        crons = [c for c in (vj.get("crons") or []) if isinstance(c, dict) and c.get("path")]
        unprot, unknown = [], []
        for c in crons:
            pth = c["path"].split("?")[0].strip("/")
            cands = [f"app/{pth}/route.ts", f"app/{pth}/route.js", f"src/app/{pth}/route.ts", f"src/app/{pth}/route.js", f"pages/{pth}.ts", f"pages/{pth}.js", f"src/pages/{pth}.ts", f"{pth}.ts", f"{pth}.js", f"{pth}/index.ts", f"{pth}/index.js"]
            hit = next((x for x in cands if x in paths), None)
            if not hit: unknown.append(c["path"]); continue
            if not re.search(r"CRON_SECRET|authorization|Authorization|x-vercel-signature|verifySignature", _read(paths[hit])): unprot.append((c["path"], hit))
        if unprot: out.append(_f("VERCEL-CRON-UNPROTECTED", f"{len(unprot)} cron endpoint(s) do not verify CRON_SECRET: anyone can trigger them", "vercel-config", "vulnerability", "high", "authn", unprot[0][1], 1, "; ".join(p for p, _ in unprot[:5]),
                                    "Check `Authorization: Bearer ${CRON_SECRET}` at the top of the handler (Vercel sends it automatically when CRON_SECRET is set)", 15, cwe=["CWE-306", "CWE-862"], owasp=["A01:2021", "API2:2023"]))
        elif unknown: out.append(_f("VERCEL-CRON-ROUTE-NOT-FOUND", f"cron path(s) {', '.join(unknown[:3])} have no matching route file to review", "vercel-config", "security_hotspot", None, "authn", vj_path, 1, ", ".join(unknown[:5]), "Make sure those endpoints verify CRON_SECRET", 10, status="needs_validation", priority="low", cwe=["CWE-306"]))
        fn = vj.get("functions") or {}
        if isinstance(fn, dict) and any(isinstance(v, dict) and (int(v.get("maxDuration", 0) or 0) > 300 or int(v.get("memory", 0) or 0) >= 3008) for v in fn.values()):
            out.append(_f("VERCEL-FUNC-LIMITS", "Serverless function limits are set very high (cost / DoS amplification)", "vercel-config", "code_smell", "low", "reliability", vj_path, _line_of(vj_txt, r'"maxDuration"|"memory"'), "maxDuration > 300s or memory 3008MB", "Lower maxDuration/memory and add rate limiting", 15, cwe=["CWE-770"], owasp=["API4:2023"]))
    # --- next.config
    if nc:
        if re.search(r"ignoreBuildErrors\s*:\s*true", nc): out.append(_f("VERCEL-TS-IGNORE", "next.config ignores TypeScript build errors", "vercel-config", "code_smell", "medium", "quality", nc_path, _line_of(nc, r"ignoreBuildErrors"), "typescript.ignoreBuildErrors: true", "Remove it and fix the type errors", 60, cwe=["CWE-1164"]))
        if re.search(r"ignoreDuringBuilds\s*:\s*true", nc) and level != "basic": out.append(_f("VERCEL-ESLINT-IGNORE", "next.config skips ESLint during builds", "vercel-config", "code_smell", "low", "quality", nc_path, _line_of(nc, r"ignoreDuringBuilds"), "eslint.ignoreDuringBuilds: true", "Remove it and run lint in CI", 30))
        if re.search(r"productionBrowserSourceMaps\s*:\s*true", nc): out.append(_f("VERCEL-SOURCEMAPS", "Production browser source maps are enabled (your source code is downloadable)", "vercel-config", "vulnerability", "medium", "exposure", nc_path, _line_of(nc, r"productionBrowserSourceMaps"), "productionBrowserSourceMaps: true", "Remove it, or upload maps privately to your error tracker (Sentry) instead of serving them", 10, cwe=["CWE-540"], owasp=["A05:2021"]))
        if re.search(r"hostname\s*:\s*['\"]\*\*?['\"]|domains\s*:\s*\[[^\]]*\*", nc): out.append(_f("VERCEL-IMAGES-WILDCARD", "next/image accepts images from any host (open image proxy / bandwidth abuse)", "vercel-config", "vulnerability", "medium", "exposure", nc_path, _line_of(nc, r"hostname|domains"), "images.remotePatterns hostname '**'", "List only the hosts you control", 10, cwe=["CWE-918", "CWE-770"], owasp=["A10:2021"]))
        if not re.search(r"poweredByHeader\s*:\s*false", nc) and level == "strict": out.append(_f("VERCEL-POWERED-BY", "X-Powered-By: Next.js header is not disabled", "vercel-config", "code_smell", "info", "hardening", nc_path, 1, "poweredByHeader not false", "Set `poweredByHeader: false`", 5, cwe=["CWE-200"]))
    # --- Next.js version (CVE-2025-29927 middleware authorization bypass)
    nv = re.search(r'"next"\s*:\s*"[\^~]?([\d.]+)', pkg_txt)
    mw = next((r for r in paths if re.match(r"(^|src/)middleware\.(ts|js)$", r)), None)
    if nv and _next_vulnerable(nv.group(1)):
        out.append(_f("VERCEL-NEXT-VULNERABLE", f"Next.js {nv.group(1)} is affected by CVE-2025-29927 (middleware authorization bypass via x-middleware-subrequest)" + ("; middleware.ts is present" if mw else ""), "vercel-config", "vulnerability", "high" if mw else "medium", "dependencies", mw or "package.json", 1,
                      f"next {nv.group(1)}; fixed in 12.3.5 / 13.5.9 / 14.2.25 / 15.2.3", "Upgrade Next.js to a patched release and re-check auth inside route handlers, not only in middleware", 30, cwe=["CWE-285", "CWE-863"], owasp=["A01:2021", "A06:2021"]))
    if mw:
        mt = _read(paths[mw])
        if AUTH_HINT.search(mt) and re.search(r"matcher\s*:\s*\[?[^\]\n]*\(\?!\s*api", mt): out.append(_f("VERCEL-MIDDLEWARE-API-GAP", "middleware authenticates pages but its matcher excludes /api: API routes are not covered", "vercel-config", "security_hotspot", None, "authz", mw, _line_of(mt, r"matcher"), "matcher excludes api", "Authenticate inside each API route (or include /api in the matcher)", 20, status="needs_validation", priority="medium", cwe=["CWE-862"], owasp=["A01:2021", "API5:2023"]))
    en = re.search(r'"node"\s*:\s*"[\^~>=\s]*(\d+)', pkg_txt)
    if en and en.group(1) in NODE_EOL and level != "basic": out.append(_f("VERCEL-NODE-EOL", f"package.json pins Node.js {en.group(1)} (end-of-life)", "vercel-config", "vulnerability", "medium", "dependencies", "package.json", 1, f"engines.node {en.group(1)}", "Use Node 20 or 22 (and set it in Project Settings)", 20, cwe=["CWE-1104"], owasp=["A06:2021"]))
    # --- public env names (examples, vercel.json env, source usage)
    names = {}
    for rel, ab in paths.items():
        b = os.path.basename(rel)
        if b.startswith(".env") or rel.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".vue", ".svelte")) or b in ("vercel.json",):
            t = _read(ab, 120_000)
            for m in re.finditer(r"\b((NEXT_PUBLIC|VITE|REACT_APP|PUBLIC|EXPO_PUBLIC|NUXT_PUBLIC|GATSBY|VUE_APP)_[A-Z0-9_]+)\b", t):
                if secret_like_public(m.group(1)): names.setdefault(m.group(1), (rel, t[:m.start()].count("\n") + 1))
    for n, (rel, ln) in list(names.items())[:6]:
        out.append(_f("VERCEL-PUBLIC-SECRET", f"`{n}` is bundled into the browser but its name says it is a secret", "vercel-config", "vulnerability", "high", "secrets", rel, ln, f"{n} (value not copied)",
                      "Rename it without the public prefix, keep it server-side, read it only in API routes/server code and rotate the value", 30, cwe=["CWE-200", "CWE-798"], owasp=["A02:2021", "A05:2021"]))
    # --- API routes without auth
    routes = [r for r in paths if re.match(r"^(src/)?(app/.+/route|pages/api/.+|api/[^/]+)\.(ts|js|tsx|jsx|mjs)$", r)]
    noauth = []
    for r in routes[:300]:
        t = _read(paths[r], 100_000)
        if MUTATING.search(t) and not AUTH_HINT.search(t): noauth.append(r)
    if noauth:
        crit = [r for r in noauth if re.search(r"admin|delete|internal|user|payment|checkout|upload|secret|token|billing|webhook", r, re.I)]
        out.append(_f("VERCEL-API-NO-AUTH", f"{len(noauth)} API route(s) accept writes without any visible authentication", "vercel-config", "security_hotspot", None, "authz", (crit or noauth)[0], 1, "; ".join((crit or noauth)[:6]),
                      "Authenticate and authorise inside every mutating route (session/JWT/API key); rate-limit them; webhooks must verify the provider signature", 40, status="needs_validation", priority="high" if crit else "medium", cwe=["CWE-306", "CWE-862"], owasp=["A01:2021", "API2:2023"]))
    # --- committed Vercel artefacts
    gi = _read(os.path.join(root, ".gitignore"))
    vtracked = [r for r in paths if r.startswith(".vercel/")]
    if vtracked:
        pulled = [r for r in vtracked if re.search(r"\.env", r)]
        if pulled: out.append(_f("VERCEL-ENV-PULLED", f"`vercel env pull` output is committed: {pulled[0]}", "vercel-config", "vulnerability", "high", "secrets", pulled[0], 1, ", ".join(pulled[:4]), "Delete it from git and history, rotate every variable it contained and ignore `.vercel`", 45, cwe=["CWE-540", "CWE-798"], owasp=["A02:2021"]))
        elif ".vercel" not in gi: out.append(_f("VERCEL-DIR-TRACKED", ".vercel/ (orgId, projectId) is committed instead of ignored", "vercel-config", "code_smell", "low", "hygiene", vtracked[0], 1, ", ".join(vtracked[:3]), "Add `.vercel` to .gitignore and untrack it (`git rm -r --cached .vercel`)", 5, cwe=["CWE-200"]))
    return out, info


# ---------------------------------------------------------------- live
def live(url, get, authorized_probes=True):
    """Passive checks of a deployed site served by Vercel. `get(url)` -> dict(status, headers(lowercase), body)."""
    out, info = [], {}
    r = get(url)
    h = r.get("headers") or {}
    if r.get("status") not in (200, 301, 302, 307, 308, 401, 403) and not h: return [], {"error": f"HTTP {r.get('status')}"}
    on_vercel = "vercel" in (h.get("server", "") or "").lower() or "x-vercel-id" in h or "x-vercel-cache" in h
    info["on_vercel"] = on_vercel
    if not on_vercel: return [], info
    info.update(region=(h.get("x-vercel-id", "") or "").split("::")[0], cache=h.get("x-vercel-cache"))
    missing = [label for k, label in SEC_HEADERS.items() if k not in h and not (k == "x-frame-options" and "frame-ancestors" in h.get("content-security-policy", ""))]
    if len(missing) >= 3: out.append(_f("VERCEL-LIVE-HEADERS", f"Deployed site lacks {len(missing)} browser security headers: {', '.join(missing[:5])}", "vercel-config", "code_smell", "low", "hardening", url, 1, "missing: " + ", ".join(missing), "Add them via vercel.json `headers` or next.config `headers()`", 20, cwe=["CWE-693"], owasp=["A05:2021"]))
    if "next" in (h.get("x-powered-by", "") or "").lower(): out.append(_f("VERCEL-LIVE-POWERED-BY", "X-Powered-By: Next.js is exposed", "vercel-config", "code_smell", "info", "hardening", url, 1, h.get("x-powered-by", ""), "Set poweredByHeader: false", 5, cwe=["CWE-200"]))
    body = r.get("body", b"")
    html = body.decode("utf-8", "ignore") if isinstance(body, bytes) else str(body)
    m = re.search(r"(/_next/static/[^\"'\s>]+?\.js)", html)
    if m and authorized_probes:
        sm = get(urllib.parse.urljoin(url, m.group(1) + ".map"))
        if sm.get("status") == 200 and b"\"mappings\"" in (sm.get("body", b"") if isinstance(sm.get("body", b""), bytes) else b""): out.append(_f("VERCEL-LIVE-SOURCEMAPS", "Production source maps are publicly downloadable", "vercel-config", "vulnerability", "medium", "exposure", urllib.parse.urljoin(url, m.group(1) + ".map"), 1, "GET <chunk>.js.map -> 200 with mappings", "Disable productionBrowserSourceMaps (or upload maps privately to your error tracker)", 10, cwe=["CWE-540"], owasp=["A05:2021"]))
    if authorized_probes:
        for pth, needle, label in (("/.env", rb"[A-Z_]{3,}=", ".env file"), ("/.git/HEAD", rb"ref:\s*refs/", ".git directory")):
            pr = get(urllib.parse.urljoin(url, pth))
            b = pr.get("body", b"") if isinstance(pr.get("body", b""), bytes) else b""
            if pr.get("status") == 200 and re.search(needle, b[:2000]): out.append(_f("VERCEL-LIVE-EXPOSED-FILE", f"{label} is publicly served at {pth}", "vercel-config", "vulnerability", "critical", "exposure", urllib.parse.urljoin(url, pth), 1, f"GET {pth} -> 200", "Remove it from the public/ or build output directory, rotate anything it contained and redeploy", 30, cwe=["CWE-538", "CWE-540"], owasp=["A05:2021"]))
    return out, info


# ---------------------------------------------------------------- Vercel REST API (read-only)
def api_audit(project, token, team=None, fetch=None):
    """Project settings and environment-variable METADATA through the Vercel API. -> (findings, info). `fetch(url, headers)` -> (status, dict) is injectable for tests."""
    out, info = [], {}
    def _fetch(u, hdr):
        req = urllib.request.Request(u, headers=hdr)
        try:
            with urllib.request.urlopen(req, timeout=20) as r: return r.status, json.loads(r.read().decode("utf-8", "ignore"))
        except urllib.error.HTTPError as e:
            try: return e.code, json.loads(e.read().decode("utf-8", "ignore"))
            except Exception: return e.code, {}
        except (urllib.error.URLError, OSError, ValueError) as e: return 0, {"error": str(e)[:80]}
    fetch = fetch or _fetch
    q = f"?teamId={urllib.parse.quote(team)}" if team else ""
    hdr = {"Authorization": "Bearer " + token, "User-Agent": "pn-ultra-audit"}
    st, p = fetch(f"https://api.vercel.com/v9/projects/{urllib.parse.quote(project)}{q}", hdr)
    if st != 200: return [], {"error": f"Vercel API HTTP {st}: " + str((p.get("error") or {}).get("message", p.get("error", "")))[:80] if isinstance(p, dict) else f"HTTP {st}"}
    label = f"vercel:{project}"
    info.update(project=p.get("name"), framework=p.get("framework"), node=p.get("nodeVersion"))
    if not p.get("ssoProtection") and not p.get("passwordProtection"):
        out.append(_f("VERCEL-API-NO-DEPLOY-PROTECTION", "Preview deployments are publicly accessible (no Vercel Authentication / password protection)", "vercel-platform", "vulnerability", "medium", "authn", label, 1, "ssoProtection: none; passwordProtection: none",
                      "Project > Settings > Deployment Protection > enable Vercel Authentication (or Password Protection) for Preview deployments", 10, cwe=["CWE-306", "CWE-200"], owasp=["A01:2021", "A05:2021"]))
    if p.get("publicSource") is True: out.append(_f("VERCEL-API-PUBLIC-SOURCE", "Project source code is public (`publicSource`)", "vercel-platform", "vulnerability", "high", "exposure", label, 1, "publicSource: true", "Settings > General > turn off Source Code visibility", 5, cwe=["CWE-540"], owasp=["A05:2021"]))
    if p.get("gitForkProtection") is False: out.append(_f("VERCEL-API-FORK-PROTECTION", "Git Fork Protection is disabled (fork PR builds can read env vars)", "vercel-platform", "vulnerability", "medium", "cicd", label, 1, "gitForkProtection: false", "Settings > Git > enable Git Fork Protection", 5, cwe=["CWE-829"], owasp=["A08:2021"]))
    if p.get("directoryListing") is True: out.append(_f("VERCEL-API-DIR-LISTING", "Directory listing is enabled", "vercel-platform", "vulnerability", "medium", "exposure", label, 1, "directoryListing: true", "Turn it off in project settings", 5, cwe=["CWE-548"], owasp=["A05:2021"]))
    nv = str(p.get("nodeVersion", "")).split(".")[0]
    if nv in NODE_EOL: out.append(_f("VERCEL-API-NODE-EOL", f"Project runs Node.js {p.get('nodeVersion')} (end-of-life)", "vercel-platform", "vulnerability", "medium", "dependencies", label, 1, f"nodeVersion {p.get('nodeVersion')}", "Settings > General > Node.js Version: pick 20.x or 22.x", 10, cwe=["CWE-1104"], owasp=["A06:2021"]))
    st, e = fetch(f"https://api.vercel.com/v10/projects/{urllib.parse.quote(project)}/env{q}{'&' if q else '?'}decrypt=false", hdr)
    envs = e.get("envs", []) if st == 200 and isinstance(e, dict) else []
    info["env_vars"] = len(envs)
    plain, pubsec, wide = [], [], []
    for v in envs:
        k, typ, tg = v.get("key", ""), v.get("type", ""), v.get("target") or []
        if isinstance(tg, str): tg = [tg]
        if secret_like_public(k): pubsec.append(k)
        elif (SECRET_WORD.search(k) or KEY_END.search(k)) and typ in ("plain", "encrypted") and not PUBLIC_PREFIX.match(k): plain.append(k)
        if (SECRET_WORD.search(k) or KEY_END.search(k)) and len(set(tg) & {"production", "preview", "development"}) == 3 and not PUBLIC_PREFIX.match(k): wide.append(k)
    if pubsec: out.append(_f("VERCEL-API-PUBLIC-ENV-SECRET", f"{len(pubsec)} public-prefixed variable(s) look like secrets: {', '.join(pubsec[:5])}", "vercel-platform", "vulnerability", "high", "secrets", label, 1, "names only: " + ", ".join(pubsec[:8]), "Rename without NEXT_PUBLIC_/VITE_ etc., keep server-only and rotate the values", 30, cwe=["CWE-200", "CWE-798"], owasp=["A02:2021"]))
    if plain: out.append(_f("VERCEL-API-PLAIN-SECRETS", f"{len(plain)} secret-like variable(s) are not stored as Sensitive: {', '.join(plain[:5])}", "vercel-platform", "code_smell", "medium", "secrets", label, 1, "names only: " + ", ".join(plain[:8]), "Recreate them as Sensitive environment variables (write-only) and rotate", 20, cwe=["CWE-522"], owasp=["A02:2021"]))
    if wide: out.append(_f("VERCEL-API-ENV-ALL-TARGETS", f"{len(wide)} secret(s) are exposed to Production, Preview AND Development: {', '.join(wide[:4])}", "vercel-platform", "security_hotspot", None, "secrets", label, 1, "names only", "Scope production secrets to Production only; use separate lower-privilege values for Preview/Development", 20, status="needs_validation", priority="medium", cwe=["CWE-250"], owasp=["A05:2021"]))
    return out, info
