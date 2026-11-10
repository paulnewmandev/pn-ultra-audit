"""Hardcode & TODO auditor (read-only, offline, stdlib).
 * TODO / FIXME / HACK / XXX / BUG markers (only inside real comments), security TODOs, "remove before prod" markers, stale markers (git blame age),
   unimplemented stubs, plus a ready-to-paste backlog (`todo-backlog.md`).
 * Hardcoded values that belong in configuration: environment URLs at call sites, IP addresses as hosts, machine-specific paths, personal emails,
   identity checks (user.id == 1) and business rates inside functions. Hardcoded SECRETS are the SAST scanner's job (SEC-*) and are shown together in the dashboard.
Precision rules: comments/docstrings are masked for value rules, tests/docs/examples/fixtures/vendor/generated files are skipped, dev defaults via env/`||`/`??` are fine."""
import os, re, subprocess, time
from .aitrace import _comment_part
from .kb import KB
from .lex import mask_noncode
from .malware import SKIP_DIR, TESTY

CODE_EXT = {"py", "pyw", "js", "jsx", "mjs", "cjs", "ts", "tsx", "vue", "svelte", "php", "phtml", "java", "kt", "kts", "scala", "groovy", "go", "rb", "erb", "cs", "dart", "swift", "m", "mm", "rs", "c", "h", "cpp", "cc", "hpp", "lua", "pl", "sh", "bash", "ps1", "sql", "ex", "exs", "r", "sol", "css", "scss", "less", "html", "htm"}
VALUE_EXT = CODE_EXT - {"css", "scss", "less", "html", "htm", "sql", "sh", "bash", "ps1", "m", "mm"}
TESTISH = re.compile(r"(?i)(^|/)([\w.-]*tests?[\w.-]*|specs?|__tests__|e2e|fixtures?|mocks?)(/|$)|(^|/)(test_[^/]+|[^/]+_tests?|[^/]+\.(?:test|spec))\.\w+$")
GEN = re.compile(r"(^|/)(_sysconfigdata[\w.-]*|config-[\d.]+[\w-]*|bundles?|dist|build|out|\.next|\.nuxt|coverage|target|generated|__generated__|gen)(/|$)|\.min\.|\.bundle\.|\.d\.ts$|\.generated\.|-[A-Za-z0-9]{8}\.(?:m?js|css)$|_pb2|\.pb\.go$|\.designer\.cs$", re.I)
DEVFILE = re.compile(r"(^|/)(vite|webpack|rollup|esbuild|next|nuxt|astro|svelte|jest|vitest|cypress|playwright|karma|protractor|wdio|storybook|gulpfile|gruntfile|setup|conftest|manage|fabfile|tasks|dev[-_.]server)\b|(^|/)(\.storybook|scripts?|tools?|dev|local|e2e|mocks?|stubs?|seeds?|migrations?|benchmarks?|playground|sandbox)/", re.I)

MARK = re.compile(r"\b(TODO|FIXME|HACK|XXX|BUG|KLUDGE|WORKAROUND)\b(?:\(([^)]{0,40})\))?\s*[:\-]?\s*(.*)")
SECURITY = re.compile(r"(?i)\b(?:auth(?!-)|authenticat\w*|authoriz\w*|authn|authz|permissions?|access control|sanitiz\w*|csrf|xss|sql ?injection|injection|rate.?limit\w*|throttl\w*|encrypt\w*|decrypt\w*|passwords?|credentials?|cors|tls|ssl|https|2fa|mfa|pii|vulnerab\w*|insecure|security|input validation|validate (?:the )?(?:user )?input|validate (?:user|request|params?)|check (?:the )?(?:user|role|permission|owner)\w*|verify (?:the )?(?:user|signature|token|owner)\w*)\b")
BLOCKER_STRONG = re.compile(r"(?i)\bremove (?:this |it |me )?before\b|\bbefore (?:prod|production|release|deploy(?:ing|ment)?|launch|shipping|go-?live|merge|merging)\b|\bdo not (?:ship|merge|commit|deploy|push)\b|\bremove me\b|\bhard-?coded for now\b")
BLOCKER_WEAK = re.compile(r"(?i)\b(?:debug|testing|dev(?:elopment)?) only\b|\bfor (?:debug|debugging|testing|dev) only\b|\btemp(?:orary)? (?:hack|fix|workaround|code|bypass)\b|\bskip(?:ping)? (?:auth\w*|validation|verification|security|csrf|ssl|tls|signature|permissions?)\b|\bbypass(?:ing)? (?:auth\w*|validation|verification|security|csrf|ssl|tls|signature|permissions?)\b|\bdisable[d]? (?:auth\w*|validation|security|csrf|ssl|tls|signature)\b")
BLOCKER_CTX = re.compile(r"(?i)\b(?:TODO|FIXME|HACK|XXX|TEMP)\b|\bfor now\b|\bremove\b|\bdelete\b|\buntil\b|\brevert\b|\bundo\b")
ACTION = re.compile(r"(?i)\b(?:add|implement|need|needs|needed|missing|enforce|require|should|must|handle|enable|restrict|protect|proper|properly|support|validate|sanitize|secure|safer|harden|fix|check|verify|forgot|still)\b")
URLS = re.compile(r"https?://\S+")
EXCL_DEFAULT = re.compile(r"process\.env|import\.meta\.env|os\.environ|getenv|environ\.get|\|\||\?\?|:-|\bdefault|fallback|config\.|settings\.|ENV\[|System\.getenv|\benv\(|Environment\.|BuildConfig|dotenv|\$\{")
URL_CALL = re.compile(r"(?i)(?:\b(?:fetch|axios(?:\.\w+)?|requests\.\w+|httpx\.\w+|aiohttp\.\w+|urllib\.request\.urlopen|urlopen|http\.(?:get|post|request)|https\.(?:get|post|request)|got(?:\.\w+)?|ky(?:\.\w+)?|superagent\.\w+|HttpClient\.\w+|RestTemplate\.\w+|WebClient\.\w+|curl_init|file_get_contents|http\.(?:Get|Post)|\$http\.\w+|\$\.(?:get|post|ajax)|new\s+URL)\s*\(\s*|\b(?:base_?url|baseurl|api_?url|apiurl|api_?base|backend_?url|server_?url|host_?url)\w*\s*[:=]\s*)[`\"']https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(?::\d+)?")
ENV_HOST = re.compile(r"[`\"'](https?://([A-Za-z0-9.-]+\.[a-z]{2,}))(?::\d+)?(?:/[^`\"'\s]*)?[`\"']")
ENV_WORD = re.compile(r"(?:^|[.-])(staging|stage|stg|uat|qa|preprod|pre-prod|dev|develop|development|test|testing|sandbox)(?:[.-]|$)")
VENDOR = re.compile(r"(?:paypal|stripe|braintree(?:gateway)?|authorize|plaid|apple|google(?:apis)?|amazonaws|azure|microsoft(?:online)?|twilio|sendgrid|mailgun|mailtrap|ngrok|example|w3|schema|github|npmjs|readthedocs|dev\.to|developer|developers|mozilla|jsdelivr|unpkg|cloudflare|googletagmanager|facebook|fb|instagram|linkedin|x|twitter|slack|discord|telegram|atlassian|jira|sentry|datadog|firebase|firebaseio|vercel|netlify|heroku|herokuapp|supabase|okta|auth0|adyen|klarna|square|shopify|paypalobjects|mercadopago|mercadolibre|openpay|culqi)\.", re.I)
IP_CFG = re.compile(r"(?i)(?:host|hostname|server|addr(?:ess)?|endpoint|url|uri|\bip\b|proxy|dsn|connection|jdbc|redis|mongo|mysql|postgres(?:ql)?|\bdb|broker|nameserver|gateway)\w*[\"']?\s*[:=]\s*[\"'`](?:[a-z][\w+.-]*://)?(?:[^@/\"'`\s]+@)?((?:\d{1,3}\.){3}\d{1,3})(?::\d+)?(?:[/\"'`?])")
IP_SKIP = re.compile(r"^(?:127\.|0\.|255\.|169\.254\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|10\.0\.2\.2$|8\.8\.[48]\.[48]$|1\.1\.1\.1$|1\.0\.0\.1$|9\.9\.9\.9$)")
ABS_PATH = re.compile(r"(?<![\w/.~-])/(?:Users|home)/(?!(?:linuxbrew|foo|bar|baz|john|jane|alice|bob|test|tester|testuser|sample|demo|example|home|runner|node|app|user|ubuntu|ec2-user|vagrant|circleci|www-data|appuser|jenkins|gitpod|vscode|codespace|build|builder|nonroot|deploy|docker|git|postgres|redis|mysql|travis|me|you|name|username|youruser|your-user|your_user|your_username|yourname|Shared|Guest|Library|<)[/\"'`]?)[A-Za-z][A-Za-z0-9._-]{1,30}/|(?<![\w])[A-Za-z]:\\{1,2}Users\\{1,2}(?!Public|Default|All Users|username|user|you|name)[A-Za-z0-9._ -]{2,30}\\{1,2}")
EMAIL = re.compile(r"[\"'`]([A-Za-z0-9._%+-]{3,})@(?:gmail|hotmail|outlook|yahoo|icloud|proton(?:mail)?|live|aol|msn|gmx|yandex|qq|163|zoho)\.(?:com|net|me|ch|es|co\.uk|cn|ru|de|fr|com\.br|com\.mx)[\"'`]", re.I)
EMAIL_SKIP = re.compile(r"(?i)^(?:test|example|user|name|email|noreply|no-reply|your|foo|bar|john|jane|someone|me|you|mail|info|hello|admin|sample|demo|username|first|last)")
ADMIN_ID = re.compile(r"(?i)(?:\b(?:if|when|unless|elif|case|assert|return)\b|&&|\|\||\bis_?admin\w*\s*[:=]|\bis_?super\w*\s*[:=]|\badmin\w*\s*[:=])[^\n;{}]{0,60}?\b(?:user_?id|userid|current_?user\.id|req\.user\.id|request\.user\.id|session\[['\"]user_?id['\"]\]|auth\(\)->id\(\)|user\.id|currentUser\.id)\s*(?:==|===|is)\s*[1-9]\d?\b")
ADMIN_NAME = re.compile(r"(?i)\b(?:email|username|user_?name|login)\w*\s*(?:==|===)\s*[\"'](?:admin|root|superuser|administrator)(?:@[\w.-]+)?[\"']")
RATE = re.compile(r"(?m)^[ \t]{4,}(?:const |let |var |final |val |double |float |decimal |auto )?([A-Za-z_]\w*)\s*(?::\s*\w+\s*)?[:=]\s*(?:0?\.\d{1,4}|\d{1,2}(?:\.\d+)?\s*/\s*100)\s*;?[ \t]*(?:(?:#|//).*)?$")
RATE_WORDS = {"tax", "vat", "iva", "commission", "fee", "fees", "discount", "markup", "interest", "margin", "surcharge"}
RATE_NAME_BAD = re.compile(r"(?i)url|_id\b|name|key|type|path|file|format|label|text|max|min|limit|count|enabled|flag|class|style|color|size")
STUB = re.compile(r"(?i)\btodo!\s*\(|\bunimplemented!\s*\(|(?<![\w.])TODO\s*\(\s*[\"']|throw\s+new\s+(?:Error|UnsupportedOperationException|NotImplementedError)\s*\(\s*[\"'](?:not (?:yet )?implemented|unimplemented|todo)|fatalError\(\s*[\"'](?:not (?:yet )?implemented|todo|unimplemented)|\bUnimplementedError\s*\(")

RULE_FIX = {
    "TODO-SECURITY": "Read the code: if the protection is really missing, implement it now (see the matching guide); if it exists elsewhere delete the stale TODO; if it must wait, ticket it with owner + date and add a compensating control.",
    "TODO-BLOCKER": "Remove the shortcut now, or gate it behind a flag that is OFF in production; add a CI check that rejects `remove before prod` / `debug only` markers.",
    "TODO-FIXME": "Treat FIXME/HACK/XXX/BUG as defects: schedule or fix them; give each an issue number (`FIXME(#123)`).",
    "TODO-STALE": "Triage the old markers in todo-backlog.md: do it, ticket it with an owner, or delete it.",
    "TODO-DEBT": "Open todo-backlog.md and triage every marker (do / ticket / delete); add a lint rule that requires an issue reference.",
    "HC-STUB": "Implement the function or remove the dead code and its callers; add a test that calls it.",
    "HC-URL-LOCAL": "Move the base URL to configuration (API_URL / BASE_URL) loaded at startup; keep the localhost default only for development.",
    "HC-URL-ENV": "Move the environment-specific URL to configuration (per-environment variable) instead of the code.",
    "HC-IP": "Use a DNS name from configuration (env var / secret manager); define a deliberate IP once, with a comment.",
    "HC-PATH": "Use a project-relative path (Path(__file__).parent / path.join(__dirname, ...)) or a configurable directory (DATA_DIR); never a personal home path.",
    "HC-EMAIL": "Move the address to configuration (ALERT_EMAIL) and use a team alias instead of a personal mailbox.",
    "HC-ADMIN-ID": "Replace the literal id/email check with a role or permission stored on the user; seed the admin through a migration or CLI.",
    "HC-RATE": "Move the rate to configuration or a per-country/date table read through one function; store the applied rate on each invoice/order.",
}


def _f(rule, title, family, sev, cat, file, line, ev, status="confirmed", priority=None, typ="code_smell", effort=10, cwe=()):
    kb = KB[family]
    return dict(rule=rule, title=title, family=family, type=typ, severity=sev if status == "confirmed" else None, category=cat, file=file, line=line, evidence=(ev or "").strip()[:260],
                impact=kb["impact"], fix=RULE_FIX.get(rule) or "; ".join(kb["steps"][:2]), effort_min=effort, cwe=list(cwe), owasp=[], status=status, priority=priority,
                why=("Heuristic: confirm it is not an intentional default or a documented exception." if status != "confirmed" else None))


def _blame_ages(root, rel, lines, budget_end):
    """{line_no: age_days} for the given 1-based lines using git blame (bounded)."""
    if time.time() > budget_end or not lines: return {}
    try:
        r = subprocess.run(["git", "-C", root, "blame", "--line-porcelain", "-w", "--", rel], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError): return {}
    if r.returncode != 0: return {}
    want, out, cur, now = set(lines), {}, 0, time.time()
    for ln in r.stdout.split("\n"):
        m = re.match(r"^[0-9a-f]{40} \d+ (\d+)", ln)
        if m: cur = int(m.group(1)); continue
        if ln.startswith("author-time ") and cur in want:
            try: out[cur] = int((now - int(ln.split()[1])) / 86400)
            except ValueError: pass
    return out


def analyze(root, files, level="standard"):
    """-> (findings, info). `files`: scanner list (rel, abs, ext, size)."""
    strict = level == "strict"
    out, seen, rule_total = [], {}, {}
    info = dict(scanned=0, todo_total=0, by_kind={}, stale=0, oldest_days=0, security=0, blockers=0, values={}, files_with_todo=[], todos=[], backlog_cut=False)
    is_git = os.path.isdir(os.path.join(root, ".git")) or os.path.isfile(os.path.join(root, ".git"))

    def add(f, cap_file=3, cap_rule=40):
        k = (f["rule"], f["file"])
        if seen.get(k, 0) >= cap_file or rule_total.get(f["rule"], 0) >= cap_rule:
            info["values"][f["rule"]] = info["values"].get(f["rule"], 0) + (1 if seen.get(k, 0) < cap_file else 0)
            return
        seen[k] = seen.get(k, 0) + 1; rule_total[f["rule"]] = rule_total.get(f["rule"], 0) + 1
        info["values"][f["rule"]] = info["values"].get(f["rule"], 0) + 1; out.append(f)

    todo_by_file = {}
    for rel, ab, ext, sz in files:
        if ext not in CODE_EXT or sz > 600_000 or SKIP_DIR.search(rel) or GEN.search(rel): continue
        if not strict and (TESTY.search(rel) or TESTISH.search(rel)): continue
        try:
            with open(ab, encoding="utf-8", errors="ignore") as fh: text = fh.read(600_000)
        except OSError: continue
        info["scanned"] += 1
        lines = text.split("\n")
        if max((len(l) for l in lines), default=0) > 2500: continue                     # minified / data files
        # ---------------- TODO / FIXME / blockers (real comments only) ----------------
        if re.search(r"TODO|FIXME|HACK|XXX|BUG|KLUDGE|WORKAROUND|(?i:remove|before|debug|temp|skip|bypass|disable|hard-?coded|do not)", text):
            for n, line in enumerate(lines, 1):
                if len(line) > 400: continue
                cp = _comment_part(line, ext)
                if not cp: continue
                m = MARK.search(cp)
                if m and m.group(1) == "XXX" and not re.match(r"\s*[:(]|\s+[a-z]", cp[m.end(1):m.end(1) + 3]): m = None   # XXX-XXX style masks
                if m and m.group(1) == "BUG" and ":" not in cp[m.end(1):m.end(1) + 2]: m = None
                if m:
                    kind, owner, body = m.group(1), (m.group(2) or "").strip(), m.group(3).strip()
                    info["todo_total"] += 1; info["by_kind"][kind] = info["by_kind"].get(kind, 0) + 1
                    todo_by_file.setdefault(rel, []).append(dict(file=rel, line=n, kind=kind, owner=owner, text=body[:160] or cp.strip()[:160]))
                    sbody = URLS.sub(' ', body)
                    if SECURITY.search(sbody) and (kind != 'XXX' or ACTION.search(sbody)):
                        info["security"] += 1
                        add(_f("TODO-SECURITY", f"{kind} says security work is still missing: {SECURITY.search(sbody).group(0).lower()}", "todo-security", None, "todo", rel, n, cp.strip(), "needs_validation", "high", "vulnerability", 30, ["CWE-1059"]), 2, 25)
                if (BLOCKER_STRONG.search(cp) or (BLOCKER_WEAK.search(cp) and BLOCKER_CTX.search(cp))) and not (m and SECURITY.search(URLS.sub(' ', m.group(3)))):
                    info["blockers"] += 1
                    add(_f("TODO-BLOCKER", "Marker says to remove or fix this before production", "todo-blocker", "medium", "todo", rel, n, cp.strip(), "confirmed", None, "code_smell", 20), 2, 25)
        # ---------------- hardcoded values ----------------
        if ext not in VALUE_EXT: continue
        mt = mask_noncode(text, ext) if ext in CODE_EXT else text
        devf = bool(DEVFILE.search(rel)) or rel.lower().endswith((".example", ".sample"))
        if not devf:
            for m in URL_CALL.finditer(mt):
                n = mt.count("\n", 0, m.start()) + 1; ln_ = lines[n - 1]
                if EXCL_DEFAULT.search(ln_): continue
                add(_f("HC-URL-LOCAL", "localhost URL hardcoded at a call site", "hc-url", "low", "hardcode", rel, n, ln_, "needs_validation", "medium", "code_smell", 15))
            for m in ENV_HOST.finditer(mt):
                host = m.group(2).lower()
                if not ENV_WORD.search(host.rsplit('.', 1)[0]) or VENDOR.search(host + ".") or host.endswith((".test", ".local", ".example")): continue
                n = mt.count("\n", 0, m.start()) + 1; ln_ = lines[n - 1]
                if EXCL_DEFAULT.search(ln_): continue
                add(_f("HC-URL-ENV", f"Environment-specific host hardcoded: {host}", "hc-url", "low", "hardcode", rel, n, ln_, "needs_validation", "low", "code_smell", 15))
            for m in IP_CFG.finditer(mt):
                ip = m.group(1); parts = ip.split(".")
                if any(int(p) > 255 for p in parts) or IP_SKIP.match(ip) or ext in ("css", "scss", "less"): continue
                n = mt.count("\n", 0, m.start()) + 1
                add(_f("HC-IP", f"IP address hardcoded as a host: {ip}", "hc-ip", "low", "hardcode", rel, n, lines[n - 1], "needs_validation", "medium", "code_smell", 20))
        for m in ABS_PATH.finditer(mt):                                  # masked text: comments/docstrings/shebangs are not runtime paths
            n = mt.count("\n", 0, m.start()) + 1; ln_ = lines[n - 1]
            if re.search(r"(?i)\be\.g\.|for example|example:|<your|\{user\}|\$user|%user", ln_): continue
            add(_f("HC-PATH", "Personal machine path hardcoded: " + m.group(0)[:40], "hc-path", "low", "hardcode", rel, n, ln_, "confirmed", None, "code_smell", 10, ["CWE-200"]))
        for m in EMAIL.finditer(mt):
            if EMAIL_SKIP.match(m.group(1)): continue
            n = mt.count("\n", 0, m.start()) + 1
            add(_f("HC-EMAIL", "Personal email address hardcoded", "hc-email", "low", "hardcode", rel, n, lines[n - 1], "needs_validation", "low", "code_smell", 10, ["CWE-200"]))
        for rx, why in ((ADMIN_ID, "Authorization depends on a literal user id"), (ADMIN_NAME, "Authorization depends on a literal admin identity")):
            for m in rx.finditer(mt):
                n = mt.count("\n", 0, m.start()) + 1
                add(_f("HC-ADMIN-ID", why, "hc-admin", None, "hardcode", rel, n, lines[n - 1], "needs_validation", "high", "vulnerability", 30, ["CWE-798", "CWE-285"]), 2, 25)
        for m in RATE.finditer(mt):
            toks = {t.lower() for t in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])", m.group(1))}
            if not (toks & RATE_WORDS) or m.group(1).isupper() or RATE_NAME_BAD.search(m.group(1)): continue
            n = mt.count("\n", 0, m.start()) + 1
            add(_f("HC-RATE", f"Business rate hardcoded in a function: {m.group(1)}", "hc-rate", "low", "hardcode", rel, n, lines[n - 1], "needs_validation", "low", "code_smell", 20))
        for m in STUB.finditer(mt):
            n = mt.count("\n", 0, m.start()) + 1
            add(_f("HC-STUB", "Unimplemented stub", "hc-stub", "low", "hardcode", rel, n, lines[n - 1], "needs_validation", "medium", "code_smell", 30), 2, 25)

    # ---------------- aggregated TODO debt (+ age from git blame) ----------------
    allt = [t for ts in todo_by_file.values() for t in ts]
    end = time.time() + 12
    ages = {}
    if is_git and allt:
        for rel, ts in sorted(todo_by_file.items(), key=lambda kv: -len(kv[1]))[:40]:
            a = _blame_ages(root, rel, [t["line"] for t in ts], end)
            for t in ts:
                if t["line"] in a: t["age_days"] = a[t["line"]]
            ages.update({(rel, k): v for k, v in a.items()})
    aged = [t for t in allt if "age_days" in t]
    stale = [t for t in aged if t["age_days"] > 365]
    info["stale"] = len(stale); info["oldest_days"] = max((t["age_days"] for t in aged), default=0)
    info["files_with_todo"] = [(r, len(ts)) for r, ts in sorted(todo_by_file.items(), key=lambda kv: -len(kv[1]))[:10]]
    info["todos"] = sorted(allt, key=lambda t: (-(t.get("age_days") or 0), t["file"], t["line"]))[:2000]; info["backlog_cut"] = len(allt) > 2000
    for rel, ts in sorted(todo_by_file.items(), key=lambda kv: -len(kv[1])):
        hard = [t for t in ts if t["kind"] in ("FIXME", "HACK", "BUG", "KLUDGE", "WORKAROUND")]
        if hard and rule_total.get("TODO-FIXME", 0) < 30:
            rule_total["TODO-FIXME"] = rule_total.get("TODO-FIXME", 0) + 1
            out.append(_f("TODO-FIXME", f"{len(hard)} FIXME/HACK marker(s) in {os.path.basename(rel)}", "todo-debt", "low", "todo", rel, hard[0]["line"], "; ".join(f"L{t['line']} {t['kind']}: {t['text'][:60]}" for t in hard[:4]), "confirmed", None, "code_smell", min(120, 10 * len(hard))))
    if stale:
        top = sorted(stale, key=lambda t: -t["age_days"])
        out.append(_f("TODO-STALE", f"{len(stale)} marker(s) older than one year (oldest {top[0]['age_days'] // 365:.0f}+ years)", "todo-debt", "low", "todo", top[0]["file"], top[0]["line"],
                      "; ".join(f"{t['file']}:{t['line']} ({t['age_days']} d)" for t in top[:4]), "confirmed", None, "code_smell", min(120, 5 * len(stale))))
    if info["todo_total"] >= 10:
        k = ", ".join(f"{v} {a}" for a, v in sorted(info["by_kind"].items(), key=lambda kv: -kv[1])[:4])
        out.append(_f("TODO-DEBT", f"{info['todo_total']} unfinished-work markers in {len(todo_by_file)} files ({k})", "todo-debt", "info", "todo", info["files_with_todo"][0][0], 1,
                      "; ".join(f"{r}:{c}" for r, c in info["files_with_todo"][:4]), "confirmed", None, "code_smell", 15))
    return out, info


def backlog_md(info, label=""):
    """Issue-ready backlog of every TODO/FIXME/HACK (oldest first)."""
    ts = info.get("todos") or []
    if not ts: return None
    L = [f"# TODO backlog - {label}".rstrip(" -"), "", f"{info.get('todo_total', 0)} markers · by kind: " + ", ".join(f"{k} {v}" for k, v in sorted((info.get('by_kind') or {}).items(), key=lambda kv: -kv[1])) + (f" · {info['stale']} older than a year" if info.get("stale") else ""), "",
         "Triage each one: **do it**, **ticket it** (`TODO(#123)`), or **delete it**. Oldest first.", "", "| | Kind | Where | Age | Text |", "|---|---|---|---:|---|"]
    for t in ts: L.append(f"| [ ] | {t['kind']} | `{t['file']}:{t['line']}` | {(str(t['age_days']) + ' d') if 'age_days' in t else '-'} | {t['text'].replace('|', '/')} |")
    if info.get("backlog_cut"): L += ["", "(list cut at 2000 markers)"]
    return "\n".join(L) + "\n"
