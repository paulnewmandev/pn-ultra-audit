"""Version advisories: known vulnerabilities and end-of-life status for the language runtime, the framework and every locked dependency,
checked against public sources LIVE (read-only; only package names and versions are sent, never code):
  * OSV.dev        - dependency advisories (GitHub, npm, PyPI, Packagist, Go, RubyGems, crates, NuGet, Maven)
  * CISA KEV       - vulnerabilities exploited in the wild (also surfaces RECENT actively exploited bugs of the detected runtime/framework, e.g. PHP)
  * NVD            - CVEs of the exact runtime version (PHP, Node.js, Python, Ruby, Go) when the version is known
  * endoflife.date - support status of runtimes and frameworks
Results are cached (12 h) and the audit keeps working offline (`--offline` or PNUA_OFFLINE=1): the report then says the advisory data was not refreshed.
Nothing here modifies the project."""
import datetime, hashlib, json, os, re, time, urllib.error, urllib.request
from concurrent.futures import ThreadPoolExecutor
from .kb import KB

UA = "pn-ultra-audit (read-only advisory lookup; package names and versions only)"
TTL = 12 * 3600
SEV_ORDER = ["critical", "high", "medium", "low"]
OSV_ECO = {"npm": "npm", "composer": "Packagist", "pypi": "PyPI", "golang": "Go", "gem": "RubyGems", "cargo": "crates.io", "pub": "Pub", "nuget": "NuGet", "maven": "Maven"}
EOL_SLUG = {"node": "nodejs", "php": "php", "python": "python", "ruby": "ruby", "go": "go", "dotnet": "dotnet", "laravel": "laravel", "symfony": "symfony", "django": "django", "rails": "rails", "spring-boot": "spring-boot",
            "react": "react", "angular": "angular", "nextjs": "nextjs", "nuxt": "nuxt", "wordpress": "wordpress", "vue": "vue"}
LABEL = {"node": "Node.js", "php": "PHP", "python": "Python", "ruby": "Ruby", "go": "Go", "dotnet": ".NET", "java": "Java", "laravel": "Laravel", "symfony": "Symfony", "django": "Django", "rails": "Rails", "spring-boot": "Spring Boot",
         "react": "React", "angular": "Angular", "nextjs": "Next.js", "nuxt": "Nuxt", "wordpress": "WordPress", "vue": "Vue"}
FRAMEWORK_PKG = {("composer", "laravel/framework"): "laravel", ("composer", "symfony/symfony"): "symfony", ("composer", "symfony/framework-bundle"): "symfony", ("pypi", "django"): "django", ("gem", "rails"): "rails", ("npm", "react"): "react",
                 ("npm", "@angular/core"): "angular", ("npm", "next"): "nextjs", ("npm", "nuxt"): "nuxt", ("npm", "vue"): "vue", ("maven", "org.springframework.boot:spring-boot"): "spring-boot"}
# vendor/product text used to match the CISA KEV catalogue against what the project runs
KEV_MATCH = {"php": ("php",), "node": ("node.js", "nodejs"), "laravel": ("laravel",), "react": ("react",), "nextjs": ("next.js",), "wordpress": ("wordpress",), "django": ("django",), "symfony": ("symfony",), "rails": ("rails", "ruby on rails"),
             "python": ("python",), "ruby": ("ruby",), "go": ("go ", "golang"), "spring-boot": ("spring",), "angular": ("angular",), "vue": ("vue",), "dotnet": (".net",), "java": ("java se", "openjdk")}
CPE = {"php": "cpe:2.3:a:php:php:{v}:*:*:*:*:*:*:*", "node": "cpe:2.3:a:nodejs:node.js:{v}:*:*:*:*:*:*:*", "python": "cpe:2.3:a:python:python:{v}:*:*:*:*:*:*:*", "ruby": "cpe:2.3:a:ruby-lang:ruby:{v}:*:*:*:*:*:*:*", "go": "cpe:2.3:a:golang:go:{v}:*:*:*:*:*:*:*"}
# offline fallback (as of 2026-11): end-of-life dates when endoflife.date cannot be reached
EOL_FALLBACK = {"php": {"7.4": "2022-11-28", "8.0": "2023-11-26", "8.1": "2025-12-31", "8.2": "2026-12-31", "8.3": "2027-12-31", "8.4": "2028-12-31"}, "node": {"16": "2023-09-11", "18": "2025-04-30", "20": "2026-04-30", "22": "2027-04-30", "24": "2028-04-30"},
                "python": {"3.8": "2024-10-07", "3.9": "2025-10-31", "3.10": "2026-10-31", "3.11": "2027-10-31", "3.12": "2028-10-31", "3.13": "2029-10-31"}, "ruby": {"2.7": "2023-03-31", "3.0": "2024-03-31", "3.1": "2025-03-31", "3.2": "2026-03-31", "3.3": "2027-03-31"}}

FETCH = None   # replaceable in tests: FETCH(url, data=None, timeout=8) -> parsed json


def offline(): return os.environ.get("PNUA_OFFLINE") == "1"


def _cache_dir():
    d = os.environ.get("PNUA_CACHE") or os.path.join(os.path.expanduser("~"), ".cache", "pn-ultra-audit")
    try: os.makedirs(d, exist_ok=True)
    except OSError: return None
    return d


def _http(url, data=None, timeout=8):
    req = urllib.request.Request(url, data=(json.dumps(data).encode() if data is not None else None), headers={"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r: return json.loads(r.read().decode("utf-8", "replace"))


def get(url, data=None, ttl=TTL, timeout=8):
    """-> (obj or None, state) with state in live | cache | stale | offline | fail (cached on disk, never raises)."""
    key = hashlib.sha1((url + json.dumps(data, sort_keys=True, default=str)).encode()).hexdigest()
    cd = _cache_dir(); path = os.path.join(cd, key + ".json") if cd else None
    cached = None
    if path and os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as fh: cached = json.load(fh)
            if time.time() - cached["t"] < ttl: return cached["d"], "cache"
        except (OSError, ValueError, KeyError): cached = None
    if offline(): return (cached["d"], "stale") if cached else (None, "offline")
    try:
        obj = (FETCH or _http)(url, data, timeout)
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return (cached["d"], "stale") if cached else (None, "fail")
    if path:
        try:
            with open(path, "w", encoding="utf-8") as fh: json.dump({"t": time.time(), "d": obj}, fh)
        except OSError: pass
    return obj, "live"


# ------------------------------------------------------------------ versions
def vkey(v):
    return [(0, int(p)) if p.isdigit() else (-1, p) for p in re.findall(r"\d+|[A-Za-z]+", str(v))]


def vcmp(a, b):
    ka, kb = vkey(a), vkey(b)
    for x, y in zip(ka, kb):
        if x != y:
            try: return -1 if x < y else 1
            except TypeError: return -1 if str(x) < str(y) else 1
    return (len(ka) > len(kb)) - (len(ka) < len(kb))


def cvss3(vector):
    """CVSS v3.x base score from the vector string (None if it cannot be parsed)."""
    try:
        m = dict(p.split(":") for p in vector.split("/")[1:])
        av = {"N": .85, "A": .62, "L": .55, "P": .2}[m["AV"]]; ac = {"L": .77, "H": .44}[m["AC"]]; ui = {"N": .85, "R": .62}[m["UI"]]; sc = m["S"] == "C"
        pr = {"N": .85, "L": .68 if sc else .62, "H": .5 if sc else .27}[m["PR"]]; cia = {"H": .56, "L": .22, "N": 0}
        iss = 1 - (1 - cia[m["C"]]) * (1 - cia[m["I"]]) * (1 - cia[m["A"]])
        imp = 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15 if sc else 6.42 * iss
        if imp <= 0: return 0.0
        ex = 8.22 * av * ac * pr * ui
        import math
        r = lambda x: math.ceil(x * 10 - 1e-9) / 10
        return r(min(1.08 * (imp + ex), 10)) if sc else r(min(imp + ex, 10))
    except (KeyError, ValueError, IndexError): return None


def sev_label(vuln):
    ds = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(ds, str) and ds.upper() in ("CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"): return {"MODERATE": "medium", "MEDIUM": "medium"}.get(ds.upper(), ds.lower())
    for s in vuln.get("severity") or []:
        sc = cvss3(s.get("score", "")) if "CVSS:3" in s.get("score", "") else None
        if sc is not None: return "critical" if sc >= 9 else "high" if sc >= 7 else "medium" if sc >= 4 else "low"
    return "medium"


def lower_sev(s): return SEV_ORDER[min(SEV_ORDER.index(s) + 1, 3)] if s in SEV_ORDER else s


# ------------------------------------------------------------------ inventory
def _read(ab, cap=60000):
    try:
        with open(ab, encoding="utf-8", errors="ignore") as fh: return fh.read(cap)
    except OSError: return ""


def runtimes(root, files):
    """Runtime/language versions declared by the project -> [dict(product, cycle, exact, source, kind)] (kind: deploy | constraint)."""
    out, seen = [], set()
    def add(prod, ver, src, kind="deploy"):
        ver = str(ver).strip().lstrip("vV").strip("'\"")
        m = re.match(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", ver)
        if not m: return
        major, minor, patch = m.group(1), m.group(2), m.group(3)
        cycle = major if prod in ("node", "java", "dotnet") and prod != "dotnet" else (f"{major}.{minor}" if minor else major)
        if prod == "dotnet": cycle = f"{major}.{minor or '0'}"
        key = (prod, cycle, src)
        if key in seen: return
        seen.add(key); out.append(dict(product=prod, cycle=cycle, exact=(f"{major}.{minor}.{patch}" if (minor and patch) else None), source=src, kind=kind))
    DOCKER = {"node": "node", "php": "php", "python": "python", "ruby": "ruby", "golang": "go", "openjdk": "java", "eclipse-temurin": "java", "amazoncorretto": "java", "dotnet": "dotnet", "aspnet": "dotnet", "sdk": "dotnet"}
    for rel, ab, ext, sz in files:
        b = os.path.basename(rel); low = b.lower()
        if rel.count("/") > 3 or sz > 400_000: continue
        t = None
        if low.startswith("dockerfile") or low.endswith(".dockerfile"):
            t = _read(ab)
            for m in re.finditer(r"(?im)^\s*FROM\s+(?:--platform=\S+\s+)?([\w./-]+):v?(\d+(?:\.\d+){0,2})", t):
                prod = DOCKER.get(m.group(1).rsplit("/", 1)[-1])
                if prod: add(prod, m.group(2), rel)
        elif b in (".nvmrc", ".node-version"): add("node", _read(ab, 100).strip().split()[0] if _read(ab, 100).strip() else "", rel)
        elif b == ".python-version": add("python", _read(ab, 100).strip().split()[0] if _read(ab, 100).strip() else "", rel)
        elif b == ".ruby-version": add("ruby", _read(ab, 100).strip().replace("ruby-", ""), rel)
        elif b == ".php-version": add("php", _read(ab, 100).strip(), rel)
        elif b == "runtime.txt": add("python", _read(ab, 100).strip().replace("python-", ""), rel)
        elif b == ".tool-versions":
            for ln in _read(ab).splitlines():
                p = ln.split()
                if len(p) >= 2 and p[0] in ("nodejs", "python", "ruby", "golang", "php", "java"): add({"nodejs": "node", "golang": "go"}.get(p[0], p[0]), p[1], rel)
        elif b == "go.mod":
            m = re.search(r"(?m)^go\s+(\d+\.\d+(?:\.\d+)?)", _read(ab)); m and add("go", m.group(1), rel, "constraint")
        elif b == "package.json":
            m = re.search(r'"engines"\s*:\s*\{[^}]*"node"\s*:\s*"([^"]+)"', _read(ab))
            if m:
                n = re.search(r"(\d+)", m.group(1)); n and add("node", n.group(1), rel, "constraint")
        elif b == "composer.json":
            m = re.search(r'"require"\s*:\s*\{[^}]*"php"\s*:\s*"([^"]+)"', _read(ab))
            if m:
                n = re.search(r"(\d+\.\d+)", m.group(1)); n and add("php", n.group(1), rel, "constraint")
        elif b == "pyproject.toml":
            m = re.search(r"requires-python\s*=\s*[\"']([^\"']+)", _read(ab))
            if m:
                n = re.search(r"(\d+\.\d+)", m.group(1)); n and add("python", n.group(1), rel, "constraint")
        elif b == "Pipfile":
            m = re.search(r'python_version\s*=\s*"(\d+\.\d+)', _read(ab)); m and add("python", m.group(1), rel)
        elif b == "pom.xml":
            m = re.search(r"<(?:java\.version|maven\.compiler\.(?:source|release))>\s*(\d+)", _read(ab)); m and add("java", m.group(1), rel, "constraint")
        elif low.endswith(".csproj"):
            m = re.search(r"<TargetFramework>net(\d+\.\d+)", _read(ab)); m and add("dotnet", m.group(1), rel, "constraint")
        elif rel.startswith(".github/workflows/") and low.endswith((".yml", ".yaml")):
            t = _read(ab)
            for key, prod in (("node-version", "node"), ("python-version", "python"), ("php-version", "php"), ("ruby-version", "ruby"), ("go-version", "go")):
                for m in re.finditer(r"%s:\s*['\"]?(\d+(?:\.\d+)?)" % key, t): add(prod, m.group(1), rel, "constraint")
        elif b == "version.php" and "wp-includes" in rel:
            m = re.search(r"\$wp_version\s*=\s*'([\d.]+)'", _read(ab)); m and add("wordpress", m.group(1), rel)
    return out


def components(root, files):
    """Locked dependencies -> [dict(eco, name, version, dev, file)] (exact versions only: lockfiles and pinned requirements)."""
    from . import sbom
    bom, _info = sbom.build(root, files)
    dev, prod = set(), set()
    for rel, ab, ext, sz in files:
        b = os.path.basename(rel)
        if b == "package.json" and rel.count("/") <= 2:
            try: j = json.loads(_read(ab, 400_000))
            except ValueError: continue
            dev |= set((j.get("devDependencies") or {}).keys()); prod |= set((j.get("dependencies") or {}).keys()) | set((j.get("peerDependencies") or {}).keys())
        elif b == "composer.json" and rel.count("/") <= 2:
            try: j = json.loads(_read(ab, 400_000))
            except ValueError: continue
            dev |= set((j.get("require-dev") or {}).keys()); prod |= set((j.get("require") or {}).keys())
    out = []
    for c in bom.get("components", []):
        m = re.match(r"pkg:([a-z]+)/(.+)@(.+)$", c.get("purl", ""))
        if not m or m.group(1) not in OSV_ECO: continue
        name = m.group(2).replace("%40", "@")
        out.append(dict(eco=m.group(1), name=name, version=m.group(3), dev=(name in dev and name not in prod), file=next((p["value"] for p in c.get("properties", []) if p.get("name") == "pnua:file"), "")))
    return out


# ------------------------------------------------------------------ live lookups
def osv_scan(comps, info, budget_end, db=None):
    """-> {(eco,name,version): [compact advisory lines]}. Uses the local text database when it has the ecosystem (offline, nothing is sent),
    otherwise OSV.dev live (querybatch + per-id details, threaded and cached)."""
    from . import vulndb
    res, live = {}, []
    for c in comps:
        if db and db.has_osv(OSV_ECO[c["eco"]]):
            hits = db.osv(OSV_ECO[c["eco"]], c["name"], c["version"])
            if hits: res[(c["eco"], c["name"], c["version"])] = hits
        else: live.append(c)
    if db and len(live) < len(comps): info["states"].append(("db", "local"))
    if not live or offline(): return res
    qs = [dict(package=dict(name=c["name"], ecosystem=OSV_ECO[c["eco"]]), version=c["version"]) for c in live]
    ids = {}
    for i in range(0, len(qs), 400):
        if time.time() > budget_end: info["errors"].append("OSV: time budget reached"); break
        obj, st = get("https://api.osv.dev/v1/querybatch", {"queries": qs[i:i + 400]}, timeout=20)
        info["states"].append(("osv", st))
        if not obj: info["errors"].append(f"OSV unavailable ({st})"); break
        for c, r in zip(live[i:i + 400], obj.get("results", [])):
            for v in (r.get("vulns") or []): ids.setdefault(v["id"], []).append(c)
    if not ids: return res
    def detail(vid):
        d, st = get(f"https://api.osv.dev/v1/vulns/{vid}", ttl=24 * 3600, timeout=10)
        return vid, d, st
    with ThreadPoolExecutor(max_workers=8) as ex: got = list(ex.map(detail, list(ids)[:300]))
    for vid, d, st in got:
        if not d: continue
        for c in ids[vid]:
            for pkg, line in vulndb.compact_osv(d, OSV_ECO[c["eco"]]):
                if pkg == vulndb.norm(OSV_ECO[c["eco"]], c["name"]): res.setdefault((c["eco"], c["name"], c["version"]), []).append(line)
    return res


def fixed_in(line, comp):
    """smallest fixed version greater than the installed one, preferring a fix inside the installed major line (no breaking jump)."""
    fx = [r[1] for r in (line.get("rg") or []) if r[1] and vcmp(r[1], comp["version"]) > 0]
    if not fx: return None
    maj = lambda v: (re.findall(r"\d+", str(v)) or ["0"])
    cur = maj(comp["version"]); same = [f for f in fx if maj(f)[:1] == cur[:1] and (cur[0] != "0" or maj(f)[:2] == cur[:2])]
    return min(same or fx, key=lambda x: vkey(x))


def kev_catalog(info, db=None):
    """-> {cve: {id, vendor, product, name, date, action}} from the local database, else live."""
    if db and db.kev():
        info["states"].append(("kev", "local")); return db.kev()
    obj, st = get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", ttl=TTL, timeout=25)
    info["states"].append(("kev", st))
    if not obj: info["errors"].append(f"CISA KEV unavailable ({st})"); return {}
    return {v["cveID"]: dict(id=v["cveID"], vendor=v.get("vendorProject"), product=v.get("product"), name=v.get("vulnerabilityName"), date=v.get("dateAdded"), action=v.get("requiredAction")) for v in obj.get("vulnerabilities", [])}


def eol_cycle(product, cycle, info, db=None):
    """-> dict(eol=date|None, latest, support, source) for a product cycle (local DB, live API, else the offline table)."""
    slug = EOL_SLUG.get(product)
    if slug:
        cycles = None
        rec = db.eol(slug) if db else None
        if rec: cycles = rec["cycles"]; info["states"].append(("eol", "local"))
        else:
            obj, st = get(f"https://endoflife.date/api/{slug}.json", ttl=24 * 3600, timeout=10)
            info["states"].append(("eol", st))
            if isinstance(obj, list): cycles = [dict(cycle=str(c.get("cycle")), eol=c.get("eol") if isinstance(c.get("eol"), str) else None, eol_flag=c.get("eol") is True, latest=c.get("latest"), support=c.get("support") if isinstance(c.get("support"), str) else None) for c in obj]
        if cycles:
            best = None
            for c in cycles:
                cy = str(c.get("cycle", ""))
                if cycle == cy or cycle.startswith(cy + "."): best = c if (best is None or len(cy) > len(str(best.get("cycle")))) else best
            if best: return dict(eol=best.get("eol"), eol_flag=bool(best.get("eol_flag")), latest=best.get("latest"), support=best.get("support"), source="endoflife.date")
    fb = (EOL_FALLBACK.get(product) or {}).get(cycle)
    return dict(eol=fb, latest=None, support=None, source="offline table (2026-11)") if fb else None


def nvd_runtime(product, exact, info, db=None):
    if product not in CPE or not exact: return []
    if db and os.path.exists(os.path.join(db.dir, "nvd", product + ".jsonl")):
        info["states"].append(("nvd", "local"))
        return [dict(id=r["id"], score=r.get("sc") or 0, summary=r.get("sm", "")[:140]) for r in db.nvd(product, exact)]
    obj, st = get("https://services.nvd.nist.gov/rest/json/cves/2.0?" + "cpeName=" + CPE[product].format(v=exact) + "&resultsPerPage=80&noRejected", ttl=24 * 3600, timeout=20)
    info["states"].append(("nvd", st))
    out = []
    for it in (obj or {}).get("vulnerabilities", []):
        c = it.get("cve", {}); m = c.get("metrics", {}); sc = None
        for k in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30"):
            if m.get(k): sc = m[k][0]["cvssData"].get("baseScore"); break
        out.append(dict(id=c.get("id"), score=sc or 0, summary=next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")[:140]))
    return sorted(out, key=lambda x: -x["score"])


# ------------------------------------------------------------------ findings
def _f(rule, title, family, sev, file, ev, fix, status="confirmed", effort=20, cwe=(), priority=None, typ="vulnerability", why=None, cat="dependency"):
    kb = KB[family]
    return dict(rule=rule, title=title, family=family, type=typ, severity=sev if status == "confirmed" else None, category=cat, file=file, line=1, evidence=ev[:380], impact=kb["impact"], fix=fix, effort_min=effort, cwe=list(cwe),
                owasp=["A06:2021"], status=status, priority=priority, why=why)


def upgrade_cmd(c, fixed):
    n = c["name"]
    return {"npm": f"npm install {n}@{fixed}", "composer": f"composer require {n}:^{fixed}", "pypi": f"pip install '{n}>={fixed}'", "gem": f"bundle update {n}", "golang": f"go get {n}@v{fixed.lstrip('v')}", "cargo": f"cargo update -p {n}"}.get(c["eco"], f"upgrade {n} to {fixed}")


def analyze(root, files, level="standard", today=None):
    """-> (findings, info)."""
    today = today or datetime.date.today()
    from . import vulndb
    db = vulndb.open_db()
    info = dict(live=not offline(), states=[], errors=[], runtimes=[], frameworks=[], components=0, vulnerable=0, kev=0, malicious=0, sources=["OSV.dev", "CISA KEV", "NVD", "endoflife.date"], fetched=today.isoformat(),
                db=dict(used=bool(db), age_days=(db.age_days() if db else None), updated=(db.meta.get("updated") if db else None)))
    out = []
    end = time.time() + 75
    rts = runtimes(root, files); comps = components(root, files)
    info["components"] = len(comps)
    kev = kev_catalog(info, db) if (comps or rts) else {}
    # ---------------- dependencies
    vulns = osv_scan(comps[:4000], info, end, db) if comps else {}
    for c in comps:
        vs = vulns.get((c["eco"], c["name"], c["version"]))
        if not vs: continue
        mal = [v for v in vs if v.get("mal")]
        if mal:
            info["malicious"] += 1
            out.append(_f("MAL-MALICIOUS-PACKAGE", f"{c['name']} {c['version']} is a KNOWN MALICIOUS package ({mal[0]['id']})", "mal-supply", "critical", c["file"] or "lockfile", f"{mal[0]['id']}: {mal[0].get('sm', '')}",
                          f"Treat as an incident: remove `{c['name']}` now, reinstall from a clean lockfile, rotate every secret the machines/CI that installed it could read, and check install logs.", "confirmed", 60, ["CWE-506"], typ="vulnerability", cat="malware"))
            vs = [v for v in vs if not v.get("mal")]
            if not vs: continue
        rows = []
        for v in vs:
            cves = [a for a in (v.get("al") or []) if a.startswith("CVE-")]
            k = next((kev[x] for x in cves if x in kev), None)
            rows.append(dict(id=(cves[0] if cves else v["id"]), ghsa=v["id"], sev=v.get("sv") or "medium", kev=bool(k), summary=(v.get("sm") or "")[:110], fixed=fixed_in(v, c), cwe=v.get("cw") or []))
        seen_ids, uniq = set(), []
        for r in sorted(rows, key=lambda r: (not r["kev"], SEV_ORDER.index(r["sev"]) if r["sev"] in SEV_ORDER else 9)):
            if r["id"] in seen_ids: continue
            seen_ids.add(r["id"]); uniq.append(r)
        worst = "critical" if any(r["kev"] for r in uniq) else min((r["sev"] for r in uniq), key=lambda s: SEV_ORDER.index(s) if s in SEV_ORDER else 9)
        sev = lower_sev(worst) if c["dev"] and not any(r["kev"] for r in uniq) else worst
        fixes = [r["fixed"] for r in uniq if r["fixed"]]
        target = max(fixes, key=lambda x: vkey(x)) if fixes else None
        ev = "; ".join(f"{r['id']} {r['sev']}{' KEV' if r['kev'] else ''}: {r['summary']}" + (f" [fix {r['fixed']}]" if r["fixed"] else "") for r in uniq[:5]) + (f"; +{len(uniq) - 5} more" if len(uniq) > 5 else "")
        crosses = target and (re.findall(r"\d+", target) or ["0"])[0] != (re.findall(r"\d+", c["version"]) or ["0"])[0]
        fx = (f"Upgrade to {target}: `{upgrade_cmd(c, target)}`" + (f" (jumps from major {re.findall(chr(92) + 'd+', c['version'])[0]} to {re.findall(chr(92) + 'd+', target)[0]}: your current line no longer receives fixes, read the migration guide)" if crosses else "") if target else "No fixed version is published: replace the package, pin a patched fork or mitigate (see the advisory).") + (" (dev-only dependency: lower urgency)" if c["dev"] else "")
        info["vulnerable"] += 1; info["kev"] += sum(1 for r in uniq if r["kev"])
        out.append(_f("DEP-VULN", f"{c['name']} {c['version']}: {len(uniq)} known vulnerabilit{'y' if len(uniq) == 1 else 'ies'}" + (" (actively exploited)" if any(r["kev"] for r in uniq) else ""), "dep-vuln", sev, c["file"] or "lockfile", ev, fx,
                      "confirmed", 15, [x for r in uniq for x in r["cwe"]][:3], typ="vulnerability"))
    # ---------------- runtimes and frameworks
    fws = {}
    for c in comps:
        p = FRAMEWORK_PKG.get((c["eco"], c["name"]))
        if p and not c["dev"]: fws.setdefault(p, dict(product=p, cycle=None, exact=c["version"], source=c["file"], kind="deploy"))
    for p, f in fws.items():
        m = re.match(r"(\d+)(?:\.(\d+))?", f["exact"]); f["cycle"] = m.group(1) if p in ("laravel", "react", "angular", "nextjs", "nuxt", "vue", "symfony") and p != "symfony" else (f"{m.group(1)}.{m.group(2)}" if m.group(2) else m.group(1))
    stack = rts + list(fws.values())
    products = set()
    for r in stack:
        products.add(r["product"])
        e = eol_cycle(r["product"], r["cycle"], info, db)
        row = dict(product=r["product"], label=LABEL.get(r["product"], r["product"]), cycle=r["cycle"], exact=r.get("exact"), source=r["source"], kind=r["kind"], eol=(e or {}).get("eol"), latest=(e or {}).get("latest"), status="unknown", framework=r["product"] in fws)
        if e and e.get("eol"):
            try: d = datetime.date.fromisoformat(e["eol"])
            except ValueError: d = None
            if d and d <= today: row["status"] = "eol"
            elif d and (d - today).days <= 180: row["status"] = "soon"
            else: row["status"] = "supported"
        elif e and e.get("eol_flag"): row["status"] = "eol"
        elif e: row["status"] = "supported"
        info["frameworks" if row["framework"] else "runtimes"].append(row)
        name = f"{row['label']} {row['exact'] or r['cycle']}"
        if row["status"] == "eol":
            dep = r["kind"] == "deploy"
            out.append(_f("RUNTIME-EOL", f"{name} is end-of-life since {row['eol'] or 'a past date'}: no more security patches", "runtime-eol", "high" if dep else None, r["source"],
                          f"{row['label']} {r['cycle']} support ended {row['eol']}; latest in this line: {row['latest'] or 'n/a'} (source: {e.get('source')}); declared in {r['source']} ({'deployment' if dep else 'version constraint'})",
                          f"Upgrade {row['label']} to a supported release (latest known: {row['latest'] or 'check endoflife.date'}), test, and update {r['source']}.", "confirmed" if dep else "needs_validation", 120, typ="vulnerability", priority=None if dep else "medium", cat="dependency",
                          why=None if dep else "Only a version constraint was found: confirm which runtime production really uses."))
        elif row["status"] == "soon":
            out.append(_f("RUNTIME-EOL", f"{name} reaches end-of-life on {row['eol']}", "runtime-eol", "medium" if r["kind"] == "deploy" else None, r["source"], f"{row['label']} {r['cycle']} security support ends {row['eol']} (source: {e.get('source')})",
                          f"Plan the upgrade to a supported {row['label']} release before {row['eol']}.", "confirmed" if r["kind"] == "deploy" else "needs_validation", 90, typ="code_smell", priority="medium"))
        # CVEs of the exact runtime version (NVD)
        if r.get("exact") and r["kind"] == "deploy" and r["product"] in CPE and time.time() < end:
            nv = [x for x in nvd_runtime(r["product"], r["exact"], info, db) if x["score"] >= 7 or x["id"] in kev]
            if nv:
                kk = [x for x in nv if x["id"] in kev]
                info["kev"] += len(kk)
                out.append(_f("RUNTIME-VULN", f"{name}: {len(nv)} high-severity CVE(s) for this exact version" + (f", {len(kk)} actively exploited" if kk else ""), "runtime-vuln", "critical" if kk else "high", r["source"],
                              "; ".join(f"{x['id']} ({x['score']}){' KEV' if x['id'] in kev else ''}: {x['summary']}" for x in nv[:5]), f"Upgrade {row['label']} to the latest patch of the {r['cycle']} line ({row['latest'] or 'see endoflife.date'}) or a supported newer release.", "confirmed", 60, typ="vulnerability"))
    # ---------------- recent actively-exploited bugs of the detected stack (CISA KEV)
    cutoff = today - datetime.timedelta(days=365)
    for p in sorted(products):
        keys = KEV_MATCH.get(p, ())
        hits = []
        for cid, v in kev.items():
            txt = ((v.get("vendor") or "") + " " + (v.get("product") or "")).lower() + " "
            if any(k in txt for k in keys):
                try: da = datetime.date.fromisoformat(v["date"])
                except (ValueError, KeyError): continue
                if da >= cutoff: hits.append((da, cid, v))
        if not hits: continue
        hits.sort(reverse=True)
        r0 = next(x for x in stack if x["product"] == p)
        out.append(_f("ADV-KEV-RECENT", f"{LABEL.get(p, p)}: {len(hits)} vulnerabilit{'y' if len(hits) == 1 else 'ies'} added to CISA KEV (exploited in the wild) in the last 12 months", "adv-kev", None, r0["source"],
                      "; ".join(f"{cid} ({v['date']}): {(v.get('name') or '')[:70]}" for da, cid, v in hits[:5]) + " | " + (hits[0][2].get("action") or "")[:120],
                      f"Check that your {LABEL.get(p, p)} version includes the fixes for {', '.join(c for _, c, _ in hits[:4])} (read each CVE's fixed versions on nvd.nist.gov) and patch to the latest release of your line.", "needs_validation", 45, typ="vulnerability", priority="high",
                      why="These bugs are being exploited in the wild: confirm your exact version is patched.", cat="dependency"))
    info["live"] = any(s in ("live", "cache", "local") for _, s in info["states"]) if info["states"] else not offline()
    info["states"] = sorted({f"{k}:{s}" for k, s in info["states"]})
    return out, info
