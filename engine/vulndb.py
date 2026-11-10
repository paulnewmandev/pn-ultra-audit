"""Local vulnerability database, stored as plain text (JSON Lines) and built from public sources:
  osv/<ecosystem>.jsonl  OSV.dev bulk dumps (GitHub Advisories, npm, PyPI, Packagist, Go, RubyGems, crates.io, Maven, NuGet, Pub, Hex, GitHub Actions ...)
                         incl. OpenSSF malicious-package reports (MAL-*); one line per (package, advisory), sorted, with a byte-offset index (<ecosystem>.idx)
  kev.jsonl              CISA Known Exploited Vulnerabilities
  eol.jsonl              endoflife.date: support lifecycle of ~490 products (languages, frameworks, databases, OSes)
  nvd/<product>.jsonl    NVD CVEs of runtimes/servers/frameworks (PHP, Node.js, Python, nginx, OpenSSL, WordPress, ...) with affected version ranges
  meta.json              what was synced, when and how much
Build it with `python3 audit.py --update-db`; the audit then queries it locally (fast, complete, works offline, no package names leave the machine).
Greppable on purpose: `grep -h '"p": "lodash"' ~/.cache/pn-ultra-audit/db/osv/npm.jsonl`."""
import datetime, io, json, os, re, time, urllib.error, urllib.request, zipfile

UA = "pn-ultra-audit-db-sync (public vulnerability data; read-only)"
OSV_BASE = "https://osv-vulnerabilities.storage.googleapis.com"
DEFAULT_ECOSYSTEMS = ["npm", "PyPI", "Packagist", "Go", "RubyGems", "crates.io", "Maven", "NuGet", "Pub", "Hex", "GitHub Actions"]
ALL_SOURCES = ["osv", "kev", "eol", "nvd"]
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EOL_URL = "https://endoflife.date/api/v1/products/full"
# product key -> (cpe vendor:product used for the NVD query, label)
NVD_PRODUCTS = {"php": ("php:php", "PHP"), "node": ("nodejs:node.js", "Node.js"), "python": ("python:python", "Python"), "ruby": ("ruby-lang:ruby", "Ruby"), "go": ("golang:go", "Go"), "openjdk": ("oracle:jdk", "Java (Oracle JDK)"),
                "nginx": ("f5:nginx", "nginx"), "apache": ("apache:http_server", "Apache httpd"), "tomcat": ("apache:tomcat", "Apache Tomcat"), "openssl": ("openssl:openssl", "OpenSSL"), "mysql": ("oracle:mysql", "MySQL"),
                "postgresql": ("postgresql:postgresql", "PostgreSQL"), "redis": ("redis:redis", "Redis"), "mongodb": ("mongodb:mongodb", "MongoDB"), "wordpress": ("wordpress:wordpress", "WordPress"), "drupal": ("drupal:drupal", "Drupal"),
                "laravel": ("laravel:laravel", "Laravel"), "symfony": ("sensiolabs:symfony", "Symfony"), "django": ("djangoproject:django", "Django"), "rails": ("rubyonrails:rails", "Ruby on Rails"), "spring": ("vmware:spring_framework", "Spring Framework"),
                "docker": ("docker:docker", "Docker"), "kubernetes": ("kubernetes:kubernetes", "Kubernetes"), "git": ("git-scm:git", "Git"), "curl": ("haxx:curl", "curl")}
FETCH_BYTES = None   # replaceable in tests: FETCH_BYTES(url, headers=None) -> (status, bytes, response_headers)


def db_dir():
    return os.environ.get("PNUA_DB") or os.path.join(os.environ.get("PNUA_CACHE") or os.path.join(os.path.expanduser("~"), ".cache", "pn-ultra-audit"), "db")


def _get_bytes(url, headers=None, timeout=300):
    h = {"User-Agent": UA}; h.update(headers or {})
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=timeout) as r: return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e: return e.code, b"", dict(e.headers or {})


def fetch(url, headers=None, timeout=300): return (FETCH_BYTES or _get_bytes)(url, headers, timeout)


def norm(eco, name):
    n = str(name)
    if eco == "PyPI": return re.sub(r"[-_.]+", "-", n).lower()
    if eco in ("Packagist", "NuGet", "RubyGems", "crates.io", "Hex", "Pub"): return n.lower()
    return n


# ------------------------------------------------------------------ version comparison (semver / PEP 440 / maven-ish, pre-releases sort before releases)
def vkey(v):
    return [(0, int(p)) if p.isdigit() else (-1, p.lower()) for p in re.findall(r"\d+|[A-Za-z]+", str(v))]


def vcmp(a, b):
    ka, kb = vkey(a), vkey(b)
    for x, y in zip(ka, kb):
        if x != y:
            if x[0] != y[0]: return -1 if x[0] < y[0] else 1
            return -1 if x[1] < y[1] else 1
    if len(ka) == len(kb): return 0
    extra = (ka if len(ka) > len(kb) else kb)[min(len(ka), len(kb))]
    longer = 1 if len(ka) > len(kb) else -1
    return -longer if extra[0] == -1 and extra[1] in ("a", "b", "rc", "alpha", "beta", "pre", "dev", "snapshot", "preview", "c") else longer


def in_ranges(version, rg, versions=None):
    """True when `version` is inside any [introduced, fixed|last_affected] interval (OSV semantics) or listed explicitly."""
    if versions and version in versions: return True
    for intro, fixed, last in rg or []:
        if intro not in (None, "", "0") and vcmp(version, intro) < 0: continue
        if fixed and vcmp(version, fixed) >= 0: continue
        if last and vcmp(version, last) > 0: continue
        return True
    return False


# ------------------------------------------------------------------ build
def _sev(d):
    ds = (d.get("database_specific") or {}).get("severity")
    if isinstance(ds, str) and ds.upper() in ("CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"): return {"MODERATE": "medium", "MEDIUM": "medium"}.get(ds.upper(), ds.lower())
    from .advisories import cvss3
    for s in d.get("severity") or []:
        if "CVSS:3" in s.get("score", ""):
            sc = cvss3(s["score"])
            if sc is not None: return "critical" if sc >= 9 else "high" if sc >= 7 else "medium" if sc >= 4 else "low"
    return "medium"


def compact_osv(d, eco):
    """one OSV record -> [(package, line_dict)] (one line per affected package of this ecosystem)."""
    if d.get("withdrawn"): return []
    out, vid = [], d.get("id", "")
    al = [a for a in (d.get("aliases") or []) if a.startswith(("CVE-", "GHSA-"))][:6]
    base = dict(id=vid, al=al, sv=_sev(d), sm=(d.get("summary") or d.get("details") or "")[:140].replace("\n", " "), cw=((d.get("database_specific") or {}).get("cwe_ids") or [])[:4], pub=(d.get("published") or "")[:10], mal=vid.startswith("MAL-"))
    for a in d.get("affected") or []:
        p = a.get("package") or {}
        if not p.get("name"): continue
        rg = []
        for r in a.get("ranges") or []:
            if r.get("type") == "GIT": continue
            cur = None
            for e in r.get("events") or []:
                if "introduced" in e: cur = [e["introduced"], None, None]; rg.append(cur)
                elif "fixed" in e and cur: cur[1] = e["fixed"]; cur = None
                elif "last_affected" in e and cur: cur[2] = e["last_affected"]; cur = None
        vs = (a.get("versions") or [])[:300]
        if not rg and not vs: continue
        line = dict(base); line["p"] = p["name"]; line["rg"] = rg
        if vs and (not rg or len(vs) <= 300): line["vs"] = vs if not rg else []
        out.append((norm(eco, p["name"]), line))
    return out


def build_osv(eco, progress=print, headers=None):
    url = f"{OSV_BASE}/{eco.replace(' ', '%20')}/all.zip"
    tmpzip = None
    if FETCH_BYTES is None:                       # stream big dumps (npm is ~220 MB) to disk instead of holding them in memory
        import tempfile, shutil
        req = urllib.request.Request(url, headers=dict({"User-Agent": UA}, **(headers or {})))
        try:
            with urllib.request.urlopen(req, timeout=300) as r, tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tf:
                shutil.copyfileobj(r, tf, 1 << 20); tmpzip = tf.name; st, rh = r.status, dict(r.headers)
        except urllib.error.HTTPError as e:
            if e.code == 304: return dict(skipped=True, note="not modified")
            raise RuntimeError(f"OSV {eco}: HTTP {e.code}")
        src = tmpzip
    else:
        st, data, rh = fetch(url, headers)
        if st == 304: return dict(skipped=True, note="not modified")
        if st != 200: raise RuntimeError(f"OSV {eco}: HTTP {st}")
        src = io.BytesIO(data)
    by = {}; n = 0
    with zipfile.ZipFile(src) as zf:
        for name in zf.namelist():
            if not name.endswith(".json"): continue
            try: d = json.loads(zf.read(name))
            except ValueError: continue
            for pkg, line in compact_osv(d, eco): by.setdefault(pkg, []).append(json.dumps(line, ensure_ascii=False, separators=(",", ":")).encode()); n += 1
    if tmpzip:
        try: os.unlink(tmpzip)
        except OSError: pass
    d = os.path.join(db_dir(), "osv"); os.makedirs(d, exist_ok=True)
    safe = eco.lower().replace(" ", "-")
    idx, off = {}, 0
    tmp = os.path.join(d, safe + ".jsonl.tmp")
    with open(tmp, "wb") as fh:
        for pkg in sorted(by):
            blob = b"\n".join(by[pkg]) + b"\n"; fh.write(blob); idx[pkg] = [off, len(blob)]; off += len(blob)
    os.replace(tmp, os.path.join(d, safe + ".jsonl"))
    with open(os.path.join(d, safe + ".idx"), "w", encoding="utf-8") as fh: json.dump(idx, fh, separators=(",", ":"))
    return dict(records=n, packages=len(idx), bytes=off, last_modified=rh.get("Last-Modified") or rh.get("last-modified"), etag=rh.get("ETag") or rh.get("etag"))


def build_kev(progress=print):
    st, data, _ = fetch(KEV_URL, timeout=60)
    if st != 200: raise RuntimeError(f"KEV: HTTP {st}")
    v = json.loads(data)["vulnerabilities"]
    os.makedirs(db_dir(), exist_ok=True)
    with open(os.path.join(db_dir(), "kev.jsonl"), "w", encoding="utf-8") as fh:
        for x in v: fh.write(json.dumps(dict(id=x["cveID"], vendor=x.get("vendorProject"), product=x.get("product"), name=x.get("vulnerabilityName"), date=x.get("dateAdded"), action=(x.get("requiredAction") or "")[:200], ransomware=x.get("knownRansomwareCampaignUse"), cwe=x.get("cwes") or []), ensure_ascii=False) + "\n")
    return dict(records=len(v))


def build_eol(progress=print):
    st, data, _ = fetch(EOL_URL, timeout=90)
    if st != 200: raise RuntimeError(f"endoflife.date: HTTP {st}")
    res = json.loads(data).get("result") or json.loads(data)
    os.makedirs(db_dir(), exist_ok=True); n = 0
    with open(os.path.join(db_dir(), "eol.jsonl"), "w", encoding="utf-8") as fh:
        for p in res:
            rel = [dict(cycle=str(r.get("name")), eol=r.get("eolFrom") if isinstance(r.get("eolFrom"), str) else None, eol_flag=bool(r.get("isEol")) and not isinstance(r.get("eolFrom"), str), latest=((r.get("latest") or {}).get("name")), support=r.get("eoasFrom") if isinstance(r.get("eoasFrom"), str) else None, lts=bool(r.get("isLts"))) for r in p.get("releases", [])]
            fh.write(json.dumps(dict(p=p.get("name"), label=p.get("label"), tags=p.get("tags"), cycles=rel), ensure_ascii=False, separators=(",", ":")) + "\n"); n += 1
    return dict(records=n)


def build_nvd(products, progress=print, api_key=None):
    d = os.path.join(db_dir(), "nvd"); os.makedirs(d, exist_ok=True); res = {}
    pause = 0.7 if api_key else 6.5
    for key in products:
        if key not in NVD_PRODUCTS: continue
        cpe, label = NVD_PRODUCTS[key]; vendor, prod = cpe.split(":")
        start, total, rows = 0, None, []
        while total is None or start < total:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:a:{cpe}&resultsPerPage=2000&startIndex={start}&noRejected"
            st, data, _ = fetch(url, {"apiKey": api_key} if api_key else None, timeout=120)
            if st != 200: progress(f"    NVD {label}: HTTP {st} (skipped; retry later or set NVD_API_KEY)"); break
            j = json.loads(data); total = j.get("totalResults", 0)
            for it in j.get("vulnerabilities", []):
                c = it["cve"]; sc = 0
                for k in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30"):
                    if c.get("metrics", {}).get(k): sc = c["metrics"][k][0]["cvssData"].get("baseScore") or 0; break
                cfg = []
                for node in c.get("configurations", []):
                    for n in node.get("nodes", []):
                        for m in n.get("cpeMatch", []):
                            if not m.get("vulnerable"): continue
                            parts = m.get("criteria", "").split(":")
                            if len(parts) < 6 or parts[3] != vendor or parts[4] != prod: continue
                            cfg.append([m.get("versionStartIncluding"), m.get("versionStartExcluding"), m.get("versionEndIncluding"), m.get("versionEndExcluding"), parts[5] if parts[5] not in ("*", "-") else None])
                if cfg: rows.append(dict(id=c["id"], sc=sc, sm=next((x["value"] for x in c.get("descriptions", []) if x.get("lang") == "en"), "")[:160], pub=(c.get("published") or "")[:10], cfg=cfg))
            start += 2000; time.sleep(pause)
        with open(os.path.join(d, key + ".jsonl"), "w", encoding="utf-8") as fh:
            for r in rows: fh.write(json.dumps(r, ensure_ascii=False, separators=(",", ":")) + "\n")
        res[key] = len(rows); progress(f"    NVD {label}: {len(rows)} CVEs")
    return res


def sync(ecosystems=None, sources=None, nvd_products=None, progress=print):
    """Download and build the database. Returns the meta dict (also written to meta.json)."""
    sources = sources or ["osv", "kev", "eol"]
    os.makedirs(db_dir(), exist_ok=True)
    mp = os.path.join(db_dir(), "meta.json")
    try:
        with open(mp, encoding="utf-8") as fh: meta = json.load(fh)
    except (OSError, ValueError): meta = {}
    meta.setdefault("osv", {}); meta["updated"] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    if "osv" in sources:
        for eco in (ecosystems or DEFAULT_ECOSYSTEMS):
            t = time.time(); old = meta["osv"].get(eco, {})
            hdr = {"If-None-Match": old["etag"]} if old.get("etag") and os.path.exists(os.path.join(db_dir(), "osv", eco.lower().replace(" ", "-") + ".jsonl")) else None
            try:
                r = build_osv(eco, progress, hdr)
                if r.get("skipped"): progress(f"  OSV {eco}: up to date"); continue
                r["synced"] = meta["updated"]; meta["osv"][eco] = r; progress(f"  OSV {eco}: {r['records']:,} advisories, {r['packages']:,} packages, {r['bytes'] / 1e6:.1f} MB ({time.time() - t:.0f}s)")
            except (RuntimeError, OSError, zipfile.BadZipFile) as e: progress(f"  OSV {eco}: FAILED ({e})")
    if "kev" in sources:
        try: meta["kev"] = dict(build_kev(progress), synced=meta["updated"]); progress(f"  CISA KEV: {meta['kev']['records']:,} actively exploited CVEs")
        except (RuntimeError, OSError, ValueError) as e: progress(f"  CISA KEV: FAILED ({e})")
    if "eol" in sources:
        try: meta["eol"] = dict(build_eol(progress), synced=meta["updated"]); progress(f"  endoflife.date: {meta['eol']['records']:,} products")
        except (RuntimeError, OSError, ValueError) as e: progress(f"  endoflife.date: FAILED ({e})")
    if "nvd" in sources:
        meta["nvd"] = dict(build_nvd(nvd_products or list(NVD_PRODUCTS), progress, os.environ.get("NVD_API_KEY")), synced=meta["updated"])
    with open(mp, "w", encoding="utf-8") as fh: json.dump(meta, fh, indent=1)
    return meta


# ------------------------------------------------------------------ query
class DB:
    def __init__(self):
        self.dir = db_dir(); self._idx = {}; self._kev = None; self._eol = None; self._nvd = {}
        try:
            with open(os.path.join(self.dir, "meta.json"), encoding="utf-8") as fh: self.meta = json.load(fh)
        except (OSError, ValueError): self.meta = {}

    def has_osv(self, eco): return os.path.exists(os.path.join(self.dir, "osv", eco.lower().replace(" ", "-") + ".idx"))

    def age_days(self):
        try: return (datetime.datetime.now(datetime.timezone.utc) - datetime.datetime.fromisoformat(self.meta["updated"])).days
        except (KeyError, ValueError): return None

    def osv(self, eco, name, version):
        """advisories (compact dicts) that affect eco/name@version."""
        safe = eco.lower().replace(" ", "-"); path = os.path.join(self.dir, "osv", safe + ".jsonl")
        if safe not in self._idx:
            try:
                with open(os.path.join(self.dir, "osv", safe + ".idx"), encoding="utf-8") as fh: self._idx[safe] = json.load(fh)
            except (OSError, ValueError): self._idx[safe] = {}
        ent = self._idx[safe].get(norm(eco, name))
        if not ent: return []
        with open(path, "rb") as fh: fh.seek(ent[0]); blob = fh.read(ent[1])
        out = []
        for ln in blob.splitlines():
            try: r = json.loads(ln)
            except ValueError: continue
            if in_ranges(version, r.get("rg"), set(r.get("vs") or [])): out.append(r)
        return out

    def kev(self):
        if self._kev is None:
            self._kev = {}
            try:
                with open(os.path.join(self.dir, "kev.jsonl"), encoding="utf-8") as fh:
                    for ln in fh:
                        r = json.loads(ln); self._kev[r["id"]] = r
            except (OSError, ValueError): pass
        return self._kev

    def eol(self, product):
        if self._eol is None:
            self._eol = {}
            try:
                with open(os.path.join(self.dir, "eol.jsonl"), encoding="utf-8") as fh:
                    for ln in fh:
                        r = json.loads(ln); self._eol[r["p"]] = r
            except (OSError, ValueError): pass
        return self._eol.get(product)

    def nvd(self, key, version):
        if key not in self._nvd:
            rows = []
            try:
                with open(os.path.join(self.dir, "nvd", key + ".jsonl"), encoding="utf-8") as fh: rows = [json.loads(ln) for ln in fh]
            except (OSError, ValueError): pass
            self._nvd[key] = rows
        out = []
        for r in self._nvd[key]:
            for si, se, ei, ee, ex in r["cfg"]:
                ok = (vcmp(version, ex) == 0) if ex else ((not si or vcmp(version, si) >= 0) and (not se or vcmp(version, se) > 0) and (not ei or vcmp(version, ei) <= 0) and (not ee or vcmp(version, ee) < 0) and (si or se or ei or ee))
                if ok: out.append(r); break
        return sorted(out, key=lambda r: -(r.get("sc") or 0))

    def status(self):
        m = self.meta
        files = {}
        for root, _d, fs in os.walk(self.dir):
            for f in fs:
                try: files[os.path.relpath(os.path.join(root, f), self.dir)] = os.path.getsize(os.path.join(root, f))
                except OSError: pass
        return dict(dir=self.dir, exists=bool(m), updated=m.get("updated"), age_days=self.age_days(), osv={e: dict(advisories=v.get("records"), packages=v.get("packages")) for e, v in (m.get("osv") or {}).items()}, kev=(m.get("kev") or {}).get("records"),
                    eol=(m.get("eol") or {}).get("records"), nvd=m.get("nvd"), total_mb=round(sum(files.values()) / 1e6, 1))


def open_db():
    db = DB()
    return db if db.meta else None
