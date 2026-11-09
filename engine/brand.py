"""Project branding and repository tree for the report.
Detects the audited project's own logo and primary colors (manifest, CSS variables, Tailwind, SCSS, Android, Flutter, iOS) and builds a
compact file tree annotated with findings. Read-only; the logo is embedded in the (local, offline) report as a data URI."""
import base64, json, os, re

HEX = re.compile(r"#(?:[0-9a-fA-F]{6}|[0-9a-fA-F]{3})\b")
LOGO_NAMES = re.compile(r"(^|/)(logo|brand|logotype|wordmark|icon|app-?icon|favicon|apple-touch-icon|android-chrome-192x192|icon-192|logo-?(light|dark|full|mark|icon|small|large|color))\.(svg|png|jpe?g|webp)$", re.I)
LOGO_DIRS = re.compile(r"(^|/)(public|static|assets|images|img|brand|branding|resources|res/drawable|media|src/assets|web|www|docs|\.github)(/|$)", re.I)
VAR_RE = re.compile(r"--(?:color-)?(primary|brand|accent|secondary|main|theme)(?:-(?:color|500|600|base))?\s*:\s*(#[0-9a-fA-F]{3,8})", re.I)
SCSS_RE = re.compile(r"\$(primary|brand|accent|secondary)(?:-color)?\s*:\s*(#[0-9a-fA-F]{3,8})", re.I)
TW_RE = re.compile(r"[\"']?(primary|brand|accent|secondary)[\"']?\s*:\s*(?:\{[^}]*?(?:DEFAULT|500)[\"']?\s*:\s*)?[\"'](#[0-9a-fA-F]{3,8})[\"']", re.I)
THEME_META = re.compile(r"<meta[^>]+name=[\"']theme-color[\"'][^>]+content=[\"'](#[0-9a-fA-F]{3,8})", re.I)
ANDROID_RE = re.compile(r"<color\s+name=[\"'](colorPrimary|primary|colorAccent|accent|colorSecondary|brand\w*)[\"']\s*>\s*(#[0-9a-fA-F]{6,8})", re.I)
FLUTTER_RE = re.compile(r"(?:seedColor|primaryColor|primary)\s*:\s*(?:const\s+)?Color\(\s*0x[0-9a-fA-F]{2}([0-9a-fA-F]{6})\s*\)", re.I)
WEIGHT = {"primary": 10, "brand": 10, "colorprimary": 10, "main": 6, "theme": 8, "accent": 6, "coloraccent": 6, "secondary": 5, "colorsecondary": 5}


def _read(ab, cap=200_000):
    try:
        with open(ab, encoding="utf-8", errors="ignore") as fh: return fh.read(cap)
    except OSError: return ""


def _norm(h):
    h = h.lstrip("#")
    if len(h) == 3: h = "".join(c * 2 for c in h)
    h = h[:6].lower()
    return "#" + h if re.fullmatch(r"[0-9a-f]{6}", h) else None


def _lum(h):
    r, g, b = (int(h[i:i + 2], 16) / 255 for i in (1, 3, 5))
    f = lambda c: c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)


def _sat(h):
    r, g, b = (int(h[i:i + 2], 16) for i in (1, 3, 5)); mx, mn = max(r, g, b), min(r, g, b)
    return 0 if mx == 0 else (mx - mn) / mx


def _usable(h):
    """A brand color must not be near-white/near-black/grey (useless as an accent)."""
    return h and 0.04 < _lum(h) < 0.85 and _sat(h) > 0.18


def colors_of(files, root):
    found = {}  # hex -> score
    def add(hx, w):
        n = _norm(hx)
        if n and _usable(n): found[n] = found.get(n, 0) + w
    for rel, ab, ext, sz in files:
        if sz > 400_000 or "node_modules" in rel or "/vendor/" in rel: continue
        base = os.path.basename(rel).lower()
        if base in ("manifest.webmanifest", "manifest.json", "site.webmanifest"):
            try:
                j = json.loads(_read(ab))
                for k in ("theme_color", "background_color"):
                    if isinstance(j.get(k), str): add(j[k], 12 if k == "theme_color" else 3)
            except ValueError: pass
        elif ext in ("css", "scss", "sass", "less", "styl", "pcss"):
            t = _read(ab)
            for m in VAR_RE.finditer(t): add(m.group(2), WEIGHT.get(m.group(1).lower(), 4) + 2)
            for m in SCSS_RE.finditer(t): add(m.group(2), WEIGHT.get(m.group(1).lower(), 4) + 1)
        elif re.search(r"tailwind\.config\.|theme\.(js|ts)$|colors?\.(js|ts)$|variables\.(scss|css)$", base):
            t = _read(ab)
            for m in TW_RE.finditer(t): add(m.group(2), WEIGHT.get(m.group(1).lower(), 4) + 3)
        elif ext in ("html", "htm", "php", "twig", "blade", "ejs", "vue", "astro"):
            for m in THEME_META.finditer(_read(ab, 60_000)): add(m.group(1), 8)
        elif ext == "xml" and "values" in rel and base.startswith("colors"):
            for m in ANDROID_RE.finditer(_read(ab)): add("#" + m.group(2)[-6:], WEIGHT.get(m.group(1).lower(), 4) + 4)
        elif ext == "dart":
            for m in FLUTTER_RE.finditer(_read(ab, 100_000)): add("#" + m.group(1), 7)
        elif ext == "json" and "colorset" in rel.lower():
            try:
                for c in json.loads(_read(ab)).get("colors", []):
                    comp = (c.get("color") or {}).get("components") or {}
                    if comp: add("#%02x%02x%02x" % tuple(int(float(comp.get(k, 0)) * (255 if float(comp.get(k, 0)) <= 1 else 1)) for k in ("red", "green", "blue")), 9)
            except (ValueError, TypeError): pass
    return [h for h, _ in sorted(found.items(), key=lambda kv: -kv[1])]


SKIP_DIRS = {"node_modules", "vendor", ".git", "dist", "build", "examples", "target", "__pycache__", ".venv", "venv", "Pods", ".next", ".nuxt", "coverage"}


def _images(root, depth=4):
    """Image files are excluded from the scan file list, so look on disk (bounded depth, common noise skipped)."""
    out = []
    if not root or not os.path.isdir(root): return out
    base = root.rstrip(os.sep).count(os.sep)
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in SKIP_DIRS and not d.startswith(".") or d == ".github"]
        if dp.count(os.sep) - base >= depth: dn[:] = []
        for f in fn:
            ext = f.rsplit(".", 1)[-1].lower() if "." in f else ""
            if ext in ("svg", "png", "jpg", "jpeg", "webp"):
                ab = os.path.join(dp, f)
                try: sz = os.path.getsize(ab)
                except OSError: continue
                out.append((os.path.relpath(ab, root).replace(os.sep, "/"), ab, ext, sz))
    return out


def logo_of(files, root):
    best = None
    for rel, ab, ext, sz in list(files) + _images(root):
        if ext not in ("svg", "png", "jpg", "jpeg", "webp") or "node_modules" in rel or "/vendor/" in rel or rel.startswith("docs/img/"): continue
        if not LOGO_NAMES.search(rel): continue
        if sz > (120_000 if ext == "svg" else 250_000) or sz < 100: continue
        name = os.path.basename(rel).lower(); score = 0
        score += 40 if name.startswith("logo") else 20 if name.startswith(("brand", "icon", "app")) else 5
        score += 10 if ext == "svg" else 4 if ext == "png" else 0
        score += 8 if LOGO_DIRS.search(rel) else 0
        score -= rel.count("/")
        score -= 12 if re.search(r"favicon|apple-touch|android-chrome|-\d{2,3}x\d{2,3}", name) else 0
        if best is None or score > best[0]: best = (score, rel, ab, ext)
    if not best: return None
    _, rel, ab, ext = best
    try: data = open(ab, "rb").read()
    except OSError: return None
    if ext == "svg":
        txt = data.decode("utf-8", "ignore")
        if re.search(r"<script|onload\s*=|onerror\s*=|javascript:", txt, re.I): return None  # never embed active content
    mime = {"svg": "image/svg+xml", "png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "webp": "image/webp"}[ext]
    return dict(path=rel, data_uri=f"data:{mime};base64," + base64.b64encode(data).decode())


def name_of(files, root, fallback):
    for rel, ab, ext, sz in files:
        b = os.path.basename(rel).lower()
        if rel.count("/") > 1: continue
        if b in ("manifest.webmanifest", "manifest.json"):
            try:
                j = json.loads(_read(ab)); n = j.get("name") or j.get("short_name")
                if n: return str(n)[:60]
            except ValueError: pass
    for rel, ab, ext, sz in files:
        if rel.lower() in ("readme.md", "readme.rst", "readme.markdown", "readme.txt"):
            m = re.search(r"^#\s+(.+?)\s*$", _read(ab, 8000), re.M)
            if m:
                t = re.sub(r"[`*_\[\]]|!\[[^\]]*\]\([^)]*\)|<[^>]+>", "", m.group(1)).strip()
                if 2 <= len(t) <= 60: return t
    return fallback


def detect(files, root, fallback_name):
    cols = colors_of(files, root); lg = logo_of(files, root)
    return dict(name=name_of(files, root, fallback_name), logo=lg, colors=cols[:4], primary=cols[0] if cols else None, secondary=cols[1] if len(cols) > 1 else None,
                source="project files" if (cols or lg) else None)


# ---------------- repository tree ----------------
def tree(files, findings, max_nodes=1800):
    """Nested dict {n: name, f: findings_in_subtree, s: worst severity, c: [children], l: lines?}. Directories sorted by risk then name."""
    order = ["critical", "high", "medium", "low", "info"]
    per = {}
    for f in findings:
        if f.get("status") != "confirmed" and f.get("status") != "needs_validation": continue
        p = (f.get("location") or {}).get("file")
        if not p or p == "." or "://" in p or p.startswith(("aws:", "ssh:")): continue
        e = per.setdefault(p, dict(n=0, s=None))
        e["n"] += 1; s = f.get("severity")
        if s in order and (e["s"] is None or order.index(s) < order.index(e["s"])): e["s"] = s
    root = dict(n="", c={}, f=0, s=None, files=0)
    for rel, ab, ext, sz in files:
        parts = [p for p in rel.split("/") if p]
        if not parts: continue
        node = root; node["files"] += 1
        for i, p in enumerate(parts):
            last = i == len(parts) - 1
            ch = node["c"].setdefault(p, dict(n=p, c={}, f=0, s=None, files=0, leaf=last))
            if not last: ch["files"] += 1
            node = ch
        e = per.get(rel)
        if e:
            node["f"] = e["n"]; node["s"] = e["s"]
    def finalize(n):
        for c in n["c"].values(): finalize(c)
        if not n.get("leaf"):
            n["f"] = sum(c["f"] for c in n["c"].values())
            sv = [c["s"] for c in n["c"].values() if c["s"]]
            n["s"] = min(sv, key=order.index) if sv else None
    finalize(root)
    count = [0]
    def out(n, depth):
        kids = list(n["c"].values())
        kids.sort(key=lambda c: (-(c["f"] > 0), order.index(c["s"]) if c["s"] else 9, -c["f"], 0 if not c.get("leaf") else 1, c["n"].lower()))
        res = []
        for c in kids:
            count[0] += 1
            if count[0] > max_nodes:
                res.append(dict(n="…", t="more")); break
            d = dict(n=c["n"])
            if c.get("leaf"): d["t"] = "f"
            else:
                d["t"] = "d"; d["k"] = c["files"]
                # collapse clean folders beyond depth 2 into a count to keep the report small
                d["c"] = out(c, depth + 1) if (c["f"] > 0 or depth < 2) else []
            if c["f"]: d["f"] = c["f"]
            if c["s"]: d["s"] = c["s"]
            res.append(d)
        return res
    return dict(files=root["files"], findings=root["f"], c=out(root, 0))


def tree_text(t, depth=3, width=100):
    """Plain-text tree for REPORT.md (dirs with file counts, flagged files with finding counts)."""
    lines = []
    def walk(nodes, prefix, d):
        for i, n in enumerate(nodes):
            last = i == len(nodes) - 1; br = "└── " if last else "├── "
            lab = n["n"] + ("/" if n.get("t") == "d" else "")
            extra = []
            if n.get("t") == "d" and n.get("k"): extra.append(f"{n['k']} files")
            if n.get("f"): extra.append(f"{n['f']} finding{'s' if n['f'] != 1 else ''}" + (f", worst {n['s']}" if n.get("s") else ""))
            lines.append((prefix + br + lab + ("  (" + ", ".join(extra) + ")" if extra else ""))[:width])
            if n.get("c") and d < depth: walk(n["c"], prefix + ("    " if last else "│   "), d + 1)
    walk(t["c"], "", 1)
    return "\n".join(lines)
