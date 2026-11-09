"""SBOM (CycloneDX 1.5 JSON) + license risk from manifests/lockfiles. Offline; no package installation."""
import json, os, re, datetime
COPYLEFT = re.compile(r"\b(AGPL|GPL|LGPL|SSPL|EUPL|CPAL|OSL|MPL|CC-BY-SA|BUSL)", re.I)
STRONG = re.compile(r"\b(AGPL|SSPL|GPL-?[23]|GPL(?!-?\w*LGPL)|BUSL|CPAL)", re.I)


def _purl(eco, name, ver): return f"pkg:{eco}/{name.replace('@', '%40', 1) if name.startswith('@') else name}@{ver}"


def build(root, files):
    comps, seen, lic = [], set(), {}
    def add(eco, name, ver, license=None, direct=None):
        k = (eco, name, ver)
        if not name or not ver or k in seen: return
        seen.add(k); c = {"type": "library", "name": name, "version": ver, "purl": _purl(eco, name, ver), "bom-ref": _purl(eco, name, ver)}
        if license: c["licenses"] = [{"license": {"id": license}}] if re.fullmatch(r"[A-Za-z0-9.\-+]+", license) else [{"expression": license}]; lic[license] = lic.get(license, 0) + 1
        comps.append(c)
    for rel, ab, e, sz in files:
        b = os.path.basename(rel); depth = rel.count("/")
        if depth > 2 or sz > 30_000_000: continue
        try: t = open(ab, errors="ignore").read()
        except OSError: continue
        try:
            if b == "package-lock.json":
                j = json.loads(t)
                for p, v in (j.get("packages") or {}).items():
                    if p: add("npm", v.get("name") or p.split("node_modules/")[-1], v.get("version"), v.get("license") if isinstance(v.get("license"), str) else None)
                for n, v in (j.get("dependencies") or {}).items(): add("npm", n, v.get("version"))
            elif b == "composer.lock":
                j = json.loads(t)
                for sec in ("packages", "packages-dev"):
                    for v in j.get(sec, []): add("composer", v["name"], v.get("version", "").lstrip("v"), "/".join(v.get("license", []) or []) or None)
            elif b == "requirements.txt":
                for l in t.splitlines():
                    m = re.match(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([\w.\-+]+)", l)
                    if m: add("pypi", m.group(1).lower(), m.group(2))
            elif b == "poetry.lock":
                for m in re.finditer(r'\[\[package\]\]\s*name = "([^"]+)"\s*version = "([^"]+)"', t): add("pypi", m.group(1).lower(), m.group(2))
            elif b == "Pipfile.lock":
                j = json.loads(t)
                for sec in ("default", "develop"):
                    for n, v in (j.get(sec) or {}).items(): add("pypi", n.lower(), (v.get("version") or "").lstrip("="))
            elif b == "go.sum":
                for m in re.finditer(r"^(\S+) (v[\w.\-+]+)(?:/go\.mod)? h1:", t, re.M): add("golang", m.group(1), m.group(2))
            elif b == "Cargo.lock":
                for m in re.finditer(r'\[\[package\]\]\s*name = "([^"]+)"\s*version = "([^"]+)"', t): add("cargo", m.group(1), m.group(2))
            elif b == "Gemfile.lock":
                for m in re.finditer(r"^    ([A-Za-z0-9_.\-]+) \(([\d][\w.\-]*)\)", t, re.M): add("gem", m.group(1), m.group(2))
            elif b == "pubspec.lock":
                for m in re.finditer(r"^  ([a-z0-9_]+):\s*\n(?:    .*\n)*?    version: \"?([\w.\-+]+)", t, re.M): add("pub", m.group(1), m.group(2))
            elif b == "yarn.lock":
                for m in re.finditer(r'^"?((?:@[^/\s"]+/)?[^@\s"]+)@[^\n]*\n\s+version "?([^"\n]+)"?', t, re.M): add("npm", m.group(1), m.group(2))
            elif b == "pnpm-lock.yaml":
                for m in re.finditer(r"^\s{2,4}/?((?:@[^/\s]+/)?[^@\s:/]+)@([\w.\-+]+)(?:\(.*?\))?:\s*$", t, re.M): add("npm", m.group(1), m.group(2))
        except (ValueError, KeyError, TypeError): continue
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "metadata": {"timestamp": datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z", "tools": {"components": [{"type": "application", "name": "PN-Ultra-Audit"}]}}, "components": comps}
    copyleft = sorted(l for l in lic if COPYLEFT.search(l)); strong = sorted(l for l in lic if STRONG.search(l))
    return bom, dict(components=len(comps), ecosystems=sorted({c["purl"].split("/")[0][4:] for c in comps}), licenses=dict(sorted(lic.items(), key=lambda kv: -kv[1])[:15]), with_license=sum(lic.values()), copyleft=copyleft, strong_copyleft=strong)
