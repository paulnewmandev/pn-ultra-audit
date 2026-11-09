"""Source files embedded in the report for the read-only code viewer.
Budgeted (default 5 MB total, 300 KB per file), secrets masked line by line, binary / oversized / sensitive files represented by a reason
instead of content. Files that have findings always come first. Read-only; never modifies the project."""
import os, re

SENSITIVE = re.compile(r"(^|/)(\.env(\.[\w.-]+)?|id_(rsa|dsa|ecdsa|ed25519)|[^/]*\.(pem|key|p12|pfx|jks|keystore|ppk|kdbx|1pux)|\.npmrc|\.pypirc|\.netrc|\.htpasswd|credentials|\.git-credentials|[^/]*\.tfstate(\.backup)?|[^/]*secrets?\.(ya?ml|json)|kubeconfig|[^/]*service-?account[^/]*\.json)$", re.I)
SAFE_ENV = re.compile(r"(example|sample|template|dist|\.dev\.)", re.I)


def _text(raw):
    return raw.decode("utf-8", "replace")


def collect(root, files, findings, mode="auto", budget=5_000_000, redact=lambda s: s, per_file=300_000):
    """-> {rel: {"t": text|None, "n": lines, "b": bytes, "e": ext, "x": reason|None, "tr": truncated?}}"""
    if mode == "none": return {}
    count = {}
    for f in findings:
        p = (f.get("location") or {}).get("file")
        if p and p != "." and "://" not in p and not p.startswith(("aws:", "ssh:", "vercel:")): count[p] = count.get(p, 0) + 1
    entries = {rel: (ab, sz, ext) for rel, ab, ext, sz in files}
    for p in count:
        if p not in entries:
            ab = os.path.join(root, p)
            try: entries[p] = (ab, os.path.getsize(ab), p.rsplit(".", 1)[-1].lower() if "." in os.path.basename(p) else "")
            except OSError: pass
    need = sorted((p for p in count if p in entries), key=lambda p: -count[p])
    rest = [] if mode == "findings" else sorted((p for p in entries if p not in count), key=lambda p: entries[p][1])
    out, total = {}, 0
    for rel in need + rest:
        ab, sz, ext = entries[rel]
        ent = {"e": ext, "b": sz}
        if SENSITIVE.search(rel) and not SAFE_ENV.search(os.path.basename(rel)): ent["x"] = "sensitive"; out[rel] = ent; continue
        must = rel in count
        if not must and total >= budget: ent["x"] = "budget"; out[rel] = ent; continue
        try:
            with open(ab, "rb") as fh: raw = fh.read(per_file + 1)
        except OSError: ent["x"] = "unreadable"; out[rel] = ent; continue
        if b"\0" in raw[:8000]: ent["x"] = "binary"; out[rel] = ent; continue
        tr = len(raw) > per_file
        text = _text(raw[:per_file])
        if tr: text = text[:text.rfind("\n")] if "\n" in text else text
        lines = [redact(l[:1500]) for l in text.split("\n")]
        ent.update(t="\n".join(lines), n=len(lines), tr=1 if tr else 0)
        total += len(ent["t"])
        if total > budget * 2 and not must: ent.pop("t"); ent["x"] = "budget"
        out[rel] = ent
    return out
