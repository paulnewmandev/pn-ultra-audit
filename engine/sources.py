"""Source files embedded in the report for the read-only code viewer.
Budgeted (default 5 MB total, 2 MB per file), secrets masked line by line, binary files shown as a hex preview, files over the budget spilled to lazy-loaded sidecar chunks, sensitive files represented by a reason
instead of content. Files that have findings always come first. Read-only; never modifies the project."""
import os, re

SENSITIVE = re.compile(r"(^|/)(\.env(\.[\w.-]+)?|id_(rsa|dsa|ecdsa|ed25519)|[^/]*\.(pem|key|p12|pfx|jks|keystore|ppk|kdbx|1pux)|\.npmrc|\.pypirc|\.netrc|\.htpasswd|credentials|\.git-credentials|[^/]*\.tfstate(\.backup)?|[^/]*secrets?\.(ya?ml|json)|kubeconfig|[^/]*service-?account[^/]*\.json)$", re.I)
SAFE_ENV = re.compile(r"(example|sample|template|dist|\.dev\.)", re.I)


def _decode(raw):
    """bytes -> (text, kind) or (None, 'binary'). Handles UTF-8/UTF-16 (BOM or NUL-interleaved)/legacy 8-bit; binary only if it really is binary."""
    if raw[:3] == b"\xef\xbb\xbf": return raw[3:].decode("utf-8", "replace"), "utf-8"
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"): return raw.decode("utf-16", "replace"), "utf-16"
    head = raw[:8000]
    if b"\0" in head:
        ev, od = head[0::2].count(0), head[1::2].count(0); n = max(len(head) // 2, 1)
        if od > n * .4 and ev < n * .05: return raw.decode("utf-16-le", "replace"), "utf-16"
        if ev > n * .4 and od < n * .05: return raw.decode("utf-16-be", "replace"), "utf-16"
        return None, "binary"
    if head[:4] in (b"\x7fELF", b"%PDF", b"PK\x03\x04", b"\x89PNG", b"GIF8", b"\xff\xd8\xff\xe0", b"\xff\xd8\xff\xe1"): return None, "binary"
    ctrl = sum(1 for b in head if b < 9 or 13 < b < 32)
    if head and ctrl > len(head) * .15: return None, "binary"
    try: return raw.decode("utf-8"), "utf-8"
    except UnicodeDecodeError: return raw.decode("cp1252", "replace"), "latin-1"


def _hex(raw, n=2048):
    rows = []
    for o in range(0, min(len(raw), n), 16):
        c = raw[o:o + 16]
        rows.append(f"{o:08x}  {' '.join(f'{b:02x}' for b in c):<47}  {''.join(chr(b) if 32 <= b < 127 else '.' for b in c)}")
    return "\n".join(rows)


def collect(root, files, findings, mode="auto", budget=5_000_000, redact=lambda s: s, per_file=2_000_000, side=None):
    """-> {rel: {"t": text|None, "n": lines, "b": bytes, "e": ext, "x": reason|None, "tr": truncated?, "hx": hex preview?, "c": sidecar chunk}}
    Files over the inline budget are not dropped: with `side` (a dict) their text is stored there (rel -> entry) for lazy-loaded sidecar chunks."""
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
        try:
            with open(ab, "rb") as fh: raw = fh.read(per_file + 1)
        except OSError: ent["x"] = "unreadable"; out[rel] = ent; continue
        text, kind = _decode(raw[:per_file])
        if text is None:
            ent.update(x="binary", t=_hex(raw), hx=1, n=len(_hex(raw).split("\n"))); out[rel] = ent; continue
        tr = len(raw) > per_file
        if tr: text = text[:text.rfind("\n")] if "\n" in text else text
        lines = [redact(l[:4000]) for l in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
        ent.update(t="\n".join(lines), n=len(lines), tr=1 if tr else 0)
        if kind != "utf-8": ent["enc"] = kind
        if not must and total + len(ent["t"]) > budget:
            if side is not None: side[rel] = {k: ent.pop(k) for k in ("t", "n", "tr", "enc", "hx") if k in ent}; ent["x"] = "lazy"
            else: ent.pop("t"); ent["x"] = "budget"
            out[rel] = ent; continue
        total += len(ent["t"])
        out[rel] = ent
    return out
