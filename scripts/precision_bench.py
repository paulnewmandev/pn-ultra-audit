#!/usr/bin/env python3
"""Precision benchmark: audit mature, widely reviewed code and list what the tool CONFIRMS.
On such code almost every confirmed critical/high finding is a false positive, so the numbers here are a conservative upper bound on the
false-positive rate.  Usage:
    python3 scripts/precision_bench.py <dir> [<dir> ...] [--only security,quality] [--samples 3] [--min-sev medium]
Prints, per directory: LOC, confirmed findings per KLOC (by severity), the noisiest rules and a few evidence samples to review by hand.
Never writes into the audited directories."""
import argparse, collections, json, os, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEV = ["critical", "high", "medium", "low", "info"]


def bench(path, only, extra, samples, min_sev):
    with tempfile.TemporaryDirectory() as out:
        cmd = [sys.executable, os.path.join(ROOT, "audit.py"), path, "--out", out, "--color", "never", "--quiet", "--lang", "en"]
        if only: cmd += ["--only", only]
        for e in extra: cmd += ["--exclude", e]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        runs = [d for d in os.listdir(out) if d.startswith("run-")]
        if not runs: return dict(error=(r.stderr or r.stdout)[-300:])
        rd = os.path.join(out, sorted(runs)[-1])
        f = json.load(open(os.path.join(rd, "findings.json"), encoding="utf-8")); m = json.load(open(os.path.join(rd, "metrics.json"), encoding="utf-8"))
    ncloc = m.get("ncloc") or 1
    conf = [x for x in f if x["status"] == "confirmed" and SEV.index(x.get("severity") or "info") <= SEV.index(min_sev)]
    by_sev = collections.Counter(x["severity"] for x in conf)
    by_rule = collections.defaultdict(list)
    for x in conf: by_rule[x["rule"]].append(x)
    return dict(ncloc=ncloc, files=m.get("files"), conf=len(conf), review=sum(1 for x in f if x["status"] != "confirmed"), by_sev=by_sev, per_kloc=round(len(conf) / (ncloc / 1000), 2),
                top=[(r_, len(v), v[:samples]) for r_, v in sorted(by_rule.items(), key=lambda kv: -len(kv[1]))[:15]])


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("dirs", nargs="+"); ap.add_argument("--only", default="security,quality,docs,tests"); ap.add_argument("--exclude", action="append", default=[])
    ap.add_argument("--samples", type=int, default=2); ap.add_argument("--min-sev", default="low", choices=SEV); ap.add_argument("--json", help="write the summary to this file")
    a = ap.parse_args(); allr = {}
    for d in a.dirs:
        r = bench(d, a.only, a.exclude, a.samples, a.min_sev); allr[os.path.basename(d.rstrip("/"))] = {k: v for k, v in r.items() if k != "top"}
        print(f"\n== {os.path.basename(d.rstrip('/'))}: " + (r.get("error") or f"{r['ncloc']:,} LOC, {r['files']} files | confirmed {r['conf']} ({r['per_kloc']}/KLOC) "
              f"{dict((k, r['by_sev'].get(k, 0)) for k in SEV[:4])} | to review {r['review']}"))
        for rule, n, ex in r.get("top", []):
            print(f"   {n:>4}  {rule}")
            for x in ex: print(f"           {x['location']['file']}:{x['location']['line']}  {(x.get('evidence') or '')[:110].strip().splitlines()[-1] if x.get('evidence') else ''}")
    if a.json: json.dump(allr, open(a.json, "w", encoding="utf-8"), indent=1, default=dict)


if __name__ == "__main__":
    main()
