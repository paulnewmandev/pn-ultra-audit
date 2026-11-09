#!/usr/bin/env python3
"""Captures REAL terminal output of the CLI and renders pretty PNG/SVG screenshots + dashboard screenshots.
Needs Chrome/Chromium for PNGs.  python3 scripts/make_screens.py"""
import html, os, re, shutil, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "docs", "img"); os.makedirs(OUT, exist_ok=True)
PY = sys.executable
CHROME = next((c for c in ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "google-chrome", "chromium", "chromium-browser") if (os.path.exists(c) or shutil.which(c))), None)
PAL = {"0": None, "1": "b", "2": "d", "31": "#ff6b81", "32": "#4ade80", "33": "#fbbf24", "34": "#60a5fa", "35": "#e879f9", "36": "#22d3ee", "90": "#7f8aa3", "1;31": "#ff4d6d", "1;35": "#f0abfc", "1;32": "#4ade80", "1;36": "#22d3ee"}
ANSI = re.compile(r"\x1b\[([0-9;]*)m")


def run(args, cwd=ROOT, env=None):
    e = dict(os.environ); e.update(env or {}); e["COLUMNS"] = "118"
    r = subprocess.run([PY] + args, cwd=cwd, capture_output=True, text=True, env=e, timeout=300)
    return r.stdout + r.stderr


def spans(line):
    out, pos, cur = [], 0, dict(color=None, bold=False, dim=False)
    for m in ANSI.finditer(line):
        if m.start() > pos: out.append((line[pos:m.start()], dict(cur)))
        code = m.group(1) or "0"
        if code == "0": cur = dict(color=None, bold=False, dim=False)
        elif code == "1": cur["bold"] = True
        elif code == "2": cur["dim"] = True
        elif code in PAL and PAL[code]: cur["color"] = PAL[code]
        pos = m.end()
    if pos < len(line): out.append((line[pos:], dict(cur)))
    return out


CHAR_W, LINE_H = 8.15, 20.6


def term_size(text):
    plain = [re.sub(r"\x1b\[[0-9;]*m", "", l.split("\r")[-1]) for l in text.rstrip("\n").split("\n")]
    return int(max(len(l) for l in plain) * CHAR_W + 48 + 92 + 20), int(len(plain) * LINE_H + 170)


def term_html(text, title, width=None):
    width = width or term_size(text)[0]
    rows = []
    for ln in text.rstrip("\n").split("\n"):
        ln = ln.split("\r")[-1]
        rows.append("".join(f'<span style="{"color:%s;" % st["color"] if st["color"] else ""}{"font-weight:700;" if st["bold"] else ""}{"opacity:.6;" if st["dim"] else ""}">{html.escape(t)}</span>' for t, st in spans(ln)) or "&nbsp;")
    body = "\n".join(rows)
    return f'''<!doctype html><meta charset="utf-8"><body style="margin:0;background:radial-gradient(900px 500px at 90% -10%,#1e3a8a55,transparent),radial-gradient(800px 500px at -10% 110%,#7c3aed66,transparent),#070b18;padding:46px;width:{width}px;box-sizing:border-box">
<div style="border-radius:14px;background:#0d1226;border:1px solid #2a3358;box-shadow:0 30px 80px rgba(0,0,0,.55),0 0 0 1px #ffffff08 inset;overflow:hidden">
<div style="display:flex;align-items:center;gap:8px;padding:12px 16px;background:linear-gradient(#1a2142,#141a36);border-bottom:1px solid #2a3358"><i style="width:12px;height:12px;border-radius:50%;background:#ff5f57"></i><i style="width:12px;height:12px;border-radius:50%;background:#febc2e"></i><i style="width:12px;height:12px;border-radius:50%;background:#28c840"></i><span style="flex:1;text-align:center;color:#8a94b8;font:600 13px -apple-system,Segoe UI,sans-serif">{html.escape(title)}</span></div>
<pre style="margin:0;padding:20px 24px 24px;color:#d7defa;display:block;font:13.5px/1.52 'JetBrains Mono','SF Mono',Menlo,Consolas,monospace;white-space:pre;overflow:hidden">{body}</pre></div></body>'''


def shot(htmlstr, name, w, h, scale=2):
    f = tempfile.NamedTemporaryFile("w", suffix=".html", delete=False); f.write(htmlstr); f.close()
    subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--hide-scrollbars", f"--force-device-scale-factor={scale}", f"--window-size={w},{h}", "--virtual-time-budget=2500", f"--screenshot={os.path.join(OUT, name)}", "file://" + f.name], capture_output=True, timeout=120)
    os.unlink(f.name); print("  ->", name)


def animated_svg(text, name, w=None):
    lines = [l.split("\r")[-1] for l in text.rstrip("\n").split("\n")]
    w = w or int(max(len(re.sub(r"\x1b\[[0-9;]*m", "", l)) for l in lines) * 8.15 + 70)
    lh, top = 21, 62; H = top + len(lines) * lh + 34; per = 0.11; total = len(lines) * per + 3.5
    css = f"@keyframes s{{0%{{opacity:0}}{100 * 0.3 / total:.2f}%{{opacity:1}}{100 * (total - 1.2) / total:.2f}%{{opacity:1}}100%{{opacity:0}}}}.l{{opacity:0;animation:s {total:.1f}s infinite}}"
    g = []
    for i, ln in enumerate(lines):
        parts = []
        for t, st in spans(ln):
            attrs = 'fill="%s"' % (st["color"] or "#d7defa") + (' font-weight="700"' if st["bold"] else "") + (' opacity=".6"' if st["dim"] else "")
            parts.append("<tspan %s>%s</tspan>" % (attrs, html.escape(t)))
        ts = "".join(parts)
        g.append(f'<text class="l" style="animation-delay:{i * per:.2f}s" x="26" y="{top + i * lh}" xml:space="preserve">{ts or " "}</text>')
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {H}" width="{w}" height="{H}" role="img" aria-label="PN-Ultra-Audit running in a terminal"><style>{css} text{{font-family:'JetBrains Mono','SF Mono',Menlo,Consolas,monospace;font-size:13.5px;white-space:pre}}</style>
<defs><linearGradient id="wb" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#1a2142"/><stop offset="1" stop-color="#141a36"/></linearGradient></defs>
<rect width="{w}" height="{H}" rx="14" fill="#0d1226" stroke="#2a3358"/><path d="M0 14a14 14 0 0 1 14-14h{w - 28}a14 14 0 0 1 14 14V38H0z" fill="url(#wb)"/><circle cx="22" cy="19" r="6" fill="#ff5f57"/><circle cx="42" cy="19" r="6" fill="#febc2e"/><circle cx="62" cy="19" r="6" fill="#28c840"/>
<text x="{w / 2}" y="24" text-anchor="middle" fill="#8a94b8" style="font-family:-apple-system,Segoe UI,sans-serif;font-size:12.5px;font-weight:600">pn-ultra-audit — zsh</text>{"".join(g)}</svg>'''


def main():
    if not CHROME: print("Chrome/Chromium not found: PNGs skipped"); 
    tmp = tempfile.mkdtemp(prefix="pnshots-"); work = os.path.join(tmp, "work"); os.makedirs(work); demo = os.path.join(work, "vulnerable-demo"); shutil.copytree(os.path.join(ROOT, "examples", "vulnerable-demo"), demo)
    AUD = os.path.join(ROOT, "audit.py")   # only used to launch; never printed
    def go(args, cwd=work): return run([AUD] + args, cwd=cwd)
    print("1/7 live scan stream");  scan = go(["vulnerable-demo", "--db", "vulnerable-demo/db/app.db", "--db-sample", "--lang", "en", "--color", "always", "--out", "audit-output/demo", "--export", "docs", "--pdf", "--evidence-pack", "audit-pack"])
    print("2/7 plan");              plan = go(["vulnerable-demo", "--plan", "--lang", "en"])
    be = os.path.join(work, "my-api"); os.makedirs(be); open(os.path.join(be, "app.py"), "w").write("from flask import Flask, request\napp = Flask(__name__)\n@app.route('/u')\ndef u():\n    return str(request.args.get('x'))\n"); open(os.path.join(be, "requirements.txt"), "w").write("flask\n")
    print("3/7 backend only plan"); plan2 = go(["my-api", "--plan", "--lang", "en"])
    print("4/7 help");              helptxt = go(["--help"])
    print("5/7 live SEO crawl");    seo = go(["--url", "https://example.com", "--authorized", "--crawl-max", "5", "--lang", "en", "--color", "always", "--out", "audit-output/seo"])
    print("6/7 web3 + git + agents"); web3t = go(["vulnerable-demo", "--only", "web3,security", "--verbose", "--lang", "en", "--color", "always", "--out", "audit-output/web3"]); gitt = go(["--git", "https://github.com/octocat/Hello-World", "--lang", "en", "--color", "always", "--out", "audit-output/git", "--history"])
    inst = os.path.join(work, "my-app"); os.makedirs(inst); agt = go(["--install-agent", "all", "--agent-dir", "my-app"])
    beg = go(["vulnerable-demo", "--level", "beginner", "--lang", "en", "--color", "always", "--out", "audit-output/beginner", "--only", "security,tests"])
    scf = go(["vulnerable-demo", "--scaffold", "--lang", "en"])
    shutil.copytree(os.path.join(ROOT, "examples", "fintech-saas-demo"), os.path.join(work, "fintech-saas-demo"))
    fin = go(["fintech-saas-demo", "--lang", "en", "--color", "always", "--out", "audit-output/fin", "--verbose"])
    shutil.copytree(os.path.join(ROOT, "examples", "pwa-demo"), os.path.join(work, "pwa-demo"))
    pwa_out = go(["pwa-demo", "--lang", "en", "--color", "always", "--out", "audit-output/pwa", "--strictness", "strict", "--verbose"])
    go(["pwa-demo", "--lang", "zh", "--color", "never", "--out", "audit-output/pwa-zh", "--strictness", "strict"])
    # sample VPS remediation script listing (generated from a synthetic finding set; the tool never runs it)
    sys.path.insert(0, ROOT)
    from engine import serverfix, remote_extra
    sec_ = {"redis": ["conf=/etc/redis/redis.conf", "bind 0.0.0.0", "ping=PONG"], "sysctlx": ["kernel.randomize_va_space=0", "apparmor=no", "auditd=inactive", "journal_persistent=no"], "userx": ["sshfile=644 /home/deploy/.ssh/id_rsa"],
            "cronx": ["backup_refs=0"], "apache2": ["ServerTokens Full", "Options Indexes"], "dockerx": ["X|/api|net=host|pid=|caps=[]|ro=false|mem=0|restart=no|user=|health=0|mounts=|secopt=[]"]}
    fx, _ = remote_extra.analyze_extra(sec_, "ssh://deploy@my-vps", {6379})
    fx += [dict(rule="SRV-SSH-ROOT", title="SSH allows direct root login", status="confirmed", severity="high", evidence=""), dict(rule="SRV-NO-FIREWALL", title="No active host firewall", status="needs_validation", severity=None, evidence=""), dict(rule="SRV-NO-FAIL2BAN", title="fail2ban not active", status="confirmed", severity="low", evidence="")]
    open(os.path.join(work, "server-fixes.sh"), "w").write(serverfix.build(fx, "ssh://deploy@my-vps", "DigitalOcean", "2026-11-08"))
    fixes_list = subprocess.run(["bash", "server-fixes.sh", "list"], cwd=work, capture_output=True, text=True).stdout
    
    # animated SVG: banner + stream + final tables (trim middle)
    sl = scan.split("\n"); keep = sl[:46] + ["   …"] + sl[-26:]
    open(os.path.join(ROOT, "assets", "terminal-demo.svg"), "w", encoding="utf-8").write(animated_svg("\n".join(keep), "terminal-demo.svg"))
    if CHROME:
        print("6/6 PNGs")
        sl2 = scan.split("\n"); i0 = next(i for i, l in enumerate(sl2) if "▶ [03" in re.sub(r"\x1b\[[0-9;]*m", "", l))
        T = "\n".join(sl2[:i0 + 26]); shot(term_html(T, "pn-ultra-audit — live scan"), "terminal-scan.png", *term_size(T))
        T = "\n".join(sl2[-36:]); shot(term_html(T, "pn-ultra-audit — result"), "terminal-result.png", *term_size(T))
        T = plan + "\n" + plan2; shot(term_html(T, "pn-ultra-audit --plan  (auto-detection)"), "terminal-plan.png", *term_size(T))
        T = "\n".join(helptxt.split("\n")[:64]); shot(term_html(T, "pn-ultra-audit --help"), "terminal-help.png", *term_size(T))
        T = "\n".join(seo.split("\n")[:48]); shot(term_html(T, "pn-ultra-audit --url https://example.com --authorized"), "terminal-seo.png", *term_size(T))
        T = "\n".join(web3t.split("\n")[:44]); shot(term_html(T, "pn-ultra-audit --only web3,security"), "terminal-web3.png", *term_size(T))
        T = "\n".join(gitt.split("\n")[:46]); shot(term_html(T, "pn-ultra-audit --git https://github.com/octocat/Hello-World --history"), "terminal-git.png", *term_size(T))
        T = agt; shot(term_html(T, "pn-ultra-audit --install-agent all"), "terminal-agents.png", *term_size(T))
        bl = beg.split("\n"); i1 = next(i for i, l in enumerate(bl) if "PROFESSIONAL LEVEL" in re.sub(r"\x1b\[[0-9;]*m", "", l)); T = "\n".join(bl[i1:i1 + 22]); shot(term_html(T, "pn-ultra-audit --level beginner"), "terminal-beginner.png", *term_size(T))
        fl = fin.split("\n"); i3 = next(i for i, l in enumerate(fl) if "Domain deep-dive" in re.sub(r"\x1b\[[0-9;]*m", "", l)); T = "\n".join(fl[i3:i3 + 14]); shot(term_html(T, "pn-ultra-audit — SaaS / fintech deep-dive"), "terminal-fintech.png", *term_size(T))
        T = scf; shot(term_html(T, "pn-ultra-audit --scaffold"), "terminal-scaffold.png", *term_size(T))
        sl3 = scan.split("\n"); i2 = next(i for i, l in enumerate(sl3) if "AUDIT READINESS" in re.sub(r"\x1b\[[0-9;]*m", "", l)); T = "\n".join(sl3[i2:i2 + 16]); shot(term_html(T, "pn-ultra-audit — audit readiness"), "terminal-compliance.png", *term_size(T))
        # dashboard screenshots
        rd = os.path.join(work, "audit-output", "demo", "run-1")
        rep = os.path.join(rd, "report.html")
        for spec in (("dash-overview-dark.png", "v=overview&theme=dark", "dark", 1600, 1500), ("dash-overview-light.png", "v=overview&theme=light", "light", 1600, 1500), ("dash-print.png", "v=print&theme=light", "light", 1500, 2200)):
            name, frag, theme, w, h = spec[:5]; r_ = os.path.join(work, "audit-output", "fin", "run-1", "report.html") if len(spec) > 5 else rep
            subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--force-device-scale-factor=1.5", f"--window-size={w},{h}", "--virtual-time-budget=3500", f"--screenshot={os.path.join(OUT, name)}", "file://" + r_ + "#" + frag], capture_output=True, timeout=120); print("  ->", name)
    if CHROME:
        def dshot(name, rpt, frag, w, h, scale):
            subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--hide-scrollbars", f"--force-device-scale-factor={scale}", f"--window-size={w},{h}", "--virtual-time-budget=4500", f"--screenshot={os.path.join(OUT, name)}", "file://" + rpt + "#" + frag], capture_output=True, timeout=120)
        prep = os.path.join(work, "audit-output", "pwa", "run-1", "report.html"); zrep = os.path.join(work, "audit-output", "pwa-zh", "run-1", "report.html")
        for name, rpt, frag, w, h in (("dash-report.png", prep, "v=report&theme=dark", 1600, 1500),):
            dshot(name, rpt, frag, w, h, 1.5)
        for name, rpt, frag in (("gal-report.png", prep, "v=report&theme=dark"), ("gal-repo.png", prep, "v=repo&theme=dark"), ("gal-pwa.png", prep, "v=pwa&theme=dark"), ("gal-zh.png", zrep, "v=report&theme=dark")):
            dshot(name, rpt, frag, 1500, 940, 1)
        T = pwa_out.split("\n"); ip = next((i for i, l in enumerate(T) if "PWA" in re.sub(r"\x1b\[[0-9;]*m", "", l) and "▶" in l), 0); T = "\n".join(T[max(0, ip - 2):ip + 22]); shot(term_html(T, "pn-ultra-audit — PWA audit (strict)"), "terminal-pwa.png", *term_size(T))
        T = "$ sudo bash server-fixes.sh list      # generated by --ssh, never executed by the tool\n" + fixes_list; shot(term_html(T, "server-fixes.sh — VPS remediation (sample)"), "terminal-server-fixes.png", *term_size(T))
    # uniform gallery thumbnails: same viewport + scale for every view => tidy README grid
    if CHROME:
        for name, frag, rpt in (("gal-issue.png", "v=issues&id=SEC-003&theme=dark", rep), ("gal-security.png", "v=security&theme=dark", rep), ("gal-roadmap.png", "v=roadmap&theme=dark", rep), ("gal-compliance.png", "v=compliance&theme=dark", rep),
                                ("gal-domain.png", "v=domain&theme=dark", os.path.join(work, "audit-output", "fin", "run-1", "report.html")), ("gal-seo.png", "v=seo&theme=dark", rep), ("gal-arch.png", "v=arch&theme=dark", rep), ("gal-owasp.png", "v=owasp&theme=dark", rep),
                                ("gal-plan.png", "v=plan&theme=light", rep), ("gal-coverage.png", "v=coverage&theme=dark", rep)):
            subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--force-device-scale-factor=1", "--window-size=1500,940", "--virtual-time-budget=3500", f"--screenshot={os.path.join(OUT, name)}", "file://" + rpt + "#" + frag], capture_output=True, timeout=120); print("  ->", name)
    # publishable sample bundle (privacy-checked): docs/demo/
    demo_out = os.path.join(ROOT, "docs", "demo"); shutil.rmtree(demo_out, ignore_errors=True); os.makedirs(demo_out)
    for src, dst in (("report.html", "index.html"), ("REPORT.md", "REPORT.md"), ("findings.sarif", "findings.sarif"), ("summary.json", "summary.json")): shutil.copy2(os.path.join(rd, src), os.path.join(demo_out, dst))
    if os.path.exists(os.path.join(work, "docs", "report.pdf")): shutil.copy2(os.path.join(work, "docs", "report.pdf"), os.path.join(demo_out, "report.pdf"))
    open(os.path.join(demo_out, ".nojekyll"), "w").close()
    for dp, dn, fn in os.walk(demo_out):
        for f in fn:
            t = open(os.path.join(dp, f), errors="ignore").read() if not f.endswith(".pdf") else ""
            for bad in (os.path.expanduser("~"), tmp, ROOT): assert bad not in t, f"PRIVACY LEAK {bad} in {f}"


if __name__ == "__main__":
    main()
