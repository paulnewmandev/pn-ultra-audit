#!/usr/bin/env python3
"""Generates all brand assets (own artwork, no third-party logos): logo, wordmark, hero banner,
language/database/platform badges and feature icons. Run:  python3 scripts/make_assets.py"""
import math, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
A = os.path.join(ROOT, "assets")
for d in ("", "badges", "features"): os.makedirs(os.path.join(A, d), exist_ok=True)
W = lambda p, t: open(os.path.join(A, p), "w", encoding="utf-8").write(t)

GRAD = '<linearGradient id="{id}" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#8b5cf6"/><stop offset=".55" stop-color="#3b82f6"/><stop offset="1" stop-color="#22d3ee"/></linearGradient>'


def mark(size=256, uid="m"):
    """Hexagonal shield + radar sweep + findings blips + verified core."""
    hexpts = " ".join(f"{128 + 112 * math.cos(math.radians(a)):.1f},{128 + 112 * math.sin(math.radians(a)):.1f}" for a in (-90, -30, 30, 90, 150, 210))
    inner = " ".join(f"{128 + 96 * math.cos(math.radians(a)):.1f},{128 + 96 * math.sin(math.radians(a)):.1f}" for a in (-90, -30, 30, 90, 150, 210))
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256" width="{size}" height="{size}" role="img" aria-label="PN-Ultra-Audit logo">
<defs>{GRAD.format(id=uid + "g")}
<radialGradient id="{uid}bg" cx=".5" cy=".4" r=".75"><stop offset="0" stop-color="#1b2250"/><stop offset="1" stop-color="#070b1c"/></radialGradient>
<linearGradient id="{uid}beam" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#22d3ee" stop-opacity=".0"/><stop offset="1" stop-color="#22d3ee" stop-opacity=".7"/></linearGradient>
<filter id="{uid}glow" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="3.2" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>
<polygon points="{hexpts}" fill="url(#{uid}bg)" stroke="url(#{uid}g)" stroke-width="8" stroke-linejoin="round"/>
<polygon points="{inner}" fill="none" stroke="#7c8cff" stroke-opacity=".22" stroke-width="1.5" stroke-linejoin="round"/>
<g fill="none" stroke="#22d3ee" stroke-opacity=".38" stroke-width="2"><circle cx="128" cy="128" r="30"/><circle cx="128" cy="128" r="58"/><circle cx="128" cy="128" r="86" stroke-dasharray="3 5"/></g>
<g stroke="#8b9cff" stroke-opacity=".2" stroke-width="1.5"><path d="M128 36V220M36 128H220"/></g>
<path d="M128 128 L176 52 A90 90 0 0 1 216 120 Z" fill="url(#{uid}beam)"/>
<path d="M128 128 L176 52" stroke="#67e8f9" stroke-width="2.5" stroke-linecap="round" filter="url(#{uid}glow)"/>
<g filter="url(#{uid}glow)"><circle cx="178" cy="92" r="7" fill="#fb7185"/><circle cx="92" cy="158" r="6" fill="#fbbf24"/><circle cx="160" cy="176" r="5.5" fill="#34d399"/></g>
<g fill="none" stroke-opacity=".5" stroke-width="1.5"><circle cx="178" cy="92" r="13" stroke="#fb7185"/><circle cx="92" cy="158" r="12" stroke="#fbbf24"/></g>
<circle cx="128" cy="128" r="24" fill="url(#{uid}g)" filter="url(#{uid}glow)"/><path d="M116 129.5l8.5 8.5 15.5-18" fill="none" stroke="#fff" stroke-width="6.5" stroke-linecap="round" stroke-linejoin="round"/></svg>'''


W("logo.svg", mark(256, "a"))
W("logo-mark-small.svg", mark(64, "b"))

# ───────── wordmark (horizontal lockup)
inner_mark = mark(120, "w").split("\n", 1)[1].rsplit("</svg>", 1)[0]
W("wordmark.svg", f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 900 150" width="900" height="150" role="img" aria-label="PN-Ultra-Audit">
<defs>{GRAD.format(id="tw")}</defs>
<svg x="6" y="10" width="130" height="130" viewBox="0 0 256 256">{inner_mark}</svg>
<text x="160" y="76" font-family="Inter,'SF Pro Display','Segoe UI',Helvetica,Arial,sans-serif" font-size="58" font-weight="800" letter-spacing="1.5" fill="url(#tw)">PN-Ultra-Audit</text>
<text x="163" y="112" font-family="Inter,'SF Pro Text','Segoe UI',Helvetica,Arial,sans-serif" font-size="17" font-weight="600" letter-spacing="4.2" fill="#8a94b8">AUDIT EVERYTHING · SHIP WITH CONFIDENCE</text></svg>''')

# ───────── hero banner
chips = ["Security", "Bugs", "Code Quality", "Docs &amp; Standards", "QA · Web &amp; Mobile", "SEO · SEM", "Databases", "Servers · SSH", "Crypto · Web3", "Git"]
cx, cy, ch = 70, 380, []
for t in chips:
    w = 44 + len(t.replace("&amp;", "&")) * 8.8
    if cx + w > 1090: cx, cy = 70, cy + 46
    ch.append(f'<g transform="translate({cx:.0f},{cy})"><rect width="{w:.0f}" height="34" rx="17" fill="#ffffff" fill-opacity=".07" stroke="#8b9cff" stroke-opacity=".35"/><circle cx="17" cy="17" r="4.5" fill="url(#bn)"/><text x="30" y="22.5" font-family="Inter,Segoe UI,Helvetica,Arial,sans-serif" font-size="14.5" font-weight="600" fill="#dbe4ff">{t}</text></g>')
    cx += w + 14
DASH = 'stroke-dasharray="4 7"'
rings = "".join(f'<circle cx="1330" cy="250" r="{r}" fill="none" stroke="#22d3ee" stroke-opacity="{o}" stroke-width="1.4" {DASH if r > 200 else ""}/>' for r, o in ((60, .35), (120, .28), (180, .22), (240, .16), (300, .1)))
def ring_gauge(x, y, v, c, label):
    r, cc = 38, 2 * math.pi * 38
    return f'<g transform="translate({x},{y})"><circle r="{r}" fill="none" stroke="#ffffff" stroke-opacity=".08" stroke-width="9"/><circle r="{r}" fill="none" stroke="{c}" stroke-width="9" stroke-linecap="round" stroke-dasharray="{v / 100 * cc:.0f} {cc:.0f}" transform="rotate(-90)"/><text y="9" text-anchor="middle" font-family="Inter,Segoe UI,Arial" font-size="26" font-weight="800" fill="#fff">{label}</text></g>'
W("banner.svg", f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1600 520" width="1600" height="520" role="img" aria-label="PN-Ultra-Audit - audit everything, ship with confidence">
<defs>{GRAD.format(id="bn")}
<linearGradient id="bgx" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#060914"/><stop offset=".6" stop-color="#0d1330"/><stop offset="1" stop-color="#14123a"/></linearGradient>
<radialGradient id="g1" cx=".85" cy=".1" r=".6"><stop offset="0" stop-color="#22d3ee" stop-opacity=".35"/><stop offset="1" stop-color="#22d3ee" stop-opacity="0"/></radialGradient>
<radialGradient id="g2" cx=".05" cy="1" r=".7"><stop offset="0" stop-color="#8b5cf6" stop-opacity=".45"/><stop offset="1" stop-color="#8b5cf6" stop-opacity="0"/></radialGradient>
<pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse"><path d="M40 0H0V40" fill="none" stroke="#8b9cff" stroke-opacity=".07"/></pattern></defs>
<rect width="1600" height="520" fill="url(#bgx)"/><rect width="1600" height="520" fill="url(#grid)"/><rect width="1600" height="520" fill="url(#g1)"/><rect width="1600" height="520" fill="url(#g2)"/>
{rings}
<svg x="60" y="64" width="150" height="150" viewBox="0 0 256 256">{mark(150, "h").split(chr(10), 1)[1].rsplit("</svg>", 1)[0]}</svg>
<text x="232" y="132" font-family="Inter,'SF Pro Display','Segoe UI',Helvetica,Arial,sans-serif" font-size="84" font-weight="800" letter-spacing="1" fill="url(#bn)">PN-Ultra-Audit</text>
<text x="236" y="176" font-family="Inter,'SF Pro Text','Segoe UI',Helvetica,Arial,sans-serif" font-size="24" font-weight="500" fill="#c3cdf5">One command to audit code, tests, docs, architecture,</text>
<text x="236" y="208" font-family="Inter,'SF Pro Text','Segoe UI',Helvetica,Arial,sans-serif" font-size="24" font-weight="500" fill="#c3cdf5">databases, servers, SEO and smart contracts -</text>
<text x="236" y="240" font-family="Inter,'SF Pro Text','Segoe UI',Helvetica,Arial,sans-serif" font-size="24" font-weight="500" fill="#c3cdf5">live in your terminal, delivered as a dashboard.</text>
<text x="70" y="316" font-family="'SF Mono',Menlo,Consolas,monospace" font-size="21" fill="#22d3ee">$ python3 audit.py . --export docs --pdf</text>
<text x="70" y="362" font-family="Inter,Segoe UI,Arial" font-size="12" letter-spacing="3.5" font-weight="700" fill="#8a94b8">COVERAGE</text>
{"".join(ch)}
<g transform="translate(1180,96)"><rect width="360" height="236" rx="18" fill="#0f1536" fill-opacity=".85" stroke="#8b9cff" stroke-opacity=".3"/>
<text x="24" y="38" font-family="Inter,Segoe UI,Arial" font-size="13" font-weight="700" letter-spacing="2" fill="#8a94b8">QUALITY GATE</text><text x="24" y="70" font-family="Inter,Segoe UI,Arial" font-size="26" font-weight="800" fill="#34d399">✔ PASSED</text>
{ring_gauge(70, 150, 92, "#22c55e", "A")}{ring_gauge(180, 150, 78, "#84cc16", "B")}{ring_gauge(290, 150, 58, "#f59e0b", "C")}
<text x="70" y="212" text-anchor="middle" font-family="Inter,Segoe UI,Arial" font-size="11" fill="#8a94b8">RELIABILITY</text><text x="180" y="212" text-anchor="middle" font-family="Inter,Segoe UI,Arial" font-size="11" fill="#8a94b8">SECURITY</text><text x="290" y="212" text-anchor="middle" font-family="Inter,Segoe UI,Arial" font-size="11" fill="#8a94b8">MAINTAINABILITY</text></g>
<text x="1360" y="372" text-anchor="middle" font-family="Inter,Segoe UI,Arial" font-size="14" fill="#8a94b8">Read-only · Zero dependencies · GPL-3.0</text>
<text x="1360" y="396" text-anchor="middle" font-family="Inter,Segoe UI,Arial" font-size="14" fill="#8a94b8">40+ languages · 9 databases · 7 AI assistants</text>
</svg>''')

# ───────── badges (own monograms, NOT official logos)
LANG = [("Python", "Py", "#3776ab"), ("JavaScript", "JS", "#e5c507", "#111"), ("TypeScript", "TS", "#3178c6"), ("PHP", "Php", "#777bb4"), ("Java", "Jv", "#e76f00"), ("Kotlin", "Kt", "#7f52ff"), ("Swift", "Sw", "#fa7343"), ("Go", "Go", "#00a7c7"),
        ("Rust", "Rs", "#ce422b"), ("C#", "C#", "#68217a"), ("C", "C", "#4b5563"), ("C++", "C++", "#00599c"), ("Ruby", "Rb", "#cc342d"), ("Dart", "Dt", "#0175c2"), ("Scala", "Sc", "#dc322f"), ("Solidity", "Sol", "#5b6178"), ("Vyper", "Vy", "#7c5cff"),
        ("Move", "Mv", "#2b8a9e"), ("Vue", "Vu", "#2fa876"), ("React", "Re", "#1aa6c9"), ("Svelte", "Sv", "#ff3e00"), ("Angular", "Ng", "#dd0031"), ("Shell", "Sh", "#3d8b2e"), ("PowerShell", "Ps", "#3b6fd9"), ("Lua", "Lu", "#1e3a8a"), ("Perl", "Pl", "#39457e"),
        ("R", "R", "#276dc3"), ("Elixir", "Ex", "#6e4a7e"), ("Haskell", "Hs", "#5d4f85"), ("Clojure", "Cl", "#5881d8"), ("Julia", "Jl", "#9558b2"), ("Terraform", "Tf", "#7b42bc"), ("Docker", "Dk", "#2496ed"), ("SQL", "Sql", "#d97706"), ("PL/SQL", "PL", "#c2410c"),
        ("T-SQL", "TS", "#0e7490"), ("GraphQL", "Gq", "#e10098"), ("Zig", "Zg", "#d98c10"), ("COBOL", "Cb", "#475569"), ("Fortran", "Ft", "#734f96"), ("Objective-C", "OC", "#438eff"), ("Groovy", "Gv", "#4298b8"), ("F#", "F#", "#378bba"), ("OCaml", "ML", "#ee6a1a"), ("Erlang", "Er", "#a90533")]
DBS = [("SQLite", "Sq", "#0f80cc"), ("PostgreSQL", "Pg", "#336791"), ("MySQL", "My", "#00758f"), ("MariaDB", "Mr", "#003545"), ("SQL Server", "Ms", "#a91d22"), ("Oracle", "Or", "#c74634"), ("MongoDB", "Mg", "#13aa52"), ("Redis", "Rd", "#d82c20"), ("AWS RDS", "RDS", "#ff9900", "#111")]
PLAT = [("Android", "An", "#2fa36b"), ("iOS", "iOS", "#111827"), ("Flutter", "Fl", "#0f8ed0"), ("React Native", "RN", "#1aa6c9"), ("Expo", "Ex", "#111827"), ("Next.js", "Nx", "#111111"), ("Node.js", "No", "#3c873a"), ("Laravel", "Lv", "#e0392b"), ("Django", "Dj", "#0c4b33"),
        ("Spring", "Sp", "#5da60d"), (".NET", ".N", "#512bd4"), ("Rails", "Ra", "#b81d1d"), ("Hardhat", "Hh", "#a8890d"), ("Foundry", "Fd", "#b45309"), ("Anchor", "Ac", "#2b6cb0"), ("Kubernetes", "K8", "#326ce5"), ("GitHub Actions", "GA", "#24292f")]
badge_html = []
def badge(name, mono, color, fg="#fff", kind="lang"):
    tw = 12 + len(name) * 7.6; mw = 12 + len(mono) * 8.2
    w = mw + tw + 4
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{w:.0f}" height="30" viewBox="0 0 {w:.0f} 30" role="img" aria-label="{name}"><defs><linearGradient id="s" x2="0" y2="1"><stop offset="0" stop-color="#fff" stop-opacity=".18"/><stop offset="1" stop-opacity=".12"/></linearGradient></defs>
<rect width="{w:.0f}" height="30" rx="8" fill="#161b33"/><rect width="{mw:.0f}" height="30" rx="8" fill="{color}"/><rect x="{mw - 8:.0f}" width="8" height="30" fill="{color}"/><rect width="{w:.0f}" height="30" rx="8" fill="url(#s)"/>
<text x="{mw / 2:.1f}" y="19.5" text-anchor="middle" font-family="'SF Mono',Menlo,Consolas,monospace" font-size="13" font-weight="800" fill="{fg}">{mono}</text>
<text x="{mw + 8:.0f}" y="19.5" font-family="Inter,'Segoe UI',Helvetica,Arial,sans-serif" font-size="13" font-weight="600" fill="#e6ebff">{name}</text></svg>'''
    fn = f"{kind}-" + "".join(c.lower() if c.isalnum() else "" for c in name) + ".svg"
    W(f"badges/{fn}", svg); return fn
index = {"languages": [], "databases": [], "platforms": []}
for t in LANG: index["languages"].append((t[0], badge(t[0], t[1], t[2], t[3] if len(t) > 3 else "#fff", "lang")))
for t in DBS: index["databases"].append((t[0], badge(t[0], t[1], t[2], t[3] if len(t) > 3 else "#fff", "db")))
for t in PLAT: index["platforms"].append((t[0], badge(t[0], t[1], t[2], t[3] if len(t) > 3 else "#fff", "plat")))
import json; json.dump(index, open(os.path.join(A, "badges", "index.json"), "w"), indent=1)

# ───────── feature icons (64px, gradient line icons)
def icon(name, body):
    W(f"features/{name}.svg", f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64" role="img" aria-label="{name}"><defs>{GRAD.format(id="i")}</defs><rect x="1" y="1" width="62" height="62" rx="16" fill="#0f1536"/><rect x="1" y="1" width="62" height="62" rx="16" fill="none" stroke="url(#i)" stroke-opacity=".6" stroke-width="1.5"/><g fill="none" stroke="url(#i)" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round">{body}</g></svg>''')
icon("security", '<path d="M32 12 46 18v11c0 10-6 17-14 21-8-4-14-11-14-21V18z"/><path d="M26 31l5 5 8-10"/>')
icon("bugs", '<ellipse cx="32" cy="36" rx="9" ry="12"/><path d="M26 25a6 6 0 0 1 12 0M23 31H15M41 31h8M23 40h-8M41 40h8M25 47l-6 6M39 47l6 6M32 24v24"/>')
icon("quality", '<path d="M14 46V30M26 46V20M38 46V34M50 46V14"/><path d="M12 50h40"/>')
icon("docs", '<path d="M20 12h18l8 8v32H20z"/><path d="M38 12v8h8M26 30h14M26 37h14M26 44h9"/>')
icon("qa", '<path d="M24 12h16M28 12v14L16 48a4 4 0 0 0 4 6h24a4 4 0 0 0 4-6L36 26V12"/><path d="M22 40h20"/>')
icon("seo", '<circle cx="28" cy="28" r="12"/><path d="M37 37l12 12"/><path d="M23 30l4 4 7-8"/>')
icon("database", '<ellipse cx="32" cy="18" rx="15" ry="6"/><path d="M17 18v28c0 3 7 6 15 6s15-3 15-6V18"/><path d="M17 32c0 3 7 6 15 6s15-3 15-6"/>')
icon("server", '<rect x="14" y="14" width="36" height="14" rx="3"/><rect x="14" y="36" width="36" height="14" rx="3"/><path d="M22 21h.1M22 43h.1M30 21h12M30 43h12"/>')
icon("git", '<circle cx="20" cy="18" r="5"/><circle cx="20" cy="46" r="5"/><circle cx="44" cy="30" r="5"/><path d="M20 23v18M25 18c10 0 14 4 14 12"/>')
icon("crypto", '<path d="M32 10 50 20v24L32 54 14 44V20z"/><path d="M26 25h8a4 4 0 0 1 0 8h-8M26 33h9a4 4 0 0 1 0 8h-9M26 21v24"/>')
icon("mobile", '<rect x="21" y="9" width="22" height="46" rx="5"/><path d="M29 15h6M31 49h2"/>')
icon("terminal", '<rect x="10" y="14" width="44" height="36" rx="5"/><path d="M19 26l8 6-8 6M31 40h12"/>')
icon("dashboard", '<rect x="11" y="12" width="42" height="40" rx="5"/><path d="M11 22h42M20 42V32M30 42V28M40 42V35"/>')
icon("architecture", '<rect x="24" y="10" width="16" height="10" rx="2"/><rect x="10" y="42" width="16" height="10" rx="2"/><rect x="38" y="42" width="16" height="10" rx="2"/><path d="M32 20v10M18 42v-6h28v6"/>')
print("assets written:", len(os.listdir(A)), "root files;", len(os.listdir(os.path.join(A, "badges"))), "badges;", len(os.listdir(os.path.join(A, "features"))), "icons")


# ───────── compliance readiness badges (own design; they say "readiness", never "certified")
os.makedirs(os.path.join(A, "compliance"), exist_ok=True)
FWS = [("SOC 2", "soc2"), ("ISO 27001", "iso27001"), ("HIPAA", "hipaa"), ("GDPR", "gdpr"), ("PCI DSS", "pci"), ("NIST CSF", "nist"), ("DORA", "dora"), ("EU AI Act", "euai"), ("WCAG 2.2", "wcag")]
for name, slug in FWS:
    W(f"compliance/{slug}.svg", f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 200" width="132" height="132" role="img" aria-label="{name} readiness"><defs>{GRAD.format(id="c")}<radialGradient id="cb" cx=".5" cy=".35" r=".8"><stop offset="0" stop-color="#1b2250"/><stop offset="1" stop-color="#0a0f26"/></radialGradient></defs>
<circle cx="100" cy="100" r="94" fill="url(#cb)" stroke="url(#c)" stroke-width="5"/><path d="M34 98a66 66 0 0 1 132 0" fill="none" stroke="url(#c)" stroke-width="7" stroke-linecap="round"/>
<text x="100" y="98" text-anchor="middle" font-family="Georgia,'Times New Roman',serif" font-size="{34 if len(name) < 8 else 27}" font-weight="700" fill="#fff">{name}</text>
<path d="M100 122l-16 7v13c0 11 7 19 16 23 9-4 16-12 16-23v-13z" fill="none" stroke="#22d3ee" stroke-width="3" stroke-linejoin="round"/><path d="M92 141l6 6 10-12" fill="none" stroke="#22d3ee" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"/>
<text x="100" y="180" text-anchor="middle" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="12.5" font-weight="700" letter-spacing="2.5" fill="#9fb0ff">READINESS</text></svg>''')
print("compliance badges:", len(FWS))
