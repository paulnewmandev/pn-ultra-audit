#!/usr/bin/env python3
"""Generates all brand assets (own artwork, no third-party logos): logo, wordmark, hero banner,
language/database/platform badges and feature icons. Run:  python3 scripts/make_assets.py"""
import math, os

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

# ───────── badges with the real logos of each technology (Simple Icons, CC0 data; trademarks of their owners, used to identify supported tech)
import json
LOGOS = json.load(open(os.path.join(A, "logos", "logos.json"))) if os.path.exists(os.path.join(A, "logos", "logos.json")) else {}
sys_path = os.path.join(ROOT, "scripts"); import importlib.util as _iu
_sp = _iu.spec_from_file_location("fetch_logos", os.path.join(sys_path, "fetch_logos.py")); _fl = _iu.module_from_spec(_sp); _sp.loader.exec_module(_fl)
SLUG = _fl.SLUGS
LANG = [("Python", "Py"), ("JavaScript", "JS"), ("TypeScript", "TS"), ("PHP", "Php"), ("Java", "Jv"), ("Kotlin", "Kt"), ("Swift", "Sw"), ("Go", "Go"), ("Rust", "Rs"), ("C#", "C#"), ("C", "C"), ("C++", "C+"), ("Ruby", "Rb"), ("Dart", "Dt"), ("Scala", "Sc"),
        ("Solidity", "Sol"), ("Vyper", "Vy"), ("Move", "Mv"), ("Vue", "Vu"), ("React", "Re"), ("Svelte", "Sv"), ("Angular", "Ng"), ("Shell", "Sh"), ("PowerShell", "Ps"), ("Lua", "Lu"), ("Perl", "Pl"), ("R", "R"), ("Elixir", "Ex"), ("Haskell", "Hs"),
        ("Clojure", "Cl"), ("Julia", "Jl"), ("Terraform", "Tf"), ("Docker", "Dk"), ("SQL", "Sql"), ("PL/SQL", "PL"), ("T-SQL", "TS"), ("GraphQL", "Gq"), ("Zig", "Zg"), ("COBOL", "Cb"), ("Fortran", "Ft"), ("Objective-C", "OC"), ("Groovy", "Gv"), ("F#", "F#"),
        ("OCaml", "ML"), ("Erlang", "Er")]
DBS = [("SQLite", "Sq"), ("PostgreSQL", "Pg"), ("MySQL", "My"), ("MariaDB", "Mr"), ("SQL Server", "Ms"), ("Oracle", "Or"), ("MongoDB", "Mg"), ("Redis", "Rd"), ("AWS RDS", "RDS"), ("Elasticsearch", "Es")]
PLAT = [("Android", "An"), ("iOS", "iOS"), ("Flutter", "Fl"), ("React Native", "RN"), ("Expo", "Ex"), ("Next.js", "Nx"), ("Node.js", "No"), ("Laravel", "Lv"), ("Django", "Dj"), ("Spring", "Sp"), (".NET", ".N"), ("Rails", "Ra"), ("Hardhat", "Hh"),
        ("Foundry", "Fd"), ("Anchor", "Ac"), ("Kubernetes", "K8"), ("GitHub Actions", "GA"), ("Vercel", "Vc"), ("Netlify", "Nl")]
CLOUDS = [("AWS", "AWS"), ("Azure", "Az"), ("Google Cloud", "GC"), ("DigitalOcean", "DO"), ("Hostinger", "Ho"), ("Hetzner", "Hz"), ("Vultr", "Vt"), ("Linode", "Ln"), ("OVHcloud", "OVH"), ("Cloudflare", "Cf"), ("Vercel", "Vc"), ("Netlify", "Nl")]
SERVERS = [("nginx", "Ng"), ("Apache", "Ap"), ("Redis", "Rd"), ("Apache Kafka", "Kf"), ("RabbitMQ", "Rm"), ("Elasticsearch", "Es"), ("Docker", "Dk"), ("Kubernetes", "K8"), ("Podman", "Pm"), ("PostgreSQL", "Pg"), ("MySQL", "My"), ("MongoDB", "Mg")]
FALLBACK = {"C#": "#68217a", "PowerShell": "#3b6fd9", "T-SQL": "#0e7490", "SQL Server": "#a91d22", "Hardhat": "#a8890d", "Azure": "#0078d4", "Linode": "#02b159", "Vyper": "#7c5cff", "Move": "#2b8a9e", "SQL": "#d97706", "COBOL": "#475569",
            "Objective-C": "#438eff", "Foundry": "#b45309", "Anchor": "#2b6cb0"}


def _lum(h):
    r, g, b = (int(h[i:i + 2], 16) / 255 for i in (1, 3, 5))
    f = lambda c: c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)


def badge(name, mono, kind):
    slug = SLUG.get(name); lg = LOGOS.get(slug) if slug else None
    color = lg["hex"] if lg else FALLBACK.get(name, "#4b5563")
    if _lum(color) < 0.02: color = "#2a3150"            # near-black brand colors stay visible on dark READMEs
    ink = "#111827" if _lum(color) > 0.45 else "#ffffff"
    cw = 38; tw = 10 + len(name) * 7.4; w = cw + tw + 6
    if lg: glyph = f'<g transform="translate({cw / 2 - 9:.1f},6) scale(0.75)"><path d="{lg["path"]}" fill="{ink}"/></g>'
    else: glyph = f'<text x="{cw / 2:.1f}" y="19.5" text-anchor="middle" font-family="Inter,Segoe UI,Helvetica,Arial,sans-serif" font-size="{13 if len(mono) < 3 else 11}" font-weight="800" fill="{ink}">{mono}</text>'
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w:.0f}" height="30" viewBox="0 0 {w:.0f} 30" role="img" aria-label="{name}"><defs><linearGradient id="s" x2="0" y2="1"><stop offset="0" stop-color="#fff" stop-opacity=".16"/><stop offset="1" stop-opacity=".12"/></linearGradient></defs>'
           f'<rect width="{w:.0f}" height="30" rx="8" fill="#161b33"/><rect width="{cw}" height="30" rx="8" fill="{color}"/><rect x="{cw - 8}" width="8" height="30" fill="{color}"/><rect width="{w:.0f}" height="30" rx="8" fill="url(#s)"/>{glyph}'
           f'<text x="{cw + 9}" y="19.5" font-family="Inter,Segoe UI,Helvetica,Arial,sans-serif" font-size="13" font-weight="600" fill="#e6ebff">{name}</text></svg>')
    fn = f"{kind}-" + "".join(c.lower() if c.isalnum() else "" for c in name.replace("+", "plus").replace("#", "sharp")) + ".svg"
    W(f"badges/{fn}", svg); return fn


index = {"languages": [], "databases": [], "platforms": [], "clouds": [], "servers": []}
for key, kind, items in (("languages", "lang", LANG), ("databases", "db", DBS), ("platforms", "plat", PLAT), ("clouds", "cloud", CLOUDS), ("servers", "srv", SERVERS)):
    for name, mono in items: index[key].append((name, badge(name, mono, kind)))
json.dump(index, open(os.path.join(A, "badges", "index.json"), "w"), indent=1)

# ───────── feature icons (64px, gradient line icons)
def icon(name, body):
    W(f"features/{name}.svg", f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64" role="img" aria-label="{name}"><defs>{GRAD.format(id="i")}</defs><rect x="1" y="1" width="62" height="62" rx="16" fill="#0f1536"/><rect x="1" y="1" width="62" height="62" rx="16" fill="none" stroke="url(#i)" stroke-opacity=".6" stroke-width="1.5"/><g fill="none" stroke="url(#i)" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round">{body}</g></svg>''')
icon("security", '<path d="M32 12 46 18v11c0 10-6 17-14 21-8-4-14-11-14-21V18z"/><path d="M26 31l5 5 8-10"/>')
icon("quality", '<path d="M14 46V30M26 46V20M38 46V34M50 46V14"/><path d="M12 50h40"/>')
icon("docs", '<path d="M20 12h18l8 8v32H20z"/><path d="M38 12v8h8M26 30h14M26 37h14M26 44h9"/>')
icon("git", '<circle cx="20" cy="18" r="5"/><circle cx="20" cy="46" r="5"/><circle cx="44" cy="30" r="5"/><path d="M20 23v18M25 18c10 0 14 4 14 12"/>')
icon("terminal", '<rect x="10" y="14" width="44" height="36" rx="5"/><path d="M19 26l8 6-8 6M31 40h12"/>')
icon("tokens", '<path d="M35 10L18 35h12l-4 19 20-27H34z"/>')
icon("key", '<circle cx="23" cy="29" r="9"/><path d="M30 35l17 14M41 45l5-5M36 41l5-5"/>')
icon("dashboard", '<rect x="11" y="12" width="42" height="40" rx="5"/><path d="M11 22h42M20 42V32M30 42V28M40 42V35"/>')
print("assets written:", len(os.listdir(A)), "root files;", len(os.listdir(os.path.join(A, "badges"))), "badges;", len(os.listdir(os.path.join(A, "features"))), "icons")


# ───────── compliance readiness badges: own iconography (a distinct pictogram per framework, name fitted to a ribbon, no overflow).
# Inspired by each framework's common visual language; NOT the official marks, and they say "readiness", never "certified".
os.makedirs(os.path.join(A, "compliance"), exist_ok=True)
import math as _m
def _stars(cx, cy, r, n=12, size=5.2, fill="#ffcc33"):
    out = []
    for i in range(n):
        a = -_m.pi / 2 + i * 2 * _m.pi / n; x, y = cx + r * _m.cos(a), cy + r * _m.sin(a)
        pts = " ".join(f"{x + (size if k % 2 == 0 else size * .42) * _m.cos(-_m.pi / 2 + k * _m.pi / 5):.1f},{y + (size if k % 2 == 0 else size * .42) * _m.sin(-_m.pi / 2 + k * _m.pi / 5):.1f}" for k in range(10))
        out.append(f'<polygon points="{pts}" fill="{fill}"/>')
    return "".join(out)
SHIELD = '<path d="M110 52l30 11v22c0 20-12 34-30 42-18-8-30-22-30-42V63z"/>'
PIC = {
 "soc2": lambda c: f'<g fill="none" stroke="{c}" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"><path d="M110 56l24 9v18c0 16-10 28-24 34-14-6-24-18-24-34V65z"/><path d="M99 87l8 8 15-17"/></g><g fill="none" stroke="#fff" stroke-opacity=".85" stroke-width="3" stroke-linecap="round"><path d="M62 96a48 48 0 0 1 14-34M158 96a48 48 0 0 1-14 34"/><path d="M76 62l-1 8-8-2M144 130l1-8 8 2"/></g>',
 "iso27001": lambda c: f'<g fill="none" stroke="{c}" stroke-width="4" stroke-linecap="round"><circle cx="110" cy="86" r="32"/><ellipse cx="110" cy="86" rx="13" ry="32"/><path d="M78 86h64M84 70h52M84 102h52"/></g><g transform="translate(128 98)"><rect x="0" y="9" width="24" height="20" rx="4" fill="#0a0f26" stroke="#fff" stroke-width="3"/><path d="M5 9V5a7 7 0 0 1 14 0v4" fill="none" stroke="#fff" stroke-width="3"/></g>',
 "hipaa": lambda c: f'<g fill="none" stroke="{c}" stroke-width="4" stroke-linejoin="round">{SHIELD}</g><path d="M110 70v34M93 87h34" stroke="#fff" stroke-width="9" stroke-linecap="round"/><path d="M76 108c10 4 18 2 24-6" fill="none" stroke="{c}" stroke-opacity=".6" stroke-width="3" stroke-linecap="round"/>',
 "gdpr": lambda c: _stars(110, 86, 38, 12, 6.2) + f'<g fill="none" stroke="#fff" stroke-width="4" stroke-linecap="round"><rect x="95" y="84" width="30" height="24" rx="5" fill="#0a0f26"/><path d="M101 84V76a9 9 0 0 1 18 0v8"/></g><circle cx="110" cy="96" r="3.6" fill="{c}"/>',
 "pci": lambda c: f'<g fill="none" stroke="{c}" stroke-width="4" stroke-linejoin="round"><rect x="68" y="66" width="84" height="54" rx="9"/></g><path d="M68 80h84" stroke="{c}" stroke-width="9"/><rect x="78" y="94" width="20" height="14" rx="3" fill="none" stroke="#fff" stroke-width="3"/><path d="M106 101h36M106 109h22" stroke="#fff" stroke-opacity=".8" stroke-width="3.4" stroke-linecap="round"/><g transform="translate(126 96) scale(.62)" fill="#0a0f26" stroke="#fff" stroke-width="5" stroke-linejoin="round"><path d="M30 8l20 7v14c0 14-8 24-20 29-12-5-20-15-20-29V15z"/></g>',
 "nist": lambda c: "".join(f'<path d="M110 86 L{110 + 40 * _m.cos(a0):.1f} {86 + 40 * _m.sin(a0):.1f} A40 40 0 0 1 {110 + 40 * _m.cos(a0 + _m.pi / 3 - .06):.1f} {86 + 40 * _m.sin(a0 + _m.pi / 3 - .06):.1f} Z" fill="{col}" fill-opacity=".9"/>' for a0, col in zip([-_m.pi / 2 + k * _m.pi / 3 for k in range(6)], ["#8b5cf6", "#6366f1", "#3b82f6", "#22d3ee", "#34d399", "#a3e635"])) + '<circle cx="110" cy="86" r="14" fill="#0a0f26" stroke="#fff" stroke-width="3"/><path d="M104 86l4 4 8-9" fill="none" stroke="#fff" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>',
 "dora": lambda c: _stars(110, 86, 40, 12, 5.4) + f'<g fill="none" stroke="#fff" stroke-width="3.6" stroke-linecap="round" stroke-linejoin="round"><path d="M82 100h56M86 100V80M98 100V80M110 100V80M122 100V80M134 100V80M80 80h60L110 62z"/></g><path d="M82 100h56" stroke="{c}" stroke-width="3.6" stroke-linecap="round"/>',
 "euai": lambda c: _stars(110, 82, 41, 12, 4.6) + f'<g fill="none" stroke="#fff" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"><rect x="88" y="60" width="44" height="44" rx="7" fill="#0a0f26"/><rect x="99" y="71" width="22" height="22" rx="4" stroke="{c}" fill="{c}" fill-opacity=".25"/><path d="M99 60v-7M110 60v-7M121 60v-7M99 104v7M110 104v7M121 104v7M88 71h-7M88 82h-7M88 93h-7M132 71h7M132 82h7M132 93h7"/></g><path d="M110 74l2.2 5.2 5.2 2.2-5.2 2.2-2.2 5.2-2.2-5.2-5.2-2.2 5.2-2.2z" fill="#fff"/>',
 "wcag": lambda c: f'<g fill="none" stroke="{c}" stroke-width="4"><circle cx="110" cy="86" r="38"/></g><g fill="#fff"><circle cx="110" cy="68" r="6.2"/><path d="M84 80c18 5 34 5 52 0l1.6 7c-8 2.6-15 3.6-21.6 4v10l7 19-8 3-8-18-8 18-8-3 7-19V91c-6.6-.4-13.6-1.4-21.6-4z"/></g>',
}
ACCENT = {"soc2": "#4f8cff", "iso27001": "#14b8a6", "hipaa": "#f43f5e", "gdpr": "#5b8def", "pci": "#f59e0b", "nist": "#8b5cf6", "dora": "#38bdf8", "euai": "#818cf8", "wcag": "#34d399"}
FWS = [("SOC 2", "soc2"), ("ISO 27001", "iso27001"), ("HIPAA", "hipaa"), ("GDPR", "gdpr"), ("PCI DSS", "pci"), ("NIST CSF", "nist"), ("DORA", "dora"), ("EU AI Act", "euai"), ("WCAG 2.2", "wcag")]
for name, slug in FWS:
    ac = ACCENT[slug]; fs = min(21, 126 / (0.62 * len(name)))
    W(f"compliance/{slug}.svg", f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 220 220" width="132" height="132" role="img" aria-label="{name} readiness"><defs><linearGradient id="r" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="{ac}"/><stop offset="1" stop-color="#22d3ee"/></linearGradient><radialGradient id="d" cx=".5" cy=".3" r=".9"><stop offset="0" stop-color="#1c2452"/><stop offset="1" stop-color="#090e24"/></radialGradient><linearGradient id="b" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="{ac}" stop-opacity=".95"/><stop offset="1" stop-color="#22d3ee" stop-opacity=".85"/></linearGradient></defs>
<circle cx="110" cy="110" r="104" fill="url(#d)" stroke="url(#r)" stroke-width="5"/><circle cx="110" cy="110" r="95" fill="none" stroke="#fff" stroke-opacity=".12" stroke-dasharray="2 5"/>
{PIC[slug](ac)}
<rect x="32" y="138" width="156" height="34" rx="17" fill="url(#b)"/><text x="110" y="160.5" text-anchor="middle" font-family="Inter,'Segoe UI',Helvetica,Arial,sans-serif" font-size="{fs:.1f}" font-weight="800" fill="#0a0f26">{name}</text>
<text x="110" y="193" text-anchor="middle" font-family="Inter,'Segoe UI',Helvetica,Arial,sans-serif" font-size="10" font-weight="700" letter-spacing="2.2" fill="#9fb0ff">READINESS</text></svg>''')
print("compliance badges:", len(FWS))


# ───────── status badges (README header) — same style as the technology badges
def status(label, value, color, glyph, fn, ink="#ffffff"):
    cw = 38; tl = len(label) * 7.0 + 12; tv = len(value) * 7.6 + 14; w = cw + tl + tv
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w:.0f}" height="30" viewBox="0 0 {w:.0f} 30" role="img" aria-label="{label}: {value}"><defs><linearGradient id="s" x2="0" y2="1"><stop offset="0" stop-color="#fff" stop-opacity=".16"/><stop offset="1" stop-opacity=".12"/></linearGradient></defs>'
           f'<rect width="{w:.0f}" height="30" rx="8" fill="#161b33"/><rect x="{cw + tl:.0f}" width="{tv:.0f}" height="30" rx="8" fill="{color}" fill-opacity=".22"/><rect x="{cw + tl:.0f}" width="8" height="30" fill="#161b33"/><rect x="{cw + tl:.0f}" width="8" height="30" fill="{color}" fill-opacity=".22"/>'
           f'<rect width="{cw}" height="30" rx="8" fill="{color}"/><rect x="{cw - 8}" width="8" height="30" fill="{color}"/><rect width="{w:.0f}" height="30" rx="8" fill="url(#s)"/>'
           f'<g transform="translate({cw / 2 - 8:.1f},7) scale(.667)" fill="none" stroke="{ink}" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round">{glyph}</g>'
           f'<text x="{cw + 8}" y="19.5" font-family="Inter,Segoe UI,Helvetica,Arial,sans-serif" font-size="13" font-weight="600" fill="#9fb0ff">{label}</text>'
           f'<text x="{cw + tl + 7:.0f}" y="19.5" font-family="Inter,Segoe UI,Helvetica,Arial,sans-serif" font-size="13" font-weight="700" fill="#f4f6ff">{value}</text></svg>')
    W(f"badges/{fn}", svg)
import re as _re
_ver = _re.search(r'VER\s*=\s*"([^"]+)"', open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "build_readme.py")).read()).group(1)
status("Version", _ver, "#8b5cf6", '<path d="M3 12l9-9h8v8l-9 9z"/><circle cx="15.5" cy="8.5" r="1.4"/>', "st-version.svg")
status("License", "GPL-3.0", "#06b6d4", '<path d="M12 3v18M5 7h14M5 7l-3 7a3.5 3 0 0 0 6 0zM19 7l-3 7a3.5 3 0 0 0 6 0zM8 21h8"/>', "st-license.svg", "#0b1020")
status("Python", "3.9+", "#3b82f6", '<path d="M12 3c-4 0-4 1.5-4 3v2h4v1H6c-2 0-3 2-3 4s1 4 3 4h2v-3c0-2 1-3 3-3h4c1.500 0 2.500-1 2.500-2.500V6c0-1.500-2-3-5.500-3z"/><path d="M12 21c4 0 4-1.500 4-3v-2h-4v-1h6c2 0 3-2 3-4s-1-4-3-4h-2v3c0 2-1 3-3 3H9c-1.500 0-2.500 1-2.500 2.500V18c0 1.500 2 3 5.500 3z"/>', "st-python.svg")
status("Dependencies", "0", "#34d399", '<path d="M12 3l8 4.500v9L12 21l-8-4.500v-9z"/><path d="M4 7.500l8 4.500 8-4.500M12 12v9"/>', "st-deps.svg", "#0b1020")
status("Target", "read-only", "#f59e0b", '<path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>', "st-readonly.svg", "#0b1020")
status("PRs", "welcome", "#ec4899", '<circle cx="6" cy="6" r="2.500"/><circle cx="6" cy="18" r="2.500"/><circle cx="18" cy="18" r="2.500"/><path d="M6 8.500v7M18 15.500V10a3 3 0 0 0-3-3h-3m2-3l-2 3 2 3"/>', "st-prs.svg")
print("status badges: 6")
