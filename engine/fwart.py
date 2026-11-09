"""Own iconography for compliance frameworks (original art, not official marks). Shared by scripts/make_assets.py (README badges) and the dashboard (medallions)."""
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
PIC.update({
 "asvs": lambda c: f'<g fill="none" stroke="{c}" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"><rect x="82" y="52" width="56" height="70" rx="8"/></g><g fill="none" stroke="#fff" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"><path d="M93 72l5 5 9-10M93 96l5 5 9-10"/><path d="M114 72h12M114 96h12"/></g>',
 "sox": lambda c: f'<g fill="none" stroke="{c}" stroke-width="4" stroke-linecap="round"><path d="M72 120h76"/></g><g fill="#fff"><rect x="80" y="92" width="14" height="28" rx="3"/><rect x="103" y="72" width="14" height="48" rx="3"/><rect x="126" y="54" width="14" height="66" rx="3"/></g>',
 "nydfs": lambda c: f'<g fill="none" stroke="{c}" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"><path d="M70 122h80"/></g><g fill="none" stroke="#fff" stroke-width="4" stroke-linejoin="round"><path d="M78 122V86h18v36M96 122V62h24v60M120 122V78h18v44"/><path d="M104 74h8M104 88h8M104 102h8" stroke-linecap="round"/></g>',
 "psd2": lambda c: f'<g fill="none" stroke="{c}" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"><rect x="74" y="58" width="72" height="24" rx="6"/></g><g fill="none" stroke="#fff" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"><path d="M84 96h48l-8-8M132 96l-8 8M136 114H88l8-8M88 114l8 8"/></g>',
 "cis": lambda c: f'<g fill="none" stroke="{c}" stroke-width="4" stroke-linejoin="round"><path d="M110 50l34 20v38l-34 20-34-20V70z"/></g><g fill="none" stroke="#fff" stroke-width="4" stroke-linejoin="round"><path d="M110 66l20 12v24l-20 12-20-12V78z"/></g><path d="M101 90l7 7 12-14" fill="none" stroke="#fff" stroke-width="4.4" stroke-linecap="round" stroke-linejoin="round"/>',
})
GENERIC = lambda c: f'<g fill="none" stroke="{c}" stroke-width="4" stroke-linejoin="round">{SHIELD}</g>'
ACCENT.update({"asvs": "#a78bfa", "sox": "#fbbf24", "nydfs": "#60a5fa", "psd2": "#2dd4bf", "cis": "#fb923c"})


def medallion(slug, pct, size=104, col="#22c55e", label=None):
    """Dashboard medallion: framework pictogram + progress ring (readiness) + readiness ribbon. Same art as the README compliance badges."""
    ac = ACCENT.get(slug, "#818cf8"); pic = PIC.get(slug, GENERIC)(ac); C = 2 * _m.pi * 100; v = 0 if pct is None else max(0, min(100, pct))
    txt = "–" if pct is None else f"{pct}%"
    return (f'<svg class="fwm" viewBox="0 0 220 220" width="{size}" height="{size}" role="img" aria-label="{label or slug} {txt}"><defs><radialGradient id="fd{slug}" cx=".5" cy=".3" r=".9"><stop offset="0" stop-color="#1c2452"/><stop offset="1" stop-color="#090e24"/></radialGradient></defs>'
            f'<circle cx="110" cy="110" r="104" fill="url(#fd{slug})"/><circle cx="110" cy="110" r="100" fill="none" stroke="#fff" stroke-opacity=".14" stroke-width="7"/>'
            f'<circle cx="110" cy="110" r="100" fill="none" stroke="{col}" stroke-width="7" stroke-linecap="round" stroke-dasharray="{C * v / 100:.1f} {C:.1f}" transform="rotate(-90 110 110)"/>'
            f'{pic}<rect x="48" y="140" width="124" height="38" rx="19" fill="{col}"/><text x="110" y="168" text-anchor="middle" font-family="Inter,Segoe UI,Helvetica,Arial,sans-serif" font-size="30" font-weight="800" fill="#0a0f26">{txt}</text></svg>')
