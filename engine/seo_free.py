"""Free SEO/SEM data without paid APIs: keyword ideas (public autocomplete), Google Search Console CSV
analysis (official, free export), competitor on-page comparison (same polite crawler). Stdlib only."""
import csv, json, re, string, time, urllib.parse
from collections import defaultdict

from .seo import _get, _f, analyze_html, UA


def keyword_ideas(seeds, lang="en", country="us", expand=True, max_calls=40, delay=0.4, ui_note=None):
    """Google/Bing/DDG autocomplete. Public endpoints, low volume, no key. Returns {seed: [ideas]} and counts."""
    res, calls = {}, 0
    for seed in seeds:
        ideas = {}
        probes = [seed] + ([f"{seed} {c}" for c in string.ascii_lowercase[:12]] + [f"{p} {seed}" for p in ("best", "how to", "what is", "cheap", "vs", "for")] if expand else [])
        for q in probes:
            if calls >= max_calls: break
            calls += 1
            if ui_note: ui_note(f"{calls}/{max_calls} {q[:30]}")
            r = _get("https://suggestqueries.google.com/complete/search?" + urllib.parse.urlencode({"client": "firefox", "q": q, "hl": lang, "gl": country}), timeout=8, maxbytes=100_000)
            if r["status"] == 200:
                try:
                    for s in json.loads(r["body"].decode("utf-8", "ignore"))[1]: ideas[s] = ideas.get(s, 0) + 1
                except (ValueError, IndexError): pass
            time.sleep(delay)
        intent = lambda k: "transactional" if re.search(r"\b(buy|price|cheap|discount|coupon|deal|order|comprar|precio)\b", k) else "commercial" if re.search(r"\b(best|top|vs|review|compare|alternative|mejor)\b", k) else "informational" if re.search(r"^(how|what|why|when|where|who|can|do|is|como|qué|que)\b", k) else "navigational/other"
        res[seed] = sorted(({"keyword": k, "intent": intent(k), "words": len(k.split())} for k in ideas), key=lambda x: (x["intent"], x["words"]))
    return res, calls


def _num(s):
    s = str(s).replace("%", "").replace(",", ".") if str(s).count(",") == 1 and "." not in str(s) else str(s).replace("%", "").replace(",", "")
    try: return float(s)
    except ValueError: return 0.0


def gsc_csv(path):
    """Search Console 'Performance' export (Queries.csv or Pages.csv). Finds quick wins."""
    out, rows = [], []
    with open(path, newline="", encoding="utf-8-sig") as fh:
        rd = csv.DictReader(fh)
        cols = {c.lower(): c for c in rd.fieldnames or []}
        key = next((cols[c] for c in cols if c in ("top queries", "query", "queries", "consulta", "consultas principales", "top pages", "page", "pages", "páginas principales", "página")), None)
        clk = next((cols[c] for c in cols if c.startswith(("clicks", "clics"))), None); imp = next((cols[c] for c in cols if c.startswith(("impressions", "impresiones"))), None)
        ctr = next((cols[c] for c in cols if c.startswith("ctr")), None); pos = next((cols[c] for c in cols if c.startswith(("position", "posición", "posicion"))), None)
        if not (key and imp and pos): return [], dict(error="unrecognized columns (need query/page, clicks, impressions, ctr, position)")
        for r in rd:
            rows.append(dict(key=r[key], clicks=_num(r.get(clk, 0)), imp=_num(r[imp]), ctr=_num(r.get(ctr, 0)), pos=_num(r[pos])))
    is_page = key.lower() in ("top pages", "page", "pages", "páginas principales", "página")
    tot_i = sum(r["imp"] for r in rows) or 1
    strike = sorted([r for r in rows if 4 <= r["pos"] <= 20 and r["imp"] >= 100], key=lambda r: -r["imp"])[:15]
    lowctr = sorted([r for r in rows if r["pos"] <= 5 and r["imp"] >= 100 and r["ctr"] < 3.0], key=lambda r: -r["imp"])[:15]
    zero = sorted([r for r in rows if r["clicks"] == 0 and r["imp"] >= 200], key=lambda r: -r["imp"])[:15]
    G = "Search Console export"
    fmt = lambda xs: "; ".join(f'{x["key"][:60]} (pos {x["pos"]:.1f}, {int(x["imp"])} imp, {x["ctr"]:.1f}% CTR)' for x in xs[:8])
    if strike: out.append(_f("SEO-GSC-STRIKING", f"{len(strike)} {'pages' if is_page else 'queries'} in 'striking distance' (positions 4-20) with ≥100 impressions", "seo-content", "code_smell", "info", "seo", G, 1, fmt(strike), "Improve these first: strengthen the title/H1 for the exact query, add internal links from strong pages, expand content to cover the intent, add FAQ/structured data", 30 * min(len(strike), 8), seo_cat="content"))
    if lowctr: out.append(_f("SEO-GSC-LOW-CTR", f"{len(lowctr)} top-5 results with CTR < 3% (title/description not compelling)", "seo-onpage", "code_smell", "low", "seo", G, 1, fmt(lowctr), "Rewrite title + meta description for these (benefit, number, brand last, match intent); A/B test one change at a time", 15 * min(len(lowctr), 10), seo_cat="onpage"))
    if zero: out.append(_f("SEO-GSC-NO-CLICKS", f"{len(zero)} entries with ≥200 impressions and zero clicks", "seo-content", "code_smell", "info", "seo", G, 1, fmt(zero), "Check intent mismatch or cannibalization (several pages for one query); consolidate or retarget", 20 * min(len(zero), 8), seo_cat="content"))
    top = sorted(rows, key=lambda r: -r["imp"])[:10]
    return out, dict(rows=len(rows), kind="pages" if is_page else "queries", impressions=int(tot_i), clicks=int(sum(r["clicks"] for r in rows)), avg_position=round(sum(r["pos"] * r["imp"] for r in rows) / tot_i, 1),
                     top=[dict(key=r["key"], clicks=int(r["clicks"]), impressions=int(r["imp"]), ctr=r["ctr"], position=r["pos"]) for r in top],
                     striking=[dict(key=r["key"], position=r["pos"], impressions=int(r["imp"]), ctr=r["ctr"]) for r in strike], low_ctr=[dict(key=r["key"], position=r["pos"], impressions=int(r["imp"]), ctr=r["ctr"]) for r in lowctr])


def competitor_compare(own_pages, comp_urls, ui_note=None, delay=0.4):
    """Fetch competitor pages (public, 1 request each) and compare on-page basics with your crawl."""
    from .seo import _fetch
    rows = []
    for u in comp_urls[:8]:
        if ui_note: ui_note(u[-40:])
        r = _fetch(u); time.sleep(delay)
        if r["status"] != 200 or b"<" not in r["body"][:2000]: rows.append(dict(url=u, status=r["status"])); continue
        p = analyze_html(r["body"].decode("utf-8", "ignore"))
        rows.append(dict(url=u, status=200, title=(p.title or "").strip(), title_len=len((p.title or "").strip()), description_len=len(p.meta.get("description", "")), h1=(p.h1_text[0].strip() if p.h1_text else ""), h2=p.h["h2"], words=p.words(), jsonld=len(p.ld), og=bool(p.og.get("og:title")), images=p.imgs, links=len(p.links), ttfb_ms=r["ms"]))
    ok = [r for r in rows if r.get("status") == 200]
    mine = [p for p in own_pages if p.get("status") == 200 and p.get("words")]
    summary = {}
    if ok and mine:
        avg = lambda xs: round(sum(xs) / len(xs)) if xs else 0
        summary = dict(avg_words_competitors=avg([r["words"] for r in ok]), avg_words_you=avg([p["words"] for p in mine]), jsonld_competitors=sum(1 for r in ok if r["jsonld"]), competitors=len(ok), ttfb_competitors=avg([r["ttfb_ms"] for r in ok]), ttfb_you=avg([p["ms"] for p in mine]))
    return rows, summary
