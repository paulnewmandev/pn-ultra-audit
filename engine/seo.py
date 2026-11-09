"""SEO + SEM audit.  Static (source/templates) and optional live crawl of a site you own.
Stdlib only.  Live mode sends polite GET requests (rate-limited, robots-aware) - needs --authorized."""
import json, os, re, shutil, subprocess, time, urllib.error, urllib.parse, urllib.request
from collections import Counter, defaultdict
from html.parser import HTMLParser

from .kb import KB

UA = "PN-Ultra-Audit/1.0 (+https://github.com/paulnewmandev/pn-ultra-audit; site-owner audit)"
TPL_EXT = {"html", "htm", "php", "twig", "ejs", "hbs", "jinja", "j2", "cshtml", "erb", "vue", "svelte", "jsx", "tsx", "astro", "liquid"}
TESTISH = re.compile(r"(^|/)(tests?|__tests__|node_modules|vendor|dist|build|\.next|storybook|stories|cypress|e2e)(/|$)")
WEIGHT = {"critical": 12, "high": 8, "medium": 4, "low": 1.5, "info": 0.3}
CATS = {"technical": "Technical & crawlability", "onpage": "On-page", "content": "Content", "perf": "Page experience", "structured": "Structured data & social", "tracking": "SEM / tracking"}


def _f(rule, title, family, typ, sev, cat, file, line, ev, fix=None, effort=15, status="confirmed", priority=None, why=None, seo_cat="onpage", owasp=()):
    kb = KB[family]
    d = dict(rule=rule, title=title, family=family, type=typ, severity=sev if status == "confirmed" else None, category=cat, file=file, line=line, evidence=ev[:500], impact=kb["impact"],
             fix=fix or "; ".join(kb["steps"][:2]), effort_min=effort, cwe=[], owasp=list(owasp), status=status, priority=priority, why=why)
    d["seo_cat"] = seo_cat
    return d


class Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = None; self._in_title = False; self.meta = {}; self.canon = None; self.h = Counter(); self.h1_text = []; self._cur = None
        self.imgs = 0; self.imgs_noalt = 0; self.imgs_nosize = 0; self.imgs_nolazy = 0; self.links = []; self.ld = []; self._in_ld = False; self.text = []
        self.lang = None; self.hreflang = []; self.scripts_blocking = 0; self.mixed = []; self.viewport = None; self._skip = 0; self.noopener = 0; self.badanchor = 0; self._a = None; self.og = {}; self.tw = {}

    def handle_starttag(self, tag, a):
        a = dict(a)
        if tag == "html": self.lang = a.get("lang")
        elif tag == "title": self._in_title = True; self.title = ""
        elif tag == "meta":
            n = (a.get("name") or "").lower(); p = (a.get("property") or "").lower()
            if n: self.meta[n] = a.get("content", "")
            if p.startswith("og:"): self.og[p] = a.get("content", "")
            if n.startswith("twitter:"): self.tw[n] = a.get("content", "")
            if n == "viewport": self.viewport = a.get("content", "")
        elif tag == "link":
            rel = (a.get("rel") or "").lower()
            if "canonical" in rel: self.canon = a.get("href")
            if "alternate" in rel and a.get("hreflang"): self.hreflang.append(a["hreflang"])
        elif tag in ("h1", "h2", "h3", "h4", "h5", "h6"): self.h[tag] += 1; self._cur = tag if tag == "h1" else None; self.h1_text.append("") if tag == "h1" else None
        elif tag == "img":
            self.imgs += 1
            if "alt" not in a: self.imgs_noalt += 1
            if not (a.get("width") and a.get("height")): self.imgs_nosize += 1
            if (a.get("loading") or "").lower() != "lazy": self.imgs_nolazy += 1
            if (a.get("src") or "").startswith("http://"): self.mixed.append(a["src"])
        elif tag == "a":
            href = a.get("href"); self._a = {"href": href, "text": ""}
            if href: self.links.append(href)
            if a.get("target") == "_blank" and "noopener" not in (a.get("rel") or "") and "noreferrer" not in (a.get("rel") or "") and href and href.startswith("http"): self.noopener += 1
            if href in ("#", "") or (href or "").startswith("javascript:"): self.badanchor += 1
        elif tag == "script":
            if a.get("type") == "application/ld+json": self._in_ld = True; self.ld.append("")
            elif a.get("src") and "async" not in a and "defer" not in a and a.get("type") != "module": self.scripts_blocking += 1
            if (a.get("src") or "").startswith("http://"): self.mixed.append(a["src"])
            self._skip += 1
        elif tag == "style": self._skip += 1

    def handle_endtag(self, tag):
        if tag == "title": self._in_title = False
        elif tag == "h1": self._cur = None
        elif tag == "script":
            self._in_ld = False; self._skip = max(0, self._skip - 1)
        elif tag == "style": self._skip = max(0, self._skip - 1)
        elif tag == "a" and self._a:
            if re.fullmatch(r"(click here|here|read more|more|link|this)", self._a["text"].strip().lower() or "x"): self.badanchor += 1
            self._a = None

    def handle_data(self, d):
        if self._in_title and self.title is not None: self.title += d
        if self._in_ld and self.ld: self.ld[-1] += d
        if self._cur == "h1" and self.h1_text: self.h1_text[-1] += d
        if self._a is not None: self._a["text"] += d
        if not self._skip: self.text.append(d)

    def words(self): return len(re.findall(r"\w+", " ".join(self.text)))


def analyze_html(t):
    p = Page()
    try: p.feed(t)
    except Exception: pass
    return p


# ───────────────────────── static ─────────────────────────
TRACKERS = [("Google Analytics 4", r"gtag\(\s*['\"]config['\"]\s*,\s*['\"]G-|googletagmanager\.com/gtag/js\?id=G-"), ("Google Tag Manager", r"googletagmanager\.com/gtm\.js|GTM-[A-Z0-9]{5,}"),
            ("Google Ads", r"['\"]AW-\d{6,}|googleadservices\.com|conversion_async|gtag\(\s*['\"]event['\"]\s*,\s*['\"]conversion"), ("Meta Pixel", r"fbq\(\s*['\"]init|connect\.facebook\.net/.*fbevents"),
            ("TikTok Pixel", r"ttq\.load|analytics\.tiktok\.com"), ("LinkedIn Insight", r"snap\.licdn\.com|_linkedin_partner_id"), ("Hotjar", r"static\.hotjar\.com|hj\('"), ("Microsoft Clarity", r"clarity\.ms|clarity\("),
            ("Plausible/Umami/Fathom", r"plausible\.io/js|umami|usefathom"), ("Segment", r"cdn\.segment\.com|analytics\.load\("), ("Pinterest Tag", r"pintrk\(")]
CONSENT = r"cookiebot|onetrust|osano|cookieconsent|cookie-consent|iubenda|usercentrics|klaro|termly|didomi|trustarc|quantcast|axeptio|gtag\(\s*['\"]consent['\"]|react-cookie-consent|cookie[_-]?banner|consent[_-]?mode"


def static_seo(root, files, S):
    out, info = [], {}
    rels = [r for r, *_ in files]; ab = {r: a for r, a, *_ in files}
    tpl = [(r, a) for r, a, e, _ in files if e in TPL_EXT and not TESTISH.search(r)]
    html_pages = [(r, a) for r, a, e, _ in files if e in ("html", "htm") and not TESTISH.search(r) and not re.search(r"(^|/)(partials?|includes?|components?|templates?)/", r)]
    fw = set(S.frameworks) if S else set()
    deps = ""
    for r in rels:
        if os.path.basename(r) == "package.json" and r.count("/") <= 2:
            try: deps += open(ab[r], errors="ignore").read(200_000)
            except OSError: pass
    is_web = bool(html_pages) or bool(re.search(r'"(next|nuxt|react-dom|vue|svelte|astro|@angular/core|gatsby|remix)"', deps)) or any(e in ("php", "twig", "blade") for _, _, e, _ in files[:400]) and any(r.endswith(".blade.php") or "views/" in r for r in rels)
    if not is_web: return out, {}
    info["is_web"] = True
    ssr = bool(re.search(r'"(next|nuxt|astro|@sveltejs/kit|@remix-run/|gatsby|@angular/ssr|@analogjs)"', deps))
    spa = bool(re.search(r'"(react-dom|vue)"', deps)) and not ssr and any(os.path.basename(r) == "index.html" for r in rels)
    pub = lambda name: any(r.endswith(("public/" + name, "static/" + name, "/" + name)) or r == name for r in rels)
    G = "."
    if not pub("robots.txt") and not re.search(r"robots\.(ts|js|txt)$|next-sitemap|robots\.php", " ".join(rels)): out.append(_f("SEO-NO-ROBOTS", "No robots.txt found in the project", "seo-technical", "code_smell", "low", "seo", G, 1, "", "Add public/robots.txt (Allow: / + Sitemap: URL) or app/robots.ts", 10, seo_cat="technical"))
    else:
        for r in rels:
            if r.endswith("robots.txt"):
                t = open(ab[r], errors="ignore").read(20000)
                if re.search(r"(?mi)^User-agent:\s*\*\s*\n(?:\s*#.*\n)*\s*Disallow:\s*/\s*$", t): out.append(_f("SEO-ROBOTS-BLOCKS-ALL", "robots.txt blocks the whole site (Disallow: /)", "seo-technical", "bug", "high", "seo", r, 1, "Disallow: /", "Remove the blanket Disallow before launch (keep it only on staging via auth, not robots)", 5, seo_cat="technical"))
                if not re.search(r"(?mi)^Sitemap:", t): out.append(_f("SEO-ROBOTS-NO-SITEMAP", "robots.txt does not reference the sitemap", "seo-technical", "code_smell", "info", "seo", r, 1, "", "Add `Sitemap: https://your-domain/sitemap.xml`", 2, seo_cat="technical"))
                if re.search(r"(?mi)^Disallow:\s*/(css|js|assets|static|_next)", t): out.append(_f("SEO-ROBOTS-BLOCKS-ASSETS", "robots.txt blocks CSS/JS assets (Google needs them to render)", "seo-technical", "code_smell", "medium", "seo", r, 1, "", "Allow CSS/JS/images", 5, seo_cat="technical"))
    if not pub("sitemap.xml") and not re.search(r"sitemap\.(ts|js|xml|php)|next-sitemap|sitemap-index|@astrojs/sitemap|nuxt-simple-sitemap|gatsby-plugin-sitemap|jekyll-sitemap|django\.contrib\.sitemaps|laravel-sitemap|spatie/laravel-sitemap", " ".join(rels) + deps):
        out.append(_f("SEO-NO-SITEMAP", "No sitemap.xml (or generator) found", "seo-technical", "code_smell", "medium", "seo", G, 1, "", "Generate sitemap.xml automatically (next-sitemap, @astrojs/sitemap, Laravel Sitemap, django.contrib.sitemaps) and submit it in Search Console", 30, seo_cat="technical"))
    if spa: out.append(_f("SEO-CSR-ONLY", "Client-side-rendered SPA without SSR/prerender (crawlers see an empty shell)", "seo-technical", "security_hotspot", None, "seo", G, 1, "index.html + react/vue without next/nuxt/astro/sveltekit", "Move to SSR/SSG (Next, Nuxt, Astro, SvelteKit, Remix) or prerender public routes (vite-plugin-ssr, react-snap)", 480, status="needs_validation", priority="high", why="Google can render JS but later and less reliably; other engines/social bots often cannot. Skip if the app is behind login only", seo_cat="technical"))
    # templates
    tit_missing, desc_missing, canon_missing, h1_bad, og_missing, ld_any, imgs_ns, noindex, blocking, lang_missing, viewport_missing = [], [], [], [], [], False, [], [], [], [], []
    for r, a in html_pages[:300]:
        try: t = open(a, errors="ignore").read(300_000)
        except OSError: continue
        if "<html" not in t.lower() and "<head" not in t.lower(): continue
        p = analyze_html(t)
        if not (p.title or "").strip(): tit_missing.append(r)
        elif len(p.title.strip()) > 65 or len(p.title.strip()) < 15: out.append(_f("SEO-TITLE-LENGTH", f"Title length {len(p.title.strip())} chars (aim 30-60)", "seo-onpage", "code_smell", "low", "seo", r, 1, p.title.strip()[:100], None, 5, seo_cat="onpage"))
        if not (p.meta.get("description") or "").strip(): desc_missing.append(r)
        elif not 50 <= len(p.meta["description"]) <= 165: out.append(_f("SEO-DESC-LENGTH", f"Meta description length {len(p.meta['description'])} chars (aim 70-160)", "seo-onpage", "code_smell", "info", "seo", r, 1, p.meta["description"][:120], None, 5, seo_cat="onpage"))
        if not p.canon: canon_missing.append(r)
        if p.h["h1"] != 1: h1_bad.append((r, p.h["h1"]))
        if not p.og.get("og:title") or not p.og.get("og:image"): og_missing.append(r)
        if p.ld: ld_any = True
        if "noindex" in (p.meta.get("robots", "") + p.meta.get("googlebot", "")).lower(): noindex.append(r)
        if p.imgs_nosize and p.imgs_nosize >= 3: imgs_ns.append((r, p.imgs_nosize))
        if p.scripts_blocking: blocking.append((r, p.scripts_blocking))
        if not p.viewport: viewport_missing.append(r)
    n_pages = len(html_pages)
    def agg(rule, title, items, sev, fam, fix, cat, typ="code_smell", effort_each=5, ev=None):
        if not items: return
        names = [i if isinstance(i, str) else i[0] for i in items]
        out.append(_f(rule, f"{title} ({len(items)} of {n_pages} HTML pages)", fam, typ, sev, "seo", names[0], 1, ev or ", ".join(names[:8]), None, effort_each * len(items), seo_cat=cat))
    agg("SEO-NO-TITLE", "Pages without <title>", tit_missing, "high", "seo-onpage", None, "onpage", "bug")
    agg("SEO-NO-DESCRIPTION", "Pages without meta description", desc_missing, "medium", "seo-onpage", None, "onpage")
    agg("SEO-NO-CANONICAL", "Pages without canonical link", canon_missing, "low", "seo-onpage", None, "technical")
    agg("SEO-H1", "Pages with zero or multiple <h1>", h1_bad, "low", "seo-onpage", None, "onpage", ev=", ".join(f"{r}({n})" for r, n in h1_bad[:8]))
    agg("SEO-NO-OG", "Pages missing Open Graph title/image", og_missing, "low", "seo-onpage", None, "structured")
    agg("SEO-NOINDEX", "Pages marked noindex (confirm this is intended)", noindex, None, "seo-technical", None, "technical")
    if noindex: out[-1].update(status="needs_validation", severity=None, priority="high", why="noindex removes the page from search - make sure it is not a staging flag that reached production")
    agg("SEO-IMG-NO-SIZE", "Pages with ≥3 images lacking width/height (layout shift)", imgs_ns, "low", "seo-perf", None, "perf", ev=", ".join(f"{r}({n})" for r, n in imgs_ns[:6]))
    agg("SEO-RENDER-BLOCKING", "Pages with render-blocking <script> (no async/defer)", blocking, "low", "seo-perf", None, "perf", ev=", ".join(f"{r}({n})" for r, n in blocking[:6]))
    agg("SEO-NO-VIEWPORT", "Pages without viewport meta (not mobile-friendly)", viewport_missing, "medium", "seo-onpage", None, "perf", "bug")
    if n_pages >= 3 and not ld_any: out.append(_f("SEO-NO-JSONLD", "No JSON-LD structured data in any page", "seo-onpage", "code_smell", "low", "seo", G, 1, "", None, 45, seo_cat="structured"))
    # template-level checks across all templates
    noopen = badanchor = 0
    for r, a in tpl[:600]:
        try: t = open(a, errors="ignore").read(200_000)
        except OSError: continue
        noopen += len(re.findall(r"""<a\b[^>]*target\s*=\s*["']_blank["'](?![^>]*\brel\s*=\s*["'][^"']*(noopener|noreferrer))[^>]*>""", t))
        badanchor += len(re.findall(r"""<a\b[^>]*href\s*=\s*["'](#|javascript:[^"']*)["']""", t))
    if noopen >= 3: out.append(_f("SEO-BLANK-NOOPENER", f"{noopen} target=_blank links without rel=noopener", "seo-onpage", "code_smell", "low", "seo", G, 1, "", "Add rel=\"noopener noreferrer\" (also prevents reverse-tabnabbing)", 2 * noopen, seo_cat="technical"))
    if badanchor >= 5: out.append(_f("SEO-NONCRAWLABLE-LINKS", f"{badanchor} anchors with href=\"#\" / javascript: (not crawlable)", "seo-technical", "code_smell", "low", "seo", G, 1, "", "Use real URLs for navigation; <button> for actions", 3 * badanchor, seo_cat="technical"))
    # Next.js / metadata frameworks
    pages = [r for r in rels if re.match(r"^(?:src/)?app/(?:.+/)?page\.(?:tsx|jsx|ts|js)$", r)]
    if pages:
        nometa = []
        for r in pages[:200]:
            d = os.path.dirname(r); lay = [x for x in rels if x == d + "/layout.tsx" or x == d + "/layout.ts" or x == d + "/layout.jsx"]
            t = open(ab[r], errors="ignore").read(100_000) + "".join(open(ab[x], errors="ignore").read(50_000) for x in lay)
            if not re.search(r"export\s+(const\s+metadata|(async\s+)?function\s+generateMetadata)|<title>|next-seo", t): nometa.append(r)
        root_layout = [r for r in rels if re.match(r"^(?:src/)?app/layout\.(tsx|jsx|ts|js)$", r)]
        has_root_meta = any(re.search(r"export\s+const\s+metadata|generateMetadata", open(ab[r], errors="ignore").read(60_000)) for r in root_layout)
        if nometa and not has_root_meta: out.append(_f("SEO-NEXT-NO-METADATA", f"{len(nometa)} Next.js pages export no metadata/generateMetadata", "seo-onpage", "code_smell", "medium", "seo", nometa[0], 1, ", ".join(nometa[:8]), "Export `metadata` (title, description, openGraph, alternates.canonical) from each page/layout", 8 * len(nometa), seo_cat="onpage"))
    # i18n
    locs = {m.group(1) for r in rels for m in [re.match(r"^(?:src/)?(?:locales?|i18n|messages|lang)/([a-z]{2}(?:[-_][A-Za-z]{2})?)[./]", r)] if m}
    if len(locs) >= 2 and not re.search(r"hreflang", " ".join(open(ab[r], errors="ignore").read(40_000) for r, _ in tpl[:300])): out.append(_f("SEO-NO-HREFLANG", f"{len(locs)} locales found but no hreflang annotations", "seo-technical", "security_hotspot", None, "seo", G, 1, ", ".join(sorted(locs)), "Add <link rel=alternate hreflang> (and x-default) or alternates.languages in Next metadata", 60, status="needs_validation", priority="medium", why="hreflang may be emitted by the framework/i18n plugin at build time", seo_cat="technical"))
    # heavy images in repo
    big = sorted(((sz, r) for r, a, e, sz in files if e in ("png", "jpg", "jpeg", "gif", "bmp") and sz > 400_000 and re.search(r"(public|static|assets|images|img)/", r)), reverse=True)
    # files list excludes images; scan directly
    heavy = []
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in ("node_modules", ".git", "vendor", "dist", "build", ".next", "audit-output")]
        for f in fn:
            if f.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".bmp")):
                try: s = os.path.getsize(os.path.join(dp, f))
                except OSError: continue
                if s > 400_000: heavy.append((s, os.path.relpath(os.path.join(dp, f), root)))
        if len(heavy) > 400: break
    heavy.sort(reverse=True)
    if heavy: out.append(_f("SEO-HEAVY-IMAGES", f"{len(heavy)} image file(s) over 400 KB in the repo (largest {heavy[0][0] // 1024} KB)", "seo-perf", "performance", "low" if len(heavy) < 5 else "medium", "seo", heavy[0][1], 1,
                            "; ".join(f"{r} {s // 1024}KB" for s, r in heavy[:6]), "Convert to AVIF/WebP, resize to display size, serve responsive srcset via an image CDN/optimizer", 10 * min(len(heavy), 20), seo_cat="perf"))
    if not any(re.search(r"(^|/)(404|not-found|\+error)\.(html|php|tsx|jsx|vue|svelte|astro)$|errors/404", r) for r in rels) and n_pages >= 3: out.append(_f("SEO-NO-404-PAGE", "No custom 404 page found", "seo-technical", "code_smell", "info", "seo", G, 1, "", "Add a helpful 404 that returns an HTTP 404 status", 20, seo_cat="technical"))
    # SEM / tracking
    alltext = {}
    for r, a in tpl[:800]:
        try: alltext[r] = open(a, errors="ignore").read(200_000)
        except OSError: pass
    for r, a, e, _ in files:
        if e in ("js", "ts", "mjs") and re.search(r"(analytics|gtm|gtag|pixel|tracking|consent)", r, re.I) and r not in alltext:
            try: alltext[r] = open(a, errors="ignore").read(100_000)
            except OSError: pass
    blob = "\n".join(alltext.values()) + deps
    found = [(n, next((r for r, t in alltext.items() if re.search(rx, t)), None)) for n, rx in TRACKERS if re.search(rx, blob)]
    info["trackers"] = [dict(name=n, file=f) for n, f in found]
    ads = [n for n, _ in found if n in ("Google Ads", "Meta Pixel", "TikTok Pixel", "LinkedIn Insight", "Pinterest Tag")]
    if found and not re.search(CONSENT, blob, re.I):
        out.append(_f("SEM-NO-CONSENT", f"Tracking tags found ({', '.join(n for n, _ in found[:5])}) but no consent management detected", "sem-tracking", "vulnerability" if ads else "security_hotspot", "medium" if ads else None, "privacy", found[0][1] or G, 1, ", ".join(f"{n} @ {f}" for n, f in found[:5]),
                      None, 120, status="confirmed" if ads else "needs_validation", priority="high", owasp=["A04:2021"], why=None if ads else "consent may be handled by the tag manager container (outside the repo)", seo_cat="tracking"))
    if re.search(r"googletagmanager\.com/gtag/js|gtag\(", blob) and re.search(CONSENT, blob, re.I) and not re.search(r"gtag\(\s*['\"]consent['\"]\s*,\s*['\"]default", blob): out.append(_f("SEM-NO-CONSENT-MODE", "Google tag without Consent Mode v2 default", "sem-tracking", "security_hotspot", None, "privacy", G, 1, "", "Add gtag('consent','default',{ad_storage:'denied',analytics_storage:'denied',ad_user_data:'denied',ad_personalization:'denied'}) before config", 30, status="needs_validation", priority="medium", why="the CMP may set it dynamically", seo_cat="tracking"))
    if found and not re.search(r"gtag\(\s*['\"]event['\"]|dataLayer\.push\(|fbq\(\s*['\"]track|ttq\.track|lintrk\(|pintrk\(\s*['\"]track", blob): out.append(_f("SEM-NO-CONVERSIONS", "Tracking installed but no conversion events found (purchase/lead/sign_up)", "sem-tracking", "security_hotspot", None, "sem", found[0][1] or G, 1, "", "Fire gtag('event','purchase'|'generate_lead'|'sign_up',{value,currency}) / dataLayer.push and import to Google Ads", 60, status="needs_validation", priority="medium", why="events may be configured inside GTM", seo_cat="tracking"))
    tags = Counter(re.findall(r"G-[A-Z0-9]{6,}|GTM-[A-Z0-9]{5,}|AW-\d{6,}", blob)); dup = [k for k, v in tags.items() if v > 1 and sum(1 for t in alltext.values() if k in t) > 3]
    if "Google Tag Manager" in dict(found) and "Google Analytics 4" in dict(found) and re.search(r"gtag/js\?id=G-", blob) and re.search(r"gtm\.js", blob): out.append(_f("SEM-DUPLICATE-GA4", "GA4 hard-coded AND Google Tag Manager present (risk of double-counting)", "sem-tracking", "security_hotspot", None, "sem", G, 1, "", "Load GA4 only through GTM (or only hard-coded), not both", 20, status="needs_validation", priority="low", why="GTM may not contain a GA4 tag", seo_cat="tracking"))
    if not found and n_pages >= 3: info["no_tracking"] = True
    return out, info


# ───────────────────────── live crawl ─────────────────────────
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None


def _get(url, timeout=12, head=False, maxbytes=1_500_000):
    op = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, method="HEAD" if head else "GET", headers={"User-Agent": UA, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8", "Accept-Encoding": "gzip"})
    t0 = time.time()
    try:
        r = op.open(req, timeout=timeout); body = b"" if head else r.read(maxbytes); code, hdr = r.status, dict((k.lower(), v) for k, v in r.getheaders())
    except urllib.error.HTTPError as e:
        code, hdr = e.code, dict((k.lower(), v) for k, v in e.headers.items())
        try: body = b"" if head else e.read(maxbytes)
        except Exception: body = b""
    except Exception as e:
        return dict(url=url, status=0, error=str(e)[:120], headers={}, body=b"", ms=int((time.time() - t0) * 1000))
    return dict(url=url, status=code, headers=hdr, body=body, ms=int((time.time() - t0) * 1000))


def _fetch(url, max_hops=5):
    hops, cur = [], url
    for _ in range(max_hops + 1):
        r = _get(cur)
        if r["status"] in (301, 302, 303, 307, 308) and r["headers"].get("location"):
            hops.append((cur, r["status"])); cur = urllib.parse.urljoin(cur, r["headers"]["location"]); continue
        r["hops"] = hops; r["final"] = cur; return r
    r["hops"] = hops; r["final"] = cur; r["loop"] = True; return r


def crawl(base, max_pages=25, delay=0.3, ui_note=None):
    out, pages = [], []
    u = urllib.parse.urlparse(base)
    if u.scheme not in ("http", "https") or not u.netloc: return out, {"error": "invalid URL"}
    origin = f"{u.scheme}://{u.netloc}"; lab = base
    def F(*a, **k):
        d = _f(*a, **k); d["file"] = k.get("file_override") or d["file"]; return d
    robots = _get(origin + "/robots.txt")
    rtxt = robots["body"].decode("utf-8", "ignore") if robots["status"] == 200 else ""
    if robots["status"] != 200: out.append(_f("SEO-LIVE-NO-ROBOTS", "robots.txt not found (HTTP %s)" % robots["status"], "seo-technical", "code_smell", "low", "seo", origin + "/robots.txt", 1, "", None, 10, seo_cat="technical"))
    elif re.search(r"(?mi)^User-agent:\s*\*\s*\n(?:\s*#.*\n)*\s*Disallow:\s*/\s*$", rtxt): out.append(_f("SEO-LIVE-ROBOTS-BLOCKS-ALL", "Live robots.txt blocks the entire site", "seo-technical", "bug", "critical", "seo", origin + "/robots.txt", 1, "Disallow: /", None, 5, seo_cat="technical"))
    disallow = [m.group(1) for m in re.finditer(r"(?mi)^Disallow:\s*(/\S*)", rtxt)] if rtxt else []
    sm_urls = re.findall(r"(?mi)^Sitemap:\s*(\S+)", rtxt)
    smap = _get(sm_urls[0] if sm_urls else origin + "/sitemap.xml")
    urls_sm = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", smap["body"].decode("utf-8", "ignore")) if smap["status"] == 200 else []
    if smap["status"] != 200: out.append(_f("SEO-LIVE-NO-SITEMAP", "sitemap.xml not found (HTTP %s)" % smap["status"], "seo-technical", "code_smell", "medium", "seo", origin + "/sitemap.xml", 1, "", None, 30, seo_cat="technical"))
    elif not sm_urls: out.append(_f("SEO-ROBOTS-NO-SITEMAP", "robots.txt does not reference the sitemap", "seo-technical", "code_smell", "info", "seo", origin + "/robots.txt", 1, "", None, 2, seo_cat="technical"))
    # http -> https
    if u.scheme == "https":
        h = _get("http://" + u.netloc + "/")
        if h["status"] not in (301, 308) or not (h["headers"].get("location", "").startswith("https://")): out.append(_f("SEO-LIVE-NO-HTTPS-REDIRECT", "http:// does not 301-redirect to https://", "seo-technical", "bug", "medium", "seo", "http://" + u.netloc + "/", 1, f"status {h['status']}", "Add a permanent redirect from http to https at the edge/server", 10, seo_cat="technical"))
    queue, seen = [base], {base.rstrip("/")}
    for x in urls_sm[:max_pages]:
        if x.rstrip("/") not in seen and urllib.parse.urlparse(x).netloc == u.netloc: queue.append(x); seen.add(x.rstrip("/"))
    titles, descs, linkset = defaultdict(list), defaultdict(list), set()
    n = 0
    while queue and n < max_pages:
        url = queue.pop(0); n += 1
        if ui_note: ui_note(f"{n}/{max_pages} {url[-50:]}")
        if any(urllib.parse.urlparse(url).path.startswith(d) for d in disallow if d != "/"): continue
        r = _fetch(url); time.sleep(delay)
        pg = dict(url=url, status=r["status"], ms=r["ms"], hops=len(r["hops"]), final=r.get("final", url), size=len(r["body"]), title=None, description=None, h1=None, words=0, canonical=None, noindex=False)
        if r["status"] == 0: out.append(_f("SEO-LIVE-UNREACHABLE", f"Page unreachable: {r.get('error', '')}", "seo-technical", "bug", "high", "seo", url, 1, r.get("error", ""), None, 30, seo_cat="technical")); pages.append(pg); continue
        if len(r["hops"]) >= 2: out.append(_f("SEO-LIVE-REDIRECT-CHAIN", f"Redirect chain of {len(r['hops'])} hops", "seo-technical", "code_smell", "medium", "seo", url, 1, " → ".join(f"{a} [{s}]" for a, s in r["hops"]) + f" → {r['final']}", "Point links and the first redirect straight to the final URL with a single 301", 15, seo_cat="technical"))
        if r.get("loop"): out.append(_f("SEO-LIVE-REDIRECT-LOOP", "Redirect loop / too many redirects", "seo-technical", "bug", "high", "seo", url, 1, "", None, 30, seo_cat="technical"))
        if r["status"] >= 400:
            out.append(_f("SEO-LIVE-ERROR-PAGE", f"HTTP {r['status']} on a discovered URL", "seo-technical", "bug", "high" if r["status"] >= 500 else "medium", "seo", url, 1, f"status {r['status']}", "Fix the page or remove/redirect links and sitemap entries pointing to it", 30, seo_cat="technical")); pages.append(pg); continue
        ct = r["headers"].get("content-type", "")
        if "html" not in ct: pages.append(pg); continue
        enc = r["headers"].get("content-encoding", "")
        raw = r["body"]
        if enc == "gzip":
            import gzip
            try: raw = gzip.decompress(raw)
            except Exception: pass
        p = analyze_html(raw.decode("utf-8", "ignore"))
        pg.update(title=(p.title or "").strip(), description=(p.meta.get("description") or "").strip(), h1=(p.h1_text[0].strip() if p.h1_text else None), words=p.words(), canonical=p.canon, noindex="noindex" in (p.meta.get("robots", "") + r["headers"].get("x-robots-tag", "")).lower(), lang=p.lang, imgs=p.imgs, imgs_noalt=p.imgs_noalt, h1_count=p.h["h1"], jsonld=len(p.ld), og=bool(p.og.get("og:title")), compressed=bool(enc))
        pages.append(pg)
        titles[pg["title"]].append(url); descs[pg["description"]].append(url)
        if not pg["title"]: out.append(_f("SEO-LIVE-NO-TITLE", "Page has no <title>", "seo-onpage", "bug", "high", "seo", url, 1, "", None, 5, seo_cat="onpage"))
        elif not 15 <= len(pg["title"]) <= 65: out.append(_f("SEO-TITLE-LENGTH", f"Title length {len(pg['title'])} chars (aim 30-60)", "seo-onpage", "code_smell", "low", "seo", url, 1, pg["title"][:100], None, 5, seo_cat="onpage"))
        if not pg["description"]: out.append(_f("SEO-LIVE-NO-DESCRIPTION", "Page has no meta description", "seo-onpage", "code_smell", "medium", "seo", url, 1, "", None, 5, seo_cat="onpage"))
        if p.h["h1"] != 1: out.append(_f("SEO-H1", f"{p.h['h1']} <h1> elements (should be exactly 1)", "seo-onpage", "code_smell", "low", "seo", url, 1, "", None, 5, seo_cat="onpage"))
        if not p.canon: out.append(_f("SEO-NO-CANONICAL", "No canonical link", "seo-onpage", "code_smell", "low", "seo", url, 1, "", None, 3, seo_cat="technical"))
        elif urllib.parse.urlparse(urllib.parse.urljoin(url, p.canon)).netloc != u.netloc: out.append(_f("SEO-LIVE-CANON-OFFSITE", "Canonical points to another host", "seo-technical", "bug", "medium", "seo", url, 1, p.canon, None, 10, seo_cat="technical"))
        if pg["noindex"]: out.append(_f("SEO-NOINDEX", "Page is noindex", "seo-technical", "security_hotspot", None, "seo", url, 1, "robots meta / X-Robots-Tag: noindex", None, 5, status="needs_validation", priority="high", why="verify this is intended - it removes the page from search", seo_cat="technical"))
        if pg["words"] < 200 and not pg["noindex"]: out.append(_f("SEO-LIVE-THIN", f"Thin content ({pg['words']} words)", "seo-content", "code_smell", "low", "seo", url, 1, "", None, 45, seo_cat="content"))
        if not p.lang: out.append(_f("A11Y-HTML-LANG", "<html> without lang attribute", "a11y", "bug", "low", "a11y", url, 1, "", None, 2, seo_cat="onpage"))
        if p.imgs_noalt: out.append(_f("SEO-IMG-ALT", f"{p.imgs_noalt} of {p.imgs} images without alt", "seo-onpage", "bug", "medium" if p.imgs_noalt >= 3 else "low", "seo", url, 1, "", None, 3 * p.imgs_noalt, seo_cat="onpage"))
        if not p.ld: out.append(_f("SEO-NO-JSONLD", "No structured data (JSON-LD)", "seo-onpage", "code_smell", "info", "seo", url, 1, "", None, 30, seo_cat="structured"))
        if not p.og.get("og:title") or not p.og.get("og:image"): out.append(_f("SEO-NO-OG", "Missing Open Graph title/image", "seo-onpage", "code_smell", "low", "seo", url, 1, "", None, 10, seo_cat="structured"))
        if not p.viewport: out.append(_f("SEO-NO-VIEWPORT", "No viewport meta", "seo-onpage", "bug", "medium", "seo", url, 1, "", None, 3, seo_cat="perf"))
        if r["ms"] > 1500: out.append(_f("SEO-LIVE-SLOW", f"Slow response ({r['ms']} ms)", "seo-perf", "performance", "medium" if r["ms"] > 3000 else "low", "seo", url, 1, f"{r['ms']} ms (includes network latency from the audit machine)", None, 60, seo_cat="perf"))
        if not enc and len(r["body"]) > 20_000: out.append(_f("SEO-LIVE-NO-COMPRESSION", "HTML is not compressed (gzip/br)", "seo-perf", "performance", "low", "seo", url, 1, f"{len(r['body']) // 1024} KB", "Enable gzip/brotli on the server/CDN", 10, seo_cat="perf"))
        if p.mixed and u.scheme == "https": out.append(_f("SEO-LIVE-MIXED-CONTENT", f"{len(p.mixed)} http:// resource(s) on an https page", "seo-technical", "bug", "medium", "seo", url, 1, ", ".join(p.mixed[:3]), "Use https:// (or protocol-relative) for all assets", 10, seo_cat="technical"))
        if p.imgs_nosize >= 3: out.append(_f("SEO-IMG-NO-SIZE", f"{p.imgs_nosize} images without width/height (layout shift)", "seo-perf", "performance", "low", "seo", url, 1, "", None, 15, seo_cat="perf"))
        for href in p.links:
            ab_ = urllib.parse.urljoin(url, href.split("#")[0]); pu = urllib.parse.urlparse(ab_)
            if pu.netloc == u.netloc and pu.scheme in ("http", "https") and ab_.rstrip("/") not in seen and not re.search(r"\.(pdf|zip|jpg|jpeg|png|gif|svg|webp|mp4|css|js|ico|xml)$", pu.path, re.I) and len(seen) < max_pages * 3:
                seen.add(ab_.rstrip("/")); queue.append(ab_)
            if pu.netloc == u.netloc: linkset.add(ab_)
    for t, us in titles.items():
        if t and len(us) > 1: out.append(_f("SEO-LIVE-DUP-TITLE", f"Duplicate title on {len(us)} pages", "seo-content", "code_smell", "medium", "seo", us[0], 1, f'"{t[:70]}" → ' + ", ".join(us[:4]), "Give each page a unique title", 10 * len(us), seo_cat="content"))
    for d, us in descs.items():
        if d and len(us) > 1: out.append(_f("SEO-LIVE-DUP-DESC", f"Duplicate meta description on {len(us)} pages", "seo-content", "code_smell", "low", "seo", us[0], 1, f'"{d[:70]}" → ' + ", ".join(us[:4]), "Write unique descriptions", 5 * len(us), seo_cat="content"))
    return out, dict(base=base, pages=pages, sitemap_urls=len(urls_sm), robots=bool(rtxt), crawled=len(pages))


def psi(url, key=None, ui_note=None):
    """Optional: Google PageSpeed Insights (sends the URL to Google). Returns findings + scores."""
    out, scores = [], {}
    for strat in ("mobile", "desktop"):
        q = urllib.parse.urlencode({"url": url, "strategy": strat, **({"key": key} if key else {})}) + "&category=performance&category=seo&category=accessibility&category=best-practices"
        r = _get("https://www.googleapis.com/pagespeedonline/v5/runPagespeed?" + q, timeout=90, maxbytes=8_000_000)
        if r["status"] != 200: scores[strat] = {"error": f"HTTP {r['status']}"}; continue
        try: j = json.loads(r["body"])["lighthouseResult"]
        except (ValueError, KeyError): continue
        sc = {k: round((v.get("score") or 0) * 100) for k, v in j["categories"].items()}
        aud = j["audits"]; vit = {k: aud[k].get("displayValue", "") for k in ("largest-contentful-paint", "cumulative-layout-shift", "total-blocking-time", "first-contentful-paint", "speed-index") if k in aud}
        scores[strat] = dict(scores=sc, vitals=vit)
        if sc.get("performance", 100) < 90: out.append(_f("SEO-PSI-PERF", f"PageSpeed {strat} performance score {sc['performance']}/100", "seo-perf", "performance", "high" if sc["performance"] < 50 else "medium", "seo", url, 1, ", ".join(f"{k}: {v}" for k, v in vit.items()), None, 120, seo_cat="perf"))
        if sc.get("seo", 100) < 90: out.append(_f("SEO-PSI-SEO", f"Lighthouse SEO score {sc['seo']}/100 ({strat})", "seo-onpage", "code_smell", "medium", "seo", url, 1, ", ".join(a["title"] for a in aud.values() if a.get("score") == 0 and "seo" in str(j["categories"]["seo"].get("auditRefs", ""))[:0] or False)[:300], None, 60, seo_cat="onpage"))
    return out, scores


def score(findings, crawl_info=None):
    """0-100 SEO/SEM health score per category from confirmed findings with seo_cat."""
    cats = {k: 100.0 for k in CATS}
    for f in findings:
        c = f.get("seo_cat")
        if c in cats and f["status"] == "confirmed": cats[c] = max(0, cats[c] - WEIGHT.get(f["severity"], 0))
    cats = {k: round(v) for k, v in cats.items()}
    total = round(sum(cats.values()) / len(cats))
    return dict(score=total, categories={CATS[k]: v for k, v in cats.items()})
