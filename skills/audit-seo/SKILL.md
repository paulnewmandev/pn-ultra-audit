---
name: audit-seo
description: SEO and SEM auditor for web projects. Checks on-page and technical SEO (titles, meta, canonical, H1, robots.txt, sitemap, noindex, redirects, structured data, Open Graph, hreflang, Core Web Vitals hints, SSR vs CSR), SEM readiness (analytics/ads tags, consent mode, conversions, landing pages) from source code AND from a live crawl of a site you own, and turns Google Search Console exports and free keyword ideas into prioritized opportunities. Optionally uses OpenSEO MCP for keyword/rank/backlink data. Use for "reporte SEO", "auditoría SEO/SEM", "keywords", "por qué no rankea", "tracking de anuncios".
---

# audit-seo

## What is free vs paid
| Need | Free, built into PN-Ultra-Audit | Paid / external |
|---|---|---|
| Technical + on-page audit (source) | `audit.py <project>` (static SEO/SEM stage) | - |
| Live site audit | `audit.py --url https://site --authorized [--psi]` (robots-aware crawler, redirects, titles, canonicals, sitemap, noindex, mixed content, compression, TTFB; PageSpeed Insights optional) | Screaming Frog/Sitebulb (desktop, closed) |
| Keyword ideas | `--keywords "seed1,seed2"` (public autocomplete; intent tags) | Keyword volume/difficulty → DataForSEO/Semrush/Ahrefs |
| Real rankings & queries | `--gsc-csv Queries.csv` / `Pages.csv` (Search Console export; striking-distance, low-CTR, zero-click) | - (GSC is free for your own site) |
| Competitor on-page | `--competitor URL` (public pages, polite) | competitor traffic/backlinks need paid data |
| Rank tracking over time | GSC exports per run + `--baseline auto` | SerpBear (MIT, self-host; needs proxies/API), OpenSEO (MIT; DataForSEO key) |
| Backlinks | - | OpenSEO / Ahrefs Webmaster Tools (free for your own verified site) / Common Crawl graph |

Be honest in the report: free modes give **audit + opportunities**, not search-volume or backlink databases.

## Workflow
1. **Static**: run the CLI on the repo; read findings with `category: seo|sem|privacy` and the **SEO/SEM score** (Technical, On-page, Content, Page experience, Structured data, Tracking).
2. **Live** (only with the owner's explicit authorization, own domain): `--url`, then fix `SEO-LIVE-*` items. Respect robots; keep `--crawl-max` small; never crawl third-party sites you don't own except single public pages via `--competitor`.
3. **Search data**: ask the user for Search Console exports (Performance → Export) and run `--gsc-csv`. Prioritize: (a) *striking distance* (positions 4-20 with impressions) → rewrite title/H1, add internal links, expand content; (b) *top-5 with CTR < 3 %* → rewrite title/description; (c) *zero clicks* → intent mismatch or cannibalization.
4. **Keywords**: `--keywords` to expand seeds; cluster by intent (informational → blog; commercial/transactional → landing/product); map each cluster to ONE URL; avoid cannibalization.
5. **SEM**: verify tag inventory (GA4, GTM, Ads, Meta, TikTok…), **consent management and Consent Mode v2**, conversion events with value/currency, no duplicate tags, UTM/gclid preserved, landing page speed (LCP < 2.5 s) and message match. Tracking before consent is a legal risk (GDPR/ePrivacy) - flag it as such.
6. **Optional OpenSEO MCP** (if the user has it configured: MIT project, needs a DataForSEO key): use its tools for keyword volume/difficulty, rank tracking, competitor and backlink data, and merge with the findings. If it is not configured, do not invent numbers.

## Checks that matter most (in order)
indexability (robots, noindex, canonical, status codes, sitemap) → rendering (SSR/SSG vs CSR) → titles/H1/intent match → internal linking & crawl depth → duplicate/thin content → Core Web Vitals (LCP/INP/CLS) → structured data (Organization, WebSite, Article, Product, FAQ, Breadcrumb) → i18n (hreflang) → security basics (HTTPS, HSTS, no mixed content) → tracking & consent.

## Output
Findings in the shared schema (category `seo`/`sem`/`privacy`, SEO findings do not affect the code Reliability/Security ratings but drive the SEO score). Deliver: score per category, top-10 wins ordered by (impact ÷ effort), a keyword-to-URL map, and a 30-day plan.
Notes: OpenSEO (every-app/open-seo, MIT) and the open-source tools SEOnaut (MIT), Greenflare (GPL), LibreCrawl, SiteOne Crawler, advertools and SerpBear are complementary; their code is not bundled here.
