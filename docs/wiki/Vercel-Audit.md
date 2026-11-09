# Vercel Audit

Vercel is serverless: there is no server to SSH into, so the **configuration is the attack surface**. PN-Ultra-Audit audits it in three ways.

## 1. Project files (always, when `vercel.json`, `.vercel/` or `@vercel/*` is present)
```bash
python3 audit.py ./my-next-app
```
| Check | Why |
|---|---|
| `vercel.json` `public: true`, literal secrets in `env`/`build.env` | source exposure, committed secrets |
| Cron endpoints without a `CRON_SECRET` check | anyone can trigger them (cost, data) |
| `NEXT_PUBLIC_` / `VITE_` / `REACT_APP_` variables named like secrets | bundled into the browser |
| API routes that write without visible authentication; middleware matcher excluding `/api` | missing authorization |
| Next.js versions affected by **CVE-2025-29927** (middleware bypass; fixed in 12.3.5, 13.5.9, 14.2.25, 15.2.3) | auth bypass |
| `ignoreBuildErrors`, `productionBrowserSourceMaps`, wildcard `images.remotePatterns`, redirects forwarding to external hosts | quality and exposure |
| Missing security headers, EOL Node version, committed `.vercel/` or `vercel env pull` output | hardening, secrets |

## 2. The deployed site
```bash
python3 audit.py --url https://my-app.vercel.app --authorized
```
Detects Vercel from headers and checks browser security headers, public source maps, and `/.env` or `/.git/HEAD` served publicly.

## 3. Project settings through the read-only API (optional)
```bash
export VERCEL_TOKEN=...        # never on the command line
python3 audit.py --vercel-project my-app --vercel-team my-team --authorized
```
Reads project settings and environment-variable **names, types and targets only** (never values): previews without Deployment Protection, public source, Git Fork Protection off, directory listing, EOL Node, secrets stored as plain text instead of Sensitive, public-prefixed secrets, production secrets also exposed to Preview and Development.

> The API part follows Vercel's documented REST API but has not been exercised against a live account by the maintainers; it degrades to a clear message on any API error. Reports are welcome.

## Fixing
Each finding has the exact change. Rotate anything exposed (see the rotation guide in [Repository Hygiene and Leaked Keys](Repository-Hygiene-and-Leaked-Keys)).
