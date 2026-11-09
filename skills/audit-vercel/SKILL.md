---
name: audit-vercel
description: Vercel / Next.js deployment auditor. Reviews vercel.json, next.config, cron endpoints (CRON_SECRET), API routes without authentication, public env vars that look like secrets, middleware coverage, security headers, source maps, Next.js CVE-2025-29927, the live site, and (with a token) project settings and env-var metadata via the read-only API. Use when the project has vercel.json, .vercel, @vercel/* packages, or the user mentions Vercel, Next.js deployment, serverless, preview deployments.
---

# audit-vercel

Vercel is serverless - there is no server to SSH into, so **the configuration is the attack surface**. Read-only.

## 0. Baseline from the CLI
`python3 <suite>/audit.py <project> --only vercel --strictness <basic|standard|strict>` (ask the user which level; default standard). Add `--url https://app.vercel.app --authorized` for the live site (headers, source maps, exposed `/.env` or `/.git/HEAD`). For project settings export `VERCEL_TOKEN` (never on the command line) and add `--vercel-project NAME [--vercel-team ID] --authorized`; only settings and variable names/types are read, never values.

## 1. Review order
1. **Secrets in the browser:** `NEXT_PUBLIC_`/`VITE_`/`REACT_APP_`/`EXPO_PUBLIC_` variables whose names say secret/token/private - rename, keep server-side, rotate.
2. **Cron and API routes:** every cron path must verify `Authorization: Bearer ${CRON_SECRET}`; every mutating route needs authentication and authorisation inside the handler (not only middleware); webhooks verify the provider signature.
3. **Next.js version:** CVE-2025-29927 (middleware bypass via `x-middleware-subrequest`) fixed in 12.3.5, 13.5.9, 14.2.25, 15.2.3.
4. **Config:** `public: true`, literal secrets in `vercel.json`, `ignoreBuildErrors`, `productionBrowserSourceMaps`, wildcard `images.remotePatterns`, redirects to external hosts, missing security headers, EOL Node.
5. **Project settings (API):** Deployment Protection for previews, public source, Git Fork Protection, secrets stored as Sensitive, production secrets not shared with Preview/Development.

## 2. Reporting
For each finding give `file:line`, the exact change, and the verification (`curl -I`, unauthenticated request returning 401, devtools Sources without maps).
