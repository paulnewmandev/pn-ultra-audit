"""Knowledge base for Vercel deployments (config, Next.js, env vars, project settings)."""
KB_VERCEL = {
"vercel-config": dict(
    title="Vercel project configuration and Next.js hardening",
    explain="Vercel runs your project as serverless/edge functions behind its CDN. Mistakes live in `vercel.json`, `next.config.*`, API routes, cron endpoints, redirects and public environment variables - there is no server to SSH into, so the config IS the attack surface.",
    impact="Secrets shipped to the browser, public cron/API endpoints anyone can trigger (cost and data abuse), exposed source maps, bypassable middleware auth and missing browser security headers.",
    steps=["Never put secrets in variables that are bundled for the browser (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `PUBLIC_`, `EXPO_PUBLIC_`): keep them server-only and read them in API routes / server components.",
           "Protect every cron and mutation endpoint: verify `Authorization: Bearer ${CRON_SECRET}` for crons and a session/JWT for API routes; do not rely on middleware alone.",
           "Add security headers in `vercel.json` (`headers`) or `next.config` `headers()`: Content-Security-Policy, X-Content-Type-Options: nosniff, Referrer-Policy, Permissions-Policy, X-Frame-Options/frame-ancestors and Strict-Transport-Security.",
           "Upgrade Next.js to a patched release (CVE-2025-29927: 12.3.5, 13.5.9, 14.2.25, 15.2.3 or newer) and keep auth checks inside route handlers/server actions too.",
           "Do not ignore build errors (`typescript.ignoreBuildErrors`, `eslint.ignoreDuringBuilds`), keep `productionBrowserSourceMaps` off, restrict `images.remotePatterns` to the hosts you own, set `poweredByHeader: false`.",
           "Add `.vercel` to `.gitignore` and never commit `vercel env pull` output (`.env.local`, `.vercel/.env.*.local`)."],
    bad="NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_...\nnext.config.js: { typescript: { ignoreBuildErrors: true }, productionBrowserSourceMaps: true }\napp/api/cron/route.ts  // no CRON_SECRET check",
    safe="// app/api/cron/route.ts\nexport async function GET(req: Request) {\n  if (req.headers.get('authorization') !== `Bearer ${process.env.CRON_SECRET}`) return new Response('Unauthorized', { status: 401 })\n  /* ... */\n}\n// vercel.json\n{ \"headers\": [{ \"source\": \"/(.*)\", \"headers\": [{ \"key\": \"X-Content-Type-Options\", \"value\": \"nosniff\" }, { \"key\": \"Referrer-Policy\", \"value\": \"strict-origin-when-cross-origin\" }] }] }",
    verify="`curl -I https://your-site` shows the headers; `curl https://your-site/api/cron/x` without the secret returns 401; browser devtools > Sources shows no source maps; `grep -rn NEXT_PUBLIC_ .env*` lists only public values."),
"vercel-platform": dict(
    title="Vercel project settings and environment variables (dashboard/API)",
    explain="Project settings decide who can open preview deployments, whether source is public, how forks deploy and how env vars are stored. Env vars stored as plain text are visible to every team member and in the dashboard.",
    impact="Unreleased features and internal data in preview deployments open to the internet, public source, secrets exposed to forks' builds, and credentials readable by anyone on the team.",
    steps=["Enable Deployment Protection: Project > Settings > Deployment Protection > Vercel Authentication (or Password Protection) for Preview deployments.",
           "Keep `Source Code` private (`publicSource: false`) and `Git Fork Protection` on so fork PRs cannot read your env vars.",
           "Store secrets as Sensitive environment variables (write-only), scope them per environment (Production only where possible) and rotate them periodically.",
           "Use OIDC federation to your cloud instead of long-lived keys in env vars, and restrict team roles (least privilege).",
           "Pin the Node.js version to a supported release and review the Activity Log for unexpected deployments."],
    bad="DATABASE_URL (type: plain, targets: production+preview+development)\nssoProtection: null  # previews are public",
    safe="DATABASE_URL (type: sensitive, target: production)\nDeployment Protection: Standard Protection (Vercel Authentication) for all deployments",
    verify="Open a preview URL in a private window: it must ask you to log in; `vercel env ls` shows secrets as Sensitive; Settings > General shows Git Fork Protection enabled."),
}
