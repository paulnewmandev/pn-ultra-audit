# PWA Audit

Detected automatically from a web app manifest, a service worker, or tooling (Workbox, vite-plugin-pwa, next-pwa, Serwist, Angular service worker).

```bash
python3 audit.py ./my-app --only pwa --strictness strict
python3 audit.py ./my-app --url https://my-app.example --authorized   # also checks the deployed manifest, icons and sw.js headers
```

| Area | Checks |
|---|---|
| **Manifest** | valid JSON, `name`/`short_name`, `start_url` inside `scope`, `display`, 192 and 512 icons, maskable icon, theme/background colors, linked from the pages, no `http://` URLs |
| **Service worker** | registered from a sensible scope, `fetch` handler, versioned caches with cleanup, offline fallback, `skipWaiting` policy, bounded caches, update flow, `sw.js` cache headers |
| **Push** | notification permission requested without a user gesture, VAPID private key in source |
| **Security** | remote `importScripts`, caching authenticated/API responses, unvalidated `message` events |
| **Strict mode adds** | rich-install fields (id, description, screenshots, categories, shortcuts), install prompt, navigation preload, cache limits |

The dashboard PWA view shows an installability checklist and score. See also the PWA findings' remediation steps (manifest and service-worker snippets are included).
