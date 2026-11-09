"""Knowledge base for Progressive Web App (PWA) findings."""
KB_PWA = {
"pwa-manifest": dict(
    title="PWA: web app manifest and installability",
    explain="The Web App Manifest tells the browser how the app installs and looks (name, start URL, display mode, icons, colors). Missing or wrong fields make the app non-installable, show a generic icon/splash, or open the wrong page.",
    impact="Browsers hide the install prompt, installed apps open at the wrong URL or with a broken icon, and the store-like install dialog looks untrustworthy.",
    steps=["Create `manifest.webmanifest` (served as `application/manifest+json`) and link it from every page: `<link rel=\"manifest\" href=\"/manifest.webmanifest\">`.",
           "Set `name`, `short_name`, `start_url` (relative, inside `scope`), `scope`, `display` (`standalone`), `background_color`, `theme_color`, `lang`, `description` and a stable `id`.",
           "Provide PNG icons 192x192 and 512x512 (`purpose: \"any\"`) plus a 512x512 `maskable` icon; keep the important art inside the central 80% safe zone.",
           "Add `screenshots` (wide and narrow) and `shortcuts` for the richer install dialog; add `<meta name=\"theme-color\">`, a viewport meta and an `apple-touch-icon` for iOS.",
           "Validate in Chrome DevTools > Application > Manifest and fix every warning."],
    bad='{ "name": "App" }   // no start_url, icons, display',
    safe='''{ "id": "/", "name": "My App", "short_name": "App", "start_url": "/?source=pwa", "scope": "/", "display": "standalone",
  "background_color": "#0b1020", "theme_color": "#7c3aed", "lang": "en",
  "icons": [ {"src": "/icons/192.png", "sizes": "192x192", "type": "image/png"},
             {"src": "/icons/512.png", "sizes": "512x512", "type": "image/png"},
             {"src": "/icons/maskable-512.png", "sizes": "512x512", "type": "image/png", "purpose": "maskable"} ] }''',
    verify="DevTools > Application > Manifest shows no errors and 'Installability' is green; Lighthouse 'Installable' passes."),
"pwa-sw": dict(
    title="PWA: service worker correctness (offline, caching, updates)",
    explain="The service worker is a programmable network proxy. Bugs in its caching strategy leave users on stale code forever, break offline mode, or keep the app from updating.",
    impact="Users stuck on an old, possibly vulnerable version; blank screens when offline; unbounded storage; hard-to-debug bugs that survive a page reload.",
    steps=["Register the worker once, after `load`: `navigator.serviceWorker.register('/sw.js')` from the site ROOT (scope = where the file lives).",
           "Handle `fetch`: network-first (with cache fallback) for HTML and APIs, cache-first with versioned names for hashed static assets, stale-while-revalidate for images.",
           "Version your cache names (`app-v42`) and delete old caches in `activate` (`caches.keys()` + `caches.delete`).",
           "Provide an offline fallback page precached at install and returned when navigation fails.",
           "Do not call `skipWaiting()` blindly: show an 'Update available' prompt, then `postMessage('SKIP_WAITING')` and reload on `controllerchange`.",
           "Bound runtime caches (max entries/age) - Workbox `ExpirationPlugin` or a manual trim - and serve `sw.js` with `Cache-Control: no-cache`."],
    bad="caches.open('cache'); self.addEventListener('fetch', e => e.respondWith(caches.match(e.request)))   // cache-only, no version, no cleanup",
    safe='''const V = 'app-v42';
self.addEventListener('install', e => e.waitUntil(caches.open(V).then(c => c.addAll(['/', '/offline.html']))));
self.addEventListener('activate', e => e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== V).map(k => caches.delete(k))))));
self.addEventListener('fetch', e => { if (e.request.method !== 'GET') return;
  e.respondWith(fetch(e.request).catch(() => caches.match(e.request).then(r => r || caches.match('/offline.html')))); });''',
    verify="DevTools > Application > Service Workers: tick Offline and reload (offline page shows); bump the version and confirm the old cache disappears."),
"pwa-security": dict(
    title="PWA: service worker and push security",
    explain="A service worker sees and can answer every request in its scope. Caching authenticated responses, importing unpinned third-party scripts, trusting `postMessage`, or leaking push keys turns that power against users.",
    impact="Cached private data readable by the next user of a shared device, supply-chain code running as a proxy on your origin, spoofed messages, or push spam through leaked VAPID keys.",
    steps=["Never cache authenticated or personalised responses (APIs, `Authorization`, cookies, `/account`) - or key the cache per user and clear it on logout.",
           "Bundle worker dependencies (Workbox) instead of `importScripts('https://cdn...')`; if you must load remotely, pin the exact version and use a hash you control.",
           "In `message` handlers verify `event.source`/`event.origin` and an allowlist of message types.",
           "Keep the VAPID private key in the server environment only; only the public key goes to the client.",
           "Ask for notification permission after a user gesture and explain the benefit first; serve everything over HTTPS only."],
    bad="importScripts('https://cdn.example.com/workbox.js');  cache.put(req, res)  // for /api/me",
    safe="import { precacheAndRoute } from 'workbox-precaching';   // bundled\nif (new URL(req.url).pathname.startsWith('/api/')) return;   // never cache APIs\nself.addEventListener('message', e => { if (e.source?.url.startsWith(self.location.origin) && e.data?.type === 'SKIP_WAITING') self.skipWaiting(); });",
    verify="Sign in, browse, sign out, go offline: no private page is served from cache; `grep -rn importScripts` shows only same-origin files."),
"pwa-ux": dict(
    title="PWA: installed-app experience (install, update, platform polish)",
    explain="Small gaps in the install flow, update flow and platform metadata make an installed web app feel unfinished compared with a native one.",
    impact="Lower install rates, users running old versions without knowing, wrong status-bar colors, missing iOS home-screen icon.",
    steps=["Capture `beforeinstallprompt`, show your own 'Install' button, call `prompt()` from a click.",
           "Listen for `updatefound` / `controllerchange` (or Workbox `onNeedRefresh`) and show a reload banner.",
           "Add `<meta name=\"theme-color\">`, `<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">`, `<link rel=\"apple-touch-icon\" href=\"/icons/180.png\">` and `apple-mobile-web-app-capable`.",
           "Use `navigationPreload` and `display_override` where it helps; test on Android Chrome and iOS Safari."],
    bad="<head><title>App</title></head>   <!-- no theme-color, viewport or apple icon -->",
    safe='<meta name="theme-color" content="#7c3aed"><meta name="viewport" content="width=device-width, initial-scale=1"><link rel="apple-touch-icon" href="/icons/180.png">',
    verify="Install on Android and iOS; status bar color matches, icon is crisp, an update shows the reload banner."),
}
