---
name: audit-pwa
description: Progressive Web App auditor. Checks the web app manifest, installability, service worker (registration, caching strategy, offline fallback, versioned caches, update flow), push notifications, HTTPS and security of the service worker (remote importScripts, cached private data, unvalidated messages, leaked VAPID keys). Use when a project has a manifest or service worker, or the user mentions PWA, offline, installable, service worker, workbox, push.
---

# audit-pwa

Goal: make the PWA **installable, offline-capable, updatable and safe**. Review first; fix the highest-risk gaps.

## 0. Baseline from the CLI
Run `python3 <suite>/audit.py <project> --only pwa --strictness <basic|standard|strict>` (ask the user which level if they did not say; default standard). With a deployed site add `--url https://site --authorized` for the live check (manifest reachable, icons load, service-worker MIME type and cache headers). Read the `PWA-*` findings and the PWA score/checklist in the dashboard (PWA view).

## 1. Manifest and installability
`name`/`short_name`, `start_url` inside `scope`, `display: standalone`, icons 192 + 512 (+ maskable), `theme_color`/`background_color`, `<link rel="manifest">` on every page, viewport meta, `apple-touch-icon`. Strict mode also wants `id`, `description`, `screenshots`, `categories`, `shortcuts`.

## 2. Service worker
Registered from the site root after `load`; `fetch` handler (network-first for HTML/API, cache-first for hashed assets, offline fallback page); **versioned cache names and cleanup in `activate`**; no unconditional `skipWaiting()` (use an update prompt); bounded runtime caches; `Cache-Control: no-cache` for `sw.js`.

## 3. Security
No `importScripts` from other origins; never cache authenticated/API responses (or key per user and clear on logout); validate `event.source` in `message` handlers; VAPID private key only on the server; notification permission only after a user gesture; HTTPS everywhere.

## 4. Report
For each finding: file:line, why it matters, the exact change, and how to verify (DevTools > Application > Manifest / Service Workers, Lighthouse "Installable" and offline test). Never claim "PWA-ready" without the checklist.
