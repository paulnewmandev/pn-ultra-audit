importScripts('https://cdn.example.com/workbox/6.0/workbox-sw.js');
const CACHE = 'cache';
self.addEventListener('install', e => { self.skipWaiting(); e.waitUntil(caches.open(CACHE).then(c => c.addAll(['/', '/app.css']))); });
self.addEventListener('message', e => { if (e.data === 'ping') e.source.postMessage('pong'); });
self.addEventListener('fetch', e => {
  e.respondWith(caches.match(e.request).then(r => r || fetch(e.request).then(res => { caches.open(CACHE).then(c => c.put(e.request, res.clone())); return res; })));
  // caches /api/me and other authenticated responses too
});
