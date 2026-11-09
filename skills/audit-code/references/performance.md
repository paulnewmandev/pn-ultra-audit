# Performance review guide

Evidence over intuition. Without measurement, mark `confidence` in description ("by inspection"); real numbers (EXPLAIN, profiler, benchmark) upgrade severity.

## Backend
- **N+1**: query inside loop/serializer/accessor/resource. Fix: eager load (`with()`, `includes`, `select_related/prefetch_related`, `JOIN FETCH`), batching, DataLoader.
- **Unbounded**: `SELECT *` over big tables, no `LIMIT`/pagination, `->get()`/`.all()` then filter in app, loading whole files into memory (use streams/chunks/cursors).
- **Index suspicion**: filters/sorts/joins on columns without index (check migrations/schema); leading-wildcard `LIKE '%x'`; function on indexed column; `OR` across columns; low-selectivity composite order.
- **Algorithmic**: nested loops over growing data, `array.includes/in_array` inside loop (use Set/hash), repeated sort, string concat in loop, regex backtracking (ReDoS also security).
- **I/O**: sync/blocking calls on event loop; serial awaits that could be parallel (`Promise.all`) - or the reverse, unbounded parallelism; missing HTTP keep-alive/pooling; no timeouts; chatty cross-service calls.
- **Caching**: obviously hot, pure, expensive computation uncached; or cache without TTL/invalidation/tenant key.
- **Queues**: heavy work in request cycle (email, PDF, image, export) → job; job without batching/backoff.
- **Memory**: retained references, global caches unbounded, large objects in session, leaking listeners.

## Frontend
- Bundle: whole-library imports (`lodash`, moment), no code splitting/lazy routes, duplicate deps, unoptimized images (no srcset/webp/lazy), blocking scripts/fonts.
- Rendering: re-render storms (unstable props/context, missing memo where measured), huge lists without virtualization, layout thrash, expensive work in render.
- Network: waterfalls, no prefetch/cache headers, over-fetching GraphQL/REST, no pagination/infinite-scroll limits.
- Web Vitals targets: LCP < 2.5s, INP < 200ms, CLS < 0.1.

## Data / infra
- Missing connection pooling; pool size vs workers; long transactions; table scans in cron; N-row updates one-by-one; no archival of growing tables; Docker images huge/no multi-stage; no gzip/brotli/HTTP cache; no CDN for static.

## Reporting
Include: where, why it scales badly (give N), expected effect of fix, how to measure (query + `EXPLAIN`, profiler, benchmark command).
