# Stack-specific review notes (load only what matches)

## PHP / Laravel
- Controllers thin; logic in services/actions; Form Requests for validation; Policies/Gates for authz on every resource route (`authorize`, `->can`, route middleware).
- Eloquent: `$fillable`/`$guarded=[]` mass-assignment; N+1 (`with`, `withCount`); `chunk/cursor/lazy` for big sets; `DB::transaction` around multi-writes; global scopes for tenancy; `whereRaw`/`DB::raw` with interpolation (SQLi); accessors causing hidden queries.
- Config: `env()` only in config files (cached config returns null otherwise); `APP_DEBUG=false` in prod; `.env` not committed.
- Queues/jobs idempotent, with `tries`/`backoff`/`failed()`; scheduler overlap protection (`withoutOverlapping`).
- Blade: `{!! !!}` with user data (XSS); CSRF on state-changing web routes; rate limiting (`throttle`) on login/API.
- Static analysis: `phpstan`/`larastan` level ≥ 5, `pint`, `composer audit`.

## Node / TypeScript (Express, Nest, Next, Fastify)
- `strict: true`; no `any` at boundaries - validate with zod/class-validator/ajv; async errors handled (express-async-errors/ wrapper); no blocking sync fs/crypto in handlers.
- Express: helmet, CORS allowlist (not `*` with credentials), body size limits, rate limit, central error handler, no stack traces to client.
- Nest: DTO validation pipe `whitelist: true`; Guards for authz; avoid circular DI; interceptors for cross-cutting.
- Next.js: server vs client component boundary; secrets never in `NEXT_PUBLIC_*`; Route Handlers/Server Actions need their own authz (not only middleware); caching/revalidation correctness; `dangerouslySetInnerHTML`.
- Deps: `npm audit`, lockfile committed, no `postinstall` surprises, `engines` pinned.

## React / Vue / Svelte / Angular
- Effects: deps complete, cleanup, no data fetch races (abort/ignore stale), derive instead of sync state; keys stable; avoid prop drilling vs context overuse; memo only after measure.
- Vue 3: reactivity loss (destructuring props/reactive), watcher cleanup, `v-html`, composables side effects.
- Angular: OnPush/signals, unsubscribe (takeUntilDestroyed), trackBy, interceptors, route guards (+ server authz).
- A11y basics: labels, alt, keyboard focus, contrast, semantic elements, aria only when needed.

## Python (Django, FastAPI, Flask)
- Django: `DEBUG`, `ALLOWED_HOSTS`, `SECRET_KEY` from env, `select_related/prefetch_related`, `.raw()` / `extra()` / f-string SQL, serializers `fields="__all__"` (over-exposure), permission_classes on every DRF view, CSRF exempt use, `mark_safe`.
- FastAPI: `Depends` for authz on every router; Pydantic v2 models for I/O (response_model to avoid leaking fields); no blocking calls in `async def` (use threadpool); session/transaction lifecycle.
- General: type hints + mypy/pyright, `ruff`, context managers for resources, `subprocess` with list args (no `shell=True`), `yaml.safe_load`, `pickle` on untrusted = RCE.

## Java / Kotlin / Spring
- Constructor injection; `@Transactional` boundaries (self-invocation pitfall, readOnly); lazy-loading outside tx; DTO vs entity exposure; `@Valid`; Spring Security config (method security, CSRF, CORS); actuator endpoints exposed; Jackson polymorphic typing / default typing (deser RCE); `Optional.get`; `equals/hashCode`; thread-safety of singletons; virtual threads pinning.
- Kotlin: structured concurrency, no `GlobalScope`, `!!` abuse, Flow collection lifecycle.

## Go
- Errors wrapped (`%w`), never ignored; `context` first param and honored; goroutine lifecycle (errgroup, cancel); `defer` in loops; copy of mutex; map concurrent access; `http.Client` timeouts; `sql.Rows` closed; table-driven tests; `-race`.

## Rust
- No `unwrap` on external input; `unsafe` blocks documented with invariants; no blocking in async; cancellation safety; `Send/Sync` bounds; clippy `-D warnings`; error types via `thiserror/anyhow` appropriately.

## C# / .NET
- `async` all the way (no `.Result/.Wait()`); `IDisposable`/`using`; EF Core: `AsNoTracking`, `Include` for N+1, avoid client-side eval; DI lifetimes (scoped in singleton bug); `[Authorize]` coverage; model binding over-posting; nullable reference types enabled.

## Mobile (Android/iOS/Flutter/RN/Expo)
- Secrets in app bundle; insecure storage (use Keychain/Keystore/SecureStore); cert pinning optional; deep link validation; lifecycle leaks; main-thread work; permissions minimal; offline/retry; crash on null from API; Flutter: const widgets, dispose controllers, rebuild scope; RN: FlatList keys/windowing, bridge chatter.

## SQL / DB
- Parameterized always; indexes match WHERE/ORDER; FK + unique constraints; migrations safe (online, reversible); no business logic in triggers without docs; least-privilege DB user; backups/restore tested.

## Docker / CI
- Non-root user, pinned base image digests/tags, multi-stage, no secrets in layers/ARG, `.dockerignore`; CI: pinned actions (SHA), least-privilege tokens, no `pull_request_target` with untrusted checkout, secrets not echoed, caching safe.
