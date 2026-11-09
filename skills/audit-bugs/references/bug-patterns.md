# Bug pattern prompts (language-agnostic first, then specifics)

Use these to *generate hypotheses*. Each needs a concrete failing input before it becomes a finding.

## Data & types
- Null/undefined/None/nil deref after lookup that can miss (`find`, `get`, `first`, map index, optional chaining dropped).
- Falsy-vs-missing confusion: `0`, `""`, `false`, `[]` treated as absent (`if (!x)`, `||` defaults, PHP `empty()`, Python `if not x`).
- Loose equality / type juggling (`==` in JS/PHP; `"0" == false`; string vs int IDs; `in_array` without strict).
- Integer overflow/truncation, float for money, rounding mode, division by zero, `%` of negatives, parse of locale numbers.
- Off-by-one: `<` vs `<=`, slice end exclusivity, pagination `offset/limit/page`, last-page empty, 0- vs 1-based.
- Mutable default args (Python), shared object references, shallow vs deep copy, array mutation during iteration.
- Unicode/encoding: length vs byte length, normalization, case-folding (Turkish i), truncation mid-codepoint.

## Time
- Timezone: naive vs aware datetimes, DST, `startOfDay` in server TZ vs user TZ, `Date` parsing without TZ, month arithmetic (Jan 31 + 1 month), leap years, week-start, ISO week year.
- Expiry compared with wrong unit (s vs ms), clock skew, monotonic vs wall clock.

## Control flow & errors
- Swallowed exceptions (`catch {}`, `except: pass`, `.catch(()=>{})`), error logged then continues as success.
- Missing `await` / un-awaited promise / fire-and-forget losing errors; `forEach(async …)`; `Promise.all` partial failure; unhandled rejection.
- `finally`/cleanup missing on early return; transaction not rolled back on error path; retries without idempotency or backoff.
- Wrong operator precedence (`a && b || c`, `!a == b`), inverted condition, unreachable branch, switch fall-through, missing default.
- Return value ignored (e.g., `save()` returning false, `fs.write` count, `Rows affected` = 0 treated as success).
- Recursion without base case / depth limit; loops where exit depends on external state.

## Concurrency & state
- Check-then-act (TOCTOU) on DB rows/files without lock or unique constraint: double-spend, double-submit, oversell stock, duplicate creation.
- Read-modify-write without atomic update (`UPDATE … SET n = n + 1` vs read then write).
- Shared mutable state across requests (module-level caches/singletons, static fields) in multi-thread/async servers.
- Lock ordering (deadlock), lock held across I/O, missing lock release on exception.
- Cache invalidation: stale reads after write, cache stampede, cache key missing tenant/user/locale.
- Event handlers/subscriptions/timers never removed; double registration on re-render/reconnect.

## Resources
- Unclosed files/sockets/DB connections/cursors/streams; connection pool exhaustion; no timeouts on HTTP/DB calls.
- Unbounded growth: arrays/maps/queues/logs never trimmed; loading entire table/file into memory; no pagination.
- Temp files not cleaned; zombie child processes; listener leaks.

## Data layer
- N+1 and missing index are perf (→ audit-code); here: wrong JOIN type dropping rows, `WHERE` on nullable with `!=`, `NOT IN` with NULLs, `LIMIT` without `ORDER BY`, soft-deleted rows resurfacing, missing tenant filter in a query (also security).
- Migrations: non-reversible, default values locking big tables, data backfill missing, enum change without code update.
- ORM: lazy-load outside session, `save()` overwriting concurrent changes (no optimistic lock), mass update ignoring hooks.

## API / contracts
- Request validated but different field used downstream; response shape differs between code paths; status code 200 on error; pagination total inconsistent.
- Idempotency: POST retried creates duplicates; webhooks processed twice; out-of-order events.
- Serialization: dates/BigInt/Decimal lost in JSON; NaN/Infinity; key ordering assumptions.

## Frontend
- Stale closure in hooks (missing deps), setState on unmounted component, key={index} on reorderable lists, effect loops, race between fetches (last response wins wrongly), uncontrolled→controlled switch, memo with unstable deps.
- SSR/CSR mismatch, `window`/`document` on server, hydration errors.
- Form: double submit, lost input on error, number inputs as strings.

## Language specifics (quick)
- **JS/TS**: `this` binding, `parseInt` without radix, `Array.sort()` default lexicographic, `typeof null`, optional chaining hiding bugs, `any` casts at boundaries, `JSON.parse` unguarded, event-loop blocking.
- **PHP/Laravel**: `==` juggling, `isset` vs `array_key_exists`, `empty("0")`, Eloquent `firstOrCreate` races, `save()` on stale model, N+1 via accessors, queue job not idempotent, `DB::transaction` missing around multi-write, mass assignment (`$guarded=[]`).
- **Python**: mutable defaults, late-binding closures in loops, `is` vs `==`, bare except, generator exhausted twice, naive datetimes, `dict` mutation during iteration, GIL ≠ atomic compound ops.
- **Go**: nil map write, loop var capture (pre-1.22), ignored `err`, goroutine leak (no ctx cancel), `defer` in loop, data race on map, `time.After` leak, shadowed `err`.
- **Java/Kotlin**: `equals/hashCode` mismatch, `Integer ==` on boxed, `SimpleDateFormat` thread-safety, `Optional.get()`, unchecked casts, lazy init races, `ConcurrentModificationException`, coroutine scope leak.
- **Rust**: `unwrap()/expect()` on fallible input, `unsafe` invariants, integer overflow in release, blocking in async, `Mutex` held across `.await`, cancellation safety.
- **C/C++**: bounds, use-after-free, uninitialized, signed overflow UB, iterator invalidation, rule-of-five violations.
- **SQL**: implicit casts defeating indexes, `COUNT(col)` vs `COUNT(*)`, `GROUP BY` non-aggregated cols, timezone in `NOW()`.
