# Architecture review guide

## Questions
1. What are the main modules/bounded contexts? Draw the dependency graph (tools: `madge`, `dependency-cruiser`, `go list -deps`, `pydeps`, IDE) or infer from imports.
2. Does the dependency direction match intent (UI → app → domain ← infra)? List violations with file:line of the import.
3. Where does business logic live? (controllers/views/models/services/SQL/triggers/frontend?) More than one answer = leak.
4. Where is state? (DB, cache, session, in-process memory, files). Is anything stateful assumed single-instance?
5. How do components communicate (sync HTTP, events, shared DB)? Any shared DB across services = hidden coupling.
6. What breaks if a dependency is slow/down? (timeouts, circuit breakers, fallbacks, queues)
7. How does it scale: what is O(users)/O(data) in memory or per request?
8. Cross-cutting: authn/authz, logging, config, i18n, feature flags - centralized or copy-pasted?

## Smells (with typical evidence)
| Smell | Evidence | Typical fix |
|---|---|---|
| Layer violation | controller imports DB client / domain imports framework | introduce port/repository; move logic to service |
| Circular dependency | A↔B import cycle | extract shared interface/module; invert dependency |
| God class/service | > 1000 lines, > 20 public methods, imported everywhere | split by responsibility; strangle behind facade |
| Anemic domain / fat controller | validation + pricing + persistence in handler | move rules to domain/service |
| Shotgun surgery | one change touches many files | consolidate the concept |
| Shared mutable global | module-level singletons/static state | inject; scope per request |
| Distributed monolith | services deploy together / share DB | merge or define real contracts |
| Config sprawl | `process.env`/`env()` reads all over | one typed config module |
| Inconsistent patterns | 3 ways to fetch data / 3 error styles | choose one, document, migrate hot paths |
| Over-engineering | 1-impl interfaces, deep inheritance, plugin system for 2 plugins | delete indirection |
| Missing seams | `new` of collaborators, static calls, time/UUID/random inline | inject clock/id/http |
| Temporal coupling | methods must be called in secret order | enforce via constructor/builder |

## Output
For architecture findings include a **mini diagram** (ASCII or mermaid) of current vs proposed boundary when it clarifies, and a **migration path** (smallest first step that leaves system working), never "rewrite".
