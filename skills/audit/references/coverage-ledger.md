# Coverage ledger

Purpose: make "what did we actually look at" explicit, so reports never imply exhaustiveness.

## Unit
One unit = **surface × boundary/area × pass**. Examples:
- `api:POST /orders × authz × audit-security`
- `module:billing/ × null-deref,race × audit-bugs`
- `module:auth/ × complexity,coupling × audit-code`
- `infra:Dockerfile,docker-compose × misconfig × audit-security`
- `deps:package-lock.json × known-vulns × audit-security`

`quick`: coarsen to surface × pass. `deep`: split per module and lifecycle (create/read/update/delete, login/refresh/logout).

## States
`planned` → `assigned` → `covered` | `candidate` (finding raised, awaiting verification) | `deferred` (reason) | `blocked` (reason, e.g. needs runtime) | `out_of_scope`.

## coverage-ledger.json
```json
[
  { "unit": "api:POST /orders × authz", "pass": "audit-security", "state": "covered",
    "files": ["src/routes/orders.ts"], "findings": ["SEC-004"], "note": "" }
]
```

## Seeding (done by audit-recon)
Priority = trust-boundary exposure × data sensitivity × change frequency.
Always seed units for: every entry point (HTTP routes, queue consumers, cron, CLI args, webhooks), authn/authz layer, data access layer, file/exec/deserialization sinks, secrets & config, CI/CD, IaC/containers, dependency manifests, and the top-10 largest or most-churned modules (`git log --since=6.months --name-only | sort | uniq -c | sort -rn | head`).

## Closing
Before reporting, every unit must be in a terminal state. The report's *Coverage* section prints counts per state and lists all `deferred`/`blocked`/`out_of_scope` with reasons.
