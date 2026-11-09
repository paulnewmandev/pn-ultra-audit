---
name: audit-saas-fintech
description: Deep review of SaaS / enterprise, fintech, banking, health-tech and e-commerce systems. Goes beyond SAST: multi-tenant isolation testing, money-handling correctness (integer cents, idempotency, atomicity, ledger invariants, reconciliation), payment-provider integration (webhooks, retries, PCI scope), authentication strength (MFA/step-up, PSD2 SCA), key management, audit trails, resilience and fraud/abuse cases, plus regulatory mapping (PCI DSS, SOC 2, ISO 27001, SOX ITGC, NYDFS 500, PSD2, GDPR, DORA, ASVS L2). Use for "audita mi SaaS", "fintech", "banco", "pagos", "multi-tenant", "marketplace", "qué me pedirá el regulador".
---

# audit-saas-fintech

Start with the CLI baseline: `python3 <suite>/audit.py <project> --domain auto --compliance all --evidence-pack ./audit-pack` (domain tab in the dashboard = deep-dive scorecard). Then do the manual work below - regex cannot prove these properties.

## 1. Threat model first (30 min, write it down)
Assets (money, balances, PII, keys, tenant data) · actors (customer, other tenant, insider, bot, PSP, attacker with stolen token) · trust boundaries (browser → API → services → DB → PSP/bank) · STRIDE per boundary. Output: top-10 abuse cases, e.g. *double-spend via parallel withdrawals*, *replayed webhook marks order paid*, *tenant A reads tenant B's invoice*, *card-testing through checkout*, *account takeover → payee change → transfer*.

## 2. Multi-tenant isolation (SaaS)
- Tenant derived from the authenticated token, **never** from request params. Central enforcement: Postgres **RLS** (`SET app.tenant` per request) or ORM global scope; raw SQL forbidden without tenant key.
- Isolation is more than SQL: caches (tenant in key), queues/jobs, object storage prefixes, search indices, exports, emails, logs, analytics events, feature flags.
- **Prove it**: generate a test per endpoint: tenant A creates a resource, tenant B requests it by id (GET/PUT/DELETE, nested ids, bulk and search endpoints, GraphQL, websockets, signed URLs) → must be 404/403. Fuzz IDs and filters (`?tenant_id=`).
- Enterprise table stakes: RBAC/ABAC with deny-by-default, SSO (SAML/OIDC) + SCIM, tenant-visible audit log, API keys hashed/scoped/rotatable, per-tenant rate limits and quotas, data export/delete, backups with PITR and restore drills, entitlements enforced server-side.

## 3. Money correctness (fintech/banking)
- **Representation**: integer minor units or DECIMAL/BigDecimal; ISO 4217 currency stored with every amount; explicit rounding rule; no floats anywhere (also in JS `Number`).
- **Idempotency**: client `Idempotency-Key` + unique constraint + stored response; same key + different body → 422; forward keys to the PSP; make webhook handlers and jobs idempotent (store event ids).
- **Atomicity & concurrency**: one transaction per money movement; guarded `UPDATE … WHERE balance >= amt` (check rows); or `SELECT … FOR UPDATE`/optimistic version. Test with 50 parallel requests; also retry storms and partial failures (kill the process between debit and credit).
- **Ledger**: append-only double-entry (sum of entries = 0 invariant, property-tested), balances derived or reconciled; no UPDATE/DELETE on ledger rows (DB privileges + triggers); every entry has actor, reason, correlation id.
- **Reconciliation**: nightly job vs PSP/bank files; unmatched items alert and block; manual-adjustment workflow with four-eyes approval.
- **PSP integration**: hosted fields/tokens (keep PAN/CVV out of scope; CVV must never be stored), webhooks verified (signature over raw body, timestamp tolerance, constant-time), timeouts + bounded backoff + circuit breaker, dead-letter queue, status polling as fallback, no secrets in client code.
- **Risk & abuse**: velocity/amount limits, device/IP signals, payee-change cooling-off, step-up auth (WebAuthn/TOTP) for transfers (PSD2 SCA with dynamic linking), card-testing protection (CAPTCHA/rate limits), sanctions/KYC/AML provider and retention.
- **Resilience**: RPO/RTO documented and tested, multi-AZ, backups encrypted, runbooks, incident playbooks, regulator notification clocks (GDPR 72 h, NYDFS 72 h, DORA major-incident reporting).

## 4. Data protection
Classification (restricted: PAN, credentials, health data); encryption in transit (TLS 1.2+) and at rest; field-level encryption with KMS/HSM and rotation; secrets in a manager; logs scrubbed (no PAN/IBAN/SSN/tokens); retention/erasure schedules; data-residency and cross-border transfer mechanisms; processor agreements.

## 5. Regulatory map (what evidence to prepare)
PCI DSS 4.0 (reduce scope via provider; Req 3, 4, 6, 8, 10, 11) · SOC 2 (CC6-CC8, A1, C1, P) · ISO 27001 Annex A · SOX ITGC (access, change, operations, audit trail) · NYDFS 500 (MFA, pen test, audit trail, 72 h notice) · PSD2/SCA + open-banking API security · GDPR Art. 25/32/33 · DORA (ICT risk, testing, third parties) · OWASP ASVS L2/L3. Use `audit-compliance` to build the evidence pack and policies.

## 6. Output
Findings in the shared schema (`../audit/references/finding-schema.md`) with categories `tenant-isolation`, `money`, `key-management`, `privacy`; for each: scenario ("attacker does X → loses Y"), reproduction test sketch, smallest fix, effort. End with a **go-live readiness verdict** per area (isolation, money integrity, payments, access, data, resilience, compliance) and the 5 blocking items.
