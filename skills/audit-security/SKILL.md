---
name: audit-security
description: White-box security audit and pentest-style review of source code, configs, IaC, CI/CD and dependencies. Traces untrusted input to dangerous sinks (injection, XSS, SSRF, path traversal, deserialization, RCE), reviews authn/authz/session/crypto/secrets/business logic/tenant isolation/file upload/LLM features, and checks known-vulnerable dependencies. Evidence-gated (confirmed / needs_validation / rejected). Dynamic testing only with explicit written authorization. Use for "security audit", "pentest", "vulnerabilidades", "find vulnerabilities", "revisar seguridad", or as the security pass of /audit.
---

# audit-security

Defensive, source-first. Find vulnerabilities that **cross a real trust boundary** and give owners evidence, safe reproduction, priority and the smallest fix. A candidate without a concrete affected principal, resource and outcome is **not** a finding.

## Operating rules
- Default = **static**: read code/config, run installed scanners, minimal local harnesses in a sandbox. No network to targets.
- **Dynamic testing** (HTTP requests to a running instance, scanners against URLs) only if the user stated in this conversation: the target URL(s), that they own/are authorized to test, and any exclusions. Then: stay inside that scope, prefer a local/staging instance, no DoS/volumetric tests, no destructive actions, no real user data, stop at minimum proof (read one dummy record, show one reflected payload). If not authorized → mark `needs_validation` with a safe validation plan for the owner.
- Never exfiltrate or print real secrets; redact. Use dummy fixtures.
- Don't run target-controlled code that could fetch the network or write outside a scratch dir. If you can't sandbox it, don't run it - report the blocker.

## Candidate gate (apply before writing any finding)
Name each of:
1. **Actor** (lower-trust principal: anonymous, user A, tenant admin, third party)
2. **Input/action** they control
3. **Intended control** that should stop them (and where it is/should be)
4. **Boundary crossed**
5. **Affected resource/principal** and **observable result**
If any is missing → not a finding. If a deployment fact outside the repo is decisive (WAF, proxy header stripping, IAM policy, env var, network ACL) → `needs_validation` with the exact missing fact. Intended same-principal authority and self-impact (self-XSS, user attacking own data) are not boundary crossings.
(Adapted from the 7-question gate: *can I show it step by step now? is the asset/impact real? does it need privileges an attacker can't get? is it documented behavior? is it already mitigated?* - one "no" kills or downgrades it.)

## Procedure

### 1. Scanners (if installed; never install)
`semgrep --config auto --json`, `gitleaks detect --no-git -v`/`trufflehog filesystem`, `trivy fs --scanners vuln,secret,misconfig`, `osv-scanner`, `npm audit --json` / `pnpm audit` / `yarn npm audit`, `composer audit`, `pip-audit`, `bandit -r`, `govulncheck`, `cargo audit`, `hadolint`, `checkov`/`tfsec`, `kube-linter`. Treat output as **leads**; verify each by reading code. Record which tools ran and which were absent.

### 2. Source-to-sink analysis (core)
For each entry point in the recon ledger, per attack class in `references/attack-classes.md`:
- Identify **sources** (params, headers, body, cookies, files, webhooks, queue messages, DB values written by others, env).
- Identify **sinks** (SQL/NoSQL/LDAP/XPath, shell/exec, eval/template/deserialize, file paths, HTTP clients, redirects, HTML/JS/URL contexts, XML parsers, regex, crypto).
- Trace propagation; list sanitizers/validators on the path and check they're **correct for the sink context** (HTML-escape ≠ JS-escape ≠ SQL-escape ≠ path-normalize).
- Emit with `trace[]` entrypoint → propagation → sink, file:line each.

### 3. Access control sweep (highest-yield category)
Enumerate every route/handler/GraphQL resolver/RPC/job and fill a matrix: `endpoint × authn required? × authz check (role/ownership/tenant) × where enforced`. Flag: missing auth, missing ownership check (IDOR/BOLA), tenant filter absent in queries, role check only in UI/middleware but not on sibling routes, mass assignment, privilege fields writable, function-level authz gaps (BFLA), admin routes reachable, default-allow guards. Include matrix in appendix.

### 4. AuthN / session / crypto / secrets
Password storage (argon2/bcrypt/scrypt vs md5/sha1/plain), reset/verification flows (token entropy, expiry, single use, host-header poisoning), MFA bypass, login rate-limit & enumeration, JWT (alg none/confusion, weak/hard-coded secret, no exp/aud/iss, kid injection), cookies (HttpOnly/Secure/SameSite), session fixation/rotation/logout invalidation, OAuth/OIDC/SAML (state, PKCE, redirect_uri matching, signature validation), API keys in URLs, CSRF, CORS (`*` + credentials, reflected origin), weak RNG (`Math.random`, `rand`) for tokens, ECB/static IV, TLS verification disabled, hard-coded keys/tokens/passwords/URLs-with-creds in code, config, CI, Dockerfiles, mobile bundles, git history (`git log -p -S` for key patterns if allowed).

### 5. Data handling & business logic
Tenant isolation, over-exposed fields (serializers returning password_hash/tokens/PII), verbose errors, PII in logs, insecure file upload (type/size/path/exec/storage), path traversal & zip-slip, SSRF via URL fetchers/webhooks/image proxies (metadata IP, DNS rebinding, redirects), open redirect, race conditions (double spend, coupon reuse, limit bypass), price/quantity/negative-value tampering, workflow-step skipping, replay, idempotency, rate limits on expensive/SMS/email endpoints, mass assignment, GraphQL (introspection, depth/complexity limits, batching, field-level authz), WebSocket authz, webhooks signature verification.

### 6. Dependencies, supply chain, CI/CD, infra
Known-vulnerable direct deps (reachability noted: is the vulnerable function used?), typosquats/unpinned/`latest`, install scripts, lockfile integrity, GitHub Actions (`pull_request_target`, unpinned third-party actions, script injection via `${{ github.event.* }}`, over-broad `GITHUB_TOKEN`/secrets), Docker (root, secrets in layers, `latest`, exposed ports), K8s (privileged, hostPath, no limits, default SA), Terraform/CloudFormation (public buckets, `0.0.0.0/0`, wildcard IAM, unencrypted storage), nginx/apache hardening, debug flags in prod, exposed admin/metrics/actuator/phpinfo.

### 7. LLM/AI features (if present)
Prompt injection (direct/indirect via retrieved docs), insecure output handling (LLM output into shell/SQL/HTML), excessive agent permissions/tools, secrets in prompts, RAG tenant leakage, unbounded token spend. Map to OWASP LLM Top 10.

### 8. Verify & write
Every candidate ≥ medium is re-checked by `audit` Phase 3. Write findings in the shared schema. Attach `cwe`, `owasp`, a minimal `fix` and, for critical/high, a `fix_diff`.

## Severity & priority
Use `../audit/references/severity-and-scoring.md`. State likelihood + impact in `description`. Add CVSS v3.1/4.0 vector **only** if you can justify each metric; otherwise omit.

## Recommend the smallest effective fix
Identify the invariant the code must enforce and the narrowest change at the **last trusted decision point** (parameterize at the query, authorize at the handler/policy, encode at output). Add a regression test sketch. Don't recommend wholesale rewrites or generic hardening in place of a real fix.

## Do not report
Missing headers with no exploitable consequence (put in a single low "hardening" finding), version disclosure alone, theoretical weaknesses without reachable input, self-XSS, clickjacking on non-sensitive pages, rate limit absence on non-sensitive endpoints, "outdated library" without a relevant vulnerability (→ audit-quality), best-practice deviations as vulnerabilities.

## References
- `references/attack-classes.md` - per-class sources/sinks/grep leads/safe patterns/fix
- `references/validation-gate.md` - kill-or-keep checklist and `needs_validation` template
