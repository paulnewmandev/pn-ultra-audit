# OWASP maps (checks per category)

Join key between standards = **CWE**. Each check names where to look.

## OWASP Top 10:2021 (web)
| ID | Category | Key checks | Typical CWEs |
|---|---|---|---|
| A01 | Broken Access Control | authz matrix on every route; IDOR; tenant scope; forced browsing; CORS; JWT claims trusted; directory traversal | 200, 284, 285, 639, 22, 352, 862, 863 |
| A02 | Cryptographic Failures | TLS everywhere, HSTS; password hashing; secrets at rest; weak algos; RNG; PII in transit/logs; key mgmt | 259, 327, 328, 330, 311, 319, 798 |
| A03 | Injection | SQL/NoSQL/OS/LDAP/template/XSS sinks; unsafe dynamic queries | 79, 89, 78, 94, 917, 611 |
| A04 | Insecure Design | missing rate limits, abuse cases, trust boundaries, business-logic flaws, no threat model for payments/reset flows | 209, 256, 501, 522, 840 |
| A05 | Security Misconfiguration | debug on, default creds, verbose errors, headers, open cloud storage, unneeded features, XXE, permissive CORS | 16, 611, 1004, 614, 942 |
| A06 | Vulnerable & Outdated Components | dependency vulns (reachability), EOL runtime/framework, unpinned | 1104, 937 |
| A07 | Identification & Auth Failures | credential stuffing protection, weak passwords allowed, session mgmt, MFA, reset flow, enumeration | 287, 306, 307, 384, 613, 620 |
| A08 | Software & Data Integrity Failures | CI/CD integrity, unsigned updates, insecure deserialization, untrusted CDN w/o SRI, auto-update | 345, 353, 426, 494, 502, 829 |
| A09 | Logging & Monitoring Failures | auth/authz failures logged, tamper-resistant logs, alerting, no PII/secrets in logs | 117, 223, 532, 778 |
| A10 | SSRF | URL-fetching features, webhooks, import/preview, cloud metadata reachable | 918 |

## OWASP API Security Top 10:2023
API1 Broken Object Level Authorization · API2 Broken Authentication · API3 Broken Object Property Level Authorization (excessive exposure + mass assignment) · API4 Unrestricted Resource Consumption (rate/size/pagination/cost) · API5 Broken Function Level Authorization · API6 Unrestricted Access to Sensitive Business Flows (bots/abuse of purchase, signup, referral) · API7 Server-Side Request Forgery · API8 Security Misconfiguration (CORS, verbose errors, TLS, headers) · API9 Improper Inventory Management (old versions, shadow/debug endpoints, undocumented) · API10 Unsafe Consumption of APIs (trusting third-party responses).
Checks: per-endpoint matrix (authn/authz/ownership/schema/rate limit); response filtering (DTO/serializer allowlist); pagination caps; versioned routes inventory vs OpenAPI; outbound client validation (TLS, timeouts, schema validation of responses).

## OWASP ASVS 4.0.3 chapters (use L1 baseline; L2 for sensitive data)
V1 Architecture · V2 Authentication · V3 Session · V4 Access Control · V5 Validation/Sanitization/Encoding · V6 Stored Cryptography · V7 Error Handling & Logging · V8 Data Protection · V9 Communications · V10 Malicious Code · V11 Business Logic · V12 Files & Resources · V13 API & Web Service · V14 Configuration.
Report per chapter: requirements checked / total relevant, % pass; list failed requirement ids (e.g., V2.1.1 password length ≥ 12).

## OWASP LLM Top 10 (2025)
LLM01 Prompt Injection · LLM02 Sensitive Information Disclosure · LLM03 Supply Chain · LLM04 Data & Model Poisoning · LLM05 Improper Output Handling · LLM06 Excessive Agency · LLM07 System Prompt Leakage · LLM08 Vector & Embedding Weaknesses · LLM09 Misinformation · LLM10 Unbounded Consumption.

## OWASP MASVS (mobile)
STORAGE · CRYPTO · AUTH · NETWORK · PLATFORM · CODE · RESILIENCE · PRIVACY. Checks: secrets in bundle, Keychain/Keystore use, cert validation/pinning, deep-link/intent validation, WebView JS bridges, backups allowed, debuggable flag, logging sensitive data, root/jailbreak (optional).

## Supply-chain / CI notes
SLSA levels (provenance, pinned deps), pinned GitHub Actions by SHA, lockfiles reviewed, 2FA on registries, least-privilege tokens, SBOM generation (`syft`, `cyclonedx`).
