---
name: audit-osint-owasp
description: Two-part pass. (1) OWASP coverage - maps the project against OWASP Top 10, API Security Top 10, ASVS, LLM Top 10 and MASVS and produces a coverage matrix (pass/fail/not-applicable/not-examined with evidence). (2) Passive OSINT / external attack-surface review of the user's OWN assets (domains, subdomains, DNS/email auth, exposed files, public repos/secrets, tech fingerprint, cloud storage), strictly authorization-gated and non-intrusive. Use for "OWASP", "OSINT", "superficie de ataque", "attack surface", "exposure", "cumplimiento ASVS", or as the compliance/exposure pass of /audit.
---

# audit-osint-owasp

## Part A - OWASP coverage matrix (static, always allowed)

Goal: show, per OWASP category, what was checked, what was found, and what was **not** examined - so the report maps to a recognized standard.

1. Pick standards by project type (details in `references/owasp-maps.md`):
   - Web app → **OWASP Top 10:2021** (+ ASVS L1/L2 chapters relevant)
   - REST/GraphQL API → **API Security Top 10:2023**
   - Mobile → **MASVS** · LLM features → **LLM Top 10 (2025)** · Cloud/CI → CIS/SLSA notes
   - Note: a newer Top 10 edition may exist; if the user needs it, map the same findings to the current categories (CWE is the stable join key).
2. For each category: list the checks from `references/owasp-maps.md`, run them using findings from `audit-security` (do not duplicate analysis; **consume** `findings.json` + do targeted extra checks), then set a status:
   - `fail` - ≥ 1 confirmed finding (list ids)
   - `pass` - checks done on all relevant ledger units, nothing found (state which units)
   - `partial` - some units checked, some deferred
   - `n/a` - category not applicable (say why, e.g. "no file uploads")
   - `not_examined` - no coverage; say what is needed
3. Output `owasp-matrix.json` and a section in the report:
```json
[{ "standard": "OWASP Top 10:2021", "id": "A01", "name": "Broken Access Control",
   "status": "fail", "findings": ["SEC-002","SEC-007"], "checked": ["authz matrix 54 routes"], "gaps": [] }]
```
4. Add `owasp`/`cwe` tags to findings lacking them.

Never mark `pass` for something you didn't inspect. "Not examined" is an honest, valid answer.

## Part B - Passive OSINT / external exposure (AUTHORIZATION GATE)

### Authorization gate - mandatory
Proceed only if the user states in this conversation **which assets** (domains, org names, repos) and that **they own or are authorized to assess them**. If not stated, ask once; if still unclear, skip Part B and say so. Limit to those assets. **Do not** profile private individuals, scrape personal social profiles, look up personal data, or investigate third parties. Org-level, technical exposure only.

### Passive-only rules
- No port scans, no brute force, no vulnerability scanners, no login attempts, no fuzzing against live hosts. Passive sources and single normal requests (like a browser) only.
- If network tools aren't available or not permitted in this session, produce the **checklist and commands for the owner to run**, and mark results `not_examined`.
- Public sources only; respect robots/ToS; rate-limit politely.

### Checks (own assets)
| Area | What to check | How (passive) |
|---|---|---|
| Domains & subdomains | forgotten/staging/dev hosts, dangling CNAMEs (takeover), wildcard certs | certificate transparency (crt.sh), DNS records, existing infra files in repo (Terraform, nginx, compose) |
| DNS & email auth | SPF, DKIM, DMARC (policy `p=`), MTA-STS, CAA, DNSSEC | `dig TXT/CAA`, read zone files in IaC |
| TLS & headers (single request) | cert validity/expiry, protocol, HSTS, CSP, cookies flags, `server` banners | one `curl -sI`, SSL Labs report by owner |
| Exposed files/paths (single GET each, only if authorized) | `/.git/`, `/.env`, `/server-status`, `/actuator`, `/phpinfo.php`, `/swagger`, backups `*.sql *.zip`, `/robots.txt`, `/sitemap.xml`, `/.well-known/security.txt` | single requests; record status code only; never download sensitive content - report existence |
| Public code & secrets | org repos public/private mistakes, leaked tokens in public repos/gists/issues, CI logs | `gh search code org:<org> "<pattern>"` (if gh available), GitHub org settings, package registries for org-owned packages |
| Cloud storage | public S3/GCS/Azure containers named after org | check names from IaC/config; owner verifies ACLs |
| Tech fingerprint | frameworks/versions visible in HTML, JS bundles, headers, source maps | read repo build output / one page fetch |
| Third-party exposure | JS includes without SRI, abandoned third-party scripts, SaaS subdomains (status page, help desk) | read HTML templates |
| Credentials exposure | org emails in breach corpora | only via owner-authorized service (e.g., HIBP domain search) - not performed by the agent |
| Metadata | document/image metadata in published files, internal paths in source maps/PDFs | inspect repo assets |
| Policies | `security.txt`, disclosure policy, privacy contact | single GET |

### Output
Section "External exposure" in report + findings with `type: security_hotspot|vulnerability`, `category: exposure`, `source_pass: audit-osint-owasp`. Each: asset, observation (what + how observed + timestamp), why it matters, fix, and `status` (`confirmed` only if directly observed). Include an **asset inventory table** (host, purpose, tech, auth, notes).

## References
- `references/owasp-maps.md` - category → checks → CWE → related audit-security classes
