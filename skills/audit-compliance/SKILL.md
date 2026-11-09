---
name: audit-compliance
description: Pre-certification readiness helper for SOC 2, ISO/IEC 27001, HIPAA, GDPR/ePrivacy, PCI DSS 4.0, NIST CSF 2.0, DORA, EU AI Act and WCAG 2.2 (VPAT). Maps the technical findings of an audit to framework controls, shows readiness and gaps, generates an SBOM and license report, and builds an auditor evidence pack (control matrix, evidence requests, remediation plan, policy templates) so the company arrives prepared when it hires an accredited assessor. NOT a certification and not legal advice. Use for "prepararme para SOC 2/ISO 27001/HIPAA/PCI", "pre-auditoría", "qué me va a pedir el auditor", "evidencias", "cumplimiento".
---

# audit-compliance (get audit-ready, then hire the auditor)

**Position the work honestly:** certification/attestation is issued by accredited third parties (CPA firm for SOC 2, certification body for ISO 27001, QSA for PCI, etc.) and also needs policies, people processes and evidence over time. This skill shortens that road: it finds technical gaps early, organizes evidence and drafts the paperwork. Never claim "compliant" or "certified".

## Workflow
1. **Scope**: ask which framework(s) and why (customer request, regulation, funding). Identify systems in scope, data types (PII, PHI, cardholder), regions, vendors, AI usage.
2. **Run**: `python3 <suite>/audit.py <project> --compliance soc2,iso27001 --evidence-pack ./audit-pack` (add `--db`, `--ssh … --authorized`, `--aws-rds` to include infrastructure evidence). Optional: `--url` for live headers/TLS/SEO, `--tools` for scanners.
3. **Read** the dashboard **Compliance** tab and `audit-pack/README.md`. Explain per framework: readiness %, what *pass* means (technical evidence exists), *gap* (fixable now), *manual* (needs documents/process), *n/a*.
4. **Close technical gaps first** (they are usually the longest-lead items): secrets, injection/authz, MFA & password hashing, TLS, logging/monitoring, CI with SAST+dependency scan, backups/restore test, change management via PRs. Re-run until gaps shrink; use `--baseline auto`.
5. **Policies & evidence**: fill `policy-templates/` with the user's real practices (never invent facts), get management approval, then collect the items in `evidence-requests.md` as dated screenshots/exports (access reviews, backup restore test, training records, vendor list, risk register, incident exercise).
6. **Choose the assessor**: SOC 2 Type I (design at a date) vs Type II (operating effectiveness over 3-12 months); ISO 27001 Stage 1/2 audits; PCI SAQ type vs QSA ROC; HIPAA is self-assessed/attested (OCR audits) - recommend counsel. Suggest a readiness assessment with the auditor before the formal window.
7. **Keep it alive**: schedule quarterly access reviews and restore tests, annual risk assessment and pen test, continuous CI scanning; re-run the audit monthly and archive the packs.

## Control mapping notes
SOC 2 CC6-CC8/A1/C1/P · ISO 27001:2022 Annex A 5/6/7/8 · HIPAA §164.308/.310/.312 · GDPR Art. 5/25/28/30/32/33 · PCI DSS 4.0 Req 1-12 (reduce scope with a PCI-validated payment processor; never store SAD) · NIST CSF 2.0 GV/ID/PR/DE/RS/RC · DORA ICT risk, incident, testing, third-party · EU AI Act (only if AI features) · WCAG 2.2 AA → VPAT/ACR.
Technical coverage is partial by design: policy, HR, physical and vendor controls are marked **manual** and must be evidenced by the organization.

## Output
A short readiness brief (per framework: %, top 5 gaps with fix steps, evidence still missing, suggested timeline and assessor type), the evidence pack folder, and the SBOM/license risks (strong copyleft needs a legal decision).
