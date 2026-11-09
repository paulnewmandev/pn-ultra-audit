# Audit readiness (SOC 2, ISO 27001, HIPAA, GDPR, PCI DSS, NIST CSF, DORA, EU AI Act, WCAG)

**This is pre-audit help, not a certification and not legal advice.** Attestations/certifications are issued by accredited assessors and also require policies, people processes and evidence collected over time.

## What you get
| Output | Purpose |
|---|---|
| Dashboard → **Compliance** tab | readiness % per framework, per-control status (pass / gap / manual / n/a), linked findings, what the auditor will ask for |
| `--evidence-pack DIR` | `README.md`, `control-matrix.csv`, `findings.csv`, `evidence-requests.md`, `remediation-plan.md`, `sbom.cdx.json`, `policy-templates/` (10 policies + RoPA) |
| SBOM (CycloneDX 1.5) | software inventory from lockfiles; license risk (AGPL/GPL/SSPL flagged for a legal decision) |
| `--compliance soc2,iso27001,…` | choose frameworks (default: all that apply; EU AI Act only if AI SDKs are detected; WCAG only for web) |

## How statuses are decided
- **pass** - every automatically checkable practice behind the control has technical evidence (e.g. TLS verification on, no secrets, CI present).
- **gap** - at least one such practice is missing; the control lists exactly which ones.
- **manual** - no automatic signal (policies, training, vendor management, physical security): you must provide documents.
- **n/a** - the practice does not apply to this project type.
Readiness % = pass ÷ (pass + gap). Manual controls are not counted - a high % never means "certified".

## Suggested path
1. `python3 audit.py . --compliance soc2 --evidence-pack ./audit-pack`
2. Close the technical gaps (`remediation-plan.md`), re-run with `--baseline auto`.
3. Fill and approve the policy templates; collect evidence from `evidence-requests.md`.
4. Book a readiness call with your assessor (SOC 2 Type I/II, ISO 27001 Stage 1/2, PCI SAQ/QSA…), share the pack.
5. Keep it alive: quarterly access reviews & restore tests, annual risk assessment and pen test, monthly re-runs.

## Framework coverage (technical signals → controls)
SOC 2 TSC (CC1-CC9, A1, C1, P) · ISO/IEC 27001:2022 Annex A (5.x, 6.x, 8.x) · HIPAA Security Rule (§164.308/.310/.312/.314) · GDPR/ePrivacy (Art. 5-7, 12-22, 25, 28, 30, 32-35, 44-49) · PCI DSS v4.0 (Req 1-12) · NIST CSF 2.0 (GV/ID/PR/DE/RS/RC) · DORA (ICT risk, resilience testing, third parties) · EU AI Act (Art. 4, 9-15, 50) · WCAG 2.2 AA (VPAT draft).
Control wording is paraphrased for orientation; always work from the official texts.
