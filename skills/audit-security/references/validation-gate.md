# Validation gate (keep / downgrade / kill)

Run for every candidate before it leaves the pass. One "no" in 1-4 = kill or `needs_validation`.

1. **Reachable?** Trace entry point → sink with file:line. Is the route registered, enabled in prod, not behind an unreachable condition? 
2. **Controlled?** Does a lower-trust actor control the value that matters (not just self)?
3. **Unmitigated?** Check: framework default escaping/parameterization, validation (type/enum/regex anchored), policy/middleware on *this* route, WAF/proxy (outside repo → needs_validation), DB constraints.
4. **Consequence concrete?** Say it in one sentence: "<actor> can <action> on <resource>, leading to <loss>". Can't? → lower severity or drop.
5. **Not intended behavior?** Check docs/tests/comments. Admin-only feature working for admins is not a vuln.
6. **Not duplicate?** Same root cause as an existing finding → merge.
7. **Reproducible safely?** Provide minimal local/sandbox repro or exact unit-test sketch; never against shared/prod without authorization.

## Verdicts
- `confirmed` - 1-5 pass with source evidence (and, where possible, local repro).
- `needs_validation` - decisive fact is outside the repo. Fill `needs_validation_reason` with: **missing fact** (e.g. "does nginx strip X-Forwarded-Host?"), **why it matters**, **safe way to check** (owner runs `curl -I https://staging…`, inspect IAM policy, read env). No severity.
- `rejected` - mitigated/unreachable/intended. Keep the record with the reason.

## Always-reject list (unless chained into real impact)
Missing security headers alone · banner/version disclosure · autocomplete on forms · missing rate limit on non-sensitive endpoints · self-XSS · CSRF on logout/non-state-changing · clickjacking on static/public pages · email/SPF-DMARC absence (infra note) · open ports without exploit · "outdated dependency" with no reachable vuln · theoretical timing attacks without measurable oracle · stack traces in dev-only config.

## Chaining
If A alone is low but A + B is high (e.g., open redirect + OAuth redirect_uri prefix match), report **one** finding for the chain with severity of the chain, and list A and B in `trace`. Don't report both separately at inflated severity.
