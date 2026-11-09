---
name: audit-recon
description: Reconnaissance phase for audits. Maps a codebase - languages, frameworks, LOC, entry points, trust boundaries, auth model, data stores, external integrations, CI/CD, IaC, dependencies, churn hotspots - and detects which scanners are installed. Produces recon.md, metrics.json and a seeded coverage ledger. Use first in /audit, or alone when asked to "map", "understand" or "get the lay of the land" of a project.
---

# audit-recon

Read-only. Output feeds every other pass. Be fast and factual; no findings here except obvious secrets/misconfig noted for the security pass.

## Steps

1. **Identify target & state**: root, `git rev-parse HEAD`, dirty files (`git status --porcelain`), branches, last commit date, contributors count (`git shortlog -sn | head`).
2. **Languages & size**: use `cloc`/`tokei` if installed, else `git ls-files | xargs wc -l` by extension (exclude `node_modules`, `vendor`, `dist`, `build`, `.venv`, lockfiles, generated, minified). Record `ncloc` per language → `metrics.json`.
3. **Stack fingerprint**: manifests (`package.json`, `composer.json`, `requirements*.txt`, `pyproject.toml`, `go.mod`, `Cargo.toml`, `pom.xml`, `build.gradle`, `Gemfile`, `*.csproj`), framework (Laravel, Express, Next, Django, FastAPI, Spring, Rails, .NET, etc.), runtime versions, DB/ORM, queues, caches, frontends.
4. **Entry points** (each becomes ledger units): HTTP routes (grep route files / decorators / `routes/*.php`), GraphQL schema/resolvers, gRPC protos, WebSocket handlers, webhooks, cron/scheduled jobs, queue consumers, CLI commands, serverless handlers, message topics, file watchers, IPC.
5. **Trust boundaries & actors**: anonymous, authenticated user, tenant admin, platform admin, service-to-service, third-party callbacks. Where is authn enforced (middleware, guard, decorator)? Where is authz enforced (policy, gate, per-handler)? Multi-tenancy key (`tenant_id`, `org_id`)?
6. **Sensitive sinks inventory** (locations only): SQL/ORM raw queries, shell/exec, file read/write/upload, deserialization, template rendering, HTTP client (SSRF), redirect, crypto/hash/random, JWT/session, email, logging of PII.
7. **Config & secrets surface**: `.env*`, config files, CI secrets usage, hard-coded keys (pattern grep only; hand to audit-security).
8. **Infra**: Dockerfile, compose, k8s manifests, Terraform/CloudFormation/Pulumi, nginx/apache conf, GitHub Actions/GitLab CI/Jenkins.
9. **Dependencies**: manifests + lockfiles present? count direct/transitive; note unpinned or abandoned.
10. **Tests**: framework, test dirs, rough test-to-source ratio, coverage config/reports present? CI runs tests?
11. **Churn & size hotspots**: `git log --since=6.months --name-only --pretty=format: | sort | uniq -c | sort -rn | head -20`; top 15 largest source files.
12. **Tooling inventory**: `command -v` for: `semgrep gitleaks trufflehog trivy grype osv-scanner npm pnpm yarn pip-audit bandit safety eslint tsc phpstan psalm composer ruff mypy golangci-lint govulncheck cargo-audit clippy cloc tokei lizard jscpd madge dependency-cruiser sonar-scanner hadolint checkov tfsec kube-linter`. Record present/absent. **Do not install anything.**
13. **Prior runs**: look for earlier `audit-output/<repo>/run-*/findings.json`; note their path so passes can carry/refute prior findings.

## Outputs

- `recon.md` — sections: Overview, Stack, Entry points (table: kind, path, file:line, auth?), Trust boundaries, Sensitive sinks, Infra, Dependencies, Tests, Hotspots, Tooling present/absent, Risks to prioritize (top 10, with reason).
- `metrics.json`:
```json
{ "ncloc": 48210, "files": 612, "languages": {"PHP": 30100, "JS": 14000}, "tests_files": 41,
  "test_ratio": 0.07, "tools": {"semgrep": false, "gitleaks": true}, "git_ref": "abc123", "dirty": false }
```
- `coverage-ledger.json` seeded per `../audit/references/coverage-ledger.md`, with `planned` units and priority.

Scanner outputs, if tools exist, are run by the pass skills (not here) so each pass owns its evidence.
