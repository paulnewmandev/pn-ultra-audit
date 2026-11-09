---
name: audit-repo
description: Repository hygiene and leaked-keys auditor. Finds sensitive files tracked in git (private keys, service-account JSON, .npmrc tokens, Terraform state, kubeconfigs, production configs, DB dumps), credentials in git remotes, sensitive files deleted but still in history, CI/CD workflow security (pull_request_target, script injection, permissions, unpinned actions, curl|sh) and repo metadata (SECURITY.md, CODEOWNERS, dependabot, secret scanning). Gives provider-specific key-rotation steps and a repo-fixes.sh. Use when a key may be exposed, before making a repo public, or when asked to review a repository or its CI.
---

# audit-repo

Goal: find exposed keys and repository risks, and lead the user through **rotate -> untrack -> purge history -> prevent**. Never print secret values.

## 0. Baseline from the CLI
`python3 <suite>/audit.py <repo> --only repo,security --history --strictness <basic|standard|strict>` (ask which level). Read the `REPO-*`, `HIST-*` and `SEC-*` secret findings; each secret finding has provider-specific rotation steps.

## 1. If a key is exposed (order matters)
1. **Rotate/revoke at the provider first** - assume it is compromised; check the provider's activity log since the first commit.
2. `git rm --cached <file>` and add the pattern to `.gitignore`.
3. Purge history if the repo is public or shared: `git filter-repo --invert-paths --path <file>` on a fresh mirror clone, force-push all branches and tags, ask everyone to re-clone.
4. Move secrets to a secret manager / the platform's encrypted variables.
5. Prevent a repeat: gitleaks in pre-commit and CI, GitHub secret scanning with push protection.

## 2. CI/CD review
`pull_request_target` must not check out PR code; never interpolate `${{ github.event.* }}` in `run:` (use `env:`); top-level `permissions: { contents: read }`; pin third-party actions to a full SHA; no secrets on command lines; no `curl | sh`.

## 3. Fix script
`repo-fixes.sh` is generated next to the report and is never executed by the tool: `bash repo-fixes.sh list`; destructive history purge needs `PNUA_CONFIRM=yes`.
