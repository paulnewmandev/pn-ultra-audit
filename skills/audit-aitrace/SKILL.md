---
name: audit-aitrace
description: Project-finish auditor for AI traces. Finds comments and docs that reveal AI-assisted authoring, AI agent and spec files committed to the repo (CLAUDE.md, AGENTS.md, .cursor/, .windsurfrules, openspec/, .specify/), git Co-Authored-By trailers and generated-by banners, provenance metadata in images/PDFs (C2PA, IPTC, Midjourney/Stable Diffusion, PDF producer), leftover truncation markers and invisible Unicode, and explains how to remove each one safely. Informational, read-only; it never defeats statistical AI watermarks.
---

# audit-aitrace

Goal: help the user deliver a polished project by removing AI-authoring noise **when appropriate**. Removing traces is their decision.

## 0. Baseline from the CLI
`python3 <suite>/audit.py <path> --only aitrace`. Read the `AITRACE-*` findings (all informational; `AITRACE-PLACEHOLDER` may indicate truncated code and needs a real look).

## 1. Ask before removing
If a contract, employer, school, licence or law (for example EU AI Act transparency for synthetic media) requires disclosing AI use, keep the notice or move it to an "AI use" section of the README. Do not help hide AI use where disclosure is required.

## 2. Remove
- Comments/docs: delete assistant chatter and generator banners; replace with comments that explain *why*.
- Agent/spec files: `git rm --cached -r <path>` + `.gitignore` (check them for secrets first).
- Git trailers: disable `Co-Authored-By` in the tool for new commits; rewriting published history is destructive (backup + team agreement + `PNUA_CONFIRM=yes`).
- Metadata: `exiftool -overwrite_original -all= <file>`.
- Placeholders such as "rest of the code remains the same": compare with `git log -p` and restore the missing code.

## 3. Fix script
`cleanup-fixes.sh` is generated next to the report and is never executed by the tool: `bash cleanup-fixes.sh list | safe | AI-COMMENTS | AI-FILES | AI-INVISIBLE | AI-META | AI-GIT-HISTORY`. It keeps backups in `.pnua-backup/`.
