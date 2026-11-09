# Security policy

## Reporting a vulnerability
Please **do not** open a public issue. Use GitHub's *Report a vulnerability* (private advisory) on this repository, with steps to reproduce. We aim to acknowledge within 72 hours.

## Scope
The CLI is read-only toward audited targets. Issues we care about: command/path injection through inputs (URLs, paths, SSH/FTP/Git options), unsafe extraction of remote content, leaking secrets or local paths into reports, and anything that makes the tool write to or execute code on an audited target.

## Supported versions
The latest release receives fixes.
