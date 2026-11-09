# Security and Privacy

- **Read-only.** Targets are never modified; remote/cloned code is never executed (`--run-tests` is the only flag that executes the project's own tests, and it says so).
- **Secrets are redacted.** Values are never copied into findings, snippets, SARIF or the dashboard; neighbouring context lines containing secrets are masked.
- **No personal paths.** Reports use relative paths; the optional project folder used for editor links is stored only in your browser.
- **Offline dashboard.** `report.html` is one self-contained file.
- **Network use is explicit:** `--url` (crawl, polite and robots-aware), `--psi` (sends the URL to Google), `--git`, `--vercel-project`, `--ssh`, `--ftp`, `--sftp`, remote `--db`. Each remote target needs `--authorized`.
- **Credentials** come from the environment, an SSH agent or key files - never from command-line arguments.

Found a vulnerability in PN-Ultra-Audit itself? See `SECURITY.md` in the repository.
