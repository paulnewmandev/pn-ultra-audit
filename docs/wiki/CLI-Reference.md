# CLI Reference

*Generated from `python3 audit.py --help`.*

```text
usage: pn-ultra-audit [-h] [--out OUT] [--lang {auto,ar,en,es,fr,hi,it,ja,pt,zh}]
                      [--profile {quick,standard,deep}]
                      [--strictness {basic,standard,strict,lenient,balanced}] [--ask] [--baseline auto|FILE]
                      [--exclude EXCLUDE] [--tools] [--semgrep-config SEMGREP_CONFIG] [--run-tests]
                      [--test-timeout TEST_TIMEOUT] [--only ONLY] [--skip SKIP] [--plan] [--list-auditors]
                      [--no-docs] [--no-qa] [--domain DOMAIN] [--compliance LIST|all] [--evidence-pack DIR]
                      [--level {beginner,pro}] [--scaffold] [--write] [--show ID] [--kb QUERY] [--run DIR]
                      [--mcp] [--verify-corpus] [--install-agent TOOL[,TOOL]] [--agent-scope {project,user}]
                      [--agent-dir AGENT_DIR] [--force] [--ftp URL] [--ftp-pass-env FTP_PASS_ENV]
                      [--ftp-allow-plain] [--sftp USER@HOST] [--git-host GIT_HOST] [--git URL]
                      [--branch BRANCH] [--depth DEPTH] [--git-token-env VAR] [--history]
                      [--history-commits HISTORY_COMMITS] [--export DIR] [--pdf] [--db DB] [--db-sample]
                      [--via-ssh] [--aws-rds] [--aws-profile AWS_PROFILE] [--aws-region AWS_REGION]
                      [--aws-db-id AWS_DB_ID] [--ssh USER@HOST[:PORT]] [--ssh-key SSH_KEY]
                      [--ssh-port SSH_PORT] [--ssh-opts SSH_OPTS] [--accept-new-hostkey] [--sudo]
                      [--remote-path REMOTE_PATH] [--remote-root REMOTE_ROOT] [--url URL]
                      [--crawl-max CRAWL_MAX] [--psi] [--psi-key PSI_KEY] [--keywords KEYWORDS]
                      [--kw-lang KW_LANG] [--kw-country KW_COUNTRY] [--gsc-csv GSC_CSV]
                      [--competitor COMPETITOR] [--vercel-project NAME] [--vercel-team TEAM_ID]
                      [--vercel-token-env VERCEL_TOKEN_ENV] [--embed-source {auto,findings,none}]
                      [--embed-budget MB] [--authorized] [--fail-on {critical,high,medium,low,info}]
                      [--brief] [--top N] [--color {auto,always,never}] [--verbose] [--quiet] [--version]
                      [path]

PN-Ultra-Audit 1.0.21 - read-only audit of code, tests, docs, architecture, databases, servers and SEO/SEM.

positional arguments:
  path                  project directory (default .; omit when auditing only a remote server / URL)

options:
  -h, --help            show this help message and exit
  --out OUT             output base dir (default ./audit-output/<name>)
  --lang {auto,ar,en,es,fr,hi,it,ja,pt,zh}
                        report/UI language: auto (system language, Spanish by default) | es | en | zh ...
                        (any pack in engine/locales/). report language (default es)
  --profile {quick,standard,deep}
                        quick: first 2500 files
  --strictness {basic,standard,strict,lenient,balanced}
                        how demanding the audit is: basic (core risks only, lenient thresholds) | standard
                        (default, balanced) | strict (enterprise-grade: tight complexity/docs/typing limits
                        and extra QA/CI/hardening checks). lenient/balanced are aliases
  --ask                 interactive: ask which strictness level to use (menu 1-3) when running in a terminal
  --baseline auto|FILE  ratchet: findings already present in the previous run (auto) or FILE are 'legacy';
                        the gate judges only NEW ones
  --exclude EXCLUDE     glob to skip (repeatable)
  --tools               also run installed scanners (semgrep, gitleaks, npm audit, pip-audit, composer
                        audit)
  --semgrep-config SEMGREP_CONFIG
  --run-tests           EXECUTES the project's own test suite (runs target code)
  --test-timeout TEST_TIMEOUT
  --only ONLY           run only these auditors (comma list):
                        security,quality,docs,tests,qa,seo,repo,vercel,pwa,web3,db,domain
  --skip SKIP           skip these auditors (comma list)
  --plan                detect the project type, print which auditors would run, and exit
  --list-auditors       list the auditors and exit
  --no-docs             (alias of --skip docs)
  --no-qa               (alias of --skip qa)
  --domain DOMAIN       deep-dive domain profile: auto | none | saas | fintech | banking | healthtech |
                        ecommerce | marketplace (comma list)
  --authorized          REQUIRED for --ssh / --aws-rds / remote DBs / --url: you own or are allowed to
                        assess them
  --fail-on {critical,high,medium,low,info}
                        exit 1 if a NEW confirmed finding is at/above this severity (CI)
  --color {auto,always,never}
  --verbose             stream every finding (incl. low and to-review)
  --quiet
  --version             show program's version number and exit

Compliance readiness (pre-audit help for SOC 2, ISO 27001, HIPAA, GDPR, PCI DSS, NIST CSF, DORA, EU AI Act, WCAG) - NOT a certification:
  --compliance LIST|all
                        frameworks to evaluate:
                        soc2,iso27001,hipaa,gdpr,pci,nist,dora,euai,wcag,asvs,sox,nydfs,psd2,cis (default
                        all)
  --evidence-pack DIR   write the auditor evidence pack: control matrix, evidence requests, remediation
                        plan, SBOM, findings.csv, policy templates

Learning / beginner friendly:
  --level {beginner,pro}
                        beginner: friendlier output, plain-language explanations, 'Start here' plan,
                        balanced strictness unless you set --strictness
  --scaffold            create the professional files that are MISSING (.gitignore, .env.example, README,
                        CI, pre-commit, SECURITY.md, docs/architecture.md). Dry-run unless --write; never
                        overwrites
  --write               with --scaffold: actually write the files

Fix retrieval (offline; token-saving for humans and AI assistants):
  --show ID             print a compact fix card for one finding (e.g. SEC-001) from the latest run (see
                        --run)
  --kb QUERY            search the offline remediation knowledge base (e.g. --kb "sql injection php")
  --run DIR             run dir / audit-output dir / project dir to read for --show and --mcp (default:
                        ./audit-output)
  --mcp                 serve results to AI assistants over MCP (stdio, read-only)
  --verify-corpus       prove every tested vulnerable->fixed pair (rule fires, then stays silent)

AI coding assistants (install the skills / rules / commands):
  --install-agent TOOL[,TOOL]
                        claude, codex, cursor, windsurf, kiro, opencode, trae, or all
  --agent-scope {project,user}
                        where to install (default: current project)
  --agent-dir AGENT_DIR
                        project directory for --agent-scope project (default: cwd)
  --force               overwrite files not created by PN-Ultra-Audit

Repositories & servers (GitHub, GitLab, Bitbucket, Azure DevOps, Gitea/Forgejo, Codeberg, self-hosted, FTP/FTPS/SFTP) - read-only:
  --ftp URL             ftps://user@host/path (or ftp://). Password from env FTP_PASSWORD or --ftp-pass-env.
                        Download-only.
  --ftp-pass-env FTP_PASS_ENV
  --ftp-allow-plain     allow unencrypted FTP (clear-text password!)
  --sftp USER@HOST      SFTP-only host (no shell): downloads --remote-path with the system sftp client (uses
                        --ssh-key/--ssh-port/--ssh-opts)
  --git-host GIT_HOST   self-hosted domain for shorthands, e.g. --git gitlab:team/app --git-host
                        git.company.com
  --git URL             github:org/repo | gitlab:group/repo | bitbucket:ws/repo | azure:org/proj/repo |
                        gitea:host/org/repo | any https://…, ssh://… or git@host:org/repo.git (your SSH keys
                        / credential helper are used)
  --branch BRANCH
  --depth DEPTH         clone depth (default 1; 0 = full)
  --git-token-env VAR   env var holding an https token for private repos (sent as an HTTP header, never
                        stored)
  --history             also scan recent git history for secrets that were committed and later removed
  --history-commits HISTORY_COMMITS

Export:
  --export DIR          copy the report bundle to DIR (e.g. docs/): index.html dashboard, REPORT.md,
                        findings.sarif/json, summary.json
  --pdf                 also write report.pdf (needs Chrome/Chromium)

databases (sqlite file | postgres:// | mysql:// | redis:// | mongodb:// | mssql://):
  --db DB               repeatable
  --db-sample           check password columns for plaintext (aggregate counts only)
  --via-ssh             reach --db URLs through an SSH tunnel to --ssh host

AWS RDS (read-only aws cli):
  --aws-rds
  --aws-profile AWS_PROFILE
  --aws-region AWS_REGION
  --aws-db-id AWS_DB_ID

SSH server audit (key/agent auth, read-only):
  --ssh USER@HOST[:PORT]
  --ssh-key SSH_KEY
  --ssh-port SSH_PORT
  --ssh-opts SSH_OPTS   e.g. "-J jump@host"
  --accept-new-hostkey
  --sudo                use `sudo -n` for root-only reads
  --remote-path REMOTE_PATH
                        remote project dir to copy locally (read-only) and scan
  --remote-root REMOTE_ROOT
                        web root(s) to inspect on the server

SEO / SEM (web):
  --url URL             live-crawl this site (polite, robots-aware; your own site)
  --crawl-max CRAWL_MAX
  --psi                 Google PageSpeed Insights for --url (sends the URL to Google)
  --psi-key PSI_KEY
  --keywords KEYWORDS   comma-separated seeds: keyword ideas from public autocomplete (no API key)
  --kw-lang KW_LANG
  --kw-country KW_COUNTRY
  --gsc-csv GSC_CSV     Search Console performance export (Queries.csv / Pages.csv)
  --competitor COMPETITOR
                        competitor URL to compare on-page basics (repeatable, max 8)

Vercel (serverless platform: audited through project config, the live site and the read-only API):
  --vercel-project NAME
                        audit project settings and env-var metadata via the Vercel API (read-only; token
                        from env VERCEL_TOKEN; needs --authorized)
  --vercel-team TEAM_ID
                        team id/slug that owns the project
  --vercel-token-env VERCEL_TOKEN_ENV
                        env var holding the Vercel token (never pass tokens on the command line)

Report:
  --embed-source {auto,findings,none}
                        source code embedded in report.html for the read-only code viewer: auto (all text
                        files within the budget, files with findings first) | findings (only files with
                        findings) | none. Secrets are masked; .env/keys/state files are never embedded
  --embed-budget MB     size budget for source embedded in report.html (default 5 MB). Files over it are NOT
                        dropped: they go to sources/chunk-*.js next to the report and load on demand in the
                        viewer

Token saving (for AI assistants and quick looks):
  --brief               print only a ~40-line summary (gate, ratings, counts, top findings, next commands)
                        instead of the live UI; implies --quiet --color never
  --top N               findings listed by --brief (default 10)
```
