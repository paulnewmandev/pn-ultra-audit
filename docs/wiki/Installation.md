# Installation

## From git (recommended)
```bash
git clone https://github.com/paulnewmandev/pn-ultra-audit
python3 pn-ultra-audit/audit.py --version
```
Optional: `bash pn-ultra-audit/install.sh` puts a `pn-ultra-audit` launcher on your PATH.

## From pip
```bash
pip install git+https://github.com/paulnewmandev/pn-ultra-audit
pn-ultra-audit --help
```
The pip package ships the CLI and engines; the `skills/` and `examples/` folders (AI-assistant skills, fix corpus) need a git clone.

## Requirements
- Python 3.9 or newer - nothing else to install.
- Optional extras the tool uses when present: `git`, `ssh`/`sftp` (servers), `psql`/`mysql`/`redis-cli`/`mongosh` (live databases), Chrome/Chromium (PDF), `semgrep`/`gitleaks`/`npm audit`/`pip-audit` (`--tools`).

## AI assistants
```bash
python3 audit.py --install-agent all --agent-dir /path/to/your/project
```
See [AI Assistants and MCP](AI-Assistants-and-MCP).

## Updating
`git pull` - results from older versions stay readable; use `--baseline auto` to compare runs.
