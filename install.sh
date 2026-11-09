#!/usr/bin/env bash
# PN-Ultra-Audit helper. Usage:
#   ./install.sh --link                       symlink `pn-ultra-audit` into ~/.local/bin
#   ./install.sh --agent all [--project DIR]  install skills/rules/commands into AI assistants (claude,codex,cursor,windsurf,kiro,opencode,trae)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
case "${1:-}" in
  --link) mkdir -p "$HOME/.local/bin"; ln -sf "$HERE/bin/pn-ultra-audit" "$HOME/.local/bin/pn-ultra-audit"; echo "linked: ~/.local/bin/pn-ultra-audit (make sure ~/.local/bin is on PATH)";;
  --agent) shift; TOOLS="${1:-all}"; shift || true; DIR="${2:-$PWD}"; [ "${1:-}" = "--project" ] && DIR="${2:-$PWD}"; python3 "$HERE/audit.py" --install-agent "$TOOLS" --agent-dir "$DIR";;
  *) echo "usage: ./install.sh --link | --agent <tool|all> [--project DIR]"; exit 2;;
esac
