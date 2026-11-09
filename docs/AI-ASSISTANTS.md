# AI assistants

`python3 audit.py --install-agent <tool>[,<tool>] [--agent-scope project|user] [--agent-dir DIR] [--force]` where tool ∈ `claude, codex, cursor, windsurf, kiro, opencode, trae, all`.

| Tool | Project scope | User scope |
|---|---|---|
| Claude Code | `.claude/skills/*`, `.claude/commands/pn-audit.md` | `~/.claude/...` |
| Codex | `.agents/skills/*`, `AGENTS.md` (managed block) | `~/.agents/skills`, `~/.codex/AGENTS.md` |
| Cursor | `.cursor/rules/pn-ultra-audit.mdc`, `.cursor/commands/pn-audit.md` | `~/.cursor/commands/` |
| Windsurf | `.windsurf/rules/pn-ultra-audit.md`, `.windsurf/workflows/pn-audit.md` | project only |
| Kiro | `.kiro/steering/pn-ultra-audit.md` (`inclusion: manual`) | `~/.kiro/steering/` |
| OpenCode | `.opencode/command/pn-audit.md`, `AGENTS.md` | `~/.config/opencode/` |
| Trae | `.trae/rules/pn-ultra-audit.md` | project only |

Locations/format follow each tool's public docs at the time of writing and may change - if a feature doesn't appear, check the tool's current documentation. Installed files carry a `pn-ultra-audit:managed` marker; foreign files are never overwritten without `--force`.
