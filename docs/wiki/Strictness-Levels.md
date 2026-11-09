# Strictness Levels

| Level | Flag | Use it when | What changes |
|---|---|---|---|
| **basic** | `--strictness basic` | prototypes, quick health check, legacy | core risks only; lenient documentation, complexity and typing thresholds; fewer hygiene findings |
| **standard** *(default)* | `--strictness standard` | most projects | balanced thresholds and checks |
| **strict** | `--strictness strict` | enterprise, fintech, pre-certification | tight limits (function length 40, cyclomatic complexity 10, 80% API docs, 70% typed), extra QA/CI/PWA/hardening/repo checks, higher severities |

- `--ask` shows a 1-2-3 menu in a terminal.
- From an AI assistant the installed skills **ask which level you want** before running.
- `lenient` and `balanced` are accepted aliases for `basic` and `standard`.
- `--level beginner` keeps `standard` and adds plain-language explanations.

Tip: adopt on an existing codebase with `--strictness standard --baseline auto` so the gate judges only **new** findings, then raise the level over time.
