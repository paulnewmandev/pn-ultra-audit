# Documentation & standards reference

## Doc comments by language (what "documented" means)
| Language | Standard | Minimum for a public symbol | Enforce with |
|---|---|---|---|
| Python | PEP 257; Google or NumPy style | one-line summary (imperative) + Args/Returns/Raises when ≥ 3 params, raises, or non-trivial return | `pydocstyle`, `interrogate`, ruff `D` rules |
| TypeScript/JS | TSDoc/JSDoc | `/** summary @param @returns @throws @example */` on every `export` | `eslint-plugin-jsdoc`, `typedoc` |
| PHP | PHPDoc | `@param @return @throws` on public methods/classes | `phpcs`, `phpstan` |
| Java/Kotlin | Javadoc / KDoc | summary + `@param/@return/@throws` | Checkstyle `MissingJavadoc*`, detekt `UndocumentedPublic*` |
| Go | comment starting with the identifier | `// Foo does ...` above every exported identifier | `revive exported`, `golint` |
| Rust | rustdoc | `///` summary + `# Examples` (doctests) + `# Errors/# Panics` | `#![warn(missing_docs)]` |
| Swift | DocC | `///` summary, `- Parameter`, `- Returns`, `- Throws` | SwiftLint `missing_docs` |
| C# | XML docs | `<summary>`, `<param>`, `<returns>`, `<exception>` | `CS1591`, StyleCop |
| Dart | dartdoc | `///` on public members | `public_member_api_docs` |

## Project documents
README (purpose, requirements, install, run, test, config table, deploy, troubleshooting) · `docs/architecture.md` (context, modules, data flow, deployment; mermaid) · ADRs (`adr/NNNN-title.md`: context, decision, consequences) · OpenAPI/GraphQL schema · CONTRIBUTING (branching, commits, checks) · CHANGELOG (Keep a Changelog + SemVer) · `.env.example` · runbook for operations · SECURITY.md.

## Standards to check
Formatter (Prettier/Biome, Black/ruff-format, Pint, gofmt, ktlint, SwiftFormat) · linter (ESLint, ruff, phpcs/phpstan, golangci-lint, detekt, SwiftLint, RuboCop, Checkstyle) · type checking (TS `strict`, mypy/pyright, phpstan ≥ 6, Kotlin explicit API) · EditorConfig · Conventional Commits · SemVer · CI required checks (lint, types, tests, build, secret scan, dependency audit) · pre-commit hooks · 12-factor config · semantic naming and domain language.

## Architecture review prompts
1. Dependency direction: UI → application → domain ← infrastructure; 2. no import cycles; 3. each module has one reason to change; 4. boundaries enforced by tooling; 5. consistent error/logging/config strategy; 6. data access behind repositories; 7. side effects at the edges; 8. public API small and documented; 9. observable (logs, metrics, traces, health); 10. documented decisions (ADRs).
