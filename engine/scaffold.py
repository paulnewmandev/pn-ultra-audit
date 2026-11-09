"""--scaffold: create the professional project files that are MISSING (never overwrites). Dry-run by default; --write applies.
Stack-aware: .gitignore, .env.example (built from env vars your code reads), .editorconfig, README skeleton, CI workflow,
dependabot, pre-commit (gitleaks), SECURITY.md, docs/architecture.md (with a mermaid diagram)."""
import json, os, re

ENV_RX = [r"process\.env\.([A-Z][A-Z0-9_]{2,})", r"import\.meta\.env\.([A-Z][A-Z0-9_]{2,})", r"os\.environ(?:\.get)?\(\s*['\"]([A-Z][A-Z0-9_]{2,})", r"os\.environ\[\s*['\"]([A-Z][A-Z0-9_]{2,})", r"os\.getenv\(\s*['\"]([A-Z][A-Z0-9_]{2,})",
          r"\benv\(\s*['\"]([A-Z][A-Z0-9_]{2,})", r"getenv\(\s*['\"]([A-Z][A-Z0-9_]{2,})", r"System\.getenv\(\s*\"([A-Z][A-Z0-9_]{2,})", r"ENV\[\s*['\"]([A-Z][A-Z0-9_]{2,})", r"os\.Getenv\(\s*\"([A-Z][A-Z0-9_]{2,})", r"\$_ENV\[\s*['\"]([A-Z][A-Z0-9_]{2,})"]
GITIGNORE = {"base": ".DS_Store\nThumbs.db\n.idea/\n.vscode/\n*.log\n.env\n.env.*\n!.env.example\naudit-output/\ncoverage/\n*.pem\n*.key\n",
             "node": "node_modules/\ndist/\nbuild/\n.next/\n.nuxt/\n.turbo/\n.cache/\n*.tsbuildinfo\n", "python": "__pycache__/\n*.py[cod]\n.venv/\nvenv/\n.pytest_cache/\n.mypy_cache/\n.ruff_cache/\n*.egg-info/\ndist/\nbuild/\n",
             "php": "vendor/\nstorage/*.key\nstorage/logs/\nbootstrap/cache/\n.phpunit.result.cache\n", "go": "bin/\n*.exe\n*.test\n*.out\nvendor/\n", "java": "target/\nbuild/\n.gradle/\n*.class\n*.jar\n", "rust": "target/\n", "ruby": ".bundle/\nvendor/bundle/\nlog/\ntmp/\n",
             "mobile": "Pods/\nDerivedData/\n*.xcuserstate\n.gradle/\nlocal.properties\n*.keystore\n*.jks\nbuild/\n.dart_tool/\n", "web3": "artifacts/\ncache/\ncache_hardhat/\nout/\nbroadcast/\ntypechain-types/\n"}


def _stacks(rels, deps):
    ex = {os.path.splitext(r)[1].lower() for r in rels}; names = {os.path.basename(r) for r in rels}; s = []
    if "package.json" in names: s.append("node")
    if ".py" in ex or "requirements.txt" in names or "pyproject.toml" in names: s.append("python")
    if "composer.json" in names or ".php" in ex: s.append("php")
    if "go.mod" in names: s.append("go")
    if "pom.xml" in names or "build.gradle" in names or "build.gradle.kts" in names: s.append("java")
    if "Cargo.toml" in names: s.append("rust")
    if "Gemfile" in names: s.append("ruby")
    if "pubspec.yaml" in names or "AndroidManifest.xml" in names or any(r.endswith(".xcodeproj/project.pbxproj") for r in rels): s.append("mobile")
    if ".sol" in ex: s.append("web3")
    return s


def _ci(stacks, scripts):
    steps = []
    if "node" in stacks:
        steps += ["      - uses: actions/setup-node@v4\n        with: { node-version: 22, cache: npm }", "      - run: npm ci"] + [f"      - run: npm run {s}" for s in ("lint", "typecheck", "test", "build") if s in scripts]
    if "python" in stacks:
        steps += ["      - uses: actions/setup-python@v5\n        with: { python-version: '3.12' }", "      - run: pip install -r requirements.txt pytest ruff 2>/dev/null || pip install -e '.[dev]'", "      - run: ruff check . || true", "      - run: pytest -q"]
    if "php" in stacks: steps += ["      - uses: shivammathur/setup-php@v2\n        with: { php-version: '8.3' }", "      - run: composer install --no-interaction --prefer-dist", "      - run: composer audit", "      - run: vendor/bin/phpunit || php artisan test"]
    if "go" in stacks: steps += ["      - uses: actions/setup-go@v5\n        with: { go-version: stable }", "      - run: go vet ./...", "      - run: go test ./..."]
    if "rust" in stacks: steps += ["      - run: cargo clippy -- -D warnings", "      - run: cargo test"]
    if "java" in stacks: steps += ["      - uses: actions/setup-java@v4\n        with: { distribution: temurin, java-version: 21 }", "      - run: ./gradlew test || mvn -q test"]
    if not steps: steps = ["      - run: echo 'add your build/test commands here'"]
    return "name: CI\non:\n  pull_request:\n  push:\n    branches: [main]\npermissions:\n  contents: read\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n" + "\n".join(steps) + "\n  secrets:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with: { fetch-depth: 0 }\n      - uses: gitleaks/gitleaks-action@v2\n        env: { GITHUB_TOKEN: \"${{ secrets.GITHUB_TOKEN }}\" }\n"


def plan(root, files, deps_text, arch=None):
    rels = [r for r, *_ in files]; lowset = {r.lower() for r in rels}
    stacks = _stacks(rels, deps_text); proj = os.path.basename(os.path.abspath(root)) or "project"; out = []
    scripts = {}
    if os.path.exists(os.path.join(root, "package.json")):
        try: scripts = json.load(open(os.path.join(root, "package.json"))).get("scripts", {})
        except (OSError, ValueError): pass
    def add(path, content, why):
        if path.lower() not in lowset and not os.path.exists(os.path.join(root, path)): out.append((path, content, why))
    gi = GITIGNORE["base"] + "".join(GITIGNORE[s] for s in stacks if s in GITIGNORE)
    add(".gitignore", gi, "keeps secrets, build output and editor files out of Git")
    envs = {}
    for r, ab, e, sz in files:
        if e in ("js", "jsx", "ts", "tsx", "mjs", "cjs", "py", "php", "rb", "go", "java", "kt", "cs", "rs", "vue", "svelte") and sz < 400_000:
            try: t = open(ab, errors="ignore").read()
            except OSError: continue
            for rx in ENV_RX:
                for m in re.finditer(rx, t): envs.setdefault(m.group(1), r)
    if envs:
        body = "# Copy to .env and fill in. Never commit .env.\n" + "\n".join(f"{k}=" + ("  # used in " + v if len(v) < 60 else "") for k, v in sorted(envs.items())) + "\n"
        add(".env.example", body, f"documents the {len(envs)} environment variables your code reads")
    add(".editorconfig", "root = true\n\n[*]\ncharset = utf-8\nend_of_line = lf\ninsert_final_newline = true\ntrim_trailing_whitespace = true\nindent_style = space\nindent_size = 2\n\n[*.{py,java,kt,rs,go}]\nindent_size = 4\n\n[Makefile]\nindent_style = tab\n", "same formatting for every editor and AI tool")
    run_cmds = "\n".join(f"- `npm run {s}`" for s in ("dev", "start", "build", "test", "lint") if s in scripts) or "- _add the command that starts the app_"
    add("README.md", f"# {proj}\n\n> One sentence: what problem does this solve and for whom?\n\n## Requirements\n\n- {', '.join(stacks) or 'list runtimes and versions'}\n\n## Install\n\n```bash\n# clone, install dependencies\n```\n\n## Run\n\n{run_cmds}\n\n## Test\n\n```bash\n# command that runs the tests\n```\n\n## Configuration\n\nCopy `.env.example` to `.env` and fill in the values.\n\n## Project structure\n\nSee [docs/architecture.md](docs/architecture.md).\n\n## Contributing / Security\n\nSee `SECURITY.md`.\n", "a newcomer (or you in a month) can run the project in 10 minutes")
    style = (arch or {}).get("style", ["modular monolith"])
    mm = "flowchart TB\n    U[Users] --> P[Presentation / UI / API handlers]\n    P --> A[Application services]\n    A --> D[Domain / models]\n    A --> I[Infrastructure: DB, queues, external APIs]\n"
    add("docs/architecture.md", f"# Architecture\n\n**Style:** {', '.join(style)}\n\n```mermaid\n{mm}```\n\n## Modules\n\n| Module | Responsibility |\n|---|---|\n| _name_ | _one sentence_ |\n\n## Data flow\n\n_Describe one request end to end._\n\n## Decisions\n\nRecord important choices as `docs/adr/0001-title.md` (context, decision, consequences).\n", "writes down the 'why' so changes stay safe")
    add(".github/workflows/ci.yml", _ci(stacks, scripts), "runs tests and a secret scan on every change")
    add(".github/dependabot.yml", "version: 2\nupdates:\n" + "".join(f"  - package-ecosystem: {e}\n    directory: /\n    schedule: {{ interval: weekly }}\n" for e in ([{'node': 'npm', 'python': 'pip', 'php': 'composer', 'go': 'gomod', 'java': 'gradle', 'rust': 'cargo', 'ruby': 'bundler'}[s] for s in stacks if s in ('node', 'python', 'php', 'go', 'java', 'rust', 'ruby')] or ["github-actions"])) + "  - package-ecosystem: github-actions\n    directory: /\n    schedule: { interval: weekly }\n", "weekly PRs for vulnerable/outdated dependencies")
    add(".pre-commit-config.yaml", "repos:\n  - repo: https://github.com/gitleaks/gitleaks\n    rev: v8.18.4\n    hooks: [{ id: gitleaks }]\n  - repo: https://github.com/pre-commit/pre-commit-hooks\n    rev: v4.6.0\n    hooks:\n      - id: end-of-file-fixer\n      - id: trailing-whitespace\n      - id: check-merge-conflict\n      - id: detect-private-key\n", "blocks secrets and sloppy commits before they happen (pip install pre-commit; pre-commit install)")
    add("SECURITY.md", "# Security policy\n\n## Reporting a vulnerability\n\nPlease do **not** open a public issue. Email the maintainers (add address) with steps to reproduce. We aim to reply within 72 hours.\n\n## Supported versions\n\nThe latest release receives security fixes.\n", "tells people how to report problems privately")
    return dict(project=proj, stacks=stacks, files=out, env_vars=len(envs))


def apply(root, p, write=False):
    log = []
    for path, content, why in p["files"]:
        dst = os.path.join(root, path)
        if write:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            if os.path.exists(dst): log.append(f"  = skipped (exists): {path}"); continue
            open(dst, "w", encoding="utf-8").write(content); log.append(f"  + created {path}  - {why}")
        else: log.append(f"  would create {path}  - {why}")
    return log
