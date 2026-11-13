"""Professional full-stack roadmap: ~45 practices every production app should have, auto-detected from the project,
grouped by dimension, scored into 5 levels, each missing item with WHY and HOW. Built for beginners (vibe coders)
who want to grow into professional full-stack developers."""
import os, re

LEVELS = [(0, "Getting started", "Prototype: it runs on your machine."), (30, "Foundations", "Basics in place; many risks left."), (50, "Solid", "Safe to show to real users with care."),
          (70, "Professional", "Team-ready: tested, automated, documented."), (88, "Production-grade", "Resilient, observable, secure by default.")]


def _deps(files, extra=""):
    t = extra
    return t.lower()


def build(files, deps_text, findings, metrics, kinds, has_ratelimit=False):
    rels = [r for r, *_ in files]; low = [r.lower() for r in rels]; names = {os.path.basename(r) for r in rels}; nl = {n.lower() for n in names}
    d = deps_text.lower(); k = set(kinds)
    conf = [f for f in findings if f["status"] == "confirmed"]
    rules = {f["rule"] for f in conf}; fams = {f["family"] for f in conf}; cats = {f["category"] for f in conf}
    sev = lambda *s: any(f["severity"] in s for f in conf if f["category"] not in ("seo", "sem", "privacy"))
    has = lambda *a: any(x in d for x in a)
    nofind = lambda *r: not any(x in rules for x in r)
    anyfile = lambda rx: any(re.search(rx, r) for r in low)
    T = metrics.get("tests", {}) or {}; ds = (metrics.get("docstrings") or {}).get("percent")
    ci = anyfile(r"^\.github/workflows/.*\.ya?ml$|^\.gitlab-ci\.yml$|^jenkinsfile$|azure-pipelines|bitbucket-pipelines|\.circleci/")
    web = "frontend" in k or "web" in k; back = "backend" in k; mob = "mobile" in k; db = "database" in k or has("sqlalchemy", "prisma", "typeorm", "sequelize", "mongoose", "eloquent", "doctrine", "gorm", "hibernate", "activerecord", "psycopg", "mysql")
    I = []
    def add(dim, id, title, ok, why, how, w=1, when=True):
        if when: I.append(dict(dim=dim, id=id, title=title, ok=bool(ok), why=why, how=how, w=w))
    # ── Version control & hygiene
    add("Foundations", "git", "Project is under Git with a .gitignore", ".gitignore" in nl and (metrics.get("git") or True), "Without Git you cannot undo mistakes or collaborate; without .gitignore you commit junk and secrets.", "git init; add a .gitignore for your stack (run `--scaffold`); commit small and often with clear messages.", 2)
    add("Foundations", "readme", "README explains how to install, run and test", "readme.md" in nl, "Future-you (and teammates) will forget how it works in a month.", "Write purpose, requirements, install, run, test, env vars. `--scaffold` creates a skeleton.", 2)
    add("Foundations", "envexample", "Configuration lives in env vars with a documented .env.example", any(n.startswith(".env.") and re.search("example|sample|template", n) for n in nl), "Hard-coded config breaks in other environments and leaks secrets.", "Read config from environment variables; commit `.env.example` (no secrets). `--scaffold` builds it from your code.", 2, back or web)
    add("Foundations", "lock", "Dependencies are locked (lockfile committed)", nofind("DEP-NO-LOCKFILE") and anyfile(r"(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|composer\.lock|poetry\.lock|pipfile\.lock|go\.sum|cargo\.lock|gemfile\.lock)") or not anyfile(r"package\.json|composer\.json|pyproject\.toml|gemfile|cargo\.toml"), "Unlocked versions make builds unrepeatable and open supply-chain risks.", "Commit the lockfile (npm i / composer install / poetry lock).", 1)
    # ── Security
    add("Security", "nosecrets", "No secrets in the code or git history", "secrets" not in cats, "Anyone with the repo can use leaked keys; git remembers forever.", "Rotate leaked keys, move them to env vars/secret manager, add gitleaks to pre-commit.", 4)
    add("Security", "nocritical", "No critical/high security findings", not sev("critical", "high") or not any(f["type"] == "vulnerability" and f["severity"] in ("critical", "high") for f in conf), "Critical issues are exploitable in minutes.", "Fix in the dashboard's Start here order; one change + one test each.", 5)
    add("Security", "injection", "No SQL/command injection or XSS patterns", not (fams & {"sqli", "cmdi", "xss"}), "Injection is the classic way apps get fully compromised.", "Parameterize queries, avoid shell, escape output (see each finding's steps).", 4)
    add("Security", "authz", "Object access is checked per user (no IDOR / mass assignment)", not (fams & {"idor", "massassign"}) and "AUTHZ-IDOR" not in rules, "Without ownership checks one user can read another's data.", "Scope every lookup by the current user/tenant; use allowlists for model fields.", 3, back)
    add("Security", "auth", "Uses a proven auth library/framework (not hand-rolled)", has("passport", "next-auth", "auth.js", "@auth/", "django.contrib.auth", "devise", "sanctum", "passport", "spring-security", "firebase-auth", "supabase", "clerk", "auth0", "keycloak", "lucia", "fastapi-users", "authlib"), "Hand-made login/session code is the #1 source of auth bugs.", "Adopt your framework's auth or a managed provider; never store plain passwords.", 3, back)
    add("Security", "validation", "Input is validated with a schema library", has("zod", "joi", "yup", "pydantic", "class-validator", "express-validator", "marshmallow", "ajv", "valibot", "bean-validation", "javax.validation", "formrequest", "cerberus", "voluptuous"), "Unvalidated input causes crashes and security bugs.", "Validate every request body/query with a schema (zod/pydantic/FormRequest).", 3, back)
    add("Security", "headers", "Security headers and CORS are configured", has("helmet", "django-csp", "flask-talisman", "secure-headers", "spatie/laravel-csp", "fastify-helmet") and "CFG-CORS" not in rules, "Headers/CORS stop whole classes of browser attacks.", "Add helmet (Node) / SecurityMiddleware+CSP (Django) / secure headers; allowlist CORS origins.", 2, back or web)
    add("Security", "ratelimit", "Rate limiting protects login and expensive endpoints", has_ratelimit or has("ratelimit", "rate-limit", "throttle", "slowapi", "limiter"), "Without it, bots can brute-force logins and take your server down.", "Add rate limiting at the edge (nginx/CDN) and in the app for auth routes.", 3, back)
    add("Security", "https", "TLS verification is never disabled", nofind("CRY-TLS"), "Disabling certificate checks removes HTTPS protection.", "Remove verify=False / rejectUnauthorized:false; add the CA bundle instead.", 2)
    add("Security", "pwdhash", "Passwords use argon2/bcrypt (never MD5/SHA-1/plain)", nofind("CRY-PWD-HASH", "DB-PLAINTEXT-PASSWORDS", "SQL-PLAIN-PWD-ROW"), "A DB leak would expose real passwords.", "Use the framework's password hasher (argon2id/bcrypt).", 3)
    add("Security", "web3sec", "Smart contracts follow checks-effects-interactions & access control", not (fams & {"web3"}) , "On-chain bugs lose funds irreversibly.", "Use OpenZeppelin, nonReentrant, access control; fuzz with Foundry; get an audit.", 4, "web3" in k)
    # ── Testing & quality
    add("Quality", "tests", "Automated tests exist", (T.get("test_files") or 0) > 0 and (T.get("test_cases") or 0) > 0, "Tests let you change code without fear.", "Start with 1 test per critical function/route (pytest/vitest/phpunit/go test).", 4)
    add("Quality", "testratio", "Tests cover the important modules (auth, payments, data)", (T.get("test_ratio") or 0) >= 0.15 and "TST-MODULE-UNTESTED" not in rules, "Untested core logic is where production bugs live.", "Add tests for the highest-risk untested modules first.", 3)
    add("Quality", "e2e", "End-to-end tests cover the critical user journeys", has("playwright", "cypress", "webdriverio", "detox", "maestro", "appium") or anyfile(r"\.maestro/|integration_test/|e2e/"), "Unit tests miss broken flows (login → buy).", "Add Playwright (web) or Maestro/Detox (mobile) for 3–5 key journeys.", 3, web or mob)
    add("Quality", "lint", "Linter + formatter are configured", nofind("STD-NO-LINTER", "STD-NO-FORMATTER") , "They catch bugs and end style arguments automatically.", "ESLint+Prettier / ruff / phpcs+pint / golangci-lint; run in CI.", 2)
    add("Quality", "types", "Static typing is on (TS strict / type hints / PHPStan)", nofind("STD-TS-NOT-STRICT", "STD-NO-PY-TYPECHECK", "STD-NO-TSCONFIG"), "Types find whole classes of bugs before you run the code.", "Enable TypeScript strict, mypy/pyright, or PHPStan level 6+.", 2)
    add("Quality", "noflaky", "Tests are reliable (no sleeps, no un-awaited asserts)", not (rules & {"QA-SLEEP", "QA-UNAWAITED-EXPECT", "TST-FOCUSED", "MOB-AND-SLEEP", "MOB-IOS-SLEEP"}), "Flaky tests teach you to ignore CI.", "Replace sleeps with auto-waiting assertions; always await expect().", 2, web or mob)
    add("Quality", "noerrswallow", "Errors are not silently swallowed", "BUG-EMPTY-CATCH" not in rules, "Hidden errors turn into mystery bugs.", "Log or re-throw; catch the narrowest exception.", 1)
    # ── Delivery / DevOps
    add("Delivery", "ci", "CI runs lint, types and tests on every change", ci and nofind("STD-CI-GAPS", "STD-NO-CI"), "Automation stops broken code reaching users.", "Add a GitHub Actions workflow (`--scaffold` creates one).", 4)
    add("Delivery", "docker", "App is containerized or has a reproducible deploy", "dockerfile" in nl or anyfile(r"(^|/)(docker-compose|compose)\.ya?ml$|serverless\.ya?ml|vercel\.json|netlify\.toml|fly\.toml|render\.yaml|procfile|wrangler\.(toml|jsonc?)"), "'Works on my machine' is not a deploy strategy.", "Add a Dockerfile (non-root user, pinned base image) or a platform config.", 2, back or web)
    add("Delivery", "dockersafe", "Container hardening basics (non-root, pinned tag)", nofind("CFG-DOCKER", "CFG-DOCKER-NOUSER") , "Root containers and `latest` tags increase blast radius.", "USER app; pin image versions; multi-stage build.", 1, "dockerfile" in nl)
    add("Delivery", "depsaudit", "Dependencies are scanned for known vulnerabilities", anyfile(r"dependabot|renovate") or has("snyk", "osv-scanner"), "Old libraries are the easiest way in.", "Enable Dependabot/Renovate and `npm audit`/`pip-audit` in CI.", 2)
    add("Delivery", "precommit", "Pre-commit hooks (format, lint, secret scan)", anyfile(r"\.pre-commit-config\.yaml|\.husky|lefthook"), "Catches problems before they are committed.", "pre-commit with gitleaks + formatter (`--scaffold` creates the file).", 1)
    # ── Data
    add("Data", "migrations", "Database changes use migrations", anyfile(r"(^|/)(migrations?|db/migrate|prisma/migrations|alembic|flyway|liquibase)(/|$)|schema\.prisma"), "Hand-edited databases drift and cannot be reproduced.", "Use your ORM's migrations (Prisma/Alembic/Laravel/Rails).", 3, db)
    add("Data", "schema", "Tables have primary keys and indexed foreign keys", nofind("SQL-NO-PK", "SQL-FK-NO-INDEX", "SQL-MONEY-FLOAT", "SQL-MYISAM", "DBD-MISSING-FK", "DBD-NO-RELATIONS", "DBD-NOT-UNIQUE"), "Missing keys/indexes cause slow queries and duplicate data.", "Add PRIMARY KEY, index every foreign key, DECIMAL for money.", 2, db)
    add("Data", "n1", "No obvious N+1 query patterns", "PERF-NPLUS1" not in rules, "N+1 makes pages slow as data grows.", "Eager-load relations / batch queries.", 1, db)
    # ── Observability
    add("Operations", "logging", "Structured logging library is used", has("winston", "pino", "bunyan", "loguru", "structlog", "monolog", "slf4j", "logback", "zap", "logrus", "serilog", "log4j", "tracing"), "Logs are your eyes in production.", "Use a logger with levels (not print/console.log); never log secrets.", 2, back)
    add("Operations", "errortrack", "Error tracking / APM is installed (Sentry, OpenTelemetry…)", has("sentry", "rollbar", "bugsnag", "honeybadger", "newrelic", "datadog", "opentelemetry", "elastic-apm", "appsignal", "raygun"), "You should learn about crashes before your users tell you.", "Add Sentry (free tier) to backend and frontend.", 3, back or web or mob)
    add("Operations", "nodebug", "Debug mode is off by default for production", "CFG-DEBUG" not in rules, "Debug pages leak code and secrets.", "Drive DEBUG from the environment; default False.", 2, back)
    # ── Documentation & architecture
    add("Craft", "docs", "Public code is documented (docstrings / JSDoc)", ds is not None and ds >= 60, "Docs make code understandable and AI assistants more accurate.", "Document public functions: what, params, returns, errors.", 2, back or web)
    add("Craft", "arch", "No circular dependencies; layers are respected", nofind("ARCH-CYCLE") and "ARCH-LAYERING" not in rules, "Cycles make changes risky and tests hard.", "Extract shared code; handlers call services, services call data access.", 2)
    add("Craft", "small", "Functions and files are small and focused", not (rules & {"ARCH-FUNC-COMPLEX", "QUA-GOD-FILE", "QUA-COMPLEX-FILE"}), "Giant functions hide bugs.", "Extract helpers; use guard clauses; split by responsibility.", 2)
    add("Craft", "archdoc", "Architecture/decisions are written down", anyfile(r"docs?/architecture|(^|/)adr/|decisions/"), "Teammates (and you) need the 'why'.", "docs/architecture.md with a diagram + ADRs for key choices.", 1)
    add("Craft", "apispec", "API is described (OpenAPI/GraphQL schema)", anyfile(r"openapi|swagger|schema\.graphql|\.proto$|postman"), "Contracts keep frontend, backend and tests in sync.", "Generate OpenAPI from your framework and commit it.", 1, back)
    # ── Frontend experience
    add("Experience", "a11y", "Accessible markup (alt text, labels, keyboard)", nofind("A11Y-IMG-ALT", "A11Y-CLICK-NONINTERACTIVE", "A11Y-HTML-LANG", "A11Y-ZOOM-DISABLED", "A11Y-TABINDEX-POSITIVE"), "15% of people have a disability; it is also a legal requirement in many places.", "Use real <button>/<a>, alt text, labels; test with axe.", 2, web)
    add("Experience", "seo", "SEO basics (title, description, sitemap, robots)", nofind("SEO-NO-TITLE", "SEO-NO-DESCRIPTION", "SEO-NO-SITEMAP", "SEO-ROBOTS-BLOCKS-ALL"), "Search engines can't rank what they can't understand.", "Unique title/description per page, sitemap.xml, robots.txt.", 2, "web" in k)
    add("Experience", "consent", "Tracking has user consent (GDPR/ePrivacy)", "SEM-NO-CONSENT" not in rules, "Tracking before consent is a legal risk.", "Add a consent banner + Google Consent Mode v2.", 2, "web" in k)
    add("Experience", "mobileperm", "Mobile permissions and privacy strings are declared", nofind("MOB-IOS-PERM-MISSING", "MOB-AND-PERM-MISSING"), "Missing keys crash iOS apps and fail store review.", "Add NS…UsageDescription / uses-permission entries.", 3, mob)
    add("Experience", "perf", "Performance budget / lightweight assets", nofind("SEO-HEAVY-IMAGES", "SEO-RENDER-BLOCKING") , "Slow pages lose users and rankings.", "Compress images (AVIF/WebP), defer scripts, set LCP/CLS budgets.", 1, web)
    # score
    items = [i for i in I]
    tot = sum(i["w"] for i in items) or 1; got = sum(i["w"] for i in items if i["ok"])
    score = round(100 * got / tot)
    lvl = max(i for i, (th, *_) in enumerate(LEVELS) if score >= th)
    dims = {}
    for i in items:
        dm = dims.setdefault(i["dim"], dict(score=0, items=[], w=0, got=0)); dm["items"].append(i); dm["w"] += i["w"]; dm["got"] += i["w"] if i["ok"] else 0
    for dm in dims.values(): dm["score"] = round(100 * dm["got"] / (dm["w"] or 1))
    nxt = LEVELS[lvl + 1][0] if lvl + 1 < len(LEVELS) else None
    todo = sorted([i for i in items if not i["ok"]], key=lambda i: -i["w"])
    return dict(score=score, level=lvl + 1, level_name=LEVELS[lvl][1], level_desc=LEVELS[lvl][2], next_level=(LEVELS[lvl + 1][1] if nxt else None), points_to_next=(nxt - score if nxt else 0),
                dimensions={k: dict(score=v["score"], items=v["items"]) for k, v in dims.items()}, next_moves=[i["id"] for i in todo[:5]], levels=[dict(n=i + 1, name=n, at=th, desc=ds_) for i, (th, n, ds_) in enumerate(LEVELS)])
