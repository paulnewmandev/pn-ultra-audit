"""Project-type detection -> decides which auditors run by default (backend only -> backend auditors, etc.)."""
import os, re

AUDITORS = {
    "security": "SAST: SQLi, XSS, DoS, injection, secrets, crypto, auth, misconfig (all languages, IaC, CI)",
    "quality": "Project checks, duplication, god files, lockfiles, committed env files",
    "docs": "Docs coverage, docstrings, standards tooling, complexity, import cycles, architecture",
    "tests": "Test inventory, untested modules, assertion-free/focused/skipped tests",
    "qa": "Front-end QA (Playwright/Cypress/axe/visual) and mobile QA (Android/iOS/Flutter/RN)",
    "seo": "SEO + SEM readiness: metadata, robots, sitemap, tracking, consent",
    "web3": "Smart contracts (Solidity/Anchor) and dApp patterns",
    "db": "SQL/migrations static checks and live DB connections (--db)",
    "domain": "Deep dive for SaaS/multi-tenant, fintech, banking, health-tech and e-commerce (tenant isolation, money, idempotency, webhooks, PCI data, audit trail)",
}
BACKEND_FW = r'"(express|fastify|koa|@nestjs/core|hapi|restify|apollo-server\w*|graphql-yoga|trpc|@trpc/server|hono|elysia)"|\b(django|flask|fastapi|starlette|tornado|aiohttp|sanic|falcon|pyramid)\b|laravel/framework|symfony/|slim/slim|spring-boot|micronaut|quarkus|ktor|gin-gonic|labstack/echo|gofiber|chi\b|actix-web|axum|rocket|rails|sinatra|hanami|phoenix|Microsoft\.AspNetCore|asp\.net'
FRONT_FW = r'"(react|react-dom|vue|svelte|@angular/core|next|nuxt|solid-js|astro|preact|lit|@remix-run/react|gatsby|ember-source|alpinejs|htmx\.org|@sveltejs/kit)"'
WEB_SSR = r'"(next|nuxt|astro|gatsby|@remix-run/react|@sveltejs/kit|@angular/ssr|eleventy|@11ty/eleventy|vitepress|docusaurus|@docusaurus/core|hugo)"'


def detect(files, deps_text=""):
    rels = [r for r, *_ in files]; exts = {}
    for _, _, e, _ in files: exts[e] = exts.get(e, 0) + 1
    low = [r.lower() for r in rels]; names = {os.path.basename(r) for r in rels}
    ev = {}
    def has(*xs): return any(x in names for x in xs)
    # mobile
    mob = []
    if "AndroidManifest.xml" in names: mob.append("Android")
    if any(r.endswith("project.pbxproj") for r in rels) or ("Podfile" in names) or exts.get("swift", 0) >= 3: mob.append("iOS")
    if "pubspec.yaml" in names: mob.append("Flutter")
    if re.search(r'"(react-native|expo)"', deps_text): mob.append("React Native/Expo")
    if mob: ev["mobile"] = mob
    # frontend
    fe = []
    m = re.findall(FRONT_FW, deps_text)
    if m: fe += sorted(set(m))[:4]
    if sum(exts.get(e, 0) for e in ("tsx", "jsx", "vue", "svelte", "astro")) >= 3: fe.append("component files")
    if exts.get("html", 0) + exts.get("htm", 0) >= 1 and (exts.get("js", 0) or exts.get("css", 0)): fe.append("HTML/JS/CSS")
    if fe: ev["frontend"] = fe
    # web (public pages -> SEO)
    web = []
    if re.search(WEB_SSR, deps_text): web.append("SSR/SSG framework")
    if exts.get("html", 0) + exts.get("htm", 0) >= 1: web.append("HTML pages")
    if any(r.endswith(".blade.php") or "/views/" in r or "/templates/" in r for r in low) and (exts.get("php", 0) or exts.get("py", 0) or exts.get("rb", 0) or exts.get("twig", 0)): web.append("server templates")
    if has("wp-config.php", "wp-settings.php") or any("wp-content" in r for r in low[:2000]): web.append("WordPress")
    if has("hugo.toml", "_config.yml", "mkdocs.yml", "docusaurus.config.js"): web.append("static site generator")
    if web: ev["web"] = web
    # backend
    be = []
    if re.search(BACKEND_FW, deps_text, re.I): be.append("web/API framework")
    server_lang = sum(exts.get(e, 0) for e in ("py", "go", "java", "kt", "php", "rb", "cs", "rs", "ex", "scala"))
    if server_lang >= 3 and not mob: be.append("server-side code")
    if any(re.search(r"(^|/)(controllers?|routes?|handlers?|resolvers?|endpoints?|api)(/|\.)", r) for r in low) and server_lang: be.append("routes/controllers")
    if has("serverless.yml", "serverless.yaml", "wrangler.toml", "wrangler.jsonc", "vercel.json", "netlify.toml") or any(r.startswith(("functions/", "netlify/functions", "api/")) for r in low): be.append("serverless/edge functions")
    if has("manage.py", "artisan", "Gemfile", "go.mod", "pom.xml", "Cargo.toml") and server_lang: be.append("backend project layout")
    if be: ev["backend"] = be
    # database
    db = []
    if exts.get("sql", 0) or exts.get("pls", 0) or exts.get("tsql", 0): db.append(f"{exts.get('sql', 0)} .sql")
    if any(re.search(r"(^|/)(migrations?|db/migrate|prisma|alembic|flyway|liquibase|knex|sequelize|typeorm|schema\.prisma)(/|$|\.)", r) for r in low): db.append("migrations/ORM schema")
    if re.search(r"\b(sqlalchemy|psycopg2?|pymysql|mysqlclient|asyncpg|prisma|typeorm|sequelize|knex|mongoose|mongodb|redis|gorm|hibernate|spring-data|eloquent|doctrine|activerecord|ef core|entityframework)\b", deps_text, re.I): db.append("DB client/ORM dependency")
    if any(r.endswith((".db", ".sqlite", ".sqlite3")) for r in low): db.append("SQLite file")
    if db: ev["database"] = db
    # web3
    w3 = []
    if exts.get("sol", 0) or exts.get("vy", 0): w3.append(f"{exts.get('sol', 0)} .sol")
    if has("hardhat.config.js", "hardhat.config.ts", "foundry.toml", "truffle-config.js", "Anchor.toml", "Move.toml", "brownie-config.yaml"): w3.append("contract framework")
    if re.search(r'"(ethers|web3|viem|wagmi|@solana/web3\.js|@web3-react/core|@openzeppelin/contracts|hardhat)"', deps_text): w3.append("web3 dependencies")
    if w3: ev["web3"] = w3
    # infra (informational)
    inf = []
    if any(os.path.basename(r).lower().startswith("dockerfile") for r in rels): inf.append("Docker")
    if exts.get("tf", 0): inf.append("Terraform")
    if any(r.endswith((".yaml", ".yml")) and re.search(r"(k8s|kubernetes|helm|charts?)/", r.lower()) for r in rels): inf.append("Kubernetes/Helm")
    if any(r.startswith(".github/workflows/") for r in rels): inf.append("GitHub Actions")
    if inf: ev["infra"] = inf
    code = sum(exts.get(e, 0) for e in ("py", "js", "jsx", "ts", "tsx", "php", "java", "kt", "go", "rb", "cs", "rs", "swift", "dart", "c", "cpp", "scala", "ex", "lua", "sol", "vue", "svelte"))
    kinds = [k for k in ("backend", "frontend", "mobile", "database", "web", "web3", "infra") if k in ev]
    if not [k for k in kinds if k not in ("infra",)] and code: kinds.insert(0, "library/cli")
    if not kinds: kinds = ["unknown"]
    return dict(kinds=kinds, evidence=ev, code_files=code)


def default_plan(d):
    k = set(d["kinds"])
    if not d["code_files"] and (k & {"database"}) and not (k & {"web", "frontend", "backend", "mobile"}): return {"security", "db"}
    if not d["code_files"] and k <= {"infra", "unknown"}: return {"security", "docs"}
    plan = {"security", "quality", "docs", "tests"}
    if k & {"frontend", "mobile"}: plan.add("qa")
    if "web" in k or ("frontend" in k and "backend" not in k and d["evidence"].get("web")): plan.add("seo")
    if "web" in k: plan.add("seo")
    if "web3" in k: plan.add("web3")
    if "database" in k: plan.add("db")
    return plan


def resolve_plan(d, only=None, skip=None):
    names = set(AUDITORS)
    if only:
        bad = [x for x in only if x not in names]
        if bad: raise ValueError("unknown auditor(s): " + ", ".join(bad) + " (valid: " + ", ".join(sorted(names)) + ")")
        plan = set(only)
    else:
        plan = default_plan(d)
    if skip:
        bad = [x for x in skip if x not in names]
        if bad: raise ValueError("unknown auditor(s) in --skip: " + ", ".join(bad))
        plan -= set(skip)
    return plan
