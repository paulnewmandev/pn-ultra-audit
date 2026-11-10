"""Project profile: WHAT the project is (technical shape) and WHAT it is for (industry / business focus), with evidence and confidence.
Read-only and offline. Signals come from dependency manifests, folder/file names, README/package descriptions, database schema names and
a bounded sample of code identifiers. A label needs several independent signals (never one keyword), and the evidence is shown so a person
or an AI assistant can verify it."""
import os, re
from collections import Counter

# ---------------------------------------------------------------- industries (id: label_en, label_es, strong terms (3 pts), weak terms (1 pt))
IND = {
 "health": ("Health / medical", "Salud / medicina", "patient patients paciente pacientes fhir hl7 dicom ehr emr telemedicine telehealth prescription receta diagnosis diagnostico clinic clinica hospital pharmacy farmacia icd10 hipaa medication triage".split(), "doctor medico medical health salud appointment cita nurse enfermera wellness therapy terapia dental vaccine lab laboratory".split()),
 "fintech": ("Fintech / banking / payments", "Fintech / banca / pagos", "ledger iban swift kyc aml wallet billetera remittance openbanking pix spei plaid stripe adyen mercadopago payout settlement chargeback reconciliation psd2 sepa ach fintech banking".split(), "payment payments pago pagos loan prestamo credit credito bank banco transfer transferencia transaction card tarjeta balance saldo invoice".split()),
 "insurance": ("Insurance", "Seguros", "underwriting actuarial insurer aseguradora policyholder claims siniestro poliza premium reinsurance".split(), "insurance seguro policy claim coverage cobertura".split()),
 "ecommerce": ("E-commerce / retail", "E-commerce / retail", "checkout carrito shopify woocommerce magento prestashop sku coupon cupon storefront catalog catalogo".split(), "cart product producto order pedido inventory stock shipping envio discount descuento wishlist store tienda".split()),
 "marketplace": ("Marketplace", "Marketplace", "marketplace seller vendedor buyer comprador commission comision escrow".split(), "vendor listing offer oferta rating review".split()),
 "business": ("Business / ERP / CRM", "Negocio / ERP / CRM", "erp crm payroll nomina accounting contabilidad purchaseorder supplier proveedor bookkeeping facturacion cfdi sunat afip dian".split(), "invoice factura customer cliente lead quote cotizacion inventory employee empleado department sales ventas report".split()),
 "education": ("Education / e-learning", "Educación / e-learning", "lms elearning classroom gradebook syllabus curriculum scorm moodle".split(), "student estudiante alumno teacher profesor course curso lesson leccion quiz exam grade school escuela university".split()),
 "logistics": ("Logistics / delivery / fleet", "Logística / reparto / flotas", "shipment courier fleet waybill dispatch warehouse almacen tracking telematics lastmile".split(), "delivery entrega driver conductor route ruta cargo package paquete pickup".split()),
 "realestate": ("Real estate / proptech", "Inmobiliaria / proptech", "proptech landlord mortgage hipoteca realtor lease arrendamiento inmueble".split(), "property propiedad listing tenant broker rent alquiler apartment".split()),
 "travel": ("Travel / hospitality", "Viajes / hotelería", "itinerary booking reservation hotel airline pms gds checkin".split(), "flight vuelo room habitacion trip viaje tour guest huesped".split()),
 "food": ("Food / restaurant", "Comida / restaurantes", "restaurant restaurante pos kitchen cocina menu recipe receta ubereats".split(), "table mesa waiter mesero food comida delivery".split()),
 "hr": ("HR / recruiting", "RR. HH. / reclutamiento", "ats recruiting recruitment applicant candidate resume cv payslip timesheet".split(), "employee job vacante empleo hiring onboarding vacation".split()),
 "legal": ("Legal / government", "Legal / gobierno", "lawyer abogado court tribunal notary notario govtech citizen ciudadano permit licencia expediente".split(), "case caso contract contrato compliance legal law".split()),
 "media": ("Media / social / community", "Medios / social / comunidad", "follower feed timeline newsletter podcast streaming playlist livestream moderation".split(), "post comment like share chat message mensaje profile perfil community video".split()),
 "gaming": ("Gaming", "Videojuegos", "unity godot unreal leaderboard matchmaking gameplay sprite tilemap".split(), "player jugador level nivel score puntaje game juego quest".split()),
 "iot": ("IoT / embedded / hardware", "IoT / embebidos / hardware", "mqtt firmware arduino esp32 raspberry sensor telemetry modbus zigbee lorawan plc scada".split(), "device dispositivo gpio embedded microcontroller".split()),
 "ai": ("AI / LLM / machine learning", "IA / LLM / machine learning", "openai anthropic langchain llamaindex llama embedding embeddings rag pinecone chroma huggingface transformers pytorch tensorflow sklearn scikit gpt llm".split(), "prompt model dataset training inference neural vector".split()),
 "bot": ("Bot / chatbot", "Bot / chatbot", "telegraf grammy discordjs whatsapp twilio rasa botpress dialogflow botframework slackbolt chatbot nlu intent".split(), "bot webhook telegram discord slack command comando".split()),
 "automation": ("Automation / workflow / scraping", "Automatización / workflows / scraping", "n8n zapier airflow celery rpa scrapy cheerio cron workflow orchestration automation automatizacion scraper scraping".split(), "puppeteer playwright selenium scheduler job queue worker pipeline etl task schedule".split()),
 "analytics": ("Analytics / BI / data", "Analítica / BI / datos", "dbt bigquery snowflake redshift superset metabase grafana etl datawarehouse olap".split(), "dashboard metrics analytics pandas report kpi warehouse".split()),
 "web3": ("Crypto / Web3", "Cripto / Web3", "solidity hardhat foundry ethers web3 wagmi anchor nft erc20 erc721 defi dao".split(), "wallet token contract blockchain staking".split()),
 "cms": ("CMS / content / blog", "CMS / contenido / blog", "wordpress strapi contentful ghost sanity drupal joomla headless".split(), "blog article articulo page post cms".split()),
}
# SaaS signals (categories) - a SaaS needs billing OR multi-tenancy plus other categories
SAAS = {
 "multi-tenancy": "tenant tenants tenant_id workspace workspaces organization organizations organisation org_id team teams account_id".split(),
 "billing": "subscription subscriptions plan plans billing stripe paddle lemonsqueezy chargebee seats seat trial pricing invoice invoices".split(),
 "auth": "oauth sso saml oidc rbac roles permissions auth0 clerk jwt login signup".split(),
 "api": "apikey apikeys webhook webhooks ratelimit".split(),
 "admin": "admin backoffice dashboard onboarding".split(),
}
FE_NAMES = {"react": "React", "vue": "Vue", "svelte": "Svelte", "@angular/core": "Angular", "next": "Next.js", "nuxt": "Nuxt", "astro": "Astro", "solid-js": "Solid", "preact": "Preact", "@remix-run/react": "Remix", "gatsby": "Gatsby", "htmx.org": "htmx"}
TOKEN = re.compile(r"[A-Za-z][a-z]{2,}|[A-Z]{3,}(?![a-z])|[a-z]{3,}")
CODE_EXT = {"py", "js", "jsx", "ts", "tsx", "php", "java", "kt", "go", "rb", "cs", "rs", "swift", "dart", "vue", "svelte", "sql", "prisma", "ex", "scala"}
SKIP = re.compile(r"(^|/)(node_modules|vendor|\.git|dist|build|\.next|__pycache__|venv|\.venv|coverage|target)(/|$)")
NON_PRODUCT = re.compile(r"(^|/)(examples?|samples?|fixtures?|demos?|docs?|tests?|__tests__|test-?data|testdata|e2e)(/|$)", re.I)


def _tok(s):
    out = []
    for w in TOKEN.findall(re.sub(r"(?<=[a-z])(?=[A-Z])", " ", s)): out.append(w.lower())
    return out


def _read(ab, cap=8000):
    try:
        with open(ab, encoding="utf-8", errors="ignore") as fh: return fh.read(cap)
    except OSError: return ""


def _gather(root, files):
    """-> {source: Counter(tokens)} with sources: path, deps, readme, schema, code."""
    pf = [f for f in files if not SKIP.search(f[0]) and not NON_PRODUCT.search(f[0])] or [f for f in files if not SKIP.search(f[0])]
    src = {k: Counter() for k in ("path", "deps", "readme", "schema", "code")}
    for rel, ab, ext, sz in pf[:6000]:
        for t in set(_tok(rel.rsplit(".", 1)[0])): src["path"][t] += 1
    base_names = {"package.json", "composer.json", "requirements.txt", "pyproject.toml", "pom.xml", "build.gradle", "build.gradle.kts", "go.mod", "Cargo.toml", "Gemfile", "pubspec.yaml", "Pipfile"}
    for rel, ab, ext, sz in pf:
        b = os.path.basename(rel)
        if b in base_names and rel.count("/") <= 3:
            t = _read(ab, 60000)
            if b == "package.json":
                m = re.search(r'"description"\s*:\s*"([^"]*)"', t); n = re.search(r'"name"\s*:\s*"([^"]*)"', t)
                for x in (m.group(1) if m else "", n.group(1) if n else ""): src["readme"].update(_tok(x))
                t = re.sub(r'"(description|keywords|name|author)"[^\n]*', "", t)
            src["deps"].update(_tok(t))
        elif b.lower() in ("readme.md", "readme.rst", "readme.txt", "readme") and rel.count("/") <= 1:
            src["readme"].update(_tok(_read(ab, 6000)))
        elif ext in ("sql", "prisma") or (ext == "py" and b in ("models.py",)) or re.search(r"(^|/)(entities|models|migrations?|schema)(/|$)", rel.lower()):
            t = _read(ab, 30000)
            names = re.findall(r"(?i)create\s+table\s+(?:if\s+not\s+exists\s+)?[`\"\[]?[\w.]*?([A-Za-z_]\w*)[`\"\]]?|model\s+(\w+)\s*\{|class\s+(\w+)\s*\((?:models\.Model|db\.Model|Base)|(?:Schema::create|create_table)\(\s*['\":]+(\w+)|@Entity\(?[^)]*\)?\s*(?:export\s+)?class\s+(\w+)", t)
            for tup in names:
                for nm in tup:
                    if nm: src["schema"].update(_tok(nm))
            if ext in ("sql", "prisma"): src["schema"].update(_tok(" ".join(re.findall(r"^\s+[`\"]?([A-Za-z_]\w+)[`\"]?\s+(?:int|varchar|text|uuid|bigint|timestamp|decimal|boolean|serial|String|Int|DateTime)\b", t, re.M | re.I))))
    code = [f for f in pf if f[2] in CODE_EXT and 200 < f[3] < 400_000 and re.search(r"(^|/)(models?|entities|services?|controllers?|domain|handlers?|routes?|api|app|src|lib)(/|$)", f[0].lower())]
    for rel, ab, ext, sz in code[:260]: src["code"].update(set(_tok(_read(ab, 6000))))
    return src


def _score(src, strong, weak):
    """weighted score + evidence + number of distinct source types."""
    sc, ev, kinds = 0.0, [], set()
    weights = {"path": 2.0, "deps": 3.0, "readme": 2.0, "schema": 3.0, "code": 0.6}
    for term in strong + weak:
        w = 3 if term in strong else 1
        for k, wt in weights.items():
            n = src[k].get(term, 0)
            if n:
                add = w * wt * min(n, 3 if k == "code" else 2) / (1 if k != "code" else 3)
                sc += add; kinds.add(k)
                if len(ev) < 12 and (term, k) not in ev: ev.append((term, k))
    return sc, ev, kinds


def _conf(sc, kinds):
    if sc >= 14 and len(kinds) >= 3: return "high"
    if sc >= 8 and len(kinds) >= 2: return "medium"
    if sc >= 5 and len(kinds) >= 2: return "low"
    return None


def analyze(root, files, deps_text="", det=None, lang="en"):
    det = det or {"kinds": [], "evidence": {}}
    ev = det.get("evidence", {}); kinds = set(det.get("kinds", []))
    src = _gather(root, files)
    es = lang == "es"
    # ---------------- industries
    industries = []
    for iid, (len_, les, strong, weak) in IND.items():
        sc, evi, ks = _score(src, strong, weak)
        c = _conf(sc, ks)
        if c in ("high", "medium"): industries.append(dict(id=iid, label=les if es else len_, confidence=c, score=round(sc, 1), evidence=[f"{t} ({k})" for t, k in evi[:8]]))
    try:
        from . import domain as _dm
        dd = _dm.detect(files, deps_text)
    except Exception: dd = {"domains": [], "evidence": {}}
    dmap = {"fintech": "fintech", "banking": "fintech", "healthtech": "health", "ecommerce": "ecommerce", "marketplace": "marketplace"}
    for d in dd["domains"]:
        iid = dmap.get(d)
        if not iid: continue
        evd = [f"{k}: {', '.join(v[:3])} (domain)" for k, v in dd["evidence"].items() if k in ("payments", "banking", "health", "ecommerce", "marketplace")][:4]
        cur = next((i for i in industries if i["id"] == iid), None)
        if cur: cur["evidence"] = (evd + cur["evidence"])[:8]; cur["confidence"] = "high" if len(evd) >= 2 or cur["confidence"] == "high" else "medium"
        else: industries.append(dict(id=iid, label=IND[iid][1 if es else 0], confidence="high" if len(evd) >= 2 else "medium", score=10.0, evidence=evd))
    # web3/AI/bot/automation also follow technical evidence
    if "web3" in kinds and not any(i["id"] == "web3" for i in industries): industries.append(dict(id="web3", label=IND["web3"][1 if es else 0], confidence="high", score=20.0, evidence=[x for x in ev.get("web3", [])][:4]))
    order = {"high": 0, "medium": 1, "low": 2}
    industries.sort(key=lambda i: (order[i["confidence"]], -i["score"]))
    industries = industries[:3]
    # ---------------- SaaS
    cats = {}
    for cat, terms in SAAS.items():
        hits = [(t, k) for t in terms for k in ("path", "deps", "schema", "readme") if src[k].get(t)] + [(t, "code") for t in terms if src["code"].get(t, 0) >= 3]
        if hits: cats[cat] = hits[:4]
    dd_saas = "saas" in dd["domains"]
    saas = bool((("multi-tenancy" in cats or "billing" in cats) and len(cats) >= 3 and not ({"cli", "library"} & kinds and len(cats) < 4)) or (dd_saas and len(cats) >= 2))
    if dd_saas: cats.setdefault("domain detector", [(", ".join(dd["evidence"].get("saas", [])[:3]), "domain")])
    saas_ev = [f"{c}: " + ", ".join(f"{t} ({k})" for t, k in h) for c, h in cats.items()]
    # ---------------- technical shape
    arch = []
    def add(aid, en, es_, conf, evidence): arch.append(dict(id=aid, label=es_ if es else en, confidence=conf, evidence=[str(x) for x in evidence][:6]))
    names = {os.path.basename(f[0]) for f in files if f[0].count("/") <= 3}
    low = [f[0].lower() for f in files if not SKIP.search(f[0])][:8000]
    exts = Counter(f[2] for f in files)
    if saas: add("saas", "SaaS (multi-tenant / subscription product)", "SaaS (multi-tenant / producto por suscripción)", "high" if len(cats) >= 4 else "medium", saas_ev)
    if "backend" in kinds: add("backend", "Backend / API", "Backend / API", "high", ev.get("backend", []))
    if "frontend" in kinds:
        fw = sorted({FE_NAMES[m] for m in FE_NAMES if re.search(r'"%s"' % re.escape(m), deps_text)})
        add("frontend", "Frontend / SPA" + (f" ({', '.join(fw)})" if fw else ""), "Frontend / SPA" + (f" ({', '.join(fw)})" if fw else ""), "high", ev.get("frontend", []))
    if "web" in kinds: add("web", "Website / web pages (SEO applies)", "Sitio web / páginas públicas (aplica SEO)", "high", ev.get("web", []))
    if "pwa" in kinds: add("pwa", "PWA (installable web app)", "PWA (app web instalable)", "high", ev.get("pwa", []))
    if "mobile" in kinds: add("mobile", "Mobile app (" + ", ".join(ev.get("mobile", [])) + ")", "App móvil (" + ", ".join(ev.get("mobile", [])) + ")", "high", ev.get("mobile", []))
    if "database" in kinds: add("database", "Database / schema", "Base de datos / esquema", "high", ev.get("database", []))
    if "web3" in kinds: add("web3", "Smart contracts / dApp", "Contratos inteligentes / dApp", "high", ev.get("web3", []))
    if "infra" in kinds: add("infra", "Infrastructure as code (" + ", ".join(ev.get("infra", [])) + ")", "Infraestructura como código (" + ", ".join(ev.get("infra", [])) + ")", "medium", ev.get("infra", []))
    if re.search(r'"(electron|@tauri-apps/api|nw)"', deps_text) or "tauri.conf.json" in names or "wails.json" in names: add("desktop", "Desktop app", "App de escritorio", "high", ["electron/tauri/wails"])
    if "manifest.json" in names and any(re.search(r'"manifest_version"\s*:\s*[23]', _read(f[1], 4000)) for f in files if os.path.basename(f[0]) == "manifest.json" and f[0].count("/") <= 3): add("extension", "Browser extension", "Extensión de navegador", "high", ["manifest.json (manifest_version)"])
    if exts.get("ipynb", 0) or re.search(r"\b(torch|tensorflow|scikit-learn|sklearn|keras|xgboost|jupyter|pandas)\b", deps_text): add("data-ml", "Data / ML project", "Proyecto de datos / ML", "medium", [f"{exts.get('ipynb', 0)} notebooks"] if exts.get("ipynb") else ["ML libraries"])
    if any(n in names for n in ("serverless.yml", "serverless.yaml", "wrangler.toml", "netlify.toml", "template.yaml", "sam.yaml")) or any(r.startswith(("netlify/functions", "functions/", "api/")) for r in low): add("serverless", "Serverless functions", "Funciones serverless", "medium", ["serverless config / functions folder"])
    svc = {os.path.dirname(f[0]).split("/")[0] for f in files if os.path.basename(f[0]) in ("package.json", "pyproject.toml", "go.mod", "pom.xml", "composer.json", "Dockerfile") and f[0].count("/") == 1 and not NON_PRODUCT.search(f[0])}
    compose = [f for f in files if os.path.basename(f[0]).startswith(("docker-compose", "compose.")) and f[0].count("/") <= 1]
    n_compose = sum(len(re.findall(r"(?m)^\s{2}[\w-]+:\s*$", _read(f[1], 20000).split("services:", 1)[-1])) for f in compose[:1]) if compose else 0
    if len(svc) >= 3 or n_compose >= 4: add("microservices", "Microservices / multi-service", "Microservicios / multi-servicio", "medium", [f"{len(svc)} service folders" if len(svc) >= 3 else f"docker-compose with ~{n_compose} services"])
    if "pnpm-workspace.yaml" in names or "lerna.json" in names or "nx.json" in names or "turbo.json" in names or re.search(r'"workspaces"\s*:', deps_text): add("monorepo", "Monorepo (workspaces)", "Monorepo (workspaces)", "high", ["workspaces config"])
    cli = bool(re.search(r"(?m)^\s*\[project\.scripts\]|console_scripts|\"bin\"\s*:|\[\[bin\]\]|\bcobra\b|\bclap\b|\bclick\b|\btyper\b|\bcommander\b|\byargs\b|\boclif\b", deps_text)) or any(r.startswith(("bin/", "cmd/")) for r in low)
    if cli and not ({"frontend", "web", "mobile"} & kinds): add("cli", "CLI / command-line tool", "Herramienta CLI", "medium", ["bin/ or CLI framework"])
    lib = bool(re.search(r'"(main|exports|module)"\s*:', deps_text) and not ({"backend", "frontend", "mobile", "web"} & kinds)) or ("setup.py" in names and not ({"backend", "frontend"} & kinds))
    if lib and "cli" not in {a["id"] for a in arch} and not saas: add("library", "Library / SDK / package", "Librería / SDK / paquete", "medium", ["package entry points"])
    # bot / automation by technical evidence (independent of industry words)
    if re.search(r"\b(telegraf|grammy|discord\.js|discord\.py|python-telegram-bot|aiogram|slack[_-]bolt|@slack/bolt|botbuilder|whatsapp-web\.js|twilio)\b", deps_text, re.I): add("bot", "Bot (chat/messaging)", "Bot (chat/mensajería)", "high", ["bot framework dependency"])
    if re.search(r"\b(n8n|apache-airflow|celery|scrapy|node-cron|apscheduler|bullmq|bull)\b", deps_text, re.I) and not ({"frontend"} & kinds and not {"backend"} & kinds): add("automation", "Automation / jobs / scraping", "Automatización / tareas / scraping", "medium", ["scheduler/queue/scraper dependency"])
    ids = {a["id"] for a in arch}
    full = {"backend", "frontend"} <= ids and ({"mobile", "pwa", "database"} & ids) and len({"backend", "frontend", "mobile", "pwa", "database", "web3", "infra"} & ids) >= 3
    # headline
    SHORT = {"backend": "Backend/API", "frontend": "Frontend", "web": "Web", "pwa": "PWA", "mobile": "Mobile", "database": "DB", "web3": "Smart contracts", "desktop": "Desktop"}
    def lab(i): return next((a["label"].split(" (")[0] for a in arch if a["id"] == i), "")
    parts = [SHORT[i] for i in ("backend", "frontend", "web", "pwa", "mobile", "database", "web3", "desktop") if i in ids]
    head_parts = []
    if saas: head_parts.append("SaaS")
    if full: head_parts.append(("Full-stack (" if not es else "Full-stack (") + " + ".join(parts[:6]) + ")")
    elif parts: head_parts.append(" + ".join(parts[:4]))
    for extra in ("microservices", "serverless", "monorepo", "bot", "automation", "data-ml", "cli", "library", "extension"):
        if extra in ids: head_parts.append(lab(extra))
    focus = ", ".join(f"{i['label']} ({i['confidence']})" for i in industries)
    headline = " · ".join(head_parts) or ("Sin clasificar" if es else "Unclassified")
    summary = headline + ((" — " + ("enfoque: " if es else "focus: ") + focus) if focus else "")
    return dict(summary=summary, headline=headline, architecture=arch, industry=industries, saas=saas, fullstack=bool(full),
                flags=dict(saas=saas, fullstack=bool(full), backend="backend" in ids, frontend="frontend" in ids, web="web" in ids, pwa="pwa" in ids, mobile="mobile" in ids, database="database" in ids))
