"""Domain deep-dive for SaaS / enterprise, fintech, banking, health-tech and e-commerce codebases.
Static heuristics: multi-tenant isolation, money handling, idempotency, atomicity/races, webhook authenticity, PCI data, audit trails,
RBAC/SSO, key management, resilience of payment-provider calls. Produces findings + a domain scorecard (used by compliance mapping)."""
import re
from collections import Counter

from .kb import KB

SIG = {
 "payments": r"stripe|adyen|braintree|plaid|dwolla|paypal|mercadopago|payu|razorpay|checkout\.com|squareup|@square|wise|mollie|klarna|authorize\.net|flutterwave|paystack|openpay|conekta|wompi|culqi|pagseguro|iugu",
 "banking": r"\biban\b|swift[_-]?(bic|code|net|message)|\bmt103\b|\bsepa\b|\bach\b|iso[-_ ]?20022|open[-_ ]?banking|account_number|routing_number|wire[_ ]transfer|core[-_ ]?banking|ledger|double[-_ ]?entry|\bkyc\b|\baml\b|sanction|ofac|treasury|reconcil",
 "saas": r"tenant|workspace_id|organization_id|org_id|multi[-_ ]?tenan|subscription|\bplan[_ ]id|seats?\b|entitlement|billing|invoice|scim|\bsaml\b|\boidc\b|sso\b",
 "health": r"\bfhir\b|\bhl7\b|\bphi\b|patient|medical|ehr\b|dicom|clinical",
 "ecommerce": r"\bcart\b|checkout|\border_items?\b|shopify|woocommerce|magento|sku\b|inventory",
 "marketplace": r"payout|connected[_ ]account|marketplace|escrow|split[_ ]payment|stripe[_ ]connect",
}
SRC = {"py", "js", "jsx", "ts", "tsx", "php", "java", "kt", "go", "rb", "cs", "rs", "ex", "scala", "sql", "prisma", "vue", "svelte", "yml", "yaml", "tf", "xml", "swift", "dart"}
TENANT_COL = r"(tenant_id|tenantid|org_id|organization_id|organisation_id|workspace_id|account_id|company_id|team_id|customer_id)"


def detect(files, deps_text):
    low = deps_text.lower(); names = " ".join(r.lower() for r, *_ in files)
    out = {}
    for k, rx in SIG.items():
        hit = re.findall(rx, low) + re.findall(rx, names)
        if k == "saas": hit = [h for h in hit if h not in ("plan_id",)]
        if len(hit) >= (1 if k in ("payments", "health") else 2): out[k] = sorted(set(hit))[:5]
    doms = []
    if "payments" in out or "banking" in out: doms.append("fintech" if "banking" not in out else "banking")
    if "saas" in out: doms.append("saas")
    for k in ("health", "ecommerce", "marketplace"):
        if k in out: doms.append({"health": "healthtech"}.get(k, k))
    if "payments" in out and "banking" in out: doms = [d for d in doms if d != "fintech"] + ["fintech"]
    return dict(domains=list(dict.fromkeys(doms)), evidence=out)


def _f(rule, title, typ, sev, cat, file, line, ev, fix, effort, fam="domain-fin", status="confirmed", priority=None, why=None, cwe=(), owasp=()):
    kb = KB[fam]
    return dict(rule=rule, title=title, family=fam, type=typ, severity=sev if status == "confirmed" else None, category=cat, file=file, line=line, evidence=ev[:400], impact=kb["impact"], fix=fix, effort_min=effort, cwe=list(cwe), owasp=list(owasp), status=status, priority=priority, why=why)


def analyze(root, files, deps_text, det, has_ratelimit=False):
    out, items = [], []
    doms = set(det["domains"]); fin = bool(doms & {"fintech", "banking"}); saas = "saas" in doms
    if not doms: return out, {}
    texts = {}
    for rel, ab, e, sz in files:
        if e in SRC and sz < 400_000 and not re.search(r"(^|/)(node_modules|vendor|dist|build|tests?|__tests__|spec|fixtures?|mocks?)(/|$)|\.(test|spec)\.", rel):
            try: texts[rel] = open(ab, errors="ignore").read()
            except OSError: pass
    blob = (deps_text + "\n" + "\n".join(texts.values())).lower()
    has = lambda rx: bool(re.search(rx, blob))
    def add(dim, id, title, ok, why, how, w=2, when=True):
        if when: items.append(dict(dim=dim, id=id, title=title, ok=bool(ok), why=why, how=how, w=w))
    # ─────────── fintech / banking ───────────
    if fin:
        fl = Counter(); first = {}
        for rel, t in texts.items():
            for m in re.finditer(r"(?i)\b(price|amount|total|balance|fee|tax|cost|subtotal|payment|salary|rate|interest|principal|commission|payout|refund)\w*\s*(?:=|:=|\+=|-=|\*=)\s*[^;\n]*(?:\bfloat\s*\(|parseFloat\(|Number\(|\(float\)|\bdouble\b|\bfloat\b|\b\d+\.\d+\b\s*\*|\*\s*\d+\.\d+|/\s*100\.0\b|\.toFixed\()", t):
                fl[rel] += 1; first.setdefault(rel, t[:m.start()].count("\n") + 1)
            for m in re.finditer(r"(?i)\b(?:double|float)\s+(price|amount|total|balance|fee|tax|cost|payment)\w*", t): fl[rel] += 1; first.setdefault(rel, t[:m.start()].count("\n") + 1)
        for rel, n in fl.most_common(15): out.append(_f("FIN-FLOAT-MONEY", f"Floating-point arithmetic on money in `{rel}` ({n} place(s))", "bug", "high", "money", rel, first[rel], "float/double used for currency values", "Use integer minor units (cents) or Decimal/BigDecimal; round explicitly with a defined mode (banker's/half-up) at the edges", 30 * min(n, 4), cwe=["CWE-681"]))
        pay_files = [r for r, t in texts.items() if re.search(r"(?i)(charge|payment|transfer|payout|refund|withdraw|deposit|capture|debit|credit)\w*\s*\(|/(charge|payments?|transfers?|payouts?|refunds?|withdraw|deposit)s?\b", t) and re.search(r"(?i)(route|router|app\.(post|put)|@(post|put)mapping|controller|handler|endpoint|api)", r + t[:3000])]
        idem = has(r"idempoten")
        for rel in pay_files[:12]:
            t = texts[rel]
            if not re.search(r"(?i)idempoten", t): out.append(_f("FIN-NO-IDEMPOTENCY", f"Money-moving handler without idempotency in `{rel}`", "security_hotspot", None, "money", rel, 1, "no Idempotency-Key / unique request id handling found in this file", "Require an Idempotency-Key per request, store (key → result) with a unique constraint, return the stored result on retry; pass idempotency keys to the PSP", 90, status="needs_validation", priority="high", why="idempotency may be enforced by middleware or the provider SDK - verify retries cannot double-charge"))
        for rel, t in texts.items():
            m = re.search(r"(?is)(if\s*\(?[^\n]{0,60}(balance|available|funds)[^\n]{0,40}(>=|>|<|<=)[^\n]{0,60}(amount|total)[^\n]{0,40}\)?:?\s*\{?[^\n]*\n(?:[^\n]*\n){0,8}?[^\n]*(balance|funds)\w*\s*(-=|=\s*[^\n]*-)|balance\w*\s*=\s*(?:\w+\.)?balance\w*\s*[-+])", t)
            if m and not re.search(r"(?i)for update|lockforupdate|with_for_update|select_for_update|@transactional|transaction\.atomic|\.transaction\(|beginTransaction|BEGIN;|serializable|mutex|redlock|advisory|optimistic|version\s*=|row_version|compare.and.swap|FOR NO KEY", t):
                out.append(_f("FIN-RACE-BALANCE", f"Check-then-update on a balance without a lock/transaction in `{rel}` (double-spend race)", "security_hotspot", None, "money", rel, t[:m.start()].count("\n") + 1, t[m.start():m.start() + 200].replace("\n", " "), "Do it atomically: `UPDATE accounts SET balance = balance - :amt WHERE id=:id AND balance >= :amt` (check rows affected) inside a transaction, or SELECT … FOR UPDATE / optimistic versioning", 120, status="needs_validation", priority="high", why="locking may happen in a caller or the DB layer - prove it with a concurrent test (50 parallel withdrawals)", cwe=["CWE-362"]))
        wh = [r for r in texts if re.search(r"webhook", r, re.I)] + [r for r, t in texts.items() if re.search(r"(?i)(post|route|router)[^\n]{0,60}webhooks?\b", t)]
        verify = has(r"construct_event|constructevent|verify_?signature|stripe-signature|x-hub-signature|x-signature|svix|hmac|compare_digest|timingsafeequal|verifywebhook|checksignature|paypal-transmission-sig|x-adyen|notificationrequestitem.*hmac")
        for rel in sorted(set(wh))[:6]:
            if not re.search(r"(?i)construct_event|constructevent|verify|signature|hmac|compare_digest|timingsafeequal|svix", texts.get(rel, "")):
                out.append(_f("FIN-WEBHOOK-UNSIGNED", f"Payment webhook handler without signature verification in `{rel}`", "vulnerability" if not verify else "security_hotspot", "high" if not verify else None, "money", rel, 1, "no signature/HMAC verification token in this file", "Verify the provider signature over the RAW body with a constant-time compare, reject old timestamps, and make the handler idempotent (store event ids)", 60, status="confirmed" if not verify else "needs_validation", priority="high", why=None if not verify else "verification exists elsewhere in the project - confirm it covers this route", cwe=["CWE-345"], owasp=["A08:2021"]))
        add("Money", "fin_decimal", "Money uses integer minor units or Decimal (no floats)", not any(f["rule"] == "FIN-FLOAT-MONEY" for f in out) and has(r"decimal|bigdecimal|bignumber|big\.js|dinero|currency\.js|minor[_ ]unit|cents|money\b|moneyphp|joda-money"), "Floats lose cents (0.1+0.2); totals drift and reconciliation breaks.", "Store cents as integers or DECIMAL; use Decimal/BigDecimal/dinero.js; define rounding rules.", 4)
        add("Money", "fin_idem", "Idempotency keys on money-moving endpoints", idem and not any(f["rule"] == "FIN-NO-IDEMPOTENCY" for f in out), "Network retries otherwise charge customers twice.", "Idempotency-Key header + unique (key) table; forward keys to the PSP.", 4)
        add("Money", "fin_atomic", "Balance changes are atomic (transactions/locks)", has(r"for update|lockforupdate|with_for_update|select_for_update|@transactional|transaction\.atomic|beginTransaction|\.transaction\(|serializable|advisory[_ ]lock") and not any(f["rule"] == "FIN-RACE-BALANCE" for f in out), "Concurrent requests can overspend a balance.", "Single UPDATE with guard + transaction; run a parallel-withdrawal test.", 4)
        add("Money", "fin_ledger", "Append-only double-entry ledger / immutable audit trail", has(r"double[-_ ]?entry|ledger|journal[_ ]entr|append[-_ ]only|event[-_ ]sourc"), "Banks must explain every cent; mutable balances can't be audited.", "Record every movement as immutable debit+credit entries; derive balances; add invariants (sum of entries = 0).", 3)
        add("Money", "fin_recon", "Reconciliation job against the provider/bank", has(r"reconcil"), "Provider and internal records drift without daily reconciliation.", "Nightly job comparing PSP/bank settlement files with the ledger; alert on differences.", 2)
        add("Payments", "fin_webhook", "Webhooks are signature-verified and idempotent", verify and not any(f["rule"] == "FIN-WEBHOOK-UNSIGNED" and f["status"] == "confirmed" for f in out), "Unsigned webhooks let anyone mark orders as paid.", "Verify signatures on the raw body; store processed event ids.", 4, bool(wh) or has(r"stripe|adyen|braintree|paypal"))
        add("Payments", "fin_pci", "Card data is handled by the provider (hosted fields), never stored", has(r"stripe\.js|elements|payment[_ ]?intent|checkout\.session|adyen.*drop-?in|braintree.*hosted|paypal.*(buttons|smart)|hosted[_ ]fields|tokeniz") and not has(r"\bcvv|\bcvc|card_?number\s*(?:=|:|varchar)"), "Storing PAN/CVV puts your whole stack in PCI scope (and CVV storage is forbidden).", "Use provider-hosted fields / tokens; store only token + last4 + brand.", 5, has(r"stripe|adyen|braintree|paypal|square|checkout\.com|authorize\.net|card"))
        add("Payments", "fin_resilience", "Provider calls have timeouts, retries with backoff and circuit breaking", has(r"retry|backoff|tenacity|axios-retry|resilience4j|polly|circuit[_ ]?breaker|opossum|cockatiel") and "DOS-NO-TIMEOUT" not in {f["rule"] for f in out}, "Payment APIs time out; naive retries duplicate charges, no retries lose orders.", "Timeouts + bounded exponential backoff + idempotency + dead-letter queue.", 3)
        add("Risk", "fin_mfa", "Strong authentication / step-up (MFA, WebAuthn, OTP) for sensitive actions", has(r"\bmfa\b|2fa|totp|webauthn|passkey|fido2|otp|step[-_ ]?up|authenticator|duo|authy"), "PSD2/SCA, FFIEC and NYDFS expect MFA and transaction authentication.", "TOTP/WebAuthn at login and step-up for transfers, payee changes, credential changes.", 4)
        add("Risk", "fin_limits", "Limits, velocity checks and fraud signals", has(r"velocity|fraud|risk[_ ]?score|sift\b|signifyd|kount|daily[_ ]limit|transaction[_ ]limit|spend[_ ]limit|riskified|feedzai"), "Account takeover and card testing drain accounts in minutes.", "Per-user/IP/device velocity limits, daily caps, anomaly alerts, manual review queue.", 3)
        add("Risk", "fin_kyc", "KYC/AML provider or documented process", has(r"onfido|sumsub|persona\b|veriff|jumio|complyadvantage|trulioo|idnow|kyc|aml"), "Regulated activity requires identity verification and sanctions screening.", "Integrate a KYC/AML provider; keep decisions and evidence for 5+ years.", 2, "banking" in doms or has(r"kyc|aml|sanction|ofac"))
        add("Data", "fin_kms", "Keys/secrets in KMS/HSM/secret manager; field-level encryption for sensitive data", has(r"\bkms\b|hashicorp|vault\b|secretsmanager|secret[_ ]manager|keyvault|cloudhsm|hsm\b|sops|doppler|aws-sdk.*kms|tink|libsodium"), "Banks and PCI require managed keys and separation of duties.", "Use KMS/Vault, envelope encryption, rotation; never keys in env files in prod.", 3)
        add("Data", "fin_iban", "Bank identifiers (IBAN/SWIFT/routing) are validated with a library", has(r"schwifty|ibantools|php-iban|iban\.js|python-stdnum|iso-?3166|swift[_-]?bic|bic[_-]?validator|ibanvalidator|luhn"), "Bad account numbers cause failed/misrouted payments.", "Validate IBAN/BIC/routing checksums; normalize before storing.", 1, has(r"\biban\b|\bswift\b|routing_number|account_number"))
        for rel, t in texts.items():
            for m in re.finditer(r"(?i)\b(?:log|logger|console|print|println|error_log|Log)\w*[.(][^\n]{0,80}\b(card_?number|cardnumber|cvv|cvc|iban|account_?number|ssn|tax_?id|routing_?number|pan)\b", t):
                out.append(_f("FIN-PII-LOG", "Financial/personal identifiers written to logs", "vulnerability", "high", "privacy", rel, t[:m.start()].count("\n") + 1, t[m.start():m.end()].replace("\n", " ")[:160], "Never log PAN/CVV/IBAN/SSN; mask (last4) or tokenize; add a log-redaction filter", 15, cwe=["CWE-532"], owasp=["A09:2021"])); break
    # ─────────────── SaaS / multi-tenant ───────────────
    if saas or fin:
        tcols = Counter(); ttables = {}
        for rel, t in texts.items():
            if rel.endswith((".sql", ".prisma", ".php", ".py", ".rb", ".ts", ".js", ".kt", ".java", ".cs", ".go")) and re.search(r"(?i)create table|schema::create|\bmodel\s+\w+\s*\{|migrations\.|create_table|@entity|class\s+\w+\(.*(models\.model|base)\)", t):
                for m in re.finditer(r"(?is)create\s+table\s+(?:if\s+not\s+exists\s+)?[`\"\[]?(\w+)[`\"\]]?\s*\((.*?)\)\s*(?:;|engine|$)", t):
                    c = re.search(TENANT_COL, m.group(2), re.I)
                    if c: ttables[m.group(1).lower()] = c.group(1).lower(); tcols[c.group(1).lower()] += 1
                for m in re.finditer(r"(?is)Schema::create\(\s*['\"](\w+)['\"].*?\}\);", t):
                    c = re.search(TENANT_COL, m.group(0), re.I)
                    if c: ttables[m.group(1).lower()] = c.group(1).lower(); tcols[c.group(1).lower()] += 1
                for m in re.finditer(r"(?is)\bmodel\s+(\w+)\s*\{(.*?)\n\}", t):
                    c = re.search(r"\b(tenantId|orgId|organizationId|workspaceId|accountId|companyId|teamId)\b", m.group(2))
                    if c: ttables[m.group(1).lower()] = c.group(1).lower(); tcols[c.group(1).lower()] += 1
        multi = bool(tcols) or has(r"multi[-_ ]?tenan|tenant")
        rls = has(r"enable row level security|create policy|set_config\(\s*'app\.|row[_ ]level[_ ]security|app\.current_tenant|\brls\b")
        scope = has(r"belongstotenant|tenantscope|global[_ ]?scope|tenant[_ ]?middleware|currenttenant|with_?tenant|tenant_?context|default_scope|acts_as_tenant|django[_-]tenants|hibernate.*tenant|@filter.*tenant|req\.tenant|ctx\.tenant|tenantid\s*=\s*req|extension.*tenant|prisma.*\$extends")
        raw_hits = 0
        for rel, t in texts.items():
            for m in re.finditer(r"(?is)\b(select\b[^;`\"']{0,400}?\bfrom\s+[`\"]?(\w+)[`\"]?|update\s+[`\"]?(\w+)[`\"]?\s+set\b|delete\s+from\s+[`\"]?(\w+)[`\"]?)([^;`\"']{0,300})", t):
                tbl = (m.group(2) or m.group(3) or m.group(4) or "").lower(); stmt = m.group(0)
                if tbl in ttables and not re.search(TENANT_COL, stmt, re.I) and not rel.endswith(("migration.sql", "schema.sql")) and "migrations" not in rel and raw_hits < 12:
                    raw_hits += 1
                    out.append(_f("SAAS-QUERY-NO-TENANT", f"Query on tenant-scoped table `{tbl}` without a `{ttables[tbl]}` filter", "vulnerability", "high", "tenant-isolation", rel, t[:m.start()].count("\n") + 1, stmt.replace("\n", " ")[:220], f"Always filter by `{ttables[tbl]}` from the authenticated context (not from user input); enforce with Postgres RLS or a global ORM scope so forgetting is impossible", 45, fam="domain-saas", cwe=["CWE-639", "CWE-284"], owasp=["A01:2021", "API1:2023"]))
        for rel, t in texts.items():
            for m in re.finditer(r"(?im)^\s*[`\"]?(api_?key|apikey|api_?secret|client_?secret|access_?token)[`\"]?\s+(varchar|text|char)", t):
                out.append(_f("SAAS-APIKEY-PLAIN", "API key/secret column stores raw values (should store a hash)", "security_hotspot", None, "key-management", rel, t[:m.start()].count("\n") + 1, m.group(0).strip()[:100], "Show the key once, store only a SHA-256/HMAC hash + prefix; scope keys per tenant/permission; allow rotation/revocation", 60, fam="domain-saas", status="needs_validation", priority="medium", why="column may already hold hashes - check the write path", cwe=["CWE-312"])); break
        add("Tenancy", "saas_isolation", "Tenant isolation is enforced centrally (RLS / global scope / tenant middleware)", rls or scope, "One forgotten WHERE clause leaks one customer's data to another - the worst SaaS incident.", "Postgres RLS with per-request `SET app.tenant`, or ORM global scopes; add cross-tenant IDOR tests for every endpoint.", 5, multi)
        add("Tenancy", "saas_queries", "No unscoped queries on tenant tables", not any(f["rule"] == "SAAS-QUERY-NO-TENANT" for f in out), "Unscoped raw SQL bypasses ORM scoping.", "Parameterize and include the tenant key; lint/grep for raw SQL in CI.", 4, bool(ttables))
        add("Tenancy", "saas_tests", "Cross-tenant access tests exist", has(r"cross[-_ ]?tenant|tenant[_ ]isolation|other[_ ]tenant|tenant_?b\b|tenant2|another[_ ]org"), "Isolation must be proven by tests, not assumed.", "For each resource: tenant A requests tenant B's id → expect 404/403.", 3, multi)
        add("Access", "saas_rbac", "Role/permission model (RBAC/ABAC) with a proven library", has(r"spatie/laravel-permission|casbin|cancancan|pundit|django-guardian|rbac|accesscontrol|oso\b|permit\.io|openfga|spicedb|cerbos|casl|role_?permission|policy"), "Enterprise customers expect roles, least privilege and per-resource policies.", "Central policy layer (Casbin/OpenFGA/Cerbos/policies); deny by default.", 3)
        add("Access", "saas_sso", "Enterprise SSO (SAML/OIDC) and SCIM provisioning", has(r"\bsaml\b|\boidc\b|openid|workos|auth0|okta|keycloak|scim|passport-saml|cognito|azure[_ ]?ad|entra"), "Large customers will not buy without SSO and automated deprovisioning.", "Add OIDC/SAML (WorkOS/Auth0/Keycloak) + SCIM; enforce MFA via the IdP.", 2, saas)
        add("Operations", "saas_audit", "Tenant-visible audit log of security-relevant events", has(r"audit[_ ]?(log|trail|event)|activity[_ ]?log|paper_trail|auditable|django-auditlog|laravel-activitylog|spatie/laravel-activitylog|audit_logs"), "Customers and auditors ask 'who did what, when'.", "Append-only audit table: actor, tenant, action, target, IP, time; export via API.", 3)
        add("Operations", "saas_export", "Data export and deletion (GDPR/CCPA) per tenant/user", has(r"data[_ ]export|export[_ ]data|delete[_ ]account|account[_ ]deletion|right[_ ]to[_ ]erasure|gdpr|dsar|purge[_ ]tenant|anonymi[sz]e"), "Privacy law and enterprise contracts require export/erasure within 30 days.", "Self-serve export (JSON/CSV) and deletion with retention rules and an audit trail.", 2, saas)
        add("Operations", "saas_backup", "Backups with point-in-time recovery and restore tests", has(r"point_in_time|pitr|backup_retention|retention_period|pg_dump|snapshot|wal-?g|barman|pgbackrest|automated_backup"), "RPO/RTO commitments in SLAs depend on tested restores.", "Enable PITR (RDS/Cloud SQL), cross-region copies, quarterly restore drill.", 3)
        add("Operations", "saas_ratelimit", "Per-tenant rate limits and quotas", has_ratelimit or has(r"rate[-_ ]?limit|throttle|quota"), "A noisy tenant must not degrade others (and abuse must be bounded).", "Per-tenant/API-key limits with 429 + Retry-After; quota metering.", 2)
        add("Operations", "saas_metering", "Entitlements/plan limits enforced server-side", has(r"entitlement|feature[_ ]?flag|plan[_ ]?limit|usage[_ ]?limit|seat[_ ]?limit|can\(.*plan|checkplan|requireplan|launchdarkly|unleash|growthbook|flagsmith"), "Client-side checks are trivially bypassed; revenue leaks.", "Check plan/seat limits in the API layer; test over-limit behavior.", 2, saas)
        add("Operations", "saas_webhooks_out", "Outbound webhooks are signed (HMAC), retried and idempotent", has(r"hmac|signature").__and__(has(r"webhook")) if has(r"webhook") else None, "Customers must be able to verify your events.", "Sign payloads (HMAC-SHA256 + timestamp), exponential retry, event ids.", 1, has(r"webhook"))
    # score
    keep = [i for i in items if True]
    return out, dict(domains=det["domains"], evidence=det["evidence"], tenant_tables=len(ttables) if (saas or fin) else 0, items=keep)


def scorecard(info):
    if not info or not info.get("items"): return None
    dims = {}
    for i in info["items"]:
        d = dims.setdefault(i["dim"], dict(items=[], w=0, got=0)); d["items"].append(i); d["w"] += i["w"]; d["got"] += i["w"] if i["ok"] else 0
    tot = sum(d["w"] for d in dims.values()) or 1; got = sum(d["got"] for d in dims.values())
    return dict(score=round(100 * got / tot), domains=info["domains"], evidence=info["evidence"], dimensions={k: dict(score=round(100 * v["got"] / (v["w"] or 1)), items=v["items"]) for k, v in dims.items()})
