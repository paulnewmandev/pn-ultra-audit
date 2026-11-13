"""API attack-surface audit from OpenAPI / Swagger / Postman files (static, read-only, stdlib only).

Instead of crawling a running API, the contract that is already in the repository is read: every operation, who can
call it, what it accepts and what it returns. Findings about missing authentication, sensitive fields accepted from
clients (mass assignment), credentials in query strings, plain-HTTP servers, unbounded lists and hard-coded tokens in
Postman collections. Contract-level facts that depend on intent are "needs_validation".

A small YAML subset reader is included (maps, lists, scalars, flow lists/maps, quotes, comments): enough for real-world
specs, no PyYAML needed. Anything it cannot parse is skipped with a note instead of guessed.
"""
import json, os, re

METHODS = ("get", "post", "put", "patch", "delete", "head", "options")
MUTATING = ("post", "put", "patch", "delete")
PUBLIC_PATH = re.compile(r"(?i)/(login|logout|signin|signup|sign-in|sign-up|register|auth|oauth|token|refresh|callback|health|healthz|ping|status|version|metrics|docs|openapi|swagger|webhooks?|public|forgot|reset|verify|confirm|csrf|\.well-known)(/|$|\{|\.)")
SENSITIVE_PROP = re.compile(r"(?i)^(is_?admin|admin|role|roles|permissions?|scopes?|is_?staff|is_?superuser|verified|is_?verified|email_?verified|balance|credits?|plan|tier|owner_?id|user_?id|tenant_?id|account_?id|org(anization)?_?id|workspace_?id|price|discount|status)$")
SECRET_QUERY = re.compile(r"(?i)^(password|passwd|pwd|secret|token|access_?token|api_?key|apikey|key|auth|authorization|session|sid|jwt)$")
PAGING = re.compile(r"(?i)^(limit|page|per_?page|page_?size|offset|cursor|after|before|size|take|skip|max|top|count)$")


# ───────────────────────── tiny YAML subset ─────────────────────────
def _scalar(s):
    s = s.strip()
    if s == "" or s in ("~", "null", "Null", "NULL"): return None
    if s in ("true", "True"): return True
    if s in ("false", "False"): return False
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'": return s[1:-1]
    if re.fullmatch(r"-?\d+", s): return int(s)
    if re.fullmatch(r"-?\d+\.\d+", s): return float(s)
    if (s.startswith("[") and s.endswith("]")) or (s.startswith("{") and s.endswith("}")):
        inner, parts, depth, cur, q = s[1:-1], [], 0, "", None
        for ch in inner:
            if q:
                if ch == q: q = None
            elif ch in "\"'": q = ch
            elif ch in "[{": depth += 1
            elif ch in "]}": depth -= 1
            if ch == "," and depth == 0 and not q: parts.append(cur); cur = ""
            else: cur += ch
        if cur.strip(): parts.append(cur)
        if s[0] == "[": return [_scalar(x) for x in parts]
        d = {}
        for x in parts:
            k, _, v = x.partition(":")
            d[k.strip().strip("\"'")] = _scalar(v)
        return d
    return s


def _strip_comment(line):
    out, q = [], None
    for i, ch in enumerate(line):
        if q:
            if ch == q: q = None
        elif ch in "\"'": q = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"): break
        out.append(ch)
    return "".join(out).rstrip()


def parse_yaml(text):
    raw = [(len(l) - len(l.lstrip(" ")), _strip_comment(l).strip()) for l in text.splitlines() if _strip_comment(l).strip() and not l.strip().startswith(("---", "..."))]
    pos = [0]

    def block(indent):
        if pos[0] >= len(raw): return None
        if raw[pos[0]][1].startswith("- ") or raw[pos[0]][1] == "-": return seq(raw[pos[0]][0])
        return mapping(raw[pos[0]][0])

    def mapping(indent):
        d = {}
        while pos[0] < len(raw):
            ind, ln = raw[pos[0]]
            if ind < indent or ln.startswith("- "): break
            if ind > indent: raise ValueError("indent")
            m = re.match(r"""("[^"]*"|'[^']*'|[^:]+?)\s*:(?:\s+(.*)|$)""", ln)
            if not m: raise ValueError("map")
            key = m.group(1).strip("\"'"); val = m.group(2)
            pos[0] += 1
            if val is None or val == "":
                if pos[0] < len(raw) and (raw[pos[0]][0] > indent or (raw[pos[0]][0] == indent and raw[pos[0]][1].startswith("- "))): d[key] = block(raw[pos[0]][0])
                else: d[key] = None
            elif val in ("|", ">", "|-", ">-"):
                while pos[0] < len(raw) and raw[pos[0]][0] > indent: pos[0] += 1
                d[key] = ""
            else: d[key] = _scalar(val)
        return d

    def seq(indent):
        a = []
        while pos[0] < len(raw):
            ind, ln = raw[pos[0]]
            if ind != indent or not (ln.startswith("- ") or ln == "-"): break
            rest = ln[1:].strip(); pos[0] += 1
            if not rest:
                a.append(block(raw[pos[0]][0]) if pos[0] < len(raw) and raw[pos[0]][0] > indent else None)
            elif re.match(r"""("[^"]*"|'[^']*'|[^:\[{]+?)\s*:(\s|$)""", rest):
                raw.insert(pos[0], (indent + 2, rest)); a.append(mapping(indent + 2))
            else: a.append(_scalar(rest))
        return a

    return block(raw[0][0]) if raw else None


# ───────────────────────── analysis ─────────────────────────
def _f(rule, title, sev, file, ev, impact, fix, effort=30, status="confirmed", priority=None, why=None, cwe=(), owasp=()):
    return dict(rule=rule, title=title, family="api-spec", type="vulnerability", severity=sev if status == "confirmed" else None, category="api", file=file, line=1, evidence=ev[:160],
                impact=impact, fix=fix, effort_min=effort, cwe=list(cwe), owasp=list(owasp), status=status, priority=priority if status != "confirmed" else None,
                why=why if status != "confirmed" else None)


def _resolve(doc, node, depth=0):
    while isinstance(node, dict) and "$ref" in node and isinstance(node["$ref"], str) and node["$ref"].startswith("#/") and depth < 8:
        cur = doc
        for part in node["$ref"][2:].split("/"):
            cur = cur.get(part.replace("~1", "/").replace("~0", "~")) if isinstance(cur, dict) else None
        node = cur; depth += 1
    return node


def _props(doc, schema, depth=0):
    schema = _resolve(doc, schema)
    out = {}
    if not isinstance(schema, dict) or depth > 4: return out
    for k, v in (schema.get("properties") or {}).items():
        out[k] = v
    for part in (schema.get("allOf") or []) + (schema.get("oneOf") or []) + (schema.get("anyOf") or []):
        out.update(_props(doc, part, depth + 1))
    return out


def analyze_openapi(doc, rel):
    out, info = [], dict(file=rel, operations=0, public=0, mutating=0, schemes=[])
    if not isinstance(doc, dict) or not isinstance(doc.get("paths"), dict): return out, info
    comps = doc.get("components") or {}
    schemes = comps.get("securitySchemes") or doc.get("securityDefinitions") or {}
    glob_sec = doc.get("security")
    info["schemes"] = sorted({str((v or {}).get("type", "?")) + (":" + str(v.get("scheme")) if (v or {}).get("scheme") else "") for v in schemes.values() if isinstance(v, dict)})
    for name, s in schemes.items():
        if not isinstance(s, dict): continue
        if s.get("type") == "apiKey" and s.get("in") == "query":
            out.append(_f("API-KEY-IN-QUERY", f"API key `{name}` is sent in the query string", "medium", rel, f"securityScheme {name}: apiKey in query", "URLs end up in access logs, browser history and Referer headers: the key leaks.", "Send the key in a header (`in: header`).", 30, cwe=["CWE-598"], owasp=["A02:2021"]))
        if s.get("type") == "http" and str(s.get("scheme", "")).lower() == "basic":
            out.append(_f("API-BASIC-AUTH", f"Scheme `{name}` uses HTTP Basic authentication", "low", rel, f"securityScheme {name}: http basic", "Static credentials sent on every request, no expiry or scoping.", "Prefer OAuth2/OIDC or short-lived bearer tokens; if Basic stays, enforce TLS and rotate.", 120, status="needs_validation", priority="low", why="Basic auth is acceptable for internal service-to-service calls over TLS."))
    for sv in (doc.get("servers") or []) if isinstance(doc.get("servers"), list) else []:
        u = str((sv or {}).get("url", ""))
        if u.startswith("http://") and not re.match(r"http://(localhost|127\.|0\.0\.0\.0|\[::1\]|host\.docker|.*\.local\b|\{)", u):
            out.append(_f("API-HTTP-SERVER", f"Server `{u}` is plain HTTP", "medium", rel, f"servers: url: {u}", "Tokens and data travel unencrypted and can be read or altered on the path.", "Serve the API over HTTPS only (and redirect/HSTS).", 30, cwe=["CWE-319"], owasp=["A02:2021"]))
    if not schemes and not glob_sec:
        out.append(_f("API-NO-AUTH-DEFINED", "The API contract defines no authentication at all", None, rel, "no securitySchemes / security", "Every operation is documented as public: clients, gateways and scanners assume no auth is required.", "Declare the scheme (bearer/OAuth2/apiKey) in `components.securitySchemes` and apply it with a global `security` list.", 60, status="needs_validation", priority="high", why="The auth may exist outside the contract (gateway); then document it in the spec."))
    no_paging, any429, ops = [], False, 0
    for path, item in doc["paths"].items():
        if not isinstance(item, dict): continue
        for meth in METHODS:
            op = _resolve(doc, item.get(meth))
            if not isinstance(op, dict): continue
            ops += 1; info["operations"] += 1; tag = f"{meth.upper()} {path}"
            sec = op.get("security", glob_sec)
            public = (sec == [] or sec is None or sec == [{}] ) and not (sec and any(sec))
            if meth in MUTATING: info["mutating"] += 1
            if public:
                info["public"] += 1
                if meth in MUTATING and not PUBLIC_PATH.search(path + "/") and (schemes or glob_sec is not None):
                    out.append(_f("API-OP-NO-AUTH", f"{tag} changes data and has no authentication", "high", rel, f"{tag}: security: {'[] (explicit)' if sec == [] else 'not set'}", "Anyone on the network can call a state-changing endpoint.", f"Add `security` to `{tag}` (or a global default) and enforce it in the handler/gateway.", 45, status="needs_validation", priority="high", why="Confirm the endpoint is meant to be public (signup, webhook with signature, health).", cwe=["CWE-306"], owasp=["A01:2021", "A07:2021"]))
                elif meth in ("get",) and not PUBLIC_PATH.search(path + "/") and re.search(r"(?i)/(admin|internal|users?|accounts?|customers?|orders?|payments?|invoices?|billing|export|backup|debug|private)", path) and (schemes or glob_sec is not None):
                    out.append(_f("API-OP-NO-AUTH", f"{tag} reads sensitive-looking data and has no authentication", "medium", rel, f"{tag}: security not set", "Personal or business data may be readable without credentials.", f"Require authentication for `{tag}` and check object ownership.", 45, status="needs_validation", priority="medium", why="Confirm this read endpoint is intentionally public.", cwe=["CWE-306"], owasp=["A01:2021"]))
            params = [_resolve(doc, p) for p in (item.get("parameters") or []) + (op.get("parameters") or [])]
            params = [p for p in params if isinstance(p, dict)]
            for p in params:
                if p.get("in") == "query" and SECRET_QUERY.match(str(p.get("name", ""))):
                    out.append(_f("API-SECRET-IN-QUERY", f"{tag}: `{p.get('name')}` is accepted in the query string", "medium", rel, f"{tag}  ?{p.get('name')}=…", "Query strings are logged by proxies/servers and stored in history: the secret leaks.", "Move it to a header or the request body.", 30, cwe=["CWE-598"], owasp=["A02:2021"]))
            if meth in ("post", "put", "patch"):
                body = _resolve(doc, op.get("requestBody")) or {}
                for ct, mt in ((body.get("content") or {}).items() if isinstance(body, dict) else []):
                    sch = (mt or {}).get("schema") if isinstance(mt, dict) else None
                    sch_r = _resolve(doc, sch)
                    hit = sorted(k for k in _props(doc, sch) if SENSITIVE_PROP.match(k) and not (_props(doc, sch)[k] or {}).get("readOnly"))
                    if hit and not PUBLIC_PATH.search(path + "/"):
                        out.append(_f("API-MASS-ASSIGNMENT", f"{tag} accepts privileged fields from the client: {', '.join(hit[:4])}", "medium", rel, f"{tag} body: {', '.join(hit[:5])}", "If the handler binds the body straight to the model, a client can set its own role, owner, price or status (mass assignment).", "Use a request DTO with only the fields a client may set; mark server-owned fields `readOnly: true`; ignore unknown properties.", 45, status="needs_validation", priority="medium", why="Fine if the server ignores/overrides these fields; check the handler.", cwe=["CWE-915"], owasp=["A01:2021", "A04:2021"]))
                        break
                    if isinstance(sch_r, dict) and sch_r.get("additionalProperties") is True:
                        out.append(_f("API-OPEN-BODY", f"{tag} accepts arbitrary extra properties", "low", rel, f"{tag} body: additionalProperties: true", "Unvalidated fields can reach the data layer (mass assignment, NoSQL operators).", "Set `additionalProperties: false` and list the allowed fields.", 20, status="needs_validation", priority="low", why="Sometimes intentional for free-form metadata.", cwe=["CWE-915"]))
                        break
            resp = op.get("responses") or {}
            if isinstance(resp, dict) and "429" in {str(k) for k in resp}: any429 = True
            if meth == "get" and isinstance(resp, dict):
                ok = _resolve(doc, resp.get("200") or resp.get(200)) or {}
                for ct, mt in ((ok.get("content") or {}).items() if isinstance(ok, dict) else []):
                    sch = _resolve(doc, (mt or {}).get("schema")) if isinstance(mt, dict) else None
                    if isinstance(sch, dict) and sch.get("type") == "array" and not any(PAGING.match(str(p.get("name", ""))) for p in params) and "{" not in path.rsplit("/", 1)[-1]:
                        no_paging.append(tag)
    if no_paging:
        out.append(_f("API-LIST-NO-PAGINATION", f"{len(no_paging)} list endpoint(s) return an array with no pagination parameter (e.g. {no_paging[0]})", "low", rel, "; ".join(no_paging[:3]), "Unbounded responses: slow queries, memory pressure and an easy denial-of-service / data-harvesting path.", "Add `limit`/`cursor` (or page/size) with a server-side maximum.", 60, status="needs_validation", priority="low", why="Fine for small fixed collections.", cwe=["CWE-770"], owasp=["API4:2023"]))
    if ops >= 5 and not any429 and not re.search(r"(?i)ratelimit|rate-limit|x-rate", json.dumps(doc)[:200000]):
        out.append(_f("API-NO-RATELIMIT", "No operation documents rate limiting (no 429 response)", "low", rel, f"{ops} operations, no 429", "Clients cannot know the limits; brute force and scraping protection is not part of the contract.", "Enforce limits at the gateway/app and document `429` + `Retry-After`.", 60, status="needs_validation", priority="low", why="Rate limiting may be applied by a gateway outside the spec.", cwe=["CWE-770"], owasp=["API4:2023"]))
    return out, info


AUTH_HEADER = re.compile(r"(?i)^(authorization|x-api-key|api-key|x-auth-token|x-access-token|cookie|proxy-authorization)$")


def analyze_postman(doc, rel):
    out, n = [], [0]
    seen = set()
    def mask(v): return v[:4] + "…" + f"({len(v)} chars)"
    def walk(items):
        for it in items or []:
            if not isinstance(it, dict): continue
            if "item" in it: walk(it["item"]); continue
            req = it.get("request") or {}
            if not isinstance(req, dict): continue
            n[0] += 1
            for h in req.get("header") or []:
                if isinstance(h, dict) and AUTH_HEADER.match(str(h.get("key", ""))) and isinstance(h.get("value"), str) and len(h["value"]) > 12 and "{{" not in h["value"] and not h.get("disabled"):
                    k = ("hdr", h["key"])
                    if k not in seen:
                        seen.add(k); out.append(_f("API-POSTMAN-SECRET", f"Postman request `{it.get('name', '?')}` hard-codes the `{h['key']}` header", "high", rel, f"{h['key']}: {mask(h['value'])}", "A live credential committed with the collection is readable by everyone with repository access.", "Rotate it, replace the value with a `{{variable}}` and keep real values in an environment file outside git.", 30, cwe=["CWE-798"], owasp=["A07:2021"]))
            au = req.get("auth")
            if isinstance(au, dict):
                for kind in ("bearer", "basic", "apikey"):
                    for e in au.get(kind) or []:
                        if isinstance(e, dict) and e.get("key") in ("token", "password", "value") and isinstance(e.get("value"), str) and e["value"] and "{{" not in e["value"] and len(e["value"]) > 6 and ("auth", kind) not in seen:
                            seen.add(("auth", kind)); out.append(_f("API-POSTMAN-SECRET", f"Postman request `{it.get('name', '?')}` hard-codes {kind} credentials", "high", rel, f"auth.{kind}: {mask(e['value'])}", "A live credential committed with the collection is readable by everyone with repository access.", "Rotate it and use `{{variables}}`.", 30, cwe=["CWE-798"], owasp=["A07:2021"]))
            url = req.get("url"); raw = url.get("raw") if isinstance(url, dict) else url
            if isinstance(raw, str) and raw.startswith("http://") and not re.match(r"http://(localhost|127\.|\{\{|0\.0\.0\.0)", raw) and ("http", raw.split("/")[2]) not in seen:
                seen.add(("http", raw.split("/")[2])); out.append(_f("API-HTTP-SERVER", f"Postman collection calls `{raw.split('/')[2]}` over plain HTTP", "low", rel, raw[:100], "Requests (and tokens) travel unencrypted.", "Use https:// endpoints.", 15, cwe=["CWE-319"]))
    walk(doc.get("item"))
    return out, dict(file=rel, operations=n[0])


def audit_project(files, read):
    """files: [(rel, abs, ext, _)]; read(abs)->text. Returns (findings, summary)."""
    out, specs, notes = [], [], []
    for rel, ab, ext, _ in files:
        base = os.path.basename(rel).lower()
        is_oa = re.match(r"^(openapi|swagger|api|spec)[\w.-]*\.(json|ya?ml)$", base) or re.search(r"(^|/)(openapi|swagger)/[^/]*\.(json|ya?ml)$", rel.lower())
        is_pm = base.endswith(".postman_collection.json") or base == "postman_collection.json"
        if not (is_oa or is_pm): continue
        if re.search(r"(^|/)(node_modules|vendor)/", rel): continue
        try:
            if os.path.getsize(ab) > 4_000_000: continue
            text = read(ab)
            doc = json.loads(text) if base.endswith(".json") else parse_yaml(text)
        except (OSError, ValueError, RecursionError, IndexError) as e:
            notes.append(f"{rel}: not parsed ({type(e).__name__})"); continue
        if not isinstance(doc, dict): continue
        if is_pm or "_postman_id" in json.dumps(doc.get("info", {})) or (isinstance(doc.get("info"), dict) and "schema" in doc["info"] and "postman" in str(doc["info"]["schema"]).lower()):
            fs, info = analyze_postman(doc, rel); info["kind"] = "postman"
        elif "paths" in doc and ("openapi" in doc or "swagger" in doc):
            fs, info = analyze_openapi(doc, rel); info["kind"] = "openapi"
        else: continue
        out += fs; specs.append(info)
    return out, dict(specs=specs, operations=sum(s.get("operations", 0) for s in specs), public=sum(s.get("public", 0) for s in specs), mutating=sum(s.get("mutating", 0) for s in specs), notes=notes)
