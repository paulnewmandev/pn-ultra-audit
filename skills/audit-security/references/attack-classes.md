# Attack classes - leads, tests, fixes

Format: **Sources → Sinks · Grep leads · Confirm · Fix**. Grep leads find candidates only.

## Injection
**SQL/NoSQL/ORM** - Sources: any request/queue/db-derived string. Sinks: `execute/query/raw/whereRaw/DB::raw/$queryRawUnsafe/extra/text()/createQuery` with concatenation/f-string/template; Mongo `$where`, operators from JSON body (`{"$ne":null}`); dynamic column/ORDER BY/table names. Grep: `execute\(.*[+%f"]`, `whereRaw|DB::raw|selectRaw|orderByRaw`, `\$queryRawUnsafe|sequelize.query`, `find\(req\.(body|query)`. Confirm: show tainted value reaches string, no whitelist. Fix: bound params; whitelist identifiers; ORM operators filtered (cast to string).
**Command** - sinks: `exec/system/popen/shell_exec/backticks/child_process.exec/subprocess(shell=True)/Runtime.exec/os.system`. Fix: arg arrays, no shell, allowlist, avoid command for the job.
**Template (SSTI)** - user input as template *source* (`render_template_string`, `Twig createTemplate`, `eval`, Velocity/Freemarker/Jinja from string). Fix: pass as context var only.
**LDAP/XPath/Header/CRLF/Log injection** - unescaped in filters/headers/log lines.
**Code eval** - `eval/exec/Function/unserialize/include $var/require(user)`.

## XSS
Sources → HTML/attr/JS/URL/CSS contexts. Sinks: `innerHTML/outerHTML/document.write/insertAdjacentHTML/dangerouslySetInnerHTML/v-html/{!! !!}/|safe/mark_safe/raw/ng-bind-html/bypassSecurityTrust*`, `href`/`src` with `javascript:`, `postMessage` handlers w/o origin check, DOM sinks from `location.*`. Stored > reflected > DOM by reach. Confirm context-correct encoding is absent; CSP does not neutralize (CSP is mitigation, not fix). Fix: framework auto-escape; sanitize rich text with DOMPurify/sanitize-html allowlist; validate URL schemes.

## Access control (most common high-impact)
- **IDOR/BOLA**: `Model::find($request->id)` / `findOrFail` / `WHERE id=?` w/o ownership/tenant clause; file download by id/path; nested resources (`/orgs/{org}/items/{item}` where item not checked to belong to org).
- **BFLA**: admin/sensitive function on route without role check; client-hidden but server-open; HTTP verb tunneling; sibling routes (v1 vs v2, mobile vs web) with different checks.
- **Mass assignment**: `create($request->all())`, `fill`, `$guarded=[]`, `Object.assign(model, body)`, DRF `fields="__all__"` writable `is_admin`/`role`/`tenant_id`/`price`.
- **Tenant isolation**: queries missing tenant scope; caches/keys without tenant; background jobs without tenant context; export/report endpoints.
- Fix: policy/gate at handler; scope queries through the owner relation (`$user->orders()->findOrFail`), global tenant scope, deny-by-default middleware, DTO allowlists.

## Authentication & session
See audit-security §4. Greps: `md5\(|sha1\(|password_hash.*PASSWORD_DEFAULT` check cost; `jwt.*(none|verify=False|ignoreExpiration)`; `Math.random|rand\(|mt_rand` near token/otp/reset; `secure:\s*false|httpOnly:\s*false|sameSite`; `verify\s*=\s*False|rejectUnauthorized:\s*false|CURLOPT_SSL_VERIFYPEER.*false`.

## SSRF
Sources: URL/host/redirect/webhook/image/RSS/import params, file-embedded URLs (SVG, PDF, Markdown images, XML entities). Sinks: `requests/axios/fetch/curl/Http::get/file_get_contents/urllib/HttpClient`, headless browsers, image processors. Confirm: no allowlist; internal IPs (127/8, 10/8, 172.16/12, 192.168/16, 169.254.169.254, `[::1]`, DNS rebinding, redirects, `@` and decimal/hex IP tricks). Fix: allowlist host+scheme, resolve-then-connect to validated IP, disable redirects, egress firewall, IMDSv2.

## Path traversal / file handling / upload
Sinks: `open/readFile/sendFile/Storage::get/include/zip extract/Path.join(user)`. Check `..`, absolute paths, symlinks, null bytes, Windows separators, zip-slip. Upload: extension/MIME/magic check, stored outside web root, random name, size cap, no exec, image re-encode, SVG sanitization, AV for user-shared. Fix: resolve + prefix check against base dir; ID→path mapping.

## Deserialization
`unserialize/pickle.loads/yaml.load/ObjectInputStream/Marshal.load/BinaryFormatter/Jackson default typing/node-serialize/vm`, signed-cookie frameworks with leaked key. Fix: JSON + schema, safe loaders, allowlisted types, integrity (HMAC) *and* encryption where needed.

## XXE / XML
Parsers with external entities/DTD enabled (`libxml_disable_entity_loader`, `DocumentBuilderFactory` w/o features, lxml `resolve_entities`). Fix: disable DTD/entities.

## CSRF / CORS / clickjacking / open redirect
State-changing cookie-auth routes without token/SameSite; `Access-Control-Allow-Origin` reflecting Origin with credentials; redirects with user-controlled `next/return_url/redirect_uri` without allowlist (matters mostly when chained: OAuth, phishing on trusted domain, token leakage).

## Race conditions / business logic
Check-then-act without lock/unique/atomic update on: coupons, balances, inventory, votes, invites, password reset use-once tokens, 2FA attempts, rate limits. Negative/zero/huge quantities, price from client, currency mismatch, state machine skip, replay of signed requests, trusting client-side validation.

## Cryptography
Home-made crypto, ECB, static/zero IV, MD5/SHA1 for security, unsalted hashes, `==` instead of constant-time compare for MAC/tokens, short keys, RSA PKCS1v1.5 where OAEP needed, nonce reuse, `Math.random` for secrets, key derivation w/o KDF, TLS verification off, secrets in client bundle.

## Secrets & config
Patterns: `AKIA[0-9A-Z]{16}`, `-----BEGIN (RSA |EC )?PRIVATE KEY-----`, `xox[baprs]-`, `ghp_[A-Za-z0-9]{36}`, `sk_live_`, `AIza[0-9A-Za-z_-]{35}`, `eyJ[A-Za-z0-9_-]+\.eyJ`, `password\s*[:=]\s*['"][^'"]{4,}`, DB URLs with creds, `.env` committed, `*.pem/*.p12/*.keystore`, Firebase/Supabase service keys, `NEXT_PUBLIC_*SECRET*`. Check git history only if repo access allows (`git log -S`). Fix: rotate **first**, then remove & purge history; secret manager.

## Denial of service / DDoS hardening (code- and config-level only)
Never run floods, stress or load tests against shared, third-party or production systems; local/staging at agreed low rates only. Review: rate limiting at edge AND app (login, signup, reset, search, expensive endpoints); client-controlled `limit/per_page/size` clamped; body/upload/array/GraphQL-depth caps; timeouts (server request/headers/keep-alive, outbound HTTP, DB); ReDoS (nested quantifiers); archive extraction limits; `*Sync`/CPU-heavy hashing in request handlers; unbounded queries/N+1; queue offloading; autoscaling cost caps; CDN/WAF presence (outside repo → `needs_validation`).

## Denial of service (code-level, details)
Unbounded input (body size, array length, regex ReDoS, zip bombs, GraphQL depth, pagination `limit=1e9`, recursion), unbounded memory/CPU per request, missing timeouts, expensive endpoints unauthenticated. Don't load-test shared systems.

## Logging / info disclosure
Stack traces/SQL errors to client, debug mode, `phpinfo`, `.git` exposed, source maps with secrets, directory listing, verbose auth errors enabling enumeration, PII/tokens in logs.

## GraphQL / gRPC / WebSocket
Introspection in prod (low), no depth/cost limit, batching brute-force, field-level authz missing, resolvers trusting parent, subscriptions without auth, WS origin check absent, gRPC reflection exposed.

## LLM-specific
Prompt injection (direct, indirect via documents/web/email), insecure output handling, tool/agent over-permission, data exfil via markdown images/links, RAG cross-tenant retrieval, secrets in system prompt, unbounded cost (OWASP LLM01/02/06/07/08/10).

## CI/CD & IaC
`pull_request_target` + checkout of PR head, `${{ github.event.issue.title }}` in `run:`, unpinned third-party actions, `permissions: write-all`, secrets to forks, self-hosted runners on public repos; Docker `USER root`, `ADD http`, secrets in ARG/ENV; Terraform `0.0.0.0/0` on admin ports, `Principal: "*"`, `Action: "*"`, public S3/GCS, no encryption/logging; K8s `privileged`, `hostNetwork`, no `runAsNonRoot`, wildcard RBAC.
