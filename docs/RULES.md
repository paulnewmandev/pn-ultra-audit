# Rule catalog

110 pattern rules + engines (docs, QA, SEO, Web3, DB, server). *Precision*: `high` = pattern is the defect (confirmed); `taint` = confirmed only if user input reaches it (else hotspot); `taint_only` = reported only when tainted; `low` = hotspot to review.

Every family links to a remediation guide with steps, vulnerable/safe examples and verification (108 guides, Spanish overlay for the main ones).

| Rule | What it finds | Family | Languages / files | Precision | CWE | OWASP |
|---|---|---|---|---|---|---|
| `A11Y-ANDROID-IMG-DESC` | ImageButton/ImageView without contentDescription | a11y | gradle, plist, xml | high |  |  |
| `A11Y-CLICK-NONINTERACTIVE` | Click handler on a non-interactive element (keyboard/screen-reader inaccessible) | a11y | blade, cjs, cshtml, ejs, erb, hbs, htm, html… | high |  |  |
| `A11Y-HTML-LANG` | <html> without lang attribute | a11y | htm, html | high |  |  |
| `A11Y-IMG-ALT` | Image without alt text | a11y | blade, cjs, cshtml, ejs, erb, hbs, htm, html… | high |  |  |
| `A11Y-INPUT-LABEL` | <input> without id/aria-label (cannot have an associated label) | a11y | blade, cjs, cshtml, ejs, erb, hbs, htm, html… | low |  |  |
| `A11Y-MEDIA-AUTOPLAY` | Media autoplay | a11y | blade, cjs, cshtml, ejs, erb, hbs, htm, html… | low |  |  |
| `A11Y-OUTLINE-NONE` | Focus outline removed | a11y | css, html, js, jsx, less, scss, svelte, ts… | low |  |  |
| `A11Y-TABINDEX-POSITIVE` | Positive tabindex breaks natural focus order | a11y | blade, cjs, cshtml, ejs, erb, hbs, htm, html… | high |  |  |
| `A11Y-ZOOM-DISABLED` | Pinch-zoom disabled in viewport meta | a11y | ejs, hbs, htm, html, js, jsx, php, ts… | high |  |  |
| `MOB-ANDROID-DEBUG` | Android: debuggable / cleartext | android | gradle, json, plist, xml | high | CWE-489, CWE-319 | M8:2024 |
| `MOB-ANDROID-MANIFEST` | Android: backup / exported component | android | gradle, plist, xml | low | CWE-200, CWE-926 | M8:2024 |
| `MOB-ANDROID-NO-MINIFY` | Release build without code shrinking/obfuscation | android | gradle, kts | low | CWE-656 | M7:2024 |
| `MOB-ANDROID-OLD-TARGET` | targetSdk is old (Play Store may reject updates) | android | gradle, kts | low |  | M8:2024 |
| `MOB-STORAGE` | Token/password in insecure local storage | android | cjs, dart, groovy, java, js, jsx, kt, kts… | low | CWE-312 | M9:2024 |
| `MOB-WEBVIEW` | WebView risk (JS enabled / bridge / file access) | android | cjs, dart, groovy, java, js, jsx, kt, kts… | low | CWE-749, CWE-79 | M4:2024 |
| `BUG-JS-FOREACH-ASYNC` | async callback in forEach (not awaited) | bug-misc | cjs, js, jsx, mjs, svelte, ts, tsx, vue | high | CWE-662 |  |
| `BUG-PHP-LOOSE-AUTH` | Loose comparison in auth/token check | bug-misc | php, phtml | high | CWE-697, CWE-1025 | A07:2021 |
| `BUG-PY-IS-LITERAL` | `is` used to compare with literal | bug-misc | __ast__ | high | CWE-597 |  |
| `BUG-PY-MUTABLE-DEFAULT` | Mutable default argument that is mutated or leaked | bug-misc | __ast__ | high | CWE-665 |  |
| `C-MEM-LEAK-HINT` | malloc without free in same file (leak hint) | bug-misc | c, cc, cpp, cu, cxx, h, hpp, m… | low | CWE-401 |  |
| `RUST-UNSAFE` | unsafe block | bug-misc | rs | low | CWE-119 |  |
| `RUST-UNWRAP` | .unwrap()/.expect() on fallible value | bug-misc | rs | low | CWE-248 |  |
| `CFG-CHMOD` | World-writable permissions | chmod | bash, c, cc, cjs, cpp, cs, cshtml, dart… | high | CWE-732 | A05:2021 |
| `CFG-HTTP-URL` | Cleartext http:// URL | cleartext | bash, c, cc, cjs, cpp, cs, cshtml, dart… | low | CWE-319 | A02:2021 |
| `C-FORMAT-STRING` | Format string from variable | cmdi | c, cc, cpp, cu, cxx, h, hpp, m… | low | CWE-134 | A03:2021 |
| `C-SYSTEM` | system()/popen() call | cmdi | c, cc, cpp, cu, cxx, h, hpp, m… | taint | CWE-78 | A03:2021 |
| `C-UNSAFE-STR` | Unsafe C string/IO function (buffer overflow) | cmdi | c, cc, cpp, cu, cxx, h, hpp, m… | low | CWE-120, CWE-676 | A03:2021 |
| `CMD-GO` | Process execution (Go) | cmdi | go | taint | CWE-78 | A03:2021 |
| `CMD-JAVA` | Process execution (Java/Kotlin) | cmdi | groovy, java, kt, kts, scala | taint | CWE-78 | A03:2021 |
| `CMD-JS` | Shell command execution (Node) | cmdi | cjs, js, jsx, mjs, svelte, ts, tsx, vue | taint | CWE-78 | A03:2021 |
| `CMD-PHP` | Shell command execution (PHP) | cmdi | php, phtml | taint | CWE-78 | A03:2021 |
| `CMD-PY` | Shell command execution (Python) | cmdi | py | taint | CWE-78 | A03:2021 |
| `CMD-RB` | Shell command execution (Ruby) | cmdi | erb, rb | taint | CWE-78 | A03:2021 |
| `PS-IEX` | PowerShell Invoke-Expression / download-execute | cmdi | bat, cmd, ps1, psm1 | low | CWE-94 | A03:2021 |
| `SH-EVAL` | eval in shell script | cmdi | bash, sh, zsh | taint | CWE-78 | A03:2021 |
| `SH-RM-VAR` | rm -rf with unquoted variable | cmdi | bash, makefile, mk, sh, zsh | low | CWE-78 |  |
| `SOL-DELEGATECALL` | Solidity delegatecall / selfdestruct / low-level call | cmdi | sol | low | CWE-829 |  |
| `CFG-COOKIE` | Insecure cookie flag | cookie | bash, c, cc, cjs, cpp, cs, cshtml, dart… | high | CWE-614, CWE-1004 | A05:2021 |
| `CFG-CORS` | Permissive CORS (*) | cors | any | low | CWE-942 | A05:2021, API8:2023 |
| `CRY-PWD-HASH` | Password hashed with MD5/SHA-1 | crypto-pwd | bash, c, cc, cjs, cpp, cs, cshtml, dart… | high | CWE-327, CWE-916 | A02:2021 |
| `CRY-RANDOM` | Non-cryptographic RNG for secrets | crypto-rand | bash, c, cc, cjs, cpp, cs, cshtml, dart… | high | CWE-338 | A02:2021 |
| `SOL-BLOCK-RANDOM` | Solidity randomness from block data | crypto-rand | sol | high | CWE-330 |  |
| `WEB3-MATH-RANDOM-KEY` | Non-CSPRNG used to generate a wallet/key | crypto-rand | cjs, js, jsx, mjs, py, svelte, ts, tsx… | high | CWE-338 |  |
| `CRY-ECB` | ECB mode / DES / RC4 | crypto-weak | bash, c, cc, cjs, cpp, cs, cshtml, dart… | high | CWE-327 | A02:2021 |
| `CRY-WEAK-HASH` | MD5/SHA-1 usage | crypto-weak | bash, c, cc, cjs, cpp, cs, cshtml, dart… | low | CWE-328 | A02:2021 |
| `CFG-DEBUG` | Debug mode enabled | debug | cjs, env, erb, ini, js, json, jsx, mjs… | low | CWE-489, CWE-209 | A05:2021 |
| `DESER` | Unsafe deserialization | deser | bash, c, cc, cjs, cpp, cs, cshtml, dart… | taint | CWE-502 | A08:2021 |
| `EX-ATOM` | Elixir String.to_atom on external input | deser | ex, exs | taint | CWE-400 |  |
| `CFG-DOCKER` | Dockerfile weakness | docker | dockerfile | low | CWE-250, CWE-829 | A05:2021, A08:2021 |
| `SH-CURL-PIPE` | curl|wget piped to shell | docker | bash, makefile, mk, sh, yaml, yml, zsh | low | CWE-494 | A08:2021 |
| `FIN-CVV-STORED` | CVV/CVC (sensitive authentication data) persisted - forbidden by PCI DSS | domain-fin | any | high | CWE-312, CWE-311 | A02:2021 |
| `FIN-PAN-COLUMN` | Card number (PAN) stored in a column/field - use provider tokens | domain-fin | cs, go, java, js, kt, php, prisma, py… | low | CWE-311 | A02:2021 |
| `DOS-ARCHIVE` | Archive extraction (zip bomb / zip-slip) | dos | cjs, erb, go, groovy, java, js, jsx, kt… | low | CWE-409, CWE-22 | A04:2021 |
| `DOS-NO-TIMEOUT` | Outbound HTTP call without timeout | dos | go, groovy, java, kt, kts, py, scala | low | CWE-400 | A04:2021 |
| `DOS-REDOS` | Regex with nested quantifiers (ReDoS) | dos | bash, c, cc, cjs, cpp, cs, cshtml, dart… | low | CWE-1333 | A05:2021 |
| `DOS-SYNC-BLOCK` | Blocking *Sync call (event-loop stall) | dos | cjs, js, jsx, mjs, svelte, ts, tsx, vue | low | CWE-400 | A04:2021 |
| `DOS-UNBOUNDED-SIZE` | Client-controlled size/limit without cap | dos | bash, c, cc, cjs, cpp, cs, cshtml, dart… | low | CWE-770 | A04:2021, API4:2023 |
| `DOS-UNLIMITED-BODY` | Unlimited request/upload size | dos | any | low | CWE-770 | A05:2021 |
| `BUG-EMPTY-CATCH` | Empty catch/except (swallowed error) | errors | bash, c, cc, cjs, cpp, cs, cshtml, dart… | high | CWE-390 | A09:2021 |
| `AUTHZ-IDOR` | Object loaded by client-supplied id (check ownership) | idor | bash, c, cc, cjs, cpp, cs, cshtml, dart… | taint_only | CWE-639, CWE-862 | A01:2021, API1:2023 |
| `CFG-CI` | CI/CD pipeline risk (GitHub Actions) | infra | yaml, yml | low | CWE-94, CWE-829 | A08:2021 |
| `CFG-K8S` | Kubernetes/Compose privilege weakness | infra | yaml, yml | low | CWE-250 | A05:2021 |
| `CFG-NGINX` | nginx/apache hardening | infra | conf, nginx | low | CWE-16 | A05:2021 |
| `CFG-TF` | Terraform/cloud over-exposure | infra | json, tf, tfvars, yaml, yml | low | CWE-284, CWE-732 | A05:2021, A01:2021 |
| `MOB-IOS-ATS` | iOS: App Transport Security disabled | ios | gradle, plist, xml | high | CWE-319 | M5:2024 |
| `JWT-HARDCODED` | JWT signed with hard-coded secret | jwt | bash, c, cc, cjs, cpp, cs, cshtml, dart… | high | CWE-798, CWE-347 | A07:2021 |
| `JWT-NOVERIFY` | JWT verification disabled / alg none | jwt | bash, c, cc, cjs, cpp, cs, cshtml, dart… | high | CWE-347 | A07:2021 |
| `SOL-TX-ORIGIN` | Solidity tx.origin authorization | jwt | sol | high | CWE-477 |  |
| `LOG-SECRET` | Secret/password written to logs | logsecret | bash, c, cc, cjs, cpp, cs, cshtml, dart… | high | CWE-532 | A09:2021 |
| `AUTHZ-MASS-ASSIGN` | Mass assignment / over-posting | massassign | bash, c, cc, cjs, cpp, cs, cshtml, dart… | low | CWE-915 | A01:2021, API3:2023 |
| `PATH-TRAVERSAL` | File access with user-controlled path | path | bash, c, cc, cjs, cpp, cs, cshtml, dart… | taint_only | CWE-22 | A01:2021 |
| `OPEN-REDIRECT` | Redirect to user-controlled URL | redirect | bash, c, cc, cjs, cpp, cs, cshtml, dart… | taint_only | CWE-601 | A01:2021 |
| `MOB-ANDROID-SIGNING-PWD` | Signing password hard-coded in Gradle | secrets | gradle, kts | high | CWE-798 | A07:2021, M9:2024 |
| `SEC-AWS-KEY` | AWS access key id | secrets | any | high | CWE-798 | A07:2021 |
| `SEC-DB-URL` | Database URL with credentials | secrets | any | high | CWE-798 | A07:2021 |
| `SEC-GITHUB-TOKEN` | GitHub token | secrets | any | high | CWE-798 | A07:2021 |
| `SEC-GOOGLE-KEY` | Google API key | secrets | any | high | CWE-798 | A07:2021 |
| `SEC-HARDCODED` | Hard-coded credential | secrets | any | high | CWE-798 | A07:2021 |
| `SEC-MNEMONIC` | Wallet mnemonic / seed phrase in source | secrets | any | high | CWE-321, CWE-798 | A02:2021 |
| `SEC-PRIVATE-KEY` | Private key in source | secrets | any | high | CWE-321 | A02:2021 |
| `SEC-RPC-KEY` | RPC/provider API key in source (Infura/Alchemy/QuickNode) | secrets | any | high | CWE-798 | A07:2021 |
| `SEC-SLACK-TOKEN` | Slack token | secrets | any | high | CWE-798 | A07:2021 |
| `SEC-STRIPE-KEY` | Stripe live secret key | secrets | any | high | CWE-798 | A07:2021 |
| `SEC-WALLET-PRIVKEY` | Wallet private key hard-coded | secrets | any | high | CWE-321, CWE-798 | A02:2021 |
| `WEB3-HARDHAT-KEY` | Private key in Hardhat/Foundry/Truffle config | secrets | cjs, js, json, toml, ts | high | CWE-798 |  |
| `ASP-REQUEST-SQL` | Classic ASP/VB SQL from Request | sqli | asp, aspx, vb, vbs | high | CWE-89 | A03:2021 |
| `COBOL-DYNSQL` | COBOL dynamic SQL (EXEC SQL PREPARE/EXECUTE IMMEDIATE) | sqli | cbl, cob | low | CWE-89 |  |
| `SQLI-CS` | SQL built with interpolation (C#/.NET) | sqli | cs, cshtml | taint | CWE-89 | A03:2021 |
| `SQLI-DART` | SQL built with interpolation (Dart/Flutter) | sqli | dart | taint | CWE-89 | A03:2021 |
| `SQLI-GO` | SQL built with Sprintf/concatenation (Go) | sqli | go | taint | CWE-89 | A03:2021 |
| `SQLI-JAVA` | SQL built with concatenation (Java/Kotlin/Android) | sqli | groovy, java, kt, kts, scala | taint | CWE-89 | A03:2021 |
| `SQLI-JS` | SQL built with template/concatenation (JS/TS) | sqli | cjs, js, jsx, mjs, svelte, ts, tsx, vue | taint | CWE-89 | A03:2021 |
| `SQLI-PHP` | SQL built with string concatenation (PHP) | sqli | php, phtml | taint | CWE-89 | A03:2021 |
| `SQLI-PROC` | Dynamic SQL inside stored procedure | sqli | sql | low | CWE-89 | A03:2021 |
| `SQLI-PY` | SQL built with string formatting (Python) | sqli | py | taint | CWE-89 | A03:2021 |
| `SQLI-RB` | SQL with interpolation (Ruby/Rails) | sqli | erb, rb | taint | CWE-89 | A03:2021 |
| `SQLI-SWIFT` | SQL built with string interpolation (Swift) | sqli | m, mm, swift | low | CWE-89 | A03:2021 |
| `SSRF` | Outbound request to user-controlled URL | ssrf | bash, c, cc, cjs, cpp, cs, cshtml, dart… | taint_only | CWE-918 | A10:2021, API7:2023 |
| `CRY-TLS` | TLS verification disabled | tls | bash, c, cc, cjs, cpp, cs, cshtml, dart… | high | CWE-295 | A02:2021 |
| `WEB3-DAPP-ETH-SIGN` | eth_sign / raw message signing (phishing-prone) | web3 | cjs, js, jsx, mjs, svelte, ts, tsx, vue | low | CWE-345 |  |
| `WEB3-DAPP-NO-CHAIN-CHECK` | Wallet connected without chain-id validation | web3 | cjs, js, jsx, mjs, svelte, ts, tsx, vue | low |  |  |
| `WEB3-DAPP-NO-SLIPPAGE` | Swap without slippage protection (amountOutMin 0) | web3 | cjs, js, jsx, mjs, sol, svelte, ts, tsx… | high | CWE-1281 |  |
| `WEB3-DAPP-UNLIMITED-APPROVE` | Unlimited token approval (MaxUint256) | web3 | cjs, js, jsx, mjs, svelte, ts, tsx, vue | low | CWE-250 |  |
| `CODE-EVAL` | Dynamic code evaluation | xss | cjs, erb, js, jsx, mjs, php, phtml, py… | taint | CWE-95 | A03:2021 |
| `PL-EVAL` | Perl/Lua/R dynamic evaluation | xss | lua, pl, pm, r | taint | CWE-95 |  |
| `XSS-DOM` | Raw HTML sink (innerHTML/document.write) | xss | cjs, ejs, hbs, htm, html, js, jsx, mjs… | taint | CWE-79 | A03:2021 |
| `XSS-ECHO-PHP` | Request data echoed without encoding (PHP) | xss | php, phtml | high | CWE-79 | A03:2021 |
| `XSS-FRAMEWORK` | Framework raw-HTML escape hatch | xss | cjs, cshtml, ejs, erb, hbs, htm, html, j2… | low | CWE-79 | A03:2021 |
| `XSS-REFLECT-JS` | User input written straight into HTML response (Node) | xss | cjs, js, jsx, mjs, svelte, ts, tsx, vue | taint_only | CWE-79 | A03:2021 |
| `XSS-REFLECT-PY` | User input rendered as HTML without escaping (Python) | xss | py | taint_only | CWE-79 | A03:2021 |

## Engines beyond regex rules

| Engine | Checks |
|---|---|
| `docs.py` | Python AST + 9 languages: public-API doc coverage, docstring completeness, function length / cyclomatic complexity / params / nesting, import cycles (Tarjan), layering hints, type-hint coverage, linter/formatter/type-checker/CI/pre-commit/.env.example, README/ADR/OpenAPI, `any`/debug leftovers, architecture profile |
| `qa.py` | Front-end: unit/component/E2E/a11y/visual/perf layers, flaky patterns, un-awaited Playwright assertions, route coverage. Mobile: Android (Compose/Espresso/MockK/Turbine/GMD), iOS (XCTest/XCUITest/Swift Testing, privacy strings), Flutter, React Native |
| `seo.py` / `seo_free.py` | Static + live SEO/SEM: titles, meta, canonical, H1, robots, sitemap, noindex, redirects, mixed content, Core Web Vitals hints, JSON-LD, hreflang, trackers, consent mode, conversions; Search Console CSV, keyword ideas, competitors |
| `web3.py` | Solidity: reentrancy, access control, unprotected initializers, unchecked calls, weak randomness, signature replay, delegatecall, oracles, tx.origin, compiler/pragma; Anchor/Solana; dApp patterns |
| `dbaudit.py` | .sql/T-SQL/PL-SQL static; live SQLite, PostgreSQL, MySQL/MariaDB, SQL Server, Redis, MongoDB (read-only) |
| `remote.py` / `aws.py` | SSH server hardening (OS/runtimes EOL, sshd, ports, firewall, web-root exposure, Docker, certs), SSH tunnel, RDS configuration |
| `gitsrc.py` | Shallow clone, repo statistics, churn hotspots, secrets in git history |

## Languages with dedicated rules

ASP, ASP.NET, Batch, C, C#, C++, C/C++, COBOL, CSS, CUDA, Dart, Docker, EJS, Elixir, Go, Gradle, Groovy, HTML, Handlebars, Java, JavaScript, Jinja, Kotlin, Lua, Make, Objective-C, PHP, Perl, PowerShell, Python, R, Ruby, Rust, SQL, Scala, Shell, Solidity, Svelte, Swift, Terraform, Twig, TypeScript, VBScript, Visual Basic, Vue, XML, YAML, plist

File types counted in size/complexity metrics: 101 extensions.
