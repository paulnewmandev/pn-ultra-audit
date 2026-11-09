# Rule Catalog

110 pattern rules plus engines (docs, QA, SEO, PWA, Vercel, repo, Web3, DB, servers), 77 remediation guides.

*Precision*: `high` = the pattern is the defect (confirmed); `taint` = flagged when untrusted input is traced to it; `taint_only` = only with traced input; `low` = hotspot to review.

| Rule | Title | Family | CWE | OWASP |
|---|---|---|---|---|
| `A11Y-ANDROID-IMG-DESC` | ImageButton/ImageView without contentDescription | a11y |  |  |
| `A11Y-CLICK-NONINTERACTIVE` | Click handler on a non-interactive element (keyboard/screen-reader inaccessible) | a11y |  |  |
| `A11Y-HTML-LANG` | <html> without lang attribute | a11y |  |  |
| `A11Y-IMG-ALT` | Image without alt text | a11y |  |  |
| `A11Y-INPUT-LABEL` | <input> without id/aria-label (cannot have an associated label) | a11y |  |  |
| `A11Y-MEDIA-AUTOPLAY` | Media autoplay | a11y |  |  |
| `A11Y-OUTLINE-NONE` | Focus outline removed | a11y |  |  |
| `A11Y-TABINDEX-POSITIVE` | Positive tabindex breaks natural focus order | a11y |  |  |
| `A11Y-ZOOM-DISABLED` | Pinch-zoom disabled in viewport meta | a11y |  |  |
| `MOB-ANDROID-DEBUG` | Android: debuggable / cleartext | android | CWE-489, CWE-319 | M8:2024 |
| `MOB-ANDROID-MANIFEST` | Android: backup / exported component | android | CWE-200, CWE-926 | M8:2024 |
| `MOB-ANDROID-NO-MINIFY` | Release build without code shrinking/obfuscation | android | CWE-656 | M7:2024 |
| `MOB-ANDROID-OLD-TARGET` | targetSdk is old (Play Store may reject updates) | android |  | M8:2024 |
| `MOB-STORAGE` | Token/password in insecure local storage | android | CWE-312 | M9:2024 |
| `MOB-WEBVIEW` | WebView risk (JS enabled / bridge / file access) | android | CWE-749, CWE-79 | M4:2024 |
| `BUG-JS-FOREACH-ASYNC` | async callback in forEach (not awaited) | bug-misc | CWE-662 |  |
| `BUG-PHP-LOOSE-AUTH` | Loose comparison in auth/token check | bug-misc | CWE-697, CWE-1025 | A07:2021 |
| `BUG-PY-IS-LITERAL` | `is` used to compare with literal | bug-misc | CWE-597 |  |
| `BUG-PY-MUTABLE-DEFAULT` | Mutable default argument | bug-misc | CWE-665 |  |
| `C-MEM-LEAK-HINT` | malloc without free in same file (leak hint) | bug-misc | CWE-401 |  |
| `RUST-UNSAFE` | unsafe block | bug-misc | CWE-119 |  |
| `RUST-UNWRAP` | .unwrap()/.expect() on fallible value | bug-misc | CWE-248 |  |
| `CFG-CHMOD` | World-writable permissions | chmod | CWE-732 | A05:2021 |
| `CFG-HTTP-URL` | Cleartext http:// URL | cleartext | CWE-319 | A02:2021 |
| `C-FORMAT-STRING` | Format string from variable | cmdi | CWE-134 | A03:2021 |
| `C-SYSTEM` | system()/popen() call | cmdi | CWE-78 | A03:2021 |
| `C-UNSAFE-STR` | Unsafe C string/IO function (buffer overflow) | cmdi | CWE-120, CWE-676 | A03:2021 |
| `CMD-GO` | Process execution (Go) | cmdi | CWE-78 | A03:2021 |
| `CMD-JAVA` | Process execution (Java/Kotlin) | cmdi | CWE-78 | A03:2021 |
| `CMD-JS` | Shell command execution (Node) | cmdi | CWE-78 | A03:2021 |
| `CMD-PHP` | Shell command execution (PHP) | cmdi | CWE-78 | A03:2021 |
| `CMD-PY` | Shell command execution (Python) | cmdi | CWE-78 | A03:2021 |
| `CMD-RB` | Shell command execution (Ruby) | cmdi | CWE-78 | A03:2021 |
| `PS-IEX` | PowerShell Invoke-Expression / download-execute | cmdi | CWE-94 | A03:2021 |
| `SH-EVAL` | eval in shell script | cmdi | CWE-78 | A03:2021 |
| `SH-RM-VAR` | rm -rf with unquoted variable | cmdi | CWE-78 |  |
| `SOL-DELEGATECALL` | Solidity delegatecall / selfdestruct / low-level call | cmdi | CWE-829 |  |
| `CFG-COOKIE` | Insecure cookie flag | cookie | CWE-614, CWE-1004 | A05:2021 |
| `CFG-CORS` | Permissive CORS (*) | cors | CWE-942 | A05:2021, API8:2023 |
| `CRY-PWD-HASH` | Password hashed with MD5/SHA-1 | crypto-pwd | CWE-327, CWE-916 | A02:2021 |
| `CRY-RANDOM` | Non-cryptographic RNG for secrets | crypto-rand | CWE-338 | A02:2021 |
| `SOL-BLOCK-RANDOM` | Solidity randomness from block data | crypto-rand | CWE-330 |  |
| `WEB3-MATH-RANDOM-KEY` | Non-CSPRNG used to generate a wallet/key | crypto-rand | CWE-338 |  |
| `CRY-ECB` | ECB mode / DES / RC4 | crypto-weak | CWE-327 | A02:2021 |
| `CRY-WEAK-HASH` | MD5/SHA-1 usage | crypto-weak | CWE-328 | A02:2021 |
| `CFG-DEBUG` | Debug mode enabled | debug | CWE-489, CWE-209 | A05:2021 |
| `DESER` | Unsafe deserialization | deser | CWE-502 | A08:2021 |
| `EX-ATOM` | Elixir String.to_atom on external input | deser | CWE-400 |  |
| `CFG-DOCKER` | Dockerfile weakness | docker | CWE-250, CWE-829 | A05:2021, A08:2021 |
| `SH-CURL-PIPE` | curl|wget piped to shell | docker | CWE-494 | A08:2021 |
| `FIN-CVV-STORED` | CVV/CVC (sensitive authentication data) persisted - forbidden by PCI DSS | domain-fin | CWE-312, CWE-311 | A02:2021 |
| `FIN-PAN-COLUMN` | Card number (PAN) stored in a column/field - use provider tokens | domain-fin | CWE-311 | A02:2021 |
| `DOS-ARCHIVE` | Archive extraction (zip bomb / zip-slip) | dos | CWE-409, CWE-22 | A04:2021 |
| `DOS-NO-TIMEOUT` | Outbound HTTP call without timeout | dos | CWE-400 | A04:2021 |
| `DOS-REDOS` | Regex with nested quantifiers (ReDoS) | dos | CWE-1333 | A05:2021 |
| `DOS-SYNC-BLOCK` | Blocking *Sync call (event-loop stall) | dos | CWE-400 | A04:2021 |
| `DOS-UNBOUNDED-SIZE` | Client-controlled size/limit without cap | dos | CWE-770 | A04:2021, API4:2023 |
| `DOS-UNLIMITED-BODY` | Unlimited request/upload size | dos | CWE-770 | A05:2021 |
| `BUG-EMPTY-CATCH` | Empty catch/except (swallowed error) | errors | CWE-390 | A09:2021 |
| `AUTHZ-IDOR` | Object loaded by client-supplied id (check ownership) | idor | CWE-639, CWE-862 | A01:2021, API1:2023 |
| `CFG-CI` | CI/CD pipeline risk (GitHub Actions) | infra | CWE-94, CWE-829 | A08:2021 |
| `CFG-K8S` | Kubernetes/Compose privilege weakness | infra | CWE-250 | A05:2021 |
| `CFG-NGINX` | nginx/apache hardening | infra | CWE-16 | A05:2021 |
| `CFG-TF` | Terraform/cloud over-exposure | infra | CWE-284, CWE-732 | A05:2021, A01:2021 |
| `MOB-IOS-ATS` | iOS: App Transport Security disabled | ios | CWE-319 | M5:2024 |
| `JWT-HARDCODED` | JWT signed with hard-coded secret | jwt | CWE-798, CWE-347 | A07:2021 |
| `JWT-NOVERIFY` | JWT verification disabled / alg none | jwt | CWE-347 | A07:2021 |
| `SOL-TX-ORIGIN` | Solidity tx.origin authorization | jwt | CWE-477 |  |
| `LOG-SECRET` | Secret/password written to logs | logsecret | CWE-532 | A09:2021 |
| `AUTHZ-MASS-ASSIGN` | Mass assignment / over-posting | massassign | CWE-915 | A01:2021, API3:2023 |
| `PATH-TRAVERSAL` | File access with user-controlled path | path | CWE-22 | A01:2021 |
| `OPEN-REDIRECT` | Redirect to user-controlled URL | redirect | CWE-601 | A01:2021 |
| `MOB-ANDROID-SIGNING-PWD` | Signing password hard-coded in Gradle | secrets | CWE-798 | A07:2021, M9:2024 |
| `SEC-AWS-KEY` | AWS access key id | secrets | CWE-798 | A07:2021 |
| `SEC-DB-URL` | Database URL with credentials | secrets | CWE-798 | A07:2021 |
| `SEC-GITHUB-TOKEN` | GitHub token | secrets | CWE-798 | A07:2021 |
| `SEC-GOOGLE-KEY` | Google API key | secrets | CWE-798 | A07:2021 |
| `SEC-HARDCODED` | Hard-coded credential | secrets | CWE-798 | A07:2021 |
| `SEC-MNEMONIC` | Wallet mnemonic / seed phrase in source | secrets | CWE-321, CWE-798 | A02:2021 |
| `SEC-PRIVATE-KEY` | Private key in source | secrets | CWE-321 | A02:2021 |
| `SEC-RPC-KEY` | RPC/provider API key in source (Infura/Alchemy/QuickNode) | secrets | CWE-798 | A07:2021 |
| `SEC-SLACK-TOKEN` | Slack token | secrets | CWE-798 | A07:2021 |
| `SEC-STRIPE-KEY` | Stripe live secret key | secrets | CWE-798 | A07:2021 |
| `SEC-WALLET-PRIVKEY` | Wallet private key hard-coded | secrets | CWE-321, CWE-798 | A02:2021 |
| `WEB3-HARDHAT-KEY` | Private key in Hardhat/Foundry/Truffle config | secrets | CWE-798 |  |
| `ASP-REQUEST-SQL` | Classic ASP/VB SQL from Request | sqli | CWE-89 | A03:2021 |
| `COBOL-DYNSQL` | COBOL dynamic SQL (EXEC SQL PREPARE/EXECUTE IMMEDIATE) | sqli | CWE-89 |  |
| `SQLI-CS` | SQL built with interpolation (C#/.NET) | sqli | CWE-89 | A03:2021 |
| `SQLI-DART` | SQL built with interpolation (Dart/Flutter) | sqli | CWE-89 | A03:2021 |
| `SQLI-GO` | SQL built with Sprintf/concatenation (Go) | sqli | CWE-89 | A03:2021 |
| `SQLI-JAVA` | SQL built with concatenation (Java/Kotlin/Android) | sqli | CWE-89 | A03:2021 |
| `SQLI-JS` | SQL built with template/concatenation (JS/TS) | sqli | CWE-89 | A03:2021 |
| `SQLI-PHP` | SQL built with string concatenation (PHP) | sqli | CWE-89 | A03:2021 |
| `SQLI-PROC` | Dynamic SQL inside stored procedure | sqli | CWE-89 | A03:2021 |
| `SQLI-PY` | SQL built with string formatting (Python) | sqli | CWE-89 | A03:2021 |
| `SQLI-RB` | SQL with interpolation (Ruby/Rails) | sqli | CWE-89 | A03:2021 |
| `SQLI-SWIFT` | SQL built with string interpolation (Swift) | sqli | CWE-89 | A03:2021 |
| `SSRF` | Outbound request to user-controlled URL | ssrf | CWE-918 | A10:2021, API7:2023 |
| `CRY-TLS` | TLS verification disabled | tls | CWE-295 | A02:2021 |
| `WEB3-DAPP-ETH-SIGN` | eth_sign / raw message signing (phishing-prone) | web3 | CWE-345 |  |
| `WEB3-DAPP-NO-CHAIN-CHECK` | Wallet connected without chain-id validation | web3 |  |  |
| `WEB3-DAPP-NO-SLIPPAGE` | Swap without slippage protection (amountOutMin 0) | web3 | CWE-1281 |  |
| `WEB3-DAPP-UNLIMITED-APPROVE` | Unlimited token approval (MaxUint256) | web3 | CWE-250 |  |
| `CODE-EVAL` | Dynamic code evaluation | xss | CWE-95 | A03:2021 |
| `PL-EVAL` | Perl/Lua/R dynamic evaluation | xss | CWE-95 |  |
| `XSS-DOM` | Raw HTML sink (innerHTML/document.write) | xss | CWE-79 | A03:2021 |
| `XSS-ECHO-PHP` | Request data echoed without encoding (PHP) | xss | CWE-79 | A03:2021 |
| `XSS-FRAMEWORK` | Framework raw-HTML escape hatch | xss | CWE-79 | A03:2021 |
| `XSS-REFLECT-JS` | User input written straight into HTML response (Node) | xss | CWE-79 | A03:2021 |
| `XSS-REFLECT-PY` | User input rendered as HTML without escaping (Python) | xss | CWE-79 | A03:2021 |
