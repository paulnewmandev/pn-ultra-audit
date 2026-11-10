#!/usr/bin/env python3
"""Generates docs/RULES.md (rule catalog) and docs/CLI.md (flag reference) from the code. python3 scripts/gen_docs.py"""
import os, subprocess, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from engine.rules import RULES
from engine.kb import KB
from engine import scanner, detect

os.makedirs(os.path.join(ROOT, "docs"), exist_ok=True)
fam = {}
for r in RULES: fam.setdefault(r.family, []).append(r)
L = ["# Rule catalog", "", f"{len(RULES)} pattern rules + engines (docs, QA, SEO, Web3, DB, server). *Precision*: `high` = pattern is the defect (confirmed); `taint` = confirmed only if user input reaches it (else hotspot); `taint_only` = reported only when tainted; `low` = hotspot to review.", "",
     f"Every family links to a remediation guide with steps, vulnerable/safe examples and verification ({len(KB)} guides, Spanish overlay for the main ones).", "", "| Rule | What it finds | Family | Languages / files | Precision | CWE | OWASP |", "|---|---|---|---|---|---|---|"]
for r in sorted(RULES, key=lambda x: (x.family, x.id)):
    ex = "any" if r.exts is None else ", ".join(sorted(r.exts)[:8]) + ("…" if len(r.exts) > 8 else "")
    L.append(f"| `{r.id}` | {r.title} | {r.family} | {ex} | {r.precision} | {', '.join(r.cwe)} | {', '.join(r.owasp)} |")
L += ["", "## Engines beyond regex rules", "", "| Engine | Checks |", "|---|---|",
      "| `docs.py` | Python AST + 9 languages: public-API doc coverage, docstring completeness, function length / cyclomatic complexity / params / nesting, import cycles (Tarjan), layering hints, type-hint coverage, linter/formatter/type-checker/CI/pre-commit/.env.example, README/ADR/OpenAPI, `any`/debug leftovers, architecture profile |",
      "| `qa.py` | Front-end: unit/component/E2E/a11y/visual/perf layers, flaky patterns, un-awaited Playwright assertions, route coverage. Mobile: Android (Compose/Espresso/MockK/Turbine/GMD), iOS (XCTest/XCUITest/Swift Testing, privacy strings), Flutter, React Native |",
      "| `seo.py` / `seo_free.py` | Static + live SEO/SEM: titles, meta, canonical, H1, robots, sitemap, noindex, redirects, mixed content, Core Web Vitals hints, JSON-LD, hreflang, trackers, consent mode, conversions; Search Console CSV, keyword ideas, competitors |",
      "| `web3.py` | Solidity: reentrancy, access control, unprotected initializers, unchecked calls, weak randomness, signature replay, delegatecall, oracles, tx.origin, compiler/pragma; Anchor/Solana; dApp patterns |",
      "| `dbaudit.py` | .sql/T-SQL/PL-SQL static; live SQLite, PostgreSQL, MySQL/MariaDB, SQL Server, Redis, MongoDB (read-only) |",
      "| `remote.py` / `aws.py` | SSH server hardening (OS/runtimes EOL, sshd, ports, firewall, web-root exposure, Docker, certs), SSH tunnel, RDS configuration |",
      "| `gitsrc.py` | Shallow clone, repo statistics, churn hotspots, secrets in git history |", "",
      "## Languages with dedicated rules", "", ", ".join(sorted({scanner.LANG[e] for r in RULES if r.exts for e in r.exts if e in scanner.LANG})), "",
      f"File types counted in size/complexity metrics: {len(scanner.LANG)} extensions.", ""]
open(os.path.join(ROOT, "docs", "RULES.md"), "w", encoding="utf-8").write("\n".join(L))
h = subprocess.run([sys.executable, os.path.join(ROOT, "audit.py"), "--help"], capture_output=True, text=True, env=dict(os.environ, COLUMNS="110")).stdout
open(os.path.join(ROOT, "docs", "CLI.md"), "w", encoding="utf-8").write("# CLI reference\n\nGenerated from `python3 audit.py --help`.\n\n```text\n" + h + "```\n\n## Auditors\n\n| Auditor | Scope |\n|---|---|\n" + "\n".join(f"| `{k}` | {v} |" for k, v in detect.AUDITORS.items()) + "\n")
print(len(RULES), "rules;", len(KB), "KB guides;", len(scanner.LANG), "extensions")
