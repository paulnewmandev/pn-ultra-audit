"""Smart-contract / crypto-project audit heuristics (Solidity/EVM, Solana-Anchor, web3 front-ends).
Regex + light structure analysis - a triage aid, NOT a substitute for a professional audit (Slither, Foundry fuzzing, formal verification)."""
import os, re
from collections import Counter

from .kb import KB

ACCESS_MODS = r"onlyOwner|onlyRole|onlyAdmin|onlyGovernance|onlyOperator|requiresAuth|auth\b|whenNotPaused|initializer|reinitializer|onlyProxy|onlyGuardian|onlyMinter|only\w+"


def _f(rule, title, typ, sev, cat, file, line, ev, fix, effort, status="confirmed", priority=None, why=None, cwe=()):
    kb = KB["web3"]
    return dict(rule=rule, title=title, family="web3", type=typ, severity=sev if status == "confirmed" else None, category=cat, file=file, line=line, evidence=ev[:400], impact=kb["impact"], fix=fix, effort_min=effort, cwe=list(cwe), owasp=[], status=status, priority=priority, why=why)


def _functions(text):
    """yield (name, line, header, body, mods) for each Solidity function"""
    for m in re.finditer(r"\bfunction\s+(\w+)\s*\(([^)]*)\)([^{;]*)\{", text):
        i = m.end(); d = 1
        while i < len(text) and d:
            d += (text[i] == "{") - (text[i] == "}"); i += 1
        yield m.group(1), text[:m.start()].count("\n") + 1, m.group(0), text[m.end():i], m.group(3)


def analyze(root, files):
    out, info = [], {}
    sol = [(r, a) for r, a, e, _ in files if e == "sol"]
    rs = [(r, a) for r, a, e, _ in files if e == "rs" and re.search(r"anchor|solana|programs?/", r)]
    names = {os.path.basename(r) for r, *_ in files}
    frameworks = [n for n, f in (("Hardhat", r"^hardhat\.config\.(js|ts|cjs)$"), ("Foundry", r"^foundry\.toml$"), ("Truffle", r"^truffle-config\.js$"), ("Brownie", r"^brownie-config\.ya?ml$"), ("Anchor (Solana)", r"^Anchor\.toml$"), ("Move", r"^Move\.toml$")) if any(re.match(f, x) for x in names)]
    web3js = any(re.search(r"\b(ethers|web3|viem|wagmi|@solana/web3\.js|@web3-react)\b", open(a, errors="ignore", encoding="utf-8").read(40_000)) for r, a, e, _ in files if os.path.basename(r) == "package.json")
    if not (sol or rs or frameworks or web3js): return out, {}
    info.update(frameworks=frameworks, solidity_files=len(sol), rust_programs=len(rs), web3_frontend=web3js)
    pragmas, contracts, ext_calls = Counter(), 0, 0
    for rel, ab in sol[:300]:
        if re.search(r"(^|/)(node_modules|lib|test|tests|mocks?|forge-std|openzeppelin)(/|$)|\.t\.sol$|\.s\.sol$", rel): continue
        try: t = open(ab, errors="ignore", encoding="utf-8").read(400_000)
        except OSError: continue
        pm = re.search(r"pragma\s+solidity\s+([^;]+);", t)
        ver = pm.group(1).strip() if pm else "?"; pragmas[ver] += 1
        contracts += len(re.findall(r"^\s*(?:abstract\s+)?contract\s+\w+", t, re.M))
        old = bool(re.search(r"[\^~>=<\s]0\.[4-7]\.", " " + ver)) and not re.search(r"0\.8", ver)
        if old and not re.search(r"SafeMath", t): out.append(_f("WEB3-OLD-COMPILER", f"Solidity {ver} (<0.8) without SafeMath: arithmetic can overflow silently", "vulnerability", "high", "smart-contract", rel, 1, f"pragma solidity {ver};", "Upgrade to ≥0.8.x (checked arithmetic) or use SafeMath everywhere", 120, cwe=["CWE-190"]))
        elif re.match(r"^\^", ver): out.append(_f("WEB3-FLOATING-PRAGMA", f"Floating pragma ({ver}): deployed bytecode may differ from what was audited", "code_smell", "low", "smart-contract", rel, 1, f"pragma solidity {ver};", "Pin the exact compiler (e.g. `pragma solidity 0.8.24;`) for deployable contracts", 5, cwe=["CWE-1104"]))
        for name, ln, hdr, body, mods in _functions(t):
            vis = "public" if "public" in mods else "external" if "external" in mods else ""
            view = bool(re.search(r"\b(view|pure)\b", mods))
            guarded = bool(re.search(ACCESS_MODS, mods)) or bool(re.search(r"require\s*\(\s*msg\.sender\s*==|if\s*\(\s*msg\.sender\s*!=|_checkOwner\(\)|hasRole\(", body))
            sends = bool(re.search(r"\.call\s*\{[^}]*value|\.transfer\s*\(|\.send\s*\(|payable\([^)]*\)\.(transfer|send|call)|safeTransfer\w*\(|_mint\(|_burn\(|selfdestruct\(|\.delegatecall\(", body))
            ext_calls += len(re.findall(r"\.call\s*[({]|\.delegatecall\(|\.staticcall\(", body))
            if vis and not view and not guarded and sends and name not in ("receive", "fallback", "deposit", "constructor") and not re.search(r"\b(balances?|_balances|deposits?)\s*\[\s*msg\.sender\s*\]", body):
                out.append(_f("WEB3-NO-ACCESS-CONTROL", f"`{name}()` moves value/mints/burns/selfdestructs but has no visible access control", "vulnerability", "high", "access-control", rel, ln, hdr.strip()[:200], "Restrict with onlyOwner/onlyRole (OpenZeppelin AccessControl) or verify msg.sender against the caller's own balance/allowance", 60, status="confirmed", cwe=["CWE-284"]))
            if name in ("initialize", "init", "__init") and vis and not re.search(r"initializer|reinitializer|onlyProxy|_initialized|Initializable", hdr + body + t[:3000]):
                out.append(_f("WEB3-UNPROTECTED-INIT", f"`{name}()` can be called by anyone and more than once", "vulnerability", "critical", "access-control", rel, ln, hdr.strip()[:200], "Use OpenZeppelin `initializer`; call `_disableInitializers()` in the implementation constructor", 45, cwe=["CWE-665"]))
            # reentrancy: external value call then state write
            m = re.search(r"\.call\s*\{[^}]*value[^}]*\}\s*\(|\.call\.value\(|\.send\s*\(|\.transfer\s*\(|safeTransfer\w*\(", body)
            if m and not view and "nonReentrant" not in mods and "nonReentrant" not in body:
                after = body[m.end():]
                if re.search(r"\b\w+(\[[^\]]+\])*\s*(-=|\+=|=(?!=))\s*[^=]|\bdelete\s+\w+", after):
                    out.append(_f("WEB3-REENTRANCY", f"`{name}()` updates state AFTER an external call (reentrancy)", "vulnerability", "high", "reentrancy", rel, ln, (body[max(0, m.start() - 60):m.end() + 120]).strip().replace("\n", " ")[:260], "Checks-Effects-Interactions: update balances before the call, and add OpenZeppelin `nonReentrant`", 60, status="confirmed", cwe=["CWE-841"]))
            if re.search(r"\.call\s*[({]", body) and not re.search(r"\(\s*bool\s+\w+\s*,[^)]*\)\s*=\s*[^;]*\.call|require\s*\(\s*\w*success|if\s*\(\s*!\s*\w*success|\.functionCall|Address\.sendValue", body):
                out.append(_f("WEB3-UNCHECKED-CALL", f"`{name}()` ignores the return value of a low-level call", "bug", "high", "smart-contract", rel, ln, "low-level .call without checking `success`", "Capture `(bool ok, ) = addr.call{...}(...)` and `require(ok)` (or use Address.sendValue)", 20, cwe=["CWE-252"]))
            if re.search(r"\b(?<!\.)transfer\s*\(\s*\w+\s*,", body) and re.search(r"IERC20|ERC20|token\w*\.transfer(From)?\(", body) and "safeTransfer" not in body and not re.search(r"require\s*\([^;]*transfer", body):
                out.append(_f("WEB3-UNCHECKED-ERC20", f"`{name}()` uses ERC-20 transfer without checking the result (use SafeERC20)", "bug", "medium", "smart-contract", rel, ln, "token.transfer(...) return value unchecked", "Use `using SafeERC20 for IERC20;` and `safeTransfer/safeTransferFrom`", 20, cwe=["CWE-252"]))
            if re.search(r"block\.(timestamp|difficulty|prevrandao|number)|blockhash\(", body) and re.search(r"rand|winner|lottery|seed|shuffle|pick", name + body, re.I):
                out.append(_f("WEB3-WEAK-RANDOMNESS", f"`{name}()` derives randomness from block data (miner/validator-influenced)", "vulnerability", "high", "randomness", rel, ln, "block.timestamp/prevrandao used for randomness", "Use Chainlink VRF (or commit-reveal); never block data for value-bearing randomness", 120, cwe=["CWE-330"]))
            if re.search(r"ecrecover\(", body) and not re.search(r"nonce|used\w*\[|chainid|EIP712|_hashTypedDataV4|ECDSA\.recover|address\(0\)", body):
                out.append(_f("WEB3-SIG-REPLAY", f"`{name}()` recovers a signature without nonce/domain separation or zero-address check", "vulnerability", "high", "signature", rel, ln, "raw ecrecover", "Use EIP-712 typed data + OpenZeppelin ECDSA/SignatureChecker with a per-signer nonce, deadline and chainId", 90, cwe=["CWE-347", "CWE-294"]))
            if re.search(r"\.delegatecall\(", body) and not guarded: out.append(_f("WEB3-DELEGATECALL", f"`{name}()` performs delegatecall without access control", "vulnerability", "critical", "smart-contract", rel, ln, "delegatecall in unguarded function", "Never delegatecall to user-supplied addresses; restrict and validate the target", 90, cwe=["CWE-829"]))
            if re.search(r"getReserves\(\)|slot0\(\)|balanceOf\(address\(this\)\)", body) and re.search(r"price|rate|quote|collateral|borrow", name + body, re.I) and not re.search(r"twap|observe\(|latestRoundData|AggregatorV3|oracle", body, re.I):
                out.append(_f("WEB3-SPOT-PRICE", f"`{name}()` prices from a spot AMM reserve/balance (flash-loan manipulable)", "vulnerability", "high", "oracle", rel, ln, "price derived from reserves/balance", "Use a manipulation-resistant oracle (Chainlink, TWAP) with staleness and deviation checks", 120, status="confirmed", cwe=["CWE-807"]))
            if "latestRoundData" in body and not re.search(r"updatedAt|answeredInRound|stale|timestamp", body): out.append(_f("WEB3-ORACLE-STALE", f"`{name}()` reads Chainlink latestRoundData without staleness/validity checks", "vulnerability", "medium", "oracle", rel, ln, "latestRoundData()", "Check `answer > 0`, `updatedAt` freshness and `answeredInRound >= roundId`", 30, cwe=["CWE-754"]))
        if re.search(r"\btx\.origin\b", t): out.append(_f("WEB3-TX-ORIGIN", "tx.origin used for authorization (phishing via intermediate contract)", "vulnerability", "high", "access-control", rel, text_line(t, r"tx\.origin"), "tx.origin", "Use msg.sender", 15, cwe=["CWE-477"]))
        if re.search(r"\bselfdestruct\s*\(", t): out.append(_f("WEB3-SELFDESTRUCT", "selfdestruct present (deprecated; can brick dependents / drain funds)", "security_hotspot", None, "smart-contract", rel, text_line(t, r"selfdestruct"), "selfdestruct", "Remove it; use pausing/withdraw patterns", 30, status="needs_validation", priority="high", why="EIP-6780 limits it post-Dencun, but funds-forcing and logic risks remain"))
        if re.search(r"\bassembly\s*\{", t): out.append(_f("WEB3-ASSEMBLY", "Inline assembly (bypasses Solidity safety checks)", "security_hotspot", None, "smart-contract", rel, text_line(t, r"assembly\s*\{"), "assembly { ... }", "Isolate, document invariants and fuzz-test; prefer audited libraries", 60, status="needs_validation", priority="medium", why="may be a gas optimization from an audited library"))
        if re.search(r"UpgradeableProxy|UUPSUpgradeable|Initializable|TransparentUpgradeableProxy", t) and not re.search(r"_disableInitializers\(\)", t) and re.search(r"^\s*constructor", t, re.M) is None and re.search(r"Initializable", t):
            out.append(_f("WEB3-IMPL-INIT", "Upgradeable implementation without _disableInitializers() in constructor", "vulnerability", "medium", "access-control", rel, 1, "no _disableInitializers()", "Add `constructor() { _disableInitializers(); }` to the implementation", 10, cwe=["CWE-665"]))
        owner_fns = [n for n, l, h, b, mo in _functions(t) if re.search(r"onlyOwner|onlyRole\(\s*DEFAULT_ADMIN", mo) and re.search(r"withdraw|drain|rescue|setFee|pause|mint|upgrade|setOracle|blacklist|setRouter", n, re.I)]
        if len(owner_fns) >= 3: out.append(_f("WEB3-CENTRALIZATION", f"{len(owner_fns)} privileged functions controlled by a single owner/admin ({', '.join(owner_fns[:4])})", "security_hotspot", None, "centralization", rel, 1, ", ".join(owner_fns[:8]), "Use a multisig + timelock; document the trust model; cap fee/parameter ranges", 90, status="needs_validation", priority="medium", why="acceptable for early-stage protocols if disclosed - decide and document"))
    info.update(contracts=contracts, pragmas=dict(pragmas), external_calls=ext_calls)
    # Solana / Anchor
    for rel, ab in rs[:200]:
        try: t = open(ab, errors="ignore", encoding="utf-8").read(300_000)
        except OSError: continue
        if re.search(r"AccountInfo<'info>|UncheckedAccount<'info>", t) and not re.search(r"CHECK:", t): out.append(_f("WEB3-SOL-UNCHECKED-ACCOUNT", "Anchor UncheckedAccount/AccountInfo without a `/// CHECK:` justification (missing owner/signer validation)", "vulnerability", "high", "access-control", rel, text_line(t, r"AccountInfo<'info>|UncheckedAccount<'info>"), "UncheckedAccount", "Prefer typed `Account<'info, T>` + `Signer<'info>`; add `has_one`/`constraint`/`seeds` checks", 60, cwe=["CWE-284"]))
        if re.search(r"invoke_signed\(|invoke\(", t) and not re.search(r"require_keys_eq|constraint\s*=|has_one|key\(\)\s*==", t): out.append(_f("WEB3-SOL-CPI", "Cross-program invocation without verifying the target program id / accounts", "security_hotspot", None, "access-control", rel, text_line(t, r"invoke"), "invoke/invoke_signed", "Validate program ids and account ownership before CPI", 60, status="needs_validation", priority="high", why="may be validated in an outer constraint"))
        if re.search(r"\bunsafe\b", t): out.append(_f("WEB3-SOL-UNSAFE", "unsafe block in on-chain program", "security_hotspot", None, "memory-safety", rel, text_line(t, r"\bunsafe\b"), "unsafe", "Remove or justify; fuzz with Trident", 60, status="needs_validation", priority="medium"))
    if not (sol or rs) and not web3js: return out, info
    # project-level
    if sol and not any(re.search(r"(^|/)(test|tests)/.*\.(t\.sol|js|ts|sol|rs)$|\.t\.sol$", r) for r, *_ in files): out.append(_f("WEB3-NO-TESTS", "Smart contracts without tests", "test_gap", "high", "test-infra", ".", 1, f"{len(sol)} .sol files, no test directory", "Add Foundry/Hardhat tests incl. fuzz/invariant tests and fork tests; target ≥ 95 % line + branch coverage", 480))
    if sol and not any(re.search(r"slither|echidna|medusa|mythril|certora|halmos|scribble", open(a, errors="ignore", encoding="utf-8").read(60_000), re.I) for r, a, e, _ in files if e in ("yml", "yaml", "toml", "json") and ("workflow" in r or "foundry" in r or "package" in r)): out.append(_f("WEB3-NO-STATIC-ANALYSIS", "No Slither/Echidna/Medusa/Certora in CI", "test_gap", "low", "test-infra", ".", 1, "", "Run `slither .` and fuzzing (forge invariants/Echidna) on every PR; get an external audit before mainnet", 90))
    return out, info


def text_line(t, rx):
    m = re.search(rx, t)
    return t[:m.start()].count("\n") + 1 if m else 1
