"""Minimal stdio MCP (JSON-RPC 2.0, newline-delimited) server exposing PN-Ultra-Audit results to AI assistants.
Read-only: it serves findings from existing runs and the knowledge base; it never scans or modifies anything by itself."""
import json, os, sys

from . import kbsearch, corpus

PROTO = "2024-11-05"
TOOLS = [
    dict(name="list_findings", description="List findings of the latest audit run (compact rows). Filter by severity, status or text.",
         inputSchema=dict(type="object", properties=dict(severity=dict(type="string", description="critical|high|medium|low|info"), status=dict(type="string", description="confirmed|needs_validation|hotspot"),
                                                         query=dict(type="string"), limit=dict(type="integer", default=25)))),
    dict(name="get_fix_card", description="Compact fix card for ONE finding id (snippet, steps, safe example, tested before/after, verify). Use instead of reading whole files.",
         inputSchema=dict(type="object", properties=dict(id=dict(type="string")), required=["id"])),
    dict(name="search_kb", description="Search the offline remediation knowledge base (BM25) and rule catalog; returns the best matching guide.",
         inputSchema=dict(type="object", properties=dict(query=dict(type="string"), limit=dict(type="integer", default=5)), required=["query"])),
    dict(name="get_summary", description="Score, ratings, gate and counts of the latest run.", inputSchema=dict(type="object", properties={})),
    dict(name="verify_corpus", description="Run the self-check: every tested vulnerable/fixed pair must fire on the flaw and stay silent on the fix.", inputSchema=dict(type="object", properties={})),
]


def _run(root):
    r = kbsearch.latest_run(root)
    if not r: raise ValueError("no audit run found under " + root + " (run: python3 audit.py <project>)")
    return r


def call(name, args, root):
    if name == "list_findings":
        fs = kbsearch.load_findings(_run(root)); sev, st, q = args.get("severity"), args.get("status"), (args.get("query") or "").lower()
        rows = [f for f in fs if (not sev or f.get("severity") == sev) and (not st or f.get("status") == st) and (not q or q in json.dumps(f, default=str).lower())]
        order = ["critical", "high", "medium", "low", "info"]; rows.sort(key=lambda f: order.index(f.get("severity")) if f.get("severity") in order else 9)
        lim = int(args.get("limit") or 25)
        out = [f"{f['id']}  {f.get('severity'):<8} {f.get('status'):<16} {f.get('rule'):<18} {(f.get('location') or {}).get('file')}:{(f.get('location') or {}).get('line')}  {f.get('title')}" for f in rows[:lim]]
        return f"{len(rows)} findings (showing {len(out)})\n" + "\n".join(out)
    if name == "get_fix_card":
        f = kbsearch.find(kbsearch.load_findings(_run(root)), args.get("id", ""))
        if not f: raise ValueError("finding not found: " + str(args.get("id")))
        return kbsearch.card(f)
    if name == "search_kb": return kbsearch.format_results(args.get("query", ""), int(args.get("limit") or 5))
    if name == "get_summary":
        p = os.path.join(_run(root), "summary.json")
        return open(p, encoding="utf-8").read() if os.path.isfile(p) else "summary.json not found"
    if name == "verify_corpus":
        r = corpus.verify(); bad = [x for x in r if not x["ok"]]
        return f"{len(r) - len(bad)}/{len(r)} pairs verified" + ("" if not bad else "\nFAILING: " + ", ".join(x["id"] for x in bad))
    raise ValueError("unknown tool: " + str(name))


def handle(msg, root):
    mid, method = msg.get("id"), msg.get("method")
    if method == "initialize":
        return dict(jsonrpc="2.0", id=mid, result=dict(protocolVersion=PROTO, capabilities=dict(tools={}), serverInfo=dict(name="pn-ultra-audit", version="1")))
    if method == "tools/list": return dict(jsonrpc="2.0", id=mid, result=dict(tools=TOOLS))
    if method == "tools/call":
        p = msg.get("params") or {}
        try: txt, err = call(p.get("name"), p.get("arguments") or {}, root), False
        except Exception as e: txt, err = f"error: {e}", True
        return dict(jsonrpc="2.0", id=mid, result=dict(content=[dict(type="text", text=txt)], isError=err))
    if method == "ping": return dict(jsonrpc="2.0", id=mid, result={})
    if mid is None: return None  # notification
    return dict(jsonrpc="2.0", id=mid, error=dict(code=-32601, message="method not found: " + str(method)))


def serve(root):
    for line in sys.stdin:
        line = line.strip()
        if not line: continue
        try: msg = json.loads(line)
        except ValueError:
            print(json.dumps(dict(jsonrpc="2.0", id=None, error=dict(code=-32700, message="parse error"))), flush=True); continue
        resp = handle(msg, root)
        if resp is not None: print(json.dumps(resp), flush=True)
