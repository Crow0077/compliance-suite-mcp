#!/usr/bin/env python3
"""Compliance Suite MCP — Enterprise Audit & Security. See README.md for docs."""
import asyncio, json, hashlib, os
from datetime import datetime, timedelta
from pathlib import Path
import httpx
from mcp.server.fastmcp import FastMCP

AUDITOR_URL = os.environ.get("COMPLIANCE_AUDITOR_URL", "http://localhost:8100/mcp")
FORENSICS_URL = os.environ.get("INCIDENT_FORENSICS_URL", "http://localhost:8101/mcp")
DATA_DIR = Path(os.environ.get("COMPLIANCE_DATA_DIR", os.path.expanduser("~/.compliance-suite")))
AUDIT_TRAIL_DIR = DATA_DIR / "audit-trail"
AUDIT_TRAIL_DIR.mkdir(parents=True, exist_ok=True)
SCAN_HISTORY_DIR = DATA_DIR / "scans"
SCAN_HISTORY_DIR.mkdir(parents=True, exist_ok=True)
PORT = int(os.environ.get("COMPLIANCE_PORT", "8111"))
mcp = FastMCP("compliance-suite", host="0.0.0.0", port=PORT)

def sign_entry(entry: dict) -> str:
    chain_file = AUDIT_TRAIL_DIR / "chain.jsonl"
    prev_hash = "0" * 64
    if chain_file.exists():
        lines = chain_file.read_text().strip().split("\n")
        if lines:
            try: prev_hash = json.loads(lines[-1]).get("hash", prev_hash)
            except: pass
    entry["timestamp"] = datetime.now().isoformat()
    entry["prev_hash"] = prev_hash
    entry["hash"] = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
    with open(chain_file, "a") as f: f.write(json.dumps(entry) + "\n")
    return entry["hash"]

async def call_mcp_tool(url: str, tool_name: str, args: dict = None) -> dict:
    async with httpx.AsyncClient(timeout=30) as client:
        init_resp = await client.post(url, json={
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "compliance-suite", "version": "1.0"}}
        }, headers={"Accept": "application/json, text/event-stream"})
        session_id = init_resp.headers.get("mcp-session-id", "")
        headers = {"Accept": "application/json, text/event-stream"}
        if session_id: headers["mcp-session-id"] = session_id
        resp = await client.post(url, json={
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": tool_name, "arguments": args or {}}
        }, headers=headers)
        try: data = resp.json()
        except: data = None
        if data is None:
            for line in resp.text.split("\n"):
                if line.startswith("data:"):
                    try: data = json.loads(line[5:].strip()); break
                    except: continue
        if data and "result" in data: return {"success": True, "data": data["result"]}
        elif data and "error" in data: return {"success": False, "error": str(data["error"])}
        return {"success": False, "error": f"No result: {resp.text[:200]}"}

@mcp.tool()
async def compliance_full_audit(target_host: str = "localhost", benchmark: str = "cis_level1") -> str:
    """Run complete compliance audit: CIS + CVE + ports + firewall + SSH. Returns report with scores."""
    tasks = [
        call_mcp_tool(AUDITOR_URL, "compliance_scan", {"target_host": target_host, "benchmark": benchmark}),
        call_mcp_tool(AUDITOR_URL, "cve_check", {"target_host": target_host}),
        call_mcp_tool(AUDITOR_URL, "port_audit", {"target_host": target_host}),
        call_mcp_tool(AUDITOR_URL, "firewall_audit", {"target_host": target_host}),
        call_mcp_tool(AUDITOR_URL, "ssh_audit", {"target_host": target_host}),
    ]
    names = ["cis_scan", "cve_check", "port_audit", "firewall_audit", "ssh_audit"]
    gathered = await asyncio.gather(*tasks)
    results = dict(zip(names, gathered))
    entry = {"action": "full_audit", "target": target_host, "benchmark": benchmark,
             "results_summary": {k: "ok" if v.get("success") else "failed" for k, v in results.items()}}
    trail_hash = sign_entry(entry)
    report = f"=== COMPLIANCE AUDIT REPORT ===\nTarget: {target_host}\nBenchmark: {benchmark}\nAudit Trail: {trail_hash[:16]}...\n\n"
    for name, result in results.items():
        status = "✓" if result.get("success") else "✗"
        report += f"\n--- {name.upper()} {status} ---\n"
        if result.get("success"):
            data = result["data"]
            if isinstance(data, dict) and "content" in data:
                for c in data["content"]:
                    if c.get("type") == "text": report += c["text"] + "\n"
            elif isinstance(data, dict): report += json.dumps(data, indent=2) + "\n"
            else: report += str(data) + "\n"
        else: report += f"Error: {result.get('error')}\n"
    scan_file = SCAN_HISTORY_DIR / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    scan_file.write_text(json.dumps({"report": report, "results": results, "trail": entry}, indent=2))
    return report

@mcp.tool()
async def compliance_scorecard(target_host: str = "localhost") -> str:
    """Executive scorecard — risk level + scores per category."""
    results = await asyncio.gather(
        call_mcp_tool(AUDITOR_URL, "compliance_scan", {"target_host": target_host, "benchmark": "cis_level1"}),
        call_mcp_tool(AUDITOR_URL, "cve_check", {"target_host": target_host}), return_exceptions=True)
    scorecard = {"target": target_host, "timestamp": datetime.now().isoformat(), "scores": {}}
    if not isinstance(results[0], Exception) and results[0].get("success"):
        data = results[0]["data"]
        if isinstance(data, dict) and "content" in data:
            for c in data["content"]:
                if c.get("type") == "text":
                    for line in c["text"].split("\n"):
                        if "score" in line.lower(): scorecard["scores"]["cis_compliance"] = line.strip(); break
    if not isinstance(results[1], Exception) and results[1].get("success"):
        data = results[1]["data"]
        if isinstance(data, dict) and "content" in data:
            for c in data["content"]:
                if c.get("type") == "text":
                    scorecard["scores"]["cve_count"] = c["text"].count("CVE-"); break
    cve_count = scorecard["scores"].get("cve_count", 0)
    scorecard["risk_level"] = "CRITICAL" if cve_count > 10 else ("HIGH" if cve_count > 5 else ("MEDIUM" if cve_count > 0 else "LOW"))
    sign_entry({"action": "scorecard", "target": target_host, "risk": scorecard["risk_level"]})
    return json.dumps(scorecard, indent=2)

@mcp.tool()
async def audit_trail_query(hours: int = 24, action: str = "") -> str:
    """Query cryptographic audit trail with chain verification."""
    chain_file = AUDIT_TRAIL_DIR / "chain.jsonl"
    if not chain_file.exists(): return "No audit trail entries yet."
    cutoff = datetime.now() - timedelta(hours=hours)
    entries, prev_hash, chain_valid = [], "0" * 64, True
    for line in chain_file.read_text().strip().split("\n"):
        try:
            entry = json.loads(line)
            if entry.get("prev_hash") != prev_hash: chain_valid = False
            prev_hash = entry.get("hash", "")
            if datetime.fromisoformat(entry["timestamp"]) >= cutoff:
                if not action or action.lower() in entry.get("action", "").lower(): entries.append(entry)
        except: pass
    result = f"Audit Trail (last {hours}h): {len(entries)} entries\nChain integrity: {'✓ VALID' if chain_valid else '✗ BROKEN'}\n\n"
    for e in entries[-20:]: result += f"[{e['timestamp'][:19]}] {e.get('action','?')} | hash: {e.get('hash','')[:12]}\n"
    sign_entry({"action": "audit_trail_query", "hours": hours, "filter": action})
    return result

@mcp.tool()
async def scheduled_scan_diff(days: int = 7) -> str:
    """Compare latest scan with previous — SOC 2 continuous monitoring evidence."""
    scans = sorted(SCAN_HISTORY_DIR.glob("scan_*.json"))
    if len(scans) < 2: return "Need at least 2 scans. Run compliance_full_audit first."
    latest, older = json.loads(scans[-1].read_text()), json.loads(scans[-2].read_text())
    report = f"=== COMPLIANCE DIFF REPORT ===\nNow: {scans[-1].stem}\nThen: {scans[-2].stem}\n\n"
    for key in latest.get("results", {}):
        now_ok = latest["results"][key].get("success", False)
        then_ok = older["results"].get(key, {}).get("success", False)
        if now_ok and not then_ok: report += f"🟢 {key}: IMPROVED\n"
        elif not now_ok and then_ok: report += f"🔴 {key}: DEGRADED\n"
        elif now_ok: report += f"⚪ {key}: Unchanged (passing)\n"
        else: report += f"⚪ {key}: Unchanged (failing)\n"
    sign_entry({"action": "scan_diff", "days": days})
    return report

@mcp.tool()
async def incident_forensic_report(incident_id: int) -> str:
    """Generate incident post-mortem from forensics data."""
    result = await call_mcp_tool(FORENSICS_URL, "incident_report", {"incident_id": incident_id})
    report = f"=== INCIDENT POST-MORTEM #{incident_id} ===\nGenerated: {datetime.now().isoformat()}\n\n"
    if result.get("success"):
        data = result["data"]
        if isinstance(data, dict) and "content" in data:
            for c in data["content"]:
                if c.get("type") == "text": report += c["text"] + "\n"
        else: report += json.dumps(data, indent=2)
    else: report += f"Error: {result.get('error')}"
    sign_entry({"action": "forensic_report", "incident_id": incident_id})
    return report

@mcp.tool()
async def compliance_export(format: str = "json", days: int = 30) -> str:
    """Export SOC 2 evidence package for auditors."""
    scans = sorted(SCAN_HISTORY_DIR.glob("scan_*.json"))
    cutoff = datetime.now() - timedelta(days=days)
    export = {"export_date": datetime.now().isoformat(), "period": f"{days} days", "node": os.uname().nodename, "total_scans": len(scans), "scans": [], "audit_trail": []}
    for sf in scans:
        try:
            data = json.loads(sf.read_text())
            ts = sf.stem.replace("scan_", "")
            if datetime.strptime(ts[:8], "%Y%m%d") >= cutoff.replace(hour=0, minute=0, second=0):
                export["scans"].append({"timestamp": ts, "results": {k: "pass" if v.get("success") else "fail" for k, v in data.get("results", {}).items()}})
        except: pass
    chain_file = AUDIT_TRAIL_DIR / "chain.jsonl"
    if chain_file.exists():
        for line in chain_file.read_text().strip().split("\n"):
            try:
                entry = json.loads(line)
                if datetime.fromisoformat(entry["timestamp"]) >= cutoff:
                    export["audit_trail"].append({"time": entry["timestamp"], "action": entry.get("action"), "hash": entry.get("hash","")[:16]})
            except: pass
    sign_entry({"action": "export", "format": format, "days": days})
    if format == "summary":
        return f"=== SOC 2 EVIDENCE PACKAGE ===\nPeriod: Last {days} days\nTotal Scans: {len(export['scans'])}\nAudit Trail Entries: {len(export['audit_trail'])}\nChain Integrity: {'✓ Verified' if _verify_chain() else '✗ Broken'}\n"
    return json.dumps(export, indent=2)

def _verify_chain() -> bool:
    chain_file = AUDIT_TRAIL_DIR / "chain.jsonl"
    if not chain_file.exists(): return True
    prev_hash = "0" * 64
    for line in chain_file.read_text().strip().split("\n"):
        try:
            entry = json.loads(line)
            if entry.get("prev_hash") != prev_hash: return False
            prev_hash = entry.get("hash", "")
        except: return False
    return True

@mcp.tool()
async def compliance_status() -> str:
    """Health check — are all compliance subsystems operational?"""
    results = await asyncio.gather(
        call_mcp_tool(AUDITOR_URL, "compliance_scan", {"target_host": "localhost", "benchmark": "cis_level1"}),
        call_mcp_tool(FORENSICS_URL, "recent_incidents", {"hours": 1}), return_exceptions=True)
    status = {
        "compliance_auditor": "UP" if not isinstance(results[0], Exception) and results[0].get("success") else "DOWN",
        "incident_forensics": "UP" if not isinstance(results[1], Exception) and results[1].get("success") else "DOWN",
        "audit_trail": f"{_count_trail_entries()} entries", "chain_valid": _verify_chain(),
        "scans_stored": len(list(SCAN_HISTORY_DIR.glob("scan_*.json")))}
    return json.dumps(status, indent=2)

def _count_trail_entries() -> int:
    chain_file = AUDIT_TRAIL_DIR / "chain.jsonl"
    return len(chain_file.read_text().strip().split("\n")) if chain_file.exists() else 0

if __name__ == "__main__":
    print(f"Compliance Suite MCP starting on port {PORT}...")
    mcp.run(transport="streamable-http")
