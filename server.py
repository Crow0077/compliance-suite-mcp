#!/usr/bin/env python3
"""
Compliance Suite MCP v2.1 — Self-contained enterprise audit & security for AI agents.
Runs entirely standalone. No external MCP dependencies. Deploy anywhere.
Works on Debian/Ubuntu (apt, ufw) and Fedora/RHEL (dnf, firewalld).

7 tools: full_audit, scorecard, audit_trail, scan_diff, forensic_report, export, status
"""
import asyncio, json, hashlib, os, re, subprocess
from datetime import datetime, timedelta
from pathlib import Path
from mcp.server.fastmcp import FastMCP

DATA_DIR = Path(os.environ.get("COMPLIANCE_DATA_DIR", os.path.expanduser("~/.compliance-suite")))
AUDIT_TRAIL_DIR = DATA_DIR / "audit-trail"
SCAN_HISTORY_DIR = DATA_DIR / "scans"
for d in [AUDIT_TRAIL_DIR, SCAN_HISTORY_DIR]: d.mkdir(parents=True, exist_ok=True)
PORT = int(os.environ.get("PORT", os.environ.get("COMPLIANCE_PORT", "8111")))
mcp = FastMCP("compliance-suite", host="0.0.0.0", port=PORT)

def sign_entry(entry: dict) -> str:
    f = AUDIT_TRAIL_DIR / "chain.jsonl"
    prev = "0"*64
    if f.exists():
        lines = f.read_text().strip().split("\n")
        if lines:
            try: prev = json.loads(lines[-1]).get("hash", prev)
            except: pass
    entry["timestamp"] = datetime.now().isoformat()
    entry["prev_hash"] = prev
    entry["hash"] = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
    with open(f, "a") as fh: fh.write(json.dumps(entry)+"\n")
    return entry["hash"]

def cmd(c: str, t: int = 15) -> dict:
    try:
        r = subprocess.run(c, shell=True, capture_output=True, text=True, timeout=t)
        return {"ok": r.returncode==0, "out": r.stdout.strip(), "err": r.stderr.strip(), "code": r.returncode}
    except: return {"ok": False, "out": "", "err": "timeout", "code": -1}

def scan_cis():
    c = []
    r = cmd("systemctl is-active firewalld 2>/dev/null || systemctl is-active ufw 2>/dev/null || echo inactive")
    c.append({"cat":"Firewall","check":"Firewall active","r":"pass" if "active" in r["out"] else "fail","sev":"critical","d":r["out"],"fix":"sudo systemctl enable --now firewalld || sudo ufw enable"})
    r = cmd("(apt list --upgradable 2>/dev/null | grep -i security | wc -l) || (dnf check-update --security 2>/dev/null | wc -l) || echo 0", 30)
    p = int(r["out"].strip()) if r["out"].strip().isdigit() else 0
    c.append({"cat":"Updates","check":"Updates current","r":"pass" if p<=1 else "fail","sev":"high","d":f"{max(0,p-1)} pending","fix":"sudo apt upgrade -y || sudo dnf update --security -y"})
    r = cmd("sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null | awk '{print $3}'")
    c.append({"cat":"Kernel","check":"ICMP redirects","r":"pass" if r["out"]=="0" else "fail","sev":"high","d":r["out"],"fix":"sysctl net.ipv4.conf.all.accept_redirects=0"})
    r = cmd("sysctl net.ipv4.conf.all.accept_source_route 2>/dev/null | awk '{print $3}'")
    c.append({"cat":"Kernel","check":"Source routing","r":"pass" if r["out"]=="0" else "fail","sev":"high","d":r["out"],"fix":"sysctl net.ipv4.conf.all.accept_source_route=0"})
    r = cmd("grep -E '^PASS_MAX_DAYS|^PASS_MIN_LEN' /etc/login.defs 2>/dev/null || echo none")
    c.append({"cat":"Auth","check":"Password policy","r":"pass" if "PASS_MAX_DAYS" in r["out"] else "fail","sev":"med","d":r["out"][:200],"fix":"Configure /etc/login.defs"})
    r = cmd("journalctl -u sshd --since '24h ago' 2>/dev/null | grep -ci failed || echo 0")
    f = int(r["out"].strip()) if r["out"].strip().isdigit() else 0
    c.append({"cat":"Auth","check":"Brute force","r":"pass" if f<10 else "fail","sev":"high","d":f"{f} failed logins","fix":"sudo apt install fail2ban -y || sudo dnf install fail2ban -y"})
    r = cmd("getenforce 2>/dev/null || echo Disabled")
    c.append({"cat":"Access","check":"SELinux/AppArmor","r":"pass" if "Enforcing" in r["out"] else "fail","sev":"high","d":r["out"],"fix":"sudo setenforce 1 || sudo aa-enforce /etc/apparmor.d/*"})
    r = cmd("sysctl fs.suid_dumpable 2>/dev/null | awk '{print $3}'")
    c.append({"cat":"Kernel","check":"Core dumps","r":"pass" if r["out"]=="0" else "fail","sev":"med","d":r["out"],"fix":"sysctl fs.suid_dumpable=0"})
    passed = sum(1 for x in c if x["r"]=="pass")
    return {"score": round(passed/max(len(c),1)*100,1), "passed": passed, "failed": len(c)-passed, "total": len(c), "findings": c}

def scan_cve():
    r = cmd("(apt list --upgradable 2>/dev/null; dnf updateinfo list --security 2>/dev/null) | grep -i 'CVE-' | head -20 || echo ''", 30)
    cves = []
    for line in r["out"].split("\n"):
        if "CVE-" in line.upper():
            parts = line.split()
            for p in parts:
                if "CVE-" in p.upper(): cves.append({"id": p, "sev": "?"}); break
    return {"found": len(cves), "cves": cves}

def scan_ports():
    r = cmd("ss -tlnp 2>/dev/null | tail -n +2")
    ports, finds = [], []
    risky = {22:"SSH",21:"FTP",23:"Telnet",3306:"MySQL",5432:"PostgreSQL",6379:"Redis",27017:"MongoDB",3389:"RDP"}
    for line in r["out"].split("\n"):
        if "LISTEN" not in line: continue
        p = line.split()
        if len(p) < 4: continue
        addr = p[3]
        if ":" in addr:
            ps = addr.split(":")[-1]
            if ps.isdigit():
                pt = int(ps)
                proc = p[-1].split('"')[0] if '"' in p[-1] else "?"
                ports.append({"port": pt, "proc": proc})
                risk = "high" if pt in [21,23,3389] else ("med" if pt in [3306,5432,6379,27017] and "127.0.0.1" not in addr else "low")
                if risk != "low": finds.append({"port": pt, "proc": proc, "risk": risk})
    return {"total": len(ports), "ports": ports, "findings": finds}

def scan_fw():
    r = cmd("(firewall-cmd --state 2>/dev/null) || (ufw status 2>/dev/null | grep -q active && echo running) || echo 'not running'")
    a = "running" in r["out"].lower()
    d = {"active": a}
    if a:
        d["svc"] = cmd("(firewall-cmd --list-services 2>/dev/null) || (ufw status 2>/dev/null)")["out"]
    return {"active": a, "details": d}

def scan_ssh():
    r = cmd("systemctl is-active sshd 2>/dev/null || echo inactive")
    a = "active" in r["out"]
    cfg = ""
    for p in ["/etc/ssh/sshd_config","/etc/ssh/ssh_config"]:
        try: cfg = Path(p).read_text(); break
        except: pass
    if not cfg: return {"active": a, "issues": [{"check":"Config readable","r":"fail","d":"Permission denied"}]}
    iss = []
    iss.append({"check":"Root login","r":"fail" if re.search(r'^PermitRootLogin\s+yes',cfg,re.M) else "pass","sev":"critical","d":"PermitRootLogin yes" if re.search(r'^PermitRootLogin\s+yes',cfg,re.M) else "OK"})
    iss.append({"check":"Password auth","r":"fail" if re.search(r'^PasswordAuthentication\s+yes',cfg,re.M) else "pass","sev":"high"})
    iss.append({"check":"Empty passwords","r":"fail" if re.search(r'^PermitEmptyPasswords\s+yes',cfg,re.M) else "pass","sev":"critical"})
    return {"active": a, "issues": iss}

def scan_incidents():
    r = cmd("journalctl -p err --since '24h ago' --no-pager 2>/dev/null | wc -l", 15)
    e = int(r["out"].strip()) if r["out"].strip().isdigit() else 0
    return {"errors": e, "incidents": 1 if e > 50 else 0}

@mcp.tool()
async def compliance_full_audit(benchmark: str = "cis_level1") -> str:
    """Run complete 5-part compliance audit: CIS benchmark + CVE + ports + firewall + SSH. Returns scored report with fixes."""
    loop = asyncio.get_event_loop()
    tasks = [loop.run_in_executor(None, f) for f in [scan_cis, scan_cve, scan_ports, scan_fw, scan_ssh]]
    names = ["cis","cve","ports","fw","ssh"]
    results = dict(zip(names, await asyncio.gather(*tasks)))
    entry = {"action":"full_audit","benchmark":benchmark,"summary":{"cis":results["cis"]["score"],"cves":results["cve"]["found"],"ports":results["ports"]["total"],"fw":results["fw"]["active"],"ssh":results["ssh"]["active"]}}
    h = sign_entry(entry)
    rpt = f"=== COMPLIANCE AUDIT REPORT ===\nAudit Trail: {h[:16]}...\nTime: {datetime.now().isoformat()}\n\nCIS: {results['cis']['score']}% ({results['cis']['passed']}/{results['cis']['total']}) | CVEs: {results['cve']['found']} | Ports: {results['ports']['total']} | FW: {'ON' if results['fw']['active'] else 'OFF'}\n\n--- FINDINGS ---\n"
    for f in results["cis"]["findings"]:
        rpt += f"  {'✓' if f['r']=='pass' else '✗'} [{f['sev'].upper()}] {f['check']}: {f.get('d','')}\n"
        if f['r']=='fail' and 'fix' in f: rpt += f"    Fix: {f['fix']}\n"
    if results["cve"]["found"]: rpt += f"\n--- CVEs ({results['cve']['found']}) ---\n"
    for cve in results["cve"]["cves"][:10]: rpt += f"  {cve['id']} [{cve['sev']}]\n"
    rpt += f"\n--- PORTS ({results['ports']['total']}) ---\n"
    for f in results["ports"]["findings"]: rpt += f"  [{f['risk'].upper()}] {f['port']}:{f['proc']}\n"
    rpt += "\n--- SSH ---\n"
    for i in results["ssh"]["issues"]: rpt += f"  {'✓' if i['r']=='pass' else '✗'} {i['check']}\n"
    sf = SCAN_HISTORY_DIR / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    sf.write_text(json.dumps({"report":rpt,"results":{k:v for k,v in results.items()},"trail":entry}, indent=2, default=str))
    return rpt

@mcp.tool()
async def compliance_scorecard() -> str:
    """Executive scorecard: risk level + CIS score + CVE count. JSON, dashboard-ready."""
    loop = asyncio.get_event_loop()
    cis, cve = await asyncio.gather(loop.run_in_executor(None, scan_cis), loop.run_in_executor(None, scan_cve))
    n = cve["found"]
    risk = "CRITICAL" if n>10 else ("HIGH" if n>5 else ("MEDIUM" if n>0 else "LOW"))
    if cis["score"] < 30: risk = "HIGH"
    sc = {"risk": risk, "cis_pct": cis["score"], "cis_pass": cis["passed"], "cis_fail": cis["failed"], "cves": n, "ts": datetime.now().isoformat()}
    sign_entry({"action":"scorecard","risk":risk,"cis":cis["score"]})
    return json.dumps(sc, indent=2)

@mcp.tool()
async def audit_trail_query(hours: int = 24, action: str = "") -> str:
    """Query cryptographic audit trail — every action logged, linked, verifiable."""
    f = AUDIT_TRAIL_DIR / "chain.jsonl"
    if not f.exists(): return "No entries yet. Run compliance_full_audit."
    cut = datetime.now() - timedelta(hours=hours)
    entries, prev, ok = [], "0"*64, True
    for line in f.read_text().strip().split("\n"):
        if not line: continue
        try:
            e = json.loads(line)
            if e.get("prev_hash") != prev: ok = False
            prev = e.get("hash","")
            if datetime.fromisoformat(e["timestamp"]) >= cut:
                if not action or action.lower() in e.get("action","").lower(): entries.append(e)
        except: pass
    rpt = f"Audit Trail ({hours}h): {len(entries)} entries | Chain: {'✓ VALID' if ok else '✗ BROKEN'}\n\n"
    for e in entries[-20:]: rpt += f"[{e['timestamp'][:19]}] {e.get('action','?'):25s} | {e.get('hash','')[:12]}\n"
    sign_entry({"action":"trail_query","hours":hours})
    return rpt

@mcp.tool()
async def scheduled_scan_diff(days: int = 7) -> str:
    """Compare latest scan vs previous — SOC 2 continuous monitoring evidence."""
    scans = sorted(SCAN_HISTORY_DIR.glob("scan_*.json"))
    if len(scans) < 2: return "Need 2+ scans. Run compliance_full_audit twice."
    a, b = json.loads(scans[-1].read_text()), json.loads(scans[-2].read_text())
    rpt = f"=== DIFF ===\nLatest: {scans[-1].stem}\nCompare: {scans[-2].stem}\n\n"
    for k in ["cis","cve","fw","ports","ssh"]:
        if k not in a.get("results",{}): continue
        na, nb = a["results"][k], b["results"].get(k,{})
        if k == "cis":
            ns, os_ = na.get("score",0), nb.get("score",0)
            rpt += f"{'🟢' if ns>os_ else '🔴' if ns<os_ else '⚪'} CIS: {os_}% → {ns}%\n"
        elif k == "cve":
            nc, oc = na.get("found",0), nb.get("found",0)
            rpt += f"{'🟢' if nc<oc else '🔴' if nc>oc else '⚪'} CVEs: {oc} → {nc}\n"
        elif k == "fw":
            rpt += f"{'🟢' if na.get('active') and not nb.get('active') else '🔴' if not na.get('active') and nb.get('active') else '⚪'} FW: {'ON' if na.get('active') else 'OFF'}\n"
        elif k == "ports":
            np_, op_ = na.get("total",0), nb.get("total",0)
            rpt += f"{'🟢' if np_<op_ else '🔴' if np_>op_ else '⚪'} Ports: {op_} → {np_}\n"
    sign_entry({"action":"scan_diff","days":days})
    return rpt

@mcp.tool()
async def incident_forensic_report(hours: int = 24) -> str:
    """Scan recent logs for errors, auth failures, and suspicious activity."""
    loop = asyncio.get_event_loop()
    i = await loop.run_in_executor(None, scan_incidents)
    rpt = f"=== FORENSIC REPORT ===\nPeriod: {hours}h\nErrors: {i['errors']}\nIncidents: {i['incidents']}\n"
    rpt += "✓ Clean\n" if i['incidents']==0 else "⚠ Review needed\n"
    sign_entry({"action":"forensic","hours":hours})
    return rpt

@mcp.tool()
async def compliance_export(format: str = "json", days: int = 30) -> str:
    """Export SOC 2 evidence package for auditors — scan history + audit trail."""
    scans = sorted(SCAN_HISTORY_DIR.glob("scan_*.json"))
    cut = datetime.now() - timedelta(days=days)
    ex = {"date": datetime.now().isoformat(), "period": f"{days}d", "host": os.uname().nodename, "scans": [], "trail": []}
    for sf in scans:
        try:
            d = json.loads(sf.read_text())
            ts = sf.stem.replace("scan_","")
            if datetime.strptime(ts[:8],"%Y%m%d") >= cut.replace(hour=0,minute=0,second=0):
                r = d.get("results",{})
                ex["scans"].append({"ts":ts,"cis":r.get("cis",{}).get("score"),"cves":r.get("cve",{}).get("found"),"fw":r.get("fw",{}).get("active")})
        except: pass
    cf = AUDIT_TRAIL_DIR / "chain.jsonl"
    if cf.exists():
        for line in cf.read_text().strip().split("\n"):
            if not line: continue
            try:
                e = json.loads(line)
                if datetime.fromisoformat(e["timestamp"]) >= cut: ex["trail"].append({"time":e["timestamp"],"action":e.get("action")})
            except: pass
    sign_entry({"action":"export","format":format,"days":days})
    if format == "summary":
        return f"=== SOC 2 PACKAGE ===\n{ex['period']} | {ex['host']} | {len(ex['scans'])} scans | {len(ex['trail'])} trail entries\n"
    return json.dumps(ex, indent=2, default=str)

@mcp.tool()
async def compliance_status() -> str:
    """Quick health check: scans stored, trail size, chain integrity, firewall state."""
    cf = AUDIT_TRAIL_DIR / "chain.jsonl"
    tc = len(cf.read_text().strip().split("\n")) if cf.exists() else 0
    ok, prev = True, "0"*64
    if cf.exists():
        for line in cf.read_text().strip().split("\n"):
            if not line: continue
            try:
                e = json.loads(line)
                if e.get("prev_hash") != prev: ok = False; break
                prev = e.get("hash","")
            except: ok = False; break
    fw = cmd("(firewall-cmd --state 2>/dev/null) || (ufw status 2>/dev/null | grep -q active && echo running) || echo inactive")
    return json.dumps({"status":"OPERATIONAL","scans":len(list(SCAN_HISTORY_DIR.glob("scan_*.json"))),"trail":tc,"chain":"VALID" if ok else "BROKEN","fw":"ON" if "running" in fw["out"].lower() else "OFF","ts":datetime.now().isoformat()}, indent=2)

if __name__ == "__main__":
    print(f"Compliance Suite MCP v2.1 — Port {PORT}")
    mcp.run(transport="streamable-http")
