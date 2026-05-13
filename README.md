# Compliance Suite MCP — Enterprise Audit & Security for AI Agents

**Self-contained compliance monitoring. Deploy anywhere — runs natively with zero external dependencies.**

[![MCP](https://img.shields.io/badge/MCP-Compatible-blue)](https://modelcontextprotocol.io)
[![Python](https://img.shields.io/badge/Python-3.11+-green)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

## What It Does

Your AI agent (Claude, ChatGPT, Gemini) can now run complete security audits. One prompt → CIS benchmark scan, CVE check, port audit, firewall audit, SSH audit — all in parallel. Every scan is cryptographically logged in a SHA-256 chained audit trail.

**No external MCP servers required.** Everything runs natively in this single process.

## Tools (7)

| Tool | What It Does |
|------|-------------|
| `compliance_full_audit` | 5 parallel scans: CIS benchmark + CVE + ports + firewall + SSH. Returns scored report with fixes. |
| `compliance_scorecard` | Executive summary — risk level, CIS score, CVE count. JSON, dashboard-ready. |
| `audit_trail_query` | Cryptographic chain — every action logged, linked via SHA-256, tamper-evident. |
| `scheduled_scan_diff` | SOC 2 evidence: exactly what changed between scans (improved/degraded). |
| `incident_forensic_report` | Scan logs for errors, auth failures, suspicious activity. |
| `compliance_export` | SOC 2 evidence package — scan history + audit trail for auditors. |
| `compliance_status` | Instant health check — scans stored, trail size, chain integrity. |

## Quick Start

```bash
pip install fastmcp
python3 server.py
# Starts on http://localhost:8111/mcp
```

Connect to Claude Desktop:
```json
{"mcpServers": {"compliance-suite": {"url": "http://localhost:8111/mcp"}}}
```

Then ask: *"Run a full compliance audit and tell me if we're secure"*

## Configuration

| Env Var | Default | Description |
|---------|---------|-------------|
| `COMPLIANCE_DATA_DIR` | `~/.compliance-suite` | Where audit trail + scan history are stored |
| `COMPLIANCE_PORT` | `8111` | Server port |

## CIS Checks (8 benchmarks)

Firewall status, security updates, ICMP redirects, source routing, password policy, brute force detection, SELinux, core dump restrictions. Each failure includes exact remediation command.

## Pricing (on MCPize)

| Tier | Price | Includes |
|------|-------|----------|
| **Free** | $0 | 5 scans/day, summary reports |
| **Pro** | $19/month | Unlimited scans, detailed reports, audit trail |
| **Team** | $49/month | Multi-node, SOC 2 export, priority support |
| **Enterprise** | $149/month | SSO, custom benchmarks, SLA |

## License

MIT
