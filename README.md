# Compliance Suite MCP — Enterprise Audit & Security for AI Agents

**SOC 2-ready compliance monitoring for your infrastructure, accessible through any MCP-compatible AI agent.**

[![MCP](https://img.shields.io/badge/MCP-Compatible-blue)](https://modelcontextprotocol.io)
[![Python](https://img.shields.io/badge/Python-3.11+-green)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

## What It Does

Compliance Suite wraps 14 security auditing tools behind 7 clean MCP endpoints. Your AI agent (Claude, ChatGPT, Gemini) can now run full CIS benchmark scans, check for CVEs, audit firewalls/SSH/ports, generate SOC 2 evidence packages, and maintain a cryptographic audit trail — all from natural language.

**One prompt → full compliance report.** No SSH, no scattered scripts, no manual evidence compilation.

## Why This Exists

The [2026 MCP Roadmap](https://modelcontextprotocol.io/development/roadmap) explicitly names "Enterprise Readiness" as a priority — audit trails, compliance, SSO, and governance. The Enterprise Working Group hasn't formed yet. This server ships the solution today.

## Tools (7)

| Tool | What It Does |
|------|-------------|
| `compliance_full_audit` | Runs all 5 audits in parallel: CIS + CVE + ports + firewall + SSH |
| `compliance_scorecard` | Executive summary — risk level + scores per category |
| `audit_trail_query` | Cryptographic chain — every action logged, linked, verifiable |
| `scheduled_scan_diff` | SOC 2 evidence: what changed between scans |
| `incident_forensic_report` | Post-mortem reports from incident data |
| `compliance_export` | Export evidence package for auditors |
| `compliance_status` | Health check: are all compliance subsystems up? |

## Quick Start

```bash
pip install fastmcp httpx
python3 server.py
# Starts on http://localhost:8111/mcp
```

Connect to Claude Desktop:
```json
{"mcpServers": {"compliance-suite": {"url": "http://localhost:8111/mcp"}}}
```

Then ask: "Run a full compliance audit and give me the scorecard"

## Architecture

```
Compliance Suite (port 8111)
  ├── Compliance Auditor (port 8100) — CIS, CVE, port, firewall, SSH
  └── Incident Forensics (port 8101) — investigations, timeline, root cause
```

Adds: cryptographic audit trail (SHA-256 chained), SOC 2 evidence export, parallel execution, diff tracking.

## Pricing (on MCPize)

| Tier | Price | Includes |
|------|-------|----------|
| **Free** | $0 | 5 scans/day, summary reports |
| **Pro** | $19/month | Unlimited scans, detailed reports, audit trail |
| **Team** | $49/month | Multi-node, SOC 2 export, priority support |
| **Enterprise** | $149/month | SSO, custom benchmarks, SLA, dedicated support |

*Activate before June 10, 2026 to lock in 85% Founding Member revenue share.*

## Who Needs This

**CISOs** deploying AI agents who need audit trails. **DevOps teams** wanting compliance-as-code. **Startups** pursuing SOC 2 affordably. **MSPs** managing multi-client compliance.

## License

MIT — see [LICENSE](LICENSE)
