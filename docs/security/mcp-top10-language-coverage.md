# OWASP MCP Top 10 Language Coverage

> **Last updated:** April 2026
> **Disclaimer:** This page is an internal package-level self-assessment, not a validated
> certification or third-party audit.
> ⚠️ The OWASP MCP Top 10 is currently in **Phase 3 — Beta Release and Pilot Testing**.

This page provides a **package-level snapshot** of how the language SDKs in Agent Governance
Toolkit map to the [OWASP Top 10 for Model Context Protocol](https://owasp.org/www-project-mcp-top-10/).

It is intentionally narrower than the broader stack-wide self-assessment in
[`../compliance/mcp-owasp-top10-mapping.md`](../compliance/mcp-owasp-top10-mapping.md), which
includes additional services, proxies, and runtime surfaces beyond the package APIs summarized
here.

## Coverage by Language

| OWASP MCP Top 10 | Python | TypeScript | .NET | Rust | Go |
|---|:---:|:---:|:---:|:---:|:---:|
| **MCP01 Token Mismanagement & Secret Exposure** | ◑ | — | ✅ | ✅ | ◑ |
| **MCP02 Privilege Escalation via Scope Creep** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **MCP03 Tool Poisoning** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **MCP04 Supply Chain Attacks & Dependency Tampering** | ◑ | ◑ | ◑ | ◑ | ◑ |
| **MCP05 Command Injection & Execution** | ◑ | ◑ | ◑ | ◑ | ◑ |
| **MCP06 Intent Flow Subversion** | ◑ | ◑ | ◑ | ◑ | ◑ |
| **MCP07 Insufficient Authentication & Authorization** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **MCP08 Lack of Audit and Telemetry** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **MCP09 Shadow MCP Servers** | ◑ | ◑ | ◑ | ◑ | ◑ |
| **MCP10 Context Injection & Over-Sharing** | ◑ | ◑ | ✅ | ◑ | ◑ |

**Legend:** ✅ Strong coverage · ◑ Partial coverage · — Not clearly exposed today

## Interpretation

- **.NET** currently provides the richest MCP-specific runtime hardening surface.
- **Rust** follows with a dedicated `agentmesh-mcp` package.
- **TypeScript** and **Go** provide strong baseline governance primitives and MCP threat scanning,
  but have lighter first-class package surfaces for secret redaction, response sanitization, and
  context-hardening.
- **Python** remains strong at the toolkit level, but some MCP coverage is expressed in broader
  governance and compliance surfaces rather than a single MCP-only package layer.
- **MCP06** and **MCP09** remain intentionally conservative here because the broader
  stack-wide OWASP MCP mapping still treats them as partial coverage today.

## Related Pages

- [Language Package Matrix](../PACKAGE-FEATURE-MATRIX.md)
- [OWASP MCP Top 10 — Compliance Mapping](../compliance/mcp-owasp-top10-mapping.md)
