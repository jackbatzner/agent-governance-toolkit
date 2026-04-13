# AgentMesh Rust SDK - OWASP MCP Security Cheat Sheet Mapping

This document maps the Rust MCP governance surface in `agentmesh` and
`agentmesh-mcp` to the
[OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html).

## Coverage summary

The Rust SDK provides direct runtime controls or integration hooks for
**11 of the 12** best-practice sections in the cheat sheet. The one section not
implemented in-library is **Section 3: Sandbox and Isolate MCP Servers**. That
gap is intentional: process isolation, syscall filtering, filesystem
confinement, and outbound network controls belong to the deployment
environment rather than the library.

| Section | Cheat sheet area | Status | Rust controls |
| --- | --- | --- | --- |
| 1 | Principle of Least Privilege | Covered | `McpGatewayConfig.allow_list`, `deny_list`, `approval_required_tools` |
| 2 | Tool Description & Schema Integrity | Covered | `McpSecurityScanner`, `McpToolFingerprint`, `McpToolDefinition` |
| 3 | Sandbox and Isolate MCP Servers | Not covered in-library | External containers, jails, and host controls required |
| 4 | Human-in-the-Loop for Sensitive Actions | Covered | `McpGateway`, `McpGatewayStatus::RequiresApproval` |
| 5 | Input and Output Validation | Covered | `McpGateway`, `McpResponseScanner`, `CredentialRedactor` |
| 6 | Authentication, Authorization & Transport Security | Covered with deployment responsibilities | `McpSessionAuthenticator`, `McpSlidingRateLimiter`; transport/TLS still belongs to the host |
| 7 | Message-Level Integrity and Replay Protection | Covered | `McpMessageSigner`, `McpSignedMessage`, `McpNonceStore` |
| 8 | Multi-Server Isolation & Cross-Origin Protection | Covered | `McpSecurityScanner`, `McpGateway`, tool fingerprinting |
| 9 | Supply Chain Security | Covered | `McpSecurityScanner`, rug-pull detection, typosquat detection |
| 10 | Monitoring, Logging & Auditing | Covered | `McpAuditSink`, `InMemoryAuditSink`, `McpMetricsCollector` |
| 11 | Consent & Installation Security | Covered with host UX responsibilities | fingerprints, approval workflow, and change detection; consent UI belongs to the host |
| 12 | Prompt Injection via Tool Return Values | Covered | `McpResponseScanner`, `CredentialRedactor`, `McpGateway` |

## 1. Principle of Least Privilege

**Rust controls**

- `McpGatewayConfig.allow_list`
- `McpGatewayConfig.deny_list`
- `McpGatewayConfig.approval_required_tools`
- `McpSessionAuthenticator` TTL and concurrent-session limits

**How it maps**

The gateway lets you expose only the tool names you intend to permit, block
high-risk tools outright, and force explicit approval for destructive or
sensitive operations.

## 2. Tool Description & Schema Integrity

**Rust controls**

- `McpSecurityScanner`
- `McpToolFingerprint`
- `McpToolDefinition`

**How it maps**

The scanner treats descriptions and schemas as prompt-injection surfaces, hashes
tool metadata for rug-pull detection, and flags permissive or instruction-bearing
schemas.

## 3. Sandbox and Isolate MCP Servers

**Status:** not implemented inside the SDK

This Rust library does not attempt to create containers, jails, or OS-level
network/file-system sandboxes. Use deployment controls such as containers,
VMs, seccomp profiles, filesystem allowlists, and loopback-only bindings around
the MCP host or server process. To reduce sandbox-escape risk, run MCP servers
as non-root users, avoid writable host mounts, default to read-only filesystems
where possible, and restrict outbound egress to the specific services each tool
needs.

## 4. Human-in-the-Loop for Sensitive Actions

**Rust controls**

- `McpGateway`
- `McpGatewayStatus::RequiresApproval`
- `McpGatewayDecision`

**How it maps**

The gateway can return an approval-required decision before execution. This lets
the host application show the exact tool name and sanitized parameters before
allowing the operation to proceed.

## 5. Input and Output Validation

**Rust controls**

- `McpGateway`
- `McpResponseScanner`
- `CredentialRedactor`
- `McpResponseFinding`

**How it maps**

The gateway sanitizes incoming payloads, the response scanner strips prompt-like
tags and exfiltration patterns from outputs, and the redactor removes secrets
from nested values before they are logged or re-used.

## 6. Authentication, Authorization & Transport Security

**Rust controls**

- `McpSessionAuthenticator`
- `McpSession`
- `McpIssuedSession`
- `McpSessionStore`
- `McpSlidingRateLimiter`

**How it maps**

The SDK provides identity-bound session tokens, TTL expiry, atomic concurrency
limits, and per-agent rate limiting. TLS, interface binding, certificate
verification, and secure credential stores remain deployment responsibilities.

## 7. Message-Level Integrity and Replay Protection

**Rust controls**

- `McpMessageSigner`
- `McpSignedMessage`
- `McpNonceStore`
- `Clock`
- `NonceGenerator`

**How it maps**

The signer applies HMAC-SHA256 to the full payload, timestamp, and nonce. Verify
paths fail closed, reject stale timestamps, and atomically reserve nonces to
block replay. Store signing secrets and session-token secrets in your existing
KMS, HSM, or secret-management system rather than in source or static config,
and rotate keys by issuing a new version before retiring the old one so active
sessions can be drained safely.

## 8. Multi-Server Isolation & Cross-Origin Protection

**Rust controls**

- `McpSecurityScanner`
- `McpGateway`
- `McpThreatType::CrossServerAttack`
- `McpToolFingerprint`

**How it maps**

The scanner flags duplicate tool names and typosquatting across servers, while
the gateway provides a stable enforcement point for allowlists, denylists, and
approval gates.

## 9. Supply Chain Security

**Rust controls**

- `McpSecurityScanner`
- rug-pull fingerprint checks
- schema-abuse and tool-poisoning detection

**How it maps**

The SDK focuses on runtime verification of approved tools: it fingerprints tool
definitions, detects post-approval mutation, and surfaces suspicious tool names
or hidden instructions before a server is trusted.

## 10. Monitoring, Logging & Auditing

**Rust controls**

- `McpAuditSink`
- `InMemoryAuditSink`
- `McpAuditEntry`
- `McpMetricsCollector`
- `McpMetricsSnapshot`

**How it maps**

Audit sinks redact before storage, and metrics record only categorical labels.
This keeps telemetry useful for SIEM or governance dashboards without leaking
secrets in logs.

## 11. Consent & Installation Security

**Rust controls**

- `McpToolFingerprint`
- `McpSecurityScanner::check_rug_pull`
- `McpGatewayStatus::RequiresApproval`

**How it maps**

The SDK can tell a host when a tool definition changed and when an operation
requires approval. The actual install-consent dialog, publisher identity UI,
and server-connection workflow must still be implemented by the MCP host.

## 12. Prompt Injection via Tool Return Values

**Rust controls**

- `McpResponseScanner`
- `McpResponseThreatType`
- `CredentialRedactor`
- `McpGateway`

**How it maps**

The response scanner strips HTML-like/system tags, redacts imperative control
phrases, removes credential leaks, and blocks or sanitizes suspicious payloads
before they are reintroduced into model context.

## Design notes

- The Rust MCP module is self-contained and can be consumed from either
  `agentmesh` or `agentmesh-mcp`.
- All store and clock seams are injectable for enterprise deployments:
  `McpSessionStore`, `McpNonceStore`, `McpRateLimitStore`, `McpAuditSink`,
  `Clock`, and `NonceGenerator`.
- Security-critical verification paths fail closed instead of silently falling
  back to permissive behavior.
