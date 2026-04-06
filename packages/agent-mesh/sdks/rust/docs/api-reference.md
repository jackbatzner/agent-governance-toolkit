# AgentMesh Rust MCP API Reference

This document covers the shipped MCP governance API from both published Rust
surfaces:

- **Full SDK**: `agentmesh`
- **Standalone MCP crate**: `agentmesh-mcp`

## Import paths

Use whichever package matches your deployment:

```rust
use agentmesh::mcp::{McpGateway, McpResponseScanner};
use agentmesh::{McpGateway as TopLevelGateway, McpResponseScanner as TopLevelScanner};
use agentmesh_mcp::{McpGateway as StandaloneGateway, McpResponseScanner as StandaloneScanner};
```

The MCP type set is the same in both crates. `agentmesh` re-exports the MCP
module twice for convenience:

1. `agentmesh::mcp::TypeName`
2. `agentmesh::TypeName`

`agentmesh-mcp` exports the same types from its crate root.

## Core error type

| Type | Purpose | Typical usage |
| --- | --- | --- |
| `McpError` | Shared error type for configuration errors, signature failures, replay detection, approval/rate-limit denials, and store failures. | `let redactor = CredentialRedactor::new()?;` |

## Time and nonce seams

| Type | Purpose | Typical usage |
| --- | --- | --- |
| `Clock` | Trait for wall-clock access in security-sensitive code. | `let clock: Arc<dyn Clock> = Arc::new(SystemClock);` |
| `SystemClock` | Production clock backed by `SystemTime::now()`. | `Arc::new(SystemClock)` |
| `FixedClock` | Deterministic clock for tests; supports manual advancement. | `let clock = FixedClock::new(SystemTime::UNIX_EPOCH);` |
| `NonceGenerator` | Trait for pluggable nonce generation. | `let gen: Arc<dyn NonceGenerator> = Arc::new(SystemNonceGenerator);` |
| `SystemNonceGenerator` | Production nonce generator backed by random alphanumeric bytes. | `Arc::new(SystemNonceGenerator)` |
| `DeterministicNonceGenerator` | Queue-backed nonce generator for tests and fixtures. | `DeterministicNonceGenerator::from_values(vec!["n1".into()])` |

## Audit types

| Type | Purpose | Typical usage |
| --- | --- | --- |
| `McpAuditEntry` | Categorical audit record for gateway, scan, session, or signing events. | `McpAuditEntry { event_type: "tool_scan".into(), ... }` |
| `McpAuditSink` | Trait for redaction-safe audit persistence. | `let sink: Arc<dyn McpAuditSink> = Arc::new(InMemoryAuditSink::new(redactor.clone()));` |
| `InMemoryAuditSink` | Default in-memory audit store that redacts before persistence. | `let audit = InMemoryAuditSink::new(redactor.clone());` |

## Metrics types

| Type | Purpose | Typical usage |
| --- | --- | --- |
| `McpDecisionLabel` | Label set for `mcp_decisions`. | `metrics.record_decision(McpDecisionLabel::Allowed)?;` |
| `McpThreatLabel` | Label set for `mcp_threats_detected`. | `metrics.record_threat(McpThreatLabel::SchemaAbuse)?;` |
| `McpScanLabel` | Label set for `mcp_scans`. | `metrics.record_scan(McpScanLabel::Gateway)?;` |
| `McpMetricsCollector` | Thread-safe categorical counter collector. | `let metrics = McpMetricsCollector::default();` |
| `McpMetricsSnapshot` | Serializable snapshot of recorded decisions, threats, scans, and rate-limit hits. | `let snapshot = metrics.snapshot()?;` |

## Credential redaction types

| Type | Purpose | Typical usage |
| --- | --- | --- |
| `CredentialKind` | Enumerates detected credential classes. | `CredentialKind::ApiKey.as_str()` |
| `RedactionResult` | Sanitized string plus detected credential labels. | `let result = redactor.redact("Authorization: Bearer token");` |
| `CredentialRedactor` | Redacts secrets from strings and nested `serde_json::Value` trees. | `let redactor = CredentialRedactor::new()?;` |

## Response scanning types

| Type | Purpose | Typical usage |
| --- | --- | --- |
| `McpResponseThreatType` | Categorical response findings: prompt tags, imperative phrases, credential leaks, or exfiltration URLs. | `McpResponseThreatType::CredentialLeakage` |
| `McpResponseFinding` | One response-layer threat finding. | `finding.threat_type` |
| `McpSanitizedResponse` | Sanitized text output plus findings and modified flag. | `let clean = scanner.scan_text(tool_output)?;` |
| `McpSanitizedValue` | Sanitized structured output plus findings and modified flag. | `let clean = scanner.scan_value(&payload)?;` |
| `McpResponseScanner` | Scans tool output before it re-enters LLM context. | `let scanner = McpResponseScanner::new(redactor, audit, metrics, clock)?;` |

## Tool metadata security types

| Type | Purpose | Typical usage |
| --- | --- | --- |
| `McpSeverity` | Threat severity for tool metadata findings. | `McpSeverity::Critical` |
| `McpThreatType` | Threat categories for metadata scanning. | `McpThreatType::RugPull` |
| `McpThreat` | One MCP metadata finding with tool/server context and redaction-safe details. | `let findings = scanner.scan_tool(&tool)?;` |
| `McpToolFingerprint` | Fingerprinted tool definition used for rug-pull detection. | `let fingerprint = scanner.register_tool(&tool)?;` |
| `McpToolDefinition` | Tool metadata passed into the scanner. | `McpToolDefinition { name, description, input_schema, server_name }` |
| `McpSecurityScanResult` | Aggregate scan result for all tools on a server. | `let result = scanner.scan_server("server-a", &tools)?;` |
| `McpSecurityScanner` | Metadata scanner for tool poisoning, schema abuse, rug pulls, and cross-server attacks. | `let scanner = McpSecurityScanner::new(redactor, audit, metrics, clock)?;` |

## Session authentication types

| Type | Purpose | Typical usage |
| --- | --- | --- |
| `McpSession` | Persisted session metadata with agent binding, TTL, and token digest. | `let session = auth.authenticate(&token, "agent-1")?;` |
| `McpIssuedSession` | Return value from session issuance containing the bearer token and persisted metadata. | `let issued = auth.issue_session("agent-1")?;` |
| `McpSessionStore` | Trait for persistent session storage with atomic concurrency checks. | `let store: Arc<dyn McpSessionStore> = Arc::new(InMemorySessionStore::default());` |
| `InMemorySessionStore` | Default in-memory session store. | `Arc::new(InMemorySessionStore::default())` |
| `McpSessionAuthenticator` | HMAC-signed session issuer/authenticator with TTL and concurrent-session limits. | `let auth = McpSessionAuthenticator::new(secret, clock, nonce_gen, store, ttl, 4)?;` |

## Message signing types

| Type | Purpose | Typical usage |
| --- | --- | --- |
| `McpSignedMessage` | Signed MCP payload envelope containing payload, timestamp, nonce, and signature. | `let signed = signer.sign(payload_json)?;` |
| `McpNonceStore` | Trait for replay-detection nonce storage with atomic reserve semantics. | `let store: Arc<dyn McpNonceStore> = Arc::new(InMemoryNonceStore::default());` |
| `InMemoryNonceStore` | Default in-memory nonce store. | `Arc::new(InMemoryNonceStore::default())` |
| `McpMessageSigner` | HMAC-SHA256 signer with timestamp window validation and replay protection. | `let signer = McpMessageSigner::new(secret, clock, nonce_gen, nonce_store, tolerance, ttl)?;` |

## Rate limiting types

| Type | Purpose | Typical usage |
| --- | --- | --- |
| `McpSlidingWindowDecision` | Rate-limit result containing `allowed`, `remaining`, and `retry_after_secs`. | `let decision = limiter.check("agent-1")?;` |
| `McpRateLimitStore` | Trait for atomic sliding-window enforcement. | `let store: Arc<dyn McpRateLimitStore> = Arc::new(InMemoryRateLimitStore::default());` |
| `InMemoryRateLimitStore` | Default in-memory sliding-window store. | `Arc::new(InMemoryRateLimitStore::default())` |
| `McpSlidingRateLimiter` | Per-agent sliding-window limiter for MCP traffic. | `let limiter = McpSlidingRateLimiter::new(60, Duration::from_secs(60), clock, store)?;` |

## Gateway types

| Type | Purpose | Typical usage |
| --- | --- | --- |
| `McpGatewayConfig` | Policy knobs for deny-list, allow-list, approval, and suspicious-payload blocking. | `let config = McpGatewayConfig { allow_list: vec!["search.docs".into()], ..Default::default() };` |
| `McpGatewayRequest` | Request envelope passed through the gateway pipeline. | `McpGatewayRequest { agent_id, tool_name, payload }` |
| `McpGatewayStatus` | Terminal gateway status: allowed, denied, rate-limited, or approval-required. | `matches!(decision.status, McpGatewayStatus::Allowed)` |
| `McpGatewayDecision` | Gateway output with sanitized payload, findings, and retry details. | `let decision = gateway.process_request(&request)?;` |
| `McpGateway` | End-to-end deny-list -> allow-list -> sanitization -> rate-limit -> approval pipeline. | `let gateway = McpGateway::new(config, scanner, limiter, audit, metrics, clock);` |

## Typical construction order

The MCP module is designed to compose from the bottom up:

1. Create a `CredentialRedactor`.
2. Create an `McpAuditSink` and `McpMetricsCollector`.
3. Choose `Clock`, `NonceGenerator`, and in-memory or custom persistence traits.
4. Build the low-level services:
   - `McpResponseScanner`
   - `McpSecurityScanner`
   - `McpSlidingRateLimiter`
   - `McpSessionAuthenticator`
   - `McpMessageSigner`
5. Put `McpGateway` in front of tool execution.

For a full integration example, see
[`mcp-tools.md`](./mcp-tools.md).
