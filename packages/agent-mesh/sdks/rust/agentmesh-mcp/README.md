# AgentMesh MCP Rust SDK

Standalone Rust crate for the [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) MCP governance/security surface — response scanning, message signing, session authentication, credential redaction, rate limiting, tool metadata scanning, gateway decisions, and categorical metrics.

> **Public Preview** — APIs may change before 1.0.

## Install

```toml
[dependencies]
agentmesh-mcp = "3.0.2"
```

## Quick Start

```rust
use agentmesh_mcp::{
    CredentialRedactor, InMemoryNonceStore, McpMessageSigner, McpSignedMessage,
    SystemClock, SystemNonceGenerator,
};
use std::sync::Arc;
use std::time::Duration;

let signer = McpMessageSigner::new(
    b"top-secret-signing-key".to_vec(),
    Arc::new(SystemClock),
    Arc::new(SystemNonceGenerator),
    Arc::new(InMemoryNonceStore::default()),
    Duration::from_secs(300),
    Duration::from_secs(600),
)?;

let signed: McpSignedMessage = signer.sign("hello from mcp")?;
signer.verify(&signed)?;

let redactor = CredentialRedactor::new()?;
let result = redactor.redact("Authorization: Bearer super-secret-token");
assert!(result.sanitized.contains("[REDACTED_BEARER_TOKEN]"));
# Ok::<(), agentmesh_mcp::McpError>(())
```

## Also Available in the Full SDK

If you also need trust, identity, policy, and audit primitives, install the full crate instead:

```bash
cargo add agentmesh
```

## Documentation

- [MCP tools guide](../docs/mcp-tools.md) - integrate scanning, gateway
  enforcement, session auth, and message signing into a Rust application.
- [MCP API reference](../docs/api-reference.md) - public types exported by both
  `agentmesh` and `agentmesh-mcp`.
- [OWASP MCP mapping](../docs/owasp-mcp-mapping.md) - section-by-section mapping
  to the OWASP MCP Security Cheat Sheet.

## License

See repository root [LICENSE](../../../../../LICENSE).
