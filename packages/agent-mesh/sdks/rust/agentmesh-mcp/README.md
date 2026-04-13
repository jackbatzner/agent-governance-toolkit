# AgentMesh MCP Rust SDK

Standalone Rust crate for the [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) MCP governance/security surface — response scanning, message signing, session authentication, credential redaction, rate limiting, tool metadata scanning, gateway decisions, and categorical metrics.

> **Public Preview** — APIs may change before 1.0.

## Install

```toml
[dependencies]
agentmesh-mcp = "3.1.0"
```

## Quick Start

```rust
use agentmesh_mcp::{
    CredentialRedactor, InMemoryNonceStore, McpMessageSigner, McpSignedMessage,
    SystemClock, SystemNonceGenerator,
};
use std::sync::Arc;
use std::time::Duration;

let signing_secret = std::env::var("MCP_SIGNING_SECRET")
    .map_err(|_| agentmesh_mcp::McpError::InvalidConfig(
        "MCP_SIGNING_SECRET must be set",
    ))?;
if signing_secret.len() < 32 {
    return Err(agentmesh_mcp::McpError::InvalidConfig(
        "MCP_SIGNING_SECRET must be at least 32 bytes",
    ));
}

let signer = McpMessageSigner::new(
    signing_secret.into_bytes(),
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

Use a distinct signing secret per environment and keep it in your normal
secret-management system; the quick start intentionally avoids hardcoded keys.

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
