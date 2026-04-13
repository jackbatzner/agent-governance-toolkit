# MCP Axum Server Example

Minimal Axum server showing how to compose the Rust MCP governance primitives in
front of an HTTP tool endpoint.

## What it demonstrates

- `McpGateway` for allow/deny, approval, sanitization, and gateway-level rate limiting
- `McpSessionAuthenticator` for identity-bound session tokens with TTL
- `McpMessageSigner` for HMAC-SHA256 sign/verify
- `McpSlidingRateLimiter` for per-tool throttling
- `McpSecurityScanner` for tool-definition checks
- `McpResponseScanner` for output scanning before response delivery
- `CredentialRedactor` for redacted logging
- `POST /call-tool` and `GET /health`

## Prerequisites

- Rust 1.75+

## Run

Set distinct 32-byte-or-longer secrets before starting the demo. Keep these in
your normal secret manager or environment injection flow rather than in source:

```bash
export MCP_SESSION_SECRET="0123456789abcdef0123456789abcdef"
export MCP_MESSAGE_SECRET="fedcba9876543210fedcba9876543210"
```

```bash
cd packages/agent-mesh/sdks/rust/examples/mcp-axum-server
cargo run
```

On startup the server prints a demo session token for `did:mesh:demo-client`.
The example exits early if either secret is missing or shorter than 32 bytes.

## Example curl commands

Health check:

```bash
curl http://127.0.0.1:3000/health
```

Governed tool call:

```bash
curl -X POST http://127.0.0.1:3000/call-tool \
  -H "content-type: application/json" \
  -d '{
    "agent_id": "did:mesh:demo-client",
    "session_token": "<TOKEN_FROM_STARTUP>",
    "tool_name": "docs.search",
    "input": {
      "query": "incident runbook"
    }
  }'
```

The example intentionally returns a response containing a prompt tag and bearer
token so you can see the response scanner and redactor sanitize the output.

## OWASP MCP mapping

This example exercises the core runtime controls from the cheat sheet:

- **Section 4** - Human-in-the-loop for sensitive actions via `approval_required_tools`
- **Section 5** - Input and output validation via `McpGateway` and `McpResponseScanner`
- **Section 6** - Authentication and session binding via `McpSessionAuthenticator`
- **Section 7** - Message integrity and replay protection via `McpMessageSigner`
- **Section 8** - Multi-server isolation hooks via `McpSecurityScanner`
- **Section 10** - Monitoring and auditing via redacted logging and categorical metrics
- **Section 12** - Prompt injection defense on tool return values via `McpResponseScanner`

It intentionally does **not** claim to replace TLS, mTLS, or publisher identity
checks. Those still belong to the surrounding deployment.
