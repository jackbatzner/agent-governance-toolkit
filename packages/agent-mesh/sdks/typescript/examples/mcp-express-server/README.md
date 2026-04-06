# MCP Express Server Example

This example shows a minimal Express.js server running the full AgentMesh MCP governance pipeline for a `POST /call-tool` endpoint.

## What it demonstrates

- `MCPGateway` allow-list, sanitization, rate limiting, and approval flow
- `MCPMessageSigner` signing and verification of tool calls
- `MCPSessionAuthenticator` session tokens with TTL-bound agent identity
- `MCPSlidingRateLimiter` per-agent request throttling
- `MCPSecurityScanner` request inspection for prompt-injection style content
- `MCPResponseScanner` output scanning for credentials and exfiltration patterns
- `CredentialRedactor` redaction before logging
- `GET /health` for readiness plus a short-lived demo session token

## Prerequisites

- Node 18+
- npm

## Install and run

```bash
cd packages/agent-mesh/sdks/typescript/examples/mcp-express-server
npm install
npx tsx src/server.ts
```

The example runs against the checked-out SDK source in this repository so reviewers can exercise the current branch without publishing a package first.

## Endpoints

- `GET /health` - readiness plus a demo session token for `demo-agent`
- `POST /call-tool` - signs, verifies, authenticates, rate-limits, scans, redacts, and executes a tool call

## Example curl flows

Fetch a demo session token:

```bash
curl http://127.0.0.1:3000/health
```

Use the returned `demoSessionToken` in a governed tool call:

```bash
curl -X POST http://127.0.0.1:3000/call-tool \
  -H "content-type: application/json" \
  -H "x-session-token: <PASTE_TOKEN_HERE>" \
  -d '{
    "agentId": "demo-agent",
    "toolName": "search_docs",
    "args": { "query": "OWASP MCP" }
  }'
```

Trigger the path-traversal guard:

```bash
curl -X POST http://127.0.0.1:3000/call-tool \
  -H "content-type: application/json" \
  -H "x-session-token: <PASTE_TOKEN_HERE>" \
  -d '{
    "agentId": "demo-agent",
    "toolName": "read_file",
    "args": { "path": "../secrets.txt", "approved": true }
  }'
```

Trigger response scanning for leaked credentials:

```bash
curl -X POST http://127.0.0.1:3000/call-tool \
  -H "content-type: application/json" \
  -H "x-session-token: <PASTE_TOKEN_HERE>" \
  -d '{
    "agentId": "demo-agent",
    "toolName": "read_file",
    "args": { "path": "workspace/secrets.txt", "approved": true }
  }'
```

## OWASP MCP mapping

| Primitive | Example role |
| --- | --- |
| `MCPSessionAuthenticator` | Session binding and expiry |
| `MCPMessageSigner` | Signed tool-call envelopes |
| `MCPGateway` | Deny/allow/sanitize/approve pipeline |
| `MCPSlidingRateLimiter` | Request throttling |
| `MCPSecurityScanner` | Prompt-injection style request inspection |
| `MCPResponseScanner` | Output scanning and fail-closed blocking |
| `CredentialRedactor` | Safe audit logging |

## Run the smoke test

```bash
npm test
```
