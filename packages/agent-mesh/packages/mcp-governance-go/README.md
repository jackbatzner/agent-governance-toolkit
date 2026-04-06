# AgentMesh MCP Governance for Go

> [!IMPORTANT]
> **Public Preview** — This Go module is a Microsoft-signed public preview release.
> APIs may change before GA.

Standalone Go module for AgentMesh MCP security primitives: HMAC signing, replay protection, session authentication, sliding-window rate limiting, tool metadata scanning, credential redaction, response scanning, and gateway enforcement.

## Installation

```bash
go get github.com/microsoft/agent-governance-toolkit/packages/mcp-governance-go
```

## Quick Start

```go
package main

import (
	"fmt"
	"time"

	mcpgovernance "github.com/microsoft/agent-governance-toolkit/packages/mcp-governance-go"
)

func main() {
	authenticator, _ := mcpgovernance.NewMcpSessionAuthenticator(
		mcpgovernance.McpSessionAuthenticatorConfig{
			SessionTTL:            15 * time.Minute,
			MaxConcurrentSessions: 4,
		},
	)

	session, _ := authenticator.CreateSession("agent-007")

	gateway, _ := mcpgovernance.NewMcpGateway(mcpgovernance.McpGatewayConfig{
		Authenticator: authenticator,
		Policy:        mcpgovernance.DefaultMcpPolicy(),
	})

	decision, _ := gateway.InterceptToolCall(mcpgovernance.McpToolCallRequest{
		SessionToken:    session.Token,
		ToolName:        "search.docs",
		ToolDescription: "Search product documentation",
		ToolSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"query": map[string]any{"type": "string"},
			},
		},
		Payload: map[string]any{"query": "OWASP MCP"},
	})

	fmt.Println(decision.Allowed, decision.Decision)
}
```

## What It Includes

| Primitive | Purpose |
| --- | --- |
| `McpMessageSigner` | HMAC-SHA256 signing with nonce replay protection |
| `McpSessionAuthenticator` | Session issuance, validation, revocation, and creation throttling |
| `McpSlidingRateLimiter` | Per-agent sliding-window rate limiting with inactive bucket eviction |
| `McpSecurityScanner` | Tool definition scanning for hidden instructions, description injection, rug-pulls, and schema abuse |
| `CredentialRedactor` | Full PEM, API key, bearer token, and connection string redaction |
| `McpResponseScanner` | Tool response scanning for leaked credentials |
| `McpGateway` | Unified auth → rate-limit → scan → sign → audit enforcement point |

## OWASP MCP Coverage

| Cheat Sheet Area | Coverage |
| --- | --- |
| §§1-3 Identity and session controls | `McpSessionAuthenticator`, `McpMessageSigner` |
| §§4-5 Abuse and DoS controls | `McpSlidingRateLimiter`, gateway fail-closed policy |
| §§6-8 Tool metadata and prompt injection defenses | `McpSecurityScanner` |
| §§9-10 Secret handling and output safety | `CredentialRedactor`, `McpResponseScanner` |
| §11 Consent UI | Out of scope for this server-side package |
| §12 Central enforcement and audit | `McpGateway`, `AuditLogger`, `McpMetrics` |

## Local Development

```bash
go test ./...
```

## License

See [LICENSE](../../../../LICENSE).
