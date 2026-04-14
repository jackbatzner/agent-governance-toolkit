# MCP Governance + Official MCP C# SDK sample

This sample is intentionally narrow and buildable:

- it uses the official `ModelContextProtocol` NuGet package for stdio transport and tool registration
- it uses `Microsoft.AgentGovernance` to evaluate each MCP tool call inside an `AddCallToolFilter`
- it does **not** claim a dedicated Agent Governance MCP adapter package exists in this repo
- it does **not** claim response redaction or full OWASP MCP coverage in this sample

## What this sample proves

The sample shows a real integration path you can review locally:

1. register the official MCP server with `AddMcpServer()`
2. expose tools with `WithTools<GovernedSampleTools>()`
3. intercept `tools/call` requests with `AddCallToolFilter(...)`
4. run each request through `GovernanceKernel.EvaluateToolCall(...)`
5. return an MCP tool error when governance denies the request

## Build

```bash
cd packages/agent-governance-dotnet/samples/McpGovernance.OfficialSdk
dotnet build
```

## Quick review run

Use the local demo mode to verify the governance decisions without attaching an MCP client:

```bash
dotnet run -- --demo
```

Expected output is similar to:

```text
read_file: ALLOWED - Matched rule 'allow-read-file' with action 'Allow'.
drop_database: DENIED - No matching rules; default action is deny.
```

## Run as an MCP server

```bash
dotnet run
```

The sample starts a stdio MCP server with two tools:

- `read_file` — allowed by the sample governance policy
- `drop_database` — registered on purpose so you can see governance deny it before execution

## Notes

- The sample uses an inline demo policy so it stays self-contained.
- The sample uses a fixed demo agent ID (`did:mesh:official-sdk-sample`) inside the request filter.
- For production use, replace the inline policy, demo agent identity, and sample tools with your own configuration.
