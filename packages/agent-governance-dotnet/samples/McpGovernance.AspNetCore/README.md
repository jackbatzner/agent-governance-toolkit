# MCP Governance — ASP.NET Core Sample

Demonstrates full MCP governance integration with ASP.NET Core:

- **DI registration** via `services.AddMcpGovernance()`
- **HTTP middleware** via `app.UseMcpGovernance()`
- **Health checks** for K8s readiness probes
- **Configuration binding** from `appsettings.json`
- **Structured logging** via `ILogger<T>`
- **gRPC interceptor** via `grpc.AddMcpGovernance()`
- **Tool discovery** via `[McpTool]` attribute

## Run

```bash
cd packages/agent-governance-dotnet/samples/McpGovernance.AspNetCore
dotnet run
```

## Test

```bash
# Health check
curl http://localhost:5000/health/ready

# Send an MCP tool call (allowed)
curl -X POST http://localhost:5000 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/data/report.csv"}}}'

# Send a denied tool call
curl -X POST http://localhost:5000 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"drop_database","arguments":{"db":"prod"}}}'
```

## Configuration

All governance settings are in `appsettings.json` under the `McpGovernance` section.
Override per-environment with `appsettings.Development.json` or environment variables:

```bash
export McpGovernance__MaxToolCallsPerAgent=1000
export McpGovernance__EnableResponseScanning=true
```
