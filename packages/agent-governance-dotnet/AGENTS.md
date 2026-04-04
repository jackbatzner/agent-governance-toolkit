# Agent Governance .NET SDK — Coding Agent Instructions

## Project Overview

The .NET SDK provides **governance-as-code for AI agents** targeting .NET 8.0+. It integrates with ASP.NET Core, gRPC, and the official ModelContextProtocol C# SDK to enforce policy, security scanning, and audit logging at the MCP protocol layer.

**Architecture:** GovernanceKernel (policy engine) + MCP governance stack

- **GovernanceKernel:** Deterministic policy evaluation, action classification, middleware pipeline
- **MCP Gateway:** 5-stage pipeline (deny-list → allow-list → sanitization → rate-limiting → human approval)
- **MCP Security Scanner:** 6-threat detection with SHA-256 fingerprinting
- **Extensions:** ASP.NET DI, middleware, health checks, IConfiguration, gRPC interceptor

## Build & Test Commands

```bash
# Build the solution (all projects)
cd packages/agent-governance-dotnet
dotnet build

# Run all tests
dotnet test

# Run tests with verbosity
dotnet test --verbosity normal

# Build samples
dotnet build samples/McpGovernance.AspNetCore/McpGovernance.AspNetCore.csproj
dotnet build samples/McpGovernance.OfficialSdk/McpGovernance.OfficialSdk.csproj
```

## Project Structure

```
packages/agent-governance-dotnet/
├── AgentGovernance.sln
├── src/
│   ├── AgentGovernance/                    # Core library (no MCP SDK dependency)
│   │   ├── AgentGovernance.csproj
│   │   ├── Core/                           # GovernanceKernel, middleware, policy
│   │   ├── Mcp/                            # MCP protocol components
│   │   ├── Extensions/                     # ASP.NET, DI, config, gRPC, health
│   │   └── Telemetry/                      # OpenTelemetry metrics
│   └── AgentGovernance.ModelContextProtocol/  # Adapter sub-package
│       ├── AgentGovernance.ModelContextProtocol.csproj
│       └── McpSdkGovernanceExtensions.cs
├── tests/
│   └── AgentGovernance.Tests/
└── samples/
    ├── McpGovernance.AspNetCore/
    └── McpGovernance.OfficialSdk/
```

## Coding Conventions

- **Target:** .NET 8.0, C# 12
- **Test framework:** xUnit 2.9.3 with `[Fact]` and `[Theory]`
- **JSON:** `System.Text.Json` (never Newtonsoft)
- **Crypto:** `System.Security.Cryptography` (HMAC-SHA256, SHA-256)
- **Logging:** `ILogger<T>` via settable property (not constructor injection), matching existing `Metrics` pattern
- **Telemetry:** `System.Diagnostics.Metrics` counters via `GovernanceMetrics`
- **DI pattern:** `IServiceCollection` extensions returning the collection for chaining
- **Fail-closed:** Any exception in governance pipeline → deny (never silent pass-through)
- **Regex safety:** All compiled regexes must have `matchTimeout: TimeSpan.FromMilliseconds(200)` for ReDoS prevention
- **Constant-time comparison:** Use `CryptographicOperations.FixedTimeEquals` for all secret comparison

## Key Design Decisions

1. **Core has no ModelContextProtocol NuGet dependency** — the adapter lives in `AgentGovernance.ModelContextProtocol` sub-package (Serilog/MediatR pattern)
2. **HMAC-SHA256** instead of Ed25519 — .NET 8 lacks Ed25519 support
3. **SortedDictionary** for schema hashing — ensures deterministic SHA-256 fingerprints
4. **Nonce cache capped at 10,000** with oldest eviction to prevent memory exhaustion
5. **Session limit checked under lock** — TOCTOU-safe concurrency for `McpSessionAuthenticator`
6. **Properties use `set` not `init`** on `McpGovernanceOptions` — required for `IConfiguration` binding

## OWASP MCP Security Coverage

11 of 12 OWASP MCP Security Cheat Sheet sections covered. §11 (Consent UI) is client-side and out of scope for a server SDK.
