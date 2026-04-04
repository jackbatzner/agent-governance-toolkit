// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// ============================================================================
// Sample: MCP Governance with ASP.NET Core
//
// Demonstrates:
//   - IServiceCollection DI registration
//   - HTTP middleware for JSON-RPC MCP messages
//   - Health checks for K8s readiness probes
//   - Configuration binding from appsettings.json
//   - Structured logging via ILogger
//   - gRPC interceptor for tool call governance
//   - Tool discovery via [McpTool] attribute
// ============================================================================

using AgentGovernance;
using AgentGovernance.Extensions;
using AgentGovernance.Mcp;

var builder = WebApplication.CreateBuilder(args);

// ── 1. Bind governance options from appsettings.json ────────────────────────
var options = new McpGovernanceOptions()
    .BindFromConfiguration(builder.Configuration, "McpGovernance");

// Add recommended defaults on top of config-driven settings
options.DeniedTools.AddRange(McpGovernanceDefaults.DeniedTools);
options.SensitiveTools.AddRange(McpGovernanceDefaults.SensitiveTools);

// ── 2. Register MCP governance services ─────────────────────────────────────
builder.Services.AddMcpGovernance(options);

// ── 3. Health checks for K8s/load balancer ──────────────────────────────────
builder.Services.AddHealthChecks()
    .AddMcpGovernanceChecks(tags: new[] { "ready" });

// ── 4. gRPC interceptor (optional — for gRPC transport) ─────────────────────
builder.Services.AddGrpc(grpc => grpc.AddMcpGovernance());

var app = builder.Build();

// ── 5. Middleware pipeline ──────────────────────────────────────────────────
app.UseMcpGovernance();  // Intercepts JSON-RPC MCP messages in HTTP body

// Health endpoints: /health/live (basic) and /health/ready (includes governance)
app.MapHealthChecks("/health/live");
app.MapHealthChecks("/health/ready", new()
{
    Predicate = check => check.Tags.Contains("ready")
});

// ── 6. Tool discovery (register [McpTool] methods from this assembly) ───────
using var scope = app.Services.CreateScope();
var handler = scope.ServiceProvider.GetRequiredService<McpMessageHandler>();
var registry = new McpToolRegistry(handler,
    scope.ServiceProvider.GetService<ILogger<McpToolRegistry>>());
registry.DiscoverTools(typeof(Program).Assembly);

// ── 7. Diagnostic endpoint ──────────────────────────────────────────────────
app.MapGet("/", () => Results.Ok(new
{
    service = "MCP Governance Sample",
    tools_registered = registry.Registrations.Count,
    endpoints = new[] { "/mcp (POST)", "/health/live", "/health/ready" }
}));

app.Run();

// ============================================================================
// Sample tools — discovered automatically via [McpTool] attribute
// ============================================================================

public static class SampleTools
{
    [McpTool(Description = "Reads a file from disk (read-only, safe)")]
    public static Dictionary<string, object> ReadFile(string path)
    {
        return new() { ["content"] = $"[simulated content of {path}]" };
    }

    [McpTool(Name = "search_database", Description = "Run a read-only database query")]
    public static Dictionary<string, object> SearchDatabase(string query, int maxRows = 50)
    {
        return new()
        {
            ["rows"] = new[] { new { id = 1, name = "sample" } },
            ["count"] = 1
        };
    }

    [McpTool(Description = "Sends an email (requires human approval)", RequiresApproval = true)]
    public static Dictionary<string, object> SendEmail(string to, string subject, string body)
    {
        return new() { ["status"] = "sent", ["to"] = to };
    }
}
