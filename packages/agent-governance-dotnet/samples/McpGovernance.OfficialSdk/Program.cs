// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.ComponentModel;
using System.Text.Json;
using AgentGovernance;
using AgentGovernance.Integration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddSingleton(static _ =>
{
    var kernel = new GovernanceKernel(new GovernanceOptions
    {
        EnablePromptInjectionDetection = true,
        EnableMetrics = false,
    });

    kernel.LoadPolicyFromYaml("""
        name: "official-sdk-sample"
        version: "1.0"
        default_action: deny
        rules:
          - name: allow-read-file
            condition: "tool_name == 'read_file'"
            action: allow
            priority: 100
        """);

    return kernel;
});

builder.Services
    .AddMcpServer()
    .WithStdioServerTransport()
    .WithTools<GovernedSampleTools>()
    .WithRequestFilters(filters =>
    {
        filters.AddCallToolFilter(next => async (request, cancellationToken) =>
        {
            var kernel = request.Services!.GetRequiredService<GovernanceKernel>();
            var decision = kernel.EvaluateToolCall(
                agentId: "did:mesh:official-sdk-sample",
                toolName: request.Params.Name,
                args: ConvertArguments(request.Params.Arguments));

            if (!decision.Allowed)
            {
                return GovernanceDenied(decision);
            }

            return await next(request, cancellationToken);
        });
    });

var host = builder.Build();

if (args.Contains("--demo", StringComparer.OrdinalIgnoreCase))
{
    var kernel = host.Services.GetRequiredService<GovernanceKernel>();

    PrintDecision(
        "read_file",
        kernel.EvaluateToolCall(
            "did:mesh:official-sdk-sample",
            "read_file",
            new Dictionary<string, object> { ["path"] = "reports/q1-summary.txt" }));

    PrintDecision(
        "drop_database",
        kernel.EvaluateToolCall(
            "did:mesh:official-sdk-sample",
            "drop_database",
            new Dictionary<string, object> { ["db"] = "prod" }));

    return;
}

await host.RunAsync();

static CallToolResult GovernanceDenied(ToolCallResult decision)
{
    return new CallToolResult
    {
        IsError = true,
        Content =
        [
            new TextContentBlock
            {
                Text = $"Governance denied: {decision.Reason}"
            }
        ]
    };
}

static Dictionary<string, object> ConvertArguments(IDictionary<string, JsonElement>? arguments)
{
    var converted = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
    if (arguments is null)
    {
        return converted;
    }

    foreach (var (key, value) in arguments)
    {
        converted[key] = value.ValueKind switch
        {
            JsonValueKind.String => value.GetString() ?? string.Empty,
            JsonValueKind.Number when value.TryGetInt64(out var intValue) => intValue,
            JsonValueKind.Number when value.TryGetDouble(out var doubleValue) => doubleValue,
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.Null => string.Empty,
            _ => value.ToString()
        };
    }

    return converted;
}

static void PrintDecision(string toolName, ToolCallResult decision)
{
    var verdict = decision.Allowed ? "ALLOWED" : "DENIED";
    Console.WriteLine($"{toolName}: {verdict} - {decision.Reason}");
}

[McpServerToolType]
public sealed class GovernedSampleTools
{
    [McpServerTool, Description("Returns a sample report when governance allows the call.")]
    public string ReadFile([Description("Logical sample path to read")] string path)
    {
        return path switch
        {
            "reports/q1-summary.txt" => "Q1 summary: revenue up 12%, no sensitive data included.",
            _ => $"Sample file not found: {path}"
        };
    }

    [McpServerTool, Description("Demonstrates a tool that remains visible but is denied by governance.")]
    public string DropDatabase([Description("Database name")] string db)
    {
        return $"This sample would have dropped '{db}' if governance had allowed the call.";
    }
}
