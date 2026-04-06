// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Diagnostics.Metrics;
using AgentGovernance.Extensions;
using AgentGovernance.Mcp;
using AgentGovernance.Telemetry;
using Xunit;

namespace AgentGovernance.Tests;

/// <summary>
/// Integration tests verifying that MCP governance components correctly
/// emit OpenTelemetry metrics through <see cref="GovernanceMetrics"/>.
/// </summary>
// Serialize metrics tests to avoid .NET Meter global state interference
// when multiple test classes create GovernanceMetrics instances in parallel.
[Collection("MetricsTests")]
public class McpMetricsIntegrationTests : IDisposable
{
    private readonly McpGovernanceStack _stack;

    public McpMetricsIntegrationTests()
    {
        _stack = McpGovernanceExtensions.AddMcpGovernance(
            mcpOptions: new McpGovernanceOptions
            {
                DeniedTools = new() { "rm_rf", "drop_database" },
                SensitiveTools = new() { "send_email" },
                MaxToolCallsPerAgent = 5,
                RequireHumanApproval = false,
                EnableResponseScanning = true
            },
            agentId: "did:mesh:metrics-test");
    }

    [Fact]
    public void Gateway_EmitsToolCallsAllowed_OnAllow()
    {
        long allowedCount = 0;

        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, listener) =>
        {
            if (instrument.Meter.Name == GovernanceMetrics.MeterName)
                listener.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<long>((instrument, measurement, tags, state) =>
        {
            if (instrument.Name == "agent_governance.tool_calls_allowed")
                allowedCount += measurement;
        });
        listener.Start();

        // Baseline
        var baseline = allowedCount;

        var (allowed, _) = _stack.Gateway.InterceptToolCall(
            "did:mesh:agent-1", "file_read", new Dictionary<string, object>());

        Assert.True(allowed);
        Assert.True(allowedCount - baseline >= 1, $"Expected ToolCallsAllowed to increment; got {allowedCount - baseline}");
    }

    [Fact]
    public void Gateway_EmitsToolCallsBlocked_OnDeny()
    {
        long blockedCount = 0;

        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, listener) =>
        {
            if (instrument.Meter.Name == GovernanceMetrics.MeterName)
                listener.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<long>((instrument, measurement, tags, state) =>
        {
            if (instrument.Name == "agent_governance.tool_calls_blocked")
                blockedCount += measurement;
        });
        listener.Start();

        var baseline = blockedCount;

        var (allowed, reason) = _stack.Gateway.InterceptToolCall(
            "did:mesh:agent-1", "rm_rf", new Dictionary<string, object>());

        Assert.False(allowed);
        Assert.Contains("deny list", reason, StringComparison.OrdinalIgnoreCase);
        Assert.True(blockedCount - baseline >= 1, $"Expected ToolCallsBlocked to increment; got {blockedCount - baseline}");
    }

    [Fact]
    public void Gateway_EmitsRateLimitHits_OnBudgetExceeded()
    {
        long rateLimitCount = 0;

        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, listener) =>
        {
            if (instrument.Meter.Name == GovernanceMetrics.MeterName)
                listener.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<long>((instrument, measurement, tags, state) =>
        {
            if (instrument.Name == "agent_governance.rate_limit_hits")
                rateLimitCount += measurement;
        });
        listener.Start();

        const string agentId = "did:mesh:rate-limit-agent";

        // Exhaust the budget (MaxToolCallsPerAgent = 5)
        for (int i = 0; i < 5; i++)
        {
            _stack.Gateway.InterceptToolCall(agentId, "safe_tool", new Dictionary<string, object>());
        }

        var baseline = rateLimitCount;

        // This call should be rate-limited
        var (allowed, reason) = _stack.Gateway.InterceptToolCall(
            agentId, "safe_tool", new Dictionary<string, object>());

        Assert.False(allowed);
        Assert.Contains("exceeded call budget", reason, StringComparison.OrdinalIgnoreCase);
        Assert.True(rateLimitCount - baseline >= 1, $"Expected RateLimitHits to increment; got {rateLimitCount - baseline}");
    }

    [Fact]
    public void Scanner_EmitsMcpThreatsDetected_WhenThreatsFound()
    {
        long threatsCount = 0;

        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, listener) =>
        {
            if (instrument.Meter.Name == GovernanceMetrics.MeterName)
                listener.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<long>((instrument, measurement, tags, state) =>
        {
            if (instrument.Name == "agent_governance.mcp.threats_detected")
                threatsCount += measurement;
        });
        listener.Start();

        var baseline = threatsCount;

        // Description with invisible Unicode should trigger a threat
        var threats = _stack.Scanner.ScanTool(
            "evil_tool",
            "Read files \u200b from disk",  // Zero-width space = tool poisoning
            serverName: "test-server");

        Assert.NotEmpty(threats);
        Assert.True(threatsCount - baseline >= 1,
            $"Expected McpThreatsDetected to increment; got {threatsCount - baseline}");
    }

    [Fact]
    public void Gateway_RecordsEvaluationLatency_GreaterThanZero()
    {
        double latencyMs = -1;

        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, listener) =>
        {
            if (instrument.Meter.Name == GovernanceMetrics.MeterName)
                listener.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<double>((instrument, measurement, tags, state) =>
        {
            if (instrument.Name == "agent_governance.evaluation_latency_ms")
                latencyMs = measurement;
        });
        listener.Start();

        _stack.Gateway.InterceptToolCall(
            "did:mesh:latency-test", "file_read", new Dictionary<string, object>());

        Assert.True(latencyMs >= 0, $"Expected EvaluationLatency >= 0; got {latencyMs}");
    }

    [Fact]
    public void Gateway_EmitsPolicyDecisions_WithStageTag()
    {
        string? capturedStage = null;

        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, listener) =>
        {
            if (instrument.Meter.Name == GovernanceMetrics.MeterName)
                listener.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<long>((instrument, measurement, tags, state) =>
        {
            if (instrument.Name == "agent_governance.policy_decisions")
            {
                foreach (var tag in tags)
                {
                    if (tag.Key == "stage")
                    {
                        capturedStage = tag.Value?.ToString();
                    }
                }
            }
        });
        listener.Start();

        // A deny-list call should produce a "deny_list" stage tag
        _stack.Gateway.InterceptToolCall(
            "did:mesh:stage-test", "rm_rf", new Dictionary<string, object>());

        Assert.Equal("deny_list", capturedStage);
    }

    [Fact]
    public void AddMcpGovernance_Stack_ContainsMetrics()
    {
        Assert.NotNull(_stack.Metrics);
        Assert.Same(_stack.Metrics, _stack.Gateway.Metrics);
        Assert.Same(_stack.Metrics, _stack.Scanner.Metrics);
    }

    [Fact]
    public void Gateway_AllowedStageTag_OnSuccessfulCall()
    {
        string? capturedStage = null;

        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, listener) =>
        {
            if (instrument.Meter.Name == GovernanceMetrics.MeterName)
                listener.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<long>((instrument, measurement, tags, state) =>
        {
            if (instrument.Name == "agent_governance.policy_decisions")
            {
                foreach (var tag in tags)
                {
                    if (tag.Key == "stage")
                    {
                        capturedStage = tag.Value?.ToString();
                    }
                }
            }
        });
        listener.Start();

        _stack.Gateway.InterceptToolCall(
            "did:mesh:stage-allow", "file_read", new Dictionary<string, object>());

        Assert.Equal("allowed", capturedStage);
    }

    public void Dispose()
    {
        _stack.Metrics?.Dispose();
    }
}
