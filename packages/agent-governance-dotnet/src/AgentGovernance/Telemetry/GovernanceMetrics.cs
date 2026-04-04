// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Diagnostics.Metrics;

namespace AgentGovernance.Telemetry;

/// <summary>
/// OpenTelemetry-compatible metrics for governance operations using
/// <see cref="System.Diagnostics.Metrics"/>. Consumers can collect these
/// metrics with any OTEL-compatible exporter (Prometheus, Azure Monitor, etc.).
/// </summary>
/// <remarks>
/// <b>Usage with OpenTelemetry:</b>
/// <code>
/// using var meterProvider = Sdk.CreateMeterProviderBuilder()
///     .AddMeter(GovernanceMetrics.MeterName)
///     .AddPrometheusExporter()
///     .Build();
/// </code>
/// </remarks>
public sealed class GovernanceMetrics : IDisposable
{
    /// <summary>
    /// The meter name used for all governance metrics.
    /// Register this with your OTEL MeterProvider to collect metrics.
    /// </summary>
    public const string MeterName = "AgentGovernance";

    private readonly Meter _meter;

    /// <summary>Total policy evaluation decisions (allowed + denied).</summary>
    public Counter<long> PolicyDecisions { get; }

    /// <summary>Tool calls blocked by policy.</summary>
    public Counter<long> ToolCallsBlocked { get; }

    /// <summary>Tool calls allowed by policy.</summary>
    public Counter<long> ToolCallsAllowed { get; }

    /// <summary>Requests rejected by rate limiting.</summary>
    public Counter<long> RateLimitHits { get; }

    /// <summary>Governance evaluation latency in milliseconds.</summary>
    public Histogram<double> EvaluationLatency { get; }

    /// <summary>Current agent trust score (0–1000).</summary>
    public ObservableGauge<double>? TrustScore { get; private set; }

    /// <summary>Number of active agents being tracked.</summary>
    public ObservableGauge<int>? ActiveAgents { get; private set; }

    /// <summary>Audit events emitted.</summary>
    public Counter<long> AuditEvents { get; }

    /// <summary>MCP security threats detected by scanner.</summary>
    public Counter<long> McpThreatsDetected { get; }

    /// <summary>MCP tool responses scanned.</summary>
    public Counter<long> McpResponsesScanned { get; }

    /// <summary>MCP sessions created.</summary>
    public Counter<long> McpSessionsCreated { get; }

    /// <summary>MCP messages verified (signed message checks).</summary>
    public Counter<long> McpMessagesVerified { get; }

    /// <summary>
    /// Initializes a new <see cref="GovernanceMetrics"/> instance with the default meter.
    /// </summary>
    public GovernanceMetrics()
    {
        _meter = new Meter(MeterName, "1.0.0");

        PolicyDecisions = _meter.CreateCounter<long>(
            "agent_governance.policy_decisions",
            description: "Total policy evaluation decisions");

        ToolCallsBlocked = _meter.CreateCounter<long>(
            "agent_governance.tool_calls_blocked",
            description: "Tool calls blocked by governance policy");

        ToolCallsAllowed = _meter.CreateCounter<long>(
            "agent_governance.tool_calls_allowed",
            description: "Tool calls allowed by governance policy");

        RateLimitHits = _meter.CreateCounter<long>(
            "agent_governance.rate_limit_hits",
            description: "Requests rejected by rate limiting");

        EvaluationLatency = _meter.CreateHistogram<double>(
            "agent_governance.evaluation_latency_ms",
            unit: "ms",
            description: "Governance evaluation latency in milliseconds");

        AuditEvents = _meter.CreateCounter<long>(
            "agent_governance.audit_events",
            description: "Total audit events emitted");

        McpThreatsDetected = _meter.CreateCounter<long>(
            "agent_governance.mcp.threats_detected",
            description: "MCP security threats detected by scanner");

        McpResponsesScanned = _meter.CreateCounter<long>(
            "agent_governance.mcp.responses_scanned",
            description: "MCP tool responses scanned");

        McpSessionsCreated = _meter.CreateCounter<long>(
            "agent_governance.mcp.sessions_created",
            description: "MCP sessions created");

        McpMessagesVerified = _meter.CreateCounter<long>(
            "agent_governance.mcp.messages_verified",
            description: "MCP messages verified (signed message checks)");
    }

    /// <summary>
    /// Registers an observable gauge for agent trust scores.
    /// The callback is invoked each time metrics are collected.
    /// </summary>
    /// <param name="observeValues">
    /// Callback that returns current trust scores as (value, tags) measurements.
    /// </param>
    public void RegisterTrustScoreGauge(Func<IEnumerable<Measurement<double>>> observeValues)
    {
        TrustScore = _meter.CreateObservableGauge(
            "agent_governance.trust_score",
            observeValues,
            description: "Current agent trust score (0-1000)");
    }

    /// <summary>
    /// Registers an observable gauge for active agent count.
    /// </summary>
    /// <param name="observeValue">Callback that returns the current active agent count.</param>
    public void RegisterActiveAgentsGauge(Func<int> observeValue)
    {
        ActiveAgents = _meter.CreateObservableGauge(
            "agent_governance.active_agents",
            observeValue,
            description: "Number of active agents being tracked");
    }

    /// <summary>
    /// Records a policy decision with the appropriate metric tags.
    /// </summary>
    /// <param name="allowed">Whether the decision was allow or deny.</param>
    /// <param name="agentId">The agent DID.</param>
    /// <param name="toolName">The tool name.</param>
    /// <param name="evaluationMs">Evaluation time in milliseconds.</param>
    /// <param name="rateLimited">Whether the request was rate-limited.</param>
    public void RecordDecision(bool allowed, string agentId, string toolName, double evaluationMs, bool rateLimited = false)
    {
        var tags = new KeyValuePair<string, object?>[]
        {
            new("agent_id", agentId),
            new("tool_name", toolName),
            new("decision", allowed ? "allow" : "deny")
        };

        PolicyDecisions.Add(1, tags);

        if (allowed)
            ToolCallsAllowed.Add(1, tags);
        else
            ToolCallsBlocked.Add(1, tags);

        if (rateLimited)
            RateLimitHits.Add(1, tags);

        EvaluationLatency.Record(evaluationMs, tags);
    }

    /// <summary>
    /// Records an MCP pipeline decision with stage information.
    /// Delegates to <see cref="RecordDecision"/> and adds a <c>stage</c> tag.
    /// </summary>
    /// <param name="allowed">Whether the decision was allow or deny.</param>
    /// <param name="agentId">The agent DID.</param>
    /// <param name="toolName">The tool name.</param>
    /// <param name="evaluationMs">Evaluation time in milliseconds.</param>
    /// <param name="stage">The pipeline stage that produced the decision
    /// (e.g. "deny_list", "allow_list", "sanitization", "rate_limit", "approval", "allowed").</param>
    /// <param name="rateLimited">Whether the request was rate-limited.</param>
    public void RecordMcpDecision(bool allowed, string agentId, string toolName, double evaluationMs, string stage, bool rateLimited = false)
    {
        // Record through the existing decision helper first
        RecordDecision(allowed, agentId, toolName, evaluationMs, rateLimited);

        // Add an additional measurement with the stage tag for MCP-specific drill-down
        var tags = new KeyValuePair<string, object?>[]
        {
            new("agent_id", agentId),
            new("tool_name", toolName),
            new("decision", allowed ? "allow" : "deny"),
            new("stage", stage)
        };

        PolicyDecisions.Add(1, tags);
    }

    /// <inheritdoc />
    public void Dispose() => _meter.Dispose();
}
