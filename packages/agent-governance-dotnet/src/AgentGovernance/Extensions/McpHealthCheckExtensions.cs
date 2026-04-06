// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace AgentGovernance.Extensions;

/// <summary>
/// Health check extensions for MCP governance services.
/// </summary>
public static class McpHealthCheckExtensions
{
    /// <summary>
    /// Adds MCP governance health checks to the health check builder.
    /// Checks rate limiter capacity, session authenticator state, and message signer availability.
    /// </summary>
    public static IHealthChecksBuilder AddMcpGovernanceChecks(
        this IHealthChecksBuilder builder,
        string name = "mcp-governance",
        HealthStatus? failureStatus = null,
        IEnumerable<string>? tags = null)
    {
        return builder.AddCheck<McpGovernanceHealthCheck>(
            name,
            failureStatus ?? HealthStatus.Degraded,
            tags ?? new[] { "mcp", "governance", "ready" });
    }
}
