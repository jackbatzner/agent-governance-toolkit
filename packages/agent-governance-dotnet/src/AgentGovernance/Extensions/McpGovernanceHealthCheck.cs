// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using AgentGovernance.Mcp;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace AgentGovernance.Extensions;

/// <summary>
/// Health check that verifies MCP governance components are operational.
/// </summary>
public sealed class McpGovernanceHealthCheck : IHealthCheck
{
    private readonly McpGateway? _gateway;
    private readonly McpSecurityScanner? _scanner;
    private readonly McpSessionAuthenticator? _sessionAuth;
    private readonly McpMessageSigner? _messageSigner;

    /// <summary>
    /// Initializes a new <see cref="McpGovernanceHealthCheck"/>.
    /// </summary>
    /// <param name="gateway">Optional MCP gateway to check.</param>
    /// <param name="scanner">Optional security scanner to check.</param>
    /// <param name="sessionAuth">Optional session authenticator to check.</param>
    /// <param name="messageSigner">Optional message signer to check.</param>
    public McpGovernanceHealthCheck(
        McpGateway? gateway = null,
        McpSecurityScanner? scanner = null,
        McpSessionAuthenticator? sessionAuth = null,
        McpMessageSigner? messageSigner = null)
    {
        _gateway = gateway;
        _scanner = scanner;
        _sessionAuth = sessionAuth;
        _messageSigner = messageSigner;
    }

    /// <inheritdoc/>
    public Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        var data = new Dictionary<string, object>();
        var issues = new List<string>();

        // Check gateway is available
        if (_gateway is not null)
        {
            data["gateway"] = "registered";
            // Test a benign tool call to verify pipeline is functional
            try
            {
                var (_, reason) = _gateway.InterceptToolCall(
                    "health-check-probe", "__health_check__", new Dictionary<string, object>());
                data["gateway_pipeline"] = "functional";
            }
            catch (Exception ex)
            {
                issues.Add($"Gateway pipeline error: {ex.Message}");
                data["gateway_pipeline"] = "error";
            }
        }
        else
        {
            data["gateway"] = "not_registered";
        }

        // Check scanner
        if (_scanner is not null)
        {
            data["scanner"] = "registered";
        }

        // Check session authenticator
        if (_sessionAuth is not null)
        {
            data["session_authenticator"] = "registered";
            data["session_ttl"] = _sessionAuth.SessionTtl.ToString();
            data["max_sessions_per_agent"] = _sessionAuth.MaxSessionsPerAgent;
        }

        // Check message signer
        if (_messageSigner is not null)
        {
            data["message_signer"] = "registered";
            // Verify signing round-trip works
            try
            {
                var signed = _messageSigner.SignMessage("{\"test\":\"health\"}");
                var result = _messageSigner.VerifyMessage(signed);
                data["message_signer_roundtrip"] = result.IsValid ? "pass" : "fail";
                if (!result.IsValid) issues.Add("Message signer round-trip verification failed");
            }
            catch (Exception ex)
            {
                issues.Add($"Message signer error: {ex.Message}");
                data["message_signer_roundtrip"] = "error";
            }
        }

        if (issues.Count > 0)
        {
            return Task.FromResult(HealthCheckResult.Degraded(
                $"MCP governance degraded: {string.Join("; ", issues)}",
                data: data));
        }

        return Task.FromResult(HealthCheckResult.Healthy(
            "MCP governance operational",
            data: data));
    }
}
