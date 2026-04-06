// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Extensions;
using AgentGovernance.Mcp;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Xunit;

namespace AgentGovernance.Tests;

public class McpHealthCheckTests
{
    [Fact]
    public async Task HealthCheck_NoServicesRegistered_ReturnsHealthy()
    {
        var check = new McpGovernanceHealthCheck();
        var result = await check.CheckHealthAsync(CreateContext());

        Assert.Equal(HealthStatus.Healthy, result.Status);
        Assert.Contains("operational", result.Description);
        Assert.Equal("not_registered", result.Data["gateway"]);
    }

    [Fact]
    public async Task HealthCheck_WithGateway_ReportsGatewayRegistered()
    {
        var gateway = CreateGateway();
        var check = new McpGovernanceHealthCheck(gateway: gateway);

        var result = await check.CheckHealthAsync(CreateContext());

        Assert.Equal("registered", result.Data["gateway"]);
    }

    [Fact]
    public async Task HealthCheck_GatewayPipelineFunctional_ReportsPass()
    {
        var gateway = CreateGateway();
        var check = new McpGovernanceHealthCheck(gateway: gateway);

        var result = await check.CheckHealthAsync(CreateContext());

        Assert.Equal(HealthStatus.Healthy, result.Status);
        Assert.Equal("functional", result.Data["gateway_pipeline"]);
    }

    [Fact]
    public async Task HealthCheck_WithScanner_ReportsRegistered()
    {
        var scanner = new McpSecurityScanner();
        var check = new McpGovernanceHealthCheck(scanner: scanner);

        var result = await check.CheckHealthAsync(CreateContext());

        Assert.Equal(HealthStatus.Healthy, result.Status);
        Assert.Equal("registered", result.Data["scanner"]);
    }

    [Fact]
    public async Task HealthCheck_WithSessionAuth_ReportsConfig()
    {
        var auth = new McpSessionAuthenticator
        {
            SessionTtl = TimeSpan.FromMinutes(30),
            MaxSessionsPerAgent = 5
        };
        var check = new McpGovernanceHealthCheck(sessionAuth: auth);

        var result = await check.CheckHealthAsync(CreateContext());

        Assert.Equal(HealthStatus.Healthy, result.Status);
        Assert.Equal("registered", result.Data["session_authenticator"]);
        Assert.Equal(TimeSpan.FromMinutes(30).ToString(), result.Data["session_ttl"]);
        Assert.Equal(5, result.Data["max_sessions_per_agent"]);
    }

    [Fact]
    public async Task HealthCheck_WithMessageSigner_RoundTripPass()
    {
        var key = McpMessageSigner.GenerateKey();
        var signer = new McpMessageSigner(key);
        var check = new McpGovernanceHealthCheck(messageSigner: signer);

        var result = await check.CheckHealthAsync(CreateContext());

        Assert.Equal(HealthStatus.Healthy, result.Status);
        Assert.Equal("registered", result.Data["message_signer"]);
        Assert.Equal("pass", result.Data["message_signer_roundtrip"]);
    }

    [Fact]
    public async Task HealthCheck_AllComponents_Healthy()
    {
        var gateway = CreateGateway();
        var scanner = new McpSecurityScanner();
        var auth = new McpSessionAuthenticator();
        var signer = new McpMessageSigner(McpMessageSigner.GenerateKey());

        var check = new McpGovernanceHealthCheck(
            gateway: gateway,
            scanner: scanner,
            sessionAuth: auth,
            messageSigner: signer);

        var result = await check.CheckHealthAsync(CreateContext());

        Assert.Equal(HealthStatus.Healthy, result.Status);
        Assert.Contains("operational", result.Description);
        Assert.Equal("registered", result.Data["gateway"]);
        Assert.Equal("registered", result.Data["scanner"]);
        Assert.Equal("registered", result.Data["session_authenticator"]);
        Assert.Equal("registered", result.Data["message_signer"]);
        Assert.Equal("pass", result.Data["message_signer_roundtrip"]);
    }

    [Fact]
    public async Task HealthCheck_GatewayWithDenyList_ProbeDeniedButPipelineFunctional()
    {
        // Gateway with a deny list that blocks the health-check probe tool name;
        // the probe is blocked by deny-list → InterceptToolCall returns Allowed=false,
        // but that is NOT an exception — pipeline is still "functional".
        var gateway = CreateGateway(deniedTools: new[] { "__health_check__" });
        var check = new McpGovernanceHealthCheck(gateway: gateway);

        var result = await check.CheckHealthAsync(CreateContext());

        Assert.Equal(HealthStatus.Healthy, result.Status);
        Assert.Equal("functional", result.Data["gateway_pipeline"]);
    }

    [Fact]
    public async Task HealthCheck_DefaultSessionAuth_ReportsDefaultValues()
    {
        var auth = new McpSessionAuthenticator();
        var check = new McpGovernanceHealthCheck(sessionAuth: auth);

        var result = await check.CheckHealthAsync(CreateContext());

        Assert.Equal(TimeSpan.FromHours(1).ToString(), result.Data["session_ttl"]);
        Assert.Equal(10, result.Data["max_sessions_per_agent"]);
    }

    [Fact]
    public async Task HealthCheck_NeverThrows()
    {
        // Even with null services, the health check should return a result (not throw)
        var check = new McpGovernanceHealthCheck(
            gateway: null,
            scanner: null,
            sessionAuth: null,
            messageSigner: null);

        var result = await check.CheckHealthAsync(CreateContext());

        Assert.Equal(HealthStatus.Healthy, result.Status);
    }

    // --- Helpers ---

    private static HealthCheckContext CreateContext()
    {
        return new HealthCheckContext
        {
            Registration = new HealthCheckRegistration(
                "mcp-governance",
                new McpGovernanceHealthCheck(),
                HealthStatus.Degraded,
                new[] { "mcp" })
        };
    }

    private static McpGateway CreateGateway(IEnumerable<string>? deniedTools = null)
    {
        var kernel = new GovernanceKernel(new GovernanceOptions { EnableAudit = true });
        return new McpGateway(
            kernel,
            deniedTools: deniedTools)
        {
            MaxToolCallsPerAgent = 1000,
            RateLimiter = new McpSlidingRateLimiter
            {
                MaxCallsPerWindow = 1000,
                WindowSize = TimeSpan.FromMinutes(5)
            }
        };
    }
}
