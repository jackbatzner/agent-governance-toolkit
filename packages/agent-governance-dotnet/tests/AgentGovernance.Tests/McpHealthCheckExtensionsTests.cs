// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Extensions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Xunit;

namespace AgentGovernance.Tests;

public class McpHealthCheckExtensionsTests
{
    [Fact]
    public void AddMcpGovernanceChecks_RegistersHealthCheck()
    {
        var services = new ServiceCollection();
        services.AddMcpGovernance();
        services.AddHealthChecks().AddMcpGovernanceChecks();

        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<HealthCheckServiceOptions>>();

        Assert.Contains(options.Value.Registrations, r => r.Name == "mcp-governance");
    }

    [Fact]
    public void AddMcpGovernanceChecks_CustomName_RegistersWithThatName()
    {
        var services = new ServiceCollection();
        services.AddMcpGovernance();
        services.AddHealthChecks().AddMcpGovernanceChecks(name: "custom-mcp-check");

        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<HealthCheckServiceOptions>>();

        Assert.Contains(options.Value.Registrations, r => r.Name == "custom-mcp-check");
    }

    [Fact]
    public void AddMcpGovernanceChecks_DefaultTags_ContainsMcpAndGovernance()
    {
        var services = new ServiceCollection();
        services.AddMcpGovernance();
        services.AddHealthChecks().AddMcpGovernanceChecks();

        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<HealthCheckServiceOptions>>();
        var registration = options.Value.Registrations.First(r => r.Name == "mcp-governance");

        Assert.Contains("mcp", registration.Tags);
        Assert.Contains("governance", registration.Tags);
        Assert.Contains("ready", registration.Tags);
    }

    [Fact]
    public void AddMcpGovernanceChecks_DefaultFailureStatus_IsDegraded()
    {
        var services = new ServiceCollection();
        services.AddMcpGovernance();
        services.AddHealthChecks().AddMcpGovernanceChecks();

        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<HealthCheckServiceOptions>>();
        var registration = options.Value.Registrations.First(r => r.Name == "mcp-governance");

        Assert.Equal(HealthStatus.Degraded, registration.FailureStatus);
    }
}
