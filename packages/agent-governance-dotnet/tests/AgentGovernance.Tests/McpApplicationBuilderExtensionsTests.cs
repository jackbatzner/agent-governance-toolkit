// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Extensions;
using Microsoft.AspNetCore.Builder;
using Xunit;

namespace AgentGovernance.Tests;

public class McpApplicationBuilderExtensionsTests
{
    [Fact]
    public void UseMcpGovernance_ReturnsBuilder()
    {
        var builder = new ApplicationBuilder(new ServiceProviderStub());
        var result = builder.UseMcpGovernance();
        Assert.Same(builder, result);
    }

    [Fact]
    public void MapMcpGovernance_ReturnsBuilder()
    {
        var builder = new ApplicationBuilder(new ServiceProviderStub());
        var result = builder.MapMcpGovernance();
        Assert.Same(builder, result);
    }

    [Fact]
    public void MapMcpGovernance_CustomPath_ReturnsBuilder()
    {
        var builder = new ApplicationBuilder(new ServiceProviderStub());
        var result = builder.MapMcpGovernance("/custom-mcp");
        Assert.Same(builder, result);
    }

    /// <summary>Minimal service provider for ApplicationBuilder construction.</summary>
    private sealed class ServiceProviderStub : IServiceProvider
    {
        public object? GetService(Type serviceType) => null;
    }
}
