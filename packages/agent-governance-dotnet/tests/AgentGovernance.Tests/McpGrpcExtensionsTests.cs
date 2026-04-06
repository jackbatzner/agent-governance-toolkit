// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Extensions;
using Grpc.AspNetCore.Server;
using Xunit;

namespace AgentGovernance.Tests;

public class McpGrpcExtensionsTests
{
    [Fact]
    public void AddMcpGovernance_RegistersInterceptor()
    {
        var options = new GrpcServiceOptions();

        options.AddMcpGovernance();

        Assert.Single(options.Interceptors);
    }

    [Fact]
    public void AddMcpGovernance_RegistersCorrectInterceptorType()
    {
        var options = new GrpcServiceOptions();

        options.AddMcpGovernance();

        Assert.Equal(typeof(McpGrpcInterceptor), options.Interceptors[0].Type);
    }

    [Fact]
    public void AddMcpGovernance_CalledTwice_RegistersTwoInterceptors()
    {
        var options = new GrpcServiceOptions();

        options.AddMcpGovernance();
        options.AddMcpGovernance();

        Assert.Equal(2, options.Interceptors.Count);
    }
}
