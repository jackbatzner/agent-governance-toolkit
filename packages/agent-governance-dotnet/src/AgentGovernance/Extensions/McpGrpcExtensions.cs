// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using Grpc.AspNetCore.Server;

namespace AgentGovernance.Extensions;

/// <summary>
/// Extension methods for adding MCP governance to gRPC services.
/// </summary>
public static class McpGrpcExtensions
{
    /// <summary>
    /// Adds the <see cref="McpGrpcInterceptor"/> to the gRPC service options.
    /// <para>
    /// Must be called after <see cref="McpServiceCollectionExtensions.AddMcpGovernance"/>
    /// to ensure the <see cref="Mcp.McpGateway"/> is registered in DI.
    /// </para>
    /// </summary>
    /// <example>
    /// <code>
    /// builder.Services.AddMcpGovernance();
    /// builder.Services.AddGrpc(options =&gt; options.AddMcpGovernance());
    /// </code>
    /// </example>
    /// <param name="options">The gRPC service options to configure.</param>
    public static void AddMcpGovernance(this GrpcServiceOptions options)
    {
        options.Interceptors.Add<McpGrpcInterceptor>();
    }
}
