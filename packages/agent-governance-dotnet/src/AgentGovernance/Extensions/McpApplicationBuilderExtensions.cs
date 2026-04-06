// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using Microsoft.AspNetCore.Builder;

namespace AgentGovernance.Extensions;

/// <summary>
/// Extension methods for adding MCP governance middleware to the ASP.NET Core HTTP pipeline.
/// </summary>
public static class McpApplicationBuilderExtensions
{
    /// <summary>
    /// Adds MCP governance middleware to the ASP.NET Core HTTP pipeline.
    /// Must be called after <see cref="McpServiceCollectionExtensions.AddMcpGovernance"/>.
    /// </summary>
    /// <param name="app">The application builder.</param>
    /// <returns>The same <see cref="IApplicationBuilder"/> for chaining.</returns>
    public static IApplicationBuilder UseMcpGovernance(this IApplicationBuilder app)
    {
        return app.UseMiddleware<McpGovernanceMiddleware>();
    }

    /// <summary>
    /// Maps an MCP governance endpoint at the specified path.
    /// Use this instead of <see cref="UseMcpGovernance"/> when you want governance
    /// only at a specific URL path (e.g., <c>"/mcp"</c>).
    /// </summary>
    /// <param name="app">The application builder.</param>
    /// <param name="path">
    /// The URL path prefix to intercept. Defaults to <c>"/mcp"</c>.
    /// </param>
    /// <returns>The same <see cref="IApplicationBuilder"/> for chaining.</returns>
    public static IApplicationBuilder MapMcpGovernance(
        this IApplicationBuilder app,
        string path = "/mcp")
    {
        return app.Map(path, branch => branch.UseMiddleware<McpGovernanceMiddleware>());
    }
}
