// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Text.Json;
using AgentGovernance.Mcp;
using Grpc.Core;
using Grpc.Core.Interceptors;
using Microsoft.Extensions.Logging;

namespace AgentGovernance.Extensions;

/// <summary>
/// gRPC server interceptor that enforces MCP governance policies on tool calls.
/// <para>
/// Extracts agent identity and tool metadata from gRPC headers, routes through
/// the <see cref="McpGateway"/> pipeline, and throws <see cref="RpcException"/>
/// with <see cref="StatusCode.PermissionDenied"/> on denial.
/// </para>
/// <para>
/// The interceptor is <b>fail-closed</b>: any unexpected exception during
/// gateway evaluation results in <see cref="StatusCode.Internal"/>.
/// </para>
/// <para>
/// Requests without MCP headers (<c>x-mcp-agent-id</c> and <c>x-mcp-tool-name</c>)
/// are passed through without governance checks.
/// </para>
/// </summary>
/// <remarks>
/// Usage:
/// <code>
/// builder.Services.AddGrpc(options =&gt; options.Interceptors.Add&lt;McpGrpcInterceptor&gt;());
/// </code>
/// — or use the extension method:
/// <code>
/// builder.Services.AddGrpc(options =&gt; options.AddMcpGovernance());
/// </code>
/// </remarks>
public sealed class McpGrpcInterceptor : Interceptor
{
    private readonly McpGateway _gateway;
    private readonly ILogger<McpGrpcInterceptor>? _logger;

    /// <summary>gRPC metadata key for the agent's decentralized identifier.</summary>
    public const string AgentIdHeader = "x-mcp-agent-id";

    /// <summary>gRPC metadata key for the tool name being invoked.</summary>
    public const string ToolNameHeader = "x-mcp-tool-name";

    /// <summary>gRPC metadata key for JSON-encoded tool parameters.</summary>
    public const string ToolParamsHeader = "x-mcp-tool-params";

    /// <summary>
    /// Initializes a new <see cref="McpGrpcInterceptor"/>.
    /// </summary>
    /// <param name="gateway">The MCP governance gateway resolved from DI.</param>
    /// <param name="logger">Optional logger for structured diagnostics.</param>
    public McpGrpcInterceptor(McpGateway gateway, ILogger<McpGrpcInterceptor>? logger = null)
    {
        _gateway = gateway ?? throw new ArgumentNullException(nameof(gateway));
        _logger = logger;
    }

    /// <inheritdoc/>
    public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(
        TRequest request,
        ServerCallContext context,
        UnaryServerMethod<TRequest, TResponse> continuation)
    {
        var agentId = GetHeader(context.RequestHeaders, AgentIdHeader);
        var toolName = GetHeader(context.RequestHeaders, ToolNameHeader);

        // If no MCP headers present, pass through (not an MCP call)
        if (agentId is null || toolName is null)
        {
            return await continuation(request, context);
        }

        _logger?.LogDebug("gRPC MCP intercept: {ToolName} by {AgentId}", toolName, agentId);

        var parameters = ParseToolParams(context.RequestHeaders);

        try
        {
            var (allowed, reason) = _gateway.InterceptToolCall(agentId, toolName, parameters);

            if (!allowed)
            {
                _logger?.LogWarning("gRPC MCP denied: {ToolName} for {AgentId} - {Reason}",
                    toolName, agentId, reason);
                throw new RpcException(new Status(StatusCode.PermissionDenied,
                    $"MCP governance denied: {reason}"));
            }

            _logger?.LogInformation("gRPC MCP allowed: {ToolName} for {AgentId}", toolName, agentId);
            return await continuation(request, context);
        }
        catch (RpcException)
        {
            throw; // Re-throw RpcException as-is
        }
        catch (Exception ex)
        {
            // Fail closed: any unexpected exception → deny with Internal status.
            _logger?.LogError(ex, "gRPC MCP gateway error for {ToolName} - failing closed", toolName);
            throw new RpcException(new Status(StatusCode.Internal,
                "MCP governance evaluation failed"));
        }
    }

    /// <inheritdoc/>
    public override async Task<TResponse> ClientStreamingServerHandler<TRequest, TResponse>(
        IAsyncStreamReader<TRequest> requestStream,
        ServerCallContext context,
        ClientStreamingServerMethod<TRequest, TResponse> continuation)
    {
        EnforceGovernanceHeaders(context);
        return await continuation(requestStream, context);
    }

    /// <inheritdoc/>
    public override async Task ServerStreamingServerHandler<TRequest, TResponse>(
        TRequest request,
        IServerStreamWriter<TResponse> responseStream,
        ServerCallContext context,
        ServerStreamingServerMethod<TRequest, TResponse> continuation)
    {
        EnforceGovernanceHeaders(context);
        await continuation(request, responseStream, context);
    }

    /// <inheritdoc/>
    public override async Task DuplexStreamingServerHandler<TRequest, TResponse>(
        IAsyncStreamReader<TRequest> requestStream,
        IServerStreamWriter<TResponse> responseStream,
        ServerCallContext context,
        DuplexStreamingServerMethod<TRequest, TResponse> continuation)
    {
        EnforceGovernanceHeaders(context);
        await continuation(requestStream, responseStream, context);
    }

    /// <summary>
    /// Shared governance enforcement for streaming handlers.
    /// Checks MCP headers and routes through the gateway pipeline.
    /// </summary>
    private void EnforceGovernanceHeaders(ServerCallContext context)
    {
        var agentId = GetHeader(context.RequestHeaders, AgentIdHeader);
        var toolName = GetHeader(context.RequestHeaders, ToolNameHeader);

        if (agentId is null || toolName is null)
        {
            return;
        }

        _logger?.LogDebug("gRPC MCP intercept: {ToolName} by {AgentId}", toolName, agentId);

        var parameters = ParseToolParams(context.RequestHeaders);

        try
        {
            var (allowed, reason) = _gateway.InterceptToolCall(agentId, toolName, parameters);

            if (!allowed)
            {
                _logger?.LogWarning("gRPC MCP denied: {ToolName} for {AgentId} - {Reason}",
                    toolName, agentId, reason);
                throw new RpcException(new Status(StatusCode.PermissionDenied,
                    $"MCP governance denied: {reason}"));
            }

            _logger?.LogInformation("gRPC MCP allowed: {ToolName} for {AgentId}", toolName, agentId);
        }
        catch (RpcException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "gRPC MCP gateway error for {ToolName} - failing closed", toolName);
            throw new RpcException(new Status(StatusCode.Internal,
                "MCP governance evaluation failed"));
        }
    }

    private static string? GetHeader(Metadata headers, string key)
    {
        return headers.Get(key)?.Value;
    }

    internal static Dictionary<string, object> ParseToolParams(Metadata headers)
    {
        var paramsJson = headers.Get(ToolParamsHeader)?.Value;
        if (paramsJson is null) return new Dictionary<string, object>();

        try
        {
            return JsonSerializer.Deserialize<Dictionary<string, object>>(paramsJson,
                    new JsonSerializerOptions { MaxDepth = 32 })
                ?? new Dictionary<string, object>();
        }
        catch (JsonException)
        {
            return new Dictionary<string, object>();
        }
    }
}
