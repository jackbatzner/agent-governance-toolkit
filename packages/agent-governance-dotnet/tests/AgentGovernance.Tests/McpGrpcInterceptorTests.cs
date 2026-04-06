// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Extensions;
using AgentGovernance.Mcp;
using AgentGovernance.Policy;
using Grpc.Core;
using Xunit;

namespace AgentGovernance.Tests;

/// <summary>
/// Tests for <see cref="McpGrpcInterceptor"/> — the gRPC server interceptor
/// that enforces MCP governance policies on tool calls.
/// </summary>
public sealed class McpGrpcInterceptorTests
{
    // ── Factory helpers ─────────────────────────────────────────────────

    private static GovernanceKernel CreateKernel()
    {
        return new GovernanceKernel(new GovernanceOptions { EnableAudit = true });
    }

    private static McpGateway CreateGateway(
        IEnumerable<string>? deniedTools = null,
        IEnumerable<string>? allowedTools = null,
        int maxCalls = 1000)
    {
        return new McpGateway(
            CreateKernel(),
            deniedTools: deniedTools,
            allowedTools: allowedTools)
        {
            MaxToolCallsPerAgent = maxCalls,
            RateLimiter = maxCalls > 0
                ? new McpSlidingRateLimiter
                {
                    MaxCallsPerWindow = maxCalls,
                    WindowSize = TimeSpan.FromMinutes(5)
                }
                : null
        };
    }

    private static McpGrpcInterceptor CreateInterceptor(McpGateway? gateway = null)
    {
        return new McpGrpcInterceptor(gateway ?? CreateGateway());
    }

    private static ServerCallContext CreateContext(Metadata? headers = null)
    {
        return new FakeServerCallContext(headers ?? new Metadata());
    }

    // Simple test message types for the generic handler methods.
    private sealed class TestRequest { }
    private sealed class TestResponse { }

    /// <summary>
    /// Creates a unary continuation that records whether it was invoked.
    /// </summary>
    private static (UnaryServerMethod<TestRequest, TestResponse> Continuation, Func<bool> WasInvoked)
        CreateContinuation(TestResponse? response = null)
    {
        var invoked = false;
        var expected = response ?? new TestResponse();

        Task<TestResponse> Handler(TestRequest req, ServerCallContext ctx)
        {
            invoked = true;
            return Task.FromResult(expected);
        }

        return (Handler, () => invoked);
    }

    // ── Stage: Unary handler — denied tool ──────────────────────────────

    [Fact]
    public async Task UnaryHandler_DeniedTool_ThrowsPermissionDenied()
    {
        var gateway = CreateGateway(deniedTools: new[] { "rm_rf", "drop_table" });
        var interceptor = CreateInterceptor(gateway);

        var headers = new Metadata
        {
            { McpGrpcInterceptor.AgentIdHeader, "did:mesh:agent1" },
            { McpGrpcInterceptor.ToolNameHeader, "rm_rf" }
        };
        var context = CreateContext(headers);
        var (continuation, wasInvoked) = CreateContinuation();

        var ex = await Assert.ThrowsAsync<RpcException>(() =>
            interceptor.UnaryServerHandler(new TestRequest(), context, continuation));

        Assert.Equal(StatusCode.PermissionDenied, ex.StatusCode);
        Assert.Contains("MCP governance denied", ex.Status.Detail);
        Assert.Contains("deny list", ex.Status.Detail);
        Assert.False(wasInvoked());
    }

    // ── Stage: Unary handler — allowed tool ─────────────────────────────

    [Fact]
    public async Task UnaryHandler_AllowedTool_CallsContinuation()
    {
        var gateway = CreateGateway();
        var interceptor = CreateInterceptor(gateway);

        var headers = new Metadata
        {
            { McpGrpcInterceptor.AgentIdHeader, "did:mesh:agent1" },
            { McpGrpcInterceptor.ToolNameHeader, "safe_tool" }
        };
        var context = CreateContext(headers);
        var expectedResponse = new TestResponse();
        var (continuation, wasInvoked) = CreateContinuation(expectedResponse);

        var result = await interceptor.UnaryServerHandler(
            new TestRequest(), context, continuation);

        Assert.True(wasInvoked());
        Assert.Same(expectedResponse, result);
    }

    // ── Stage: Unary handler — no MCP headers ───────────────────────────

    [Fact]
    public async Task UnaryHandler_NoMcpHeaders_PassesThrough()
    {
        var interceptor = CreateInterceptor();
        var context = CreateContext(); // No headers
        var expectedResponse = new TestResponse();
        var (continuation, wasInvoked) = CreateContinuation(expectedResponse);

        var result = await interceptor.UnaryServerHandler(
            new TestRequest(), context, continuation);

        Assert.True(wasInvoked());
        Assert.Same(expectedResponse, result);
    }

    // ── Stage: Unary handler — missing agent ID ─────────────────────────

    [Fact]
    public async Task UnaryHandler_MissingAgentId_PassesThrough()
    {
        var interceptor = CreateInterceptor();

        // Only tool name header, no agent ID
        var headers = new Metadata
        {
            { McpGrpcInterceptor.ToolNameHeader, "some_tool" }
        };
        var context = CreateContext(headers);
        var expectedResponse = new TestResponse();
        var (continuation, wasInvoked) = CreateContinuation(expectedResponse);

        var result = await interceptor.UnaryServerHandler(
            new TestRequest(), context, continuation);

        Assert.True(wasInvoked());
        Assert.Same(expectedResponse, result);
    }

    // ── Stage: Unary handler — missing tool name ────────────────────────

    [Fact]
    public async Task UnaryHandler_MissingToolName_PassesThrough()
    {
        var interceptor = CreateInterceptor();

        // Only agent ID header, no tool name
        var headers = new Metadata
        {
            { McpGrpcInterceptor.AgentIdHeader, "did:mesh:agent1" }
        };
        var context = CreateContext(headers);
        var expectedResponse = new TestResponse();
        var (continuation, wasInvoked) = CreateContinuation(expectedResponse);

        var result = await interceptor.UnaryServerHandler(
            new TestRequest(), context, continuation);

        Assert.True(wasInvoked());
        Assert.Same(expectedResponse, result);
    }

    // ── Stage: Unary handler — gateway exception → fail closed ──────────

    [Fact]
    public async Task UnaryHandler_GatewayException_FailsClosed()
    {
        var gateway = CreateGateway();
        var interceptor = CreateInterceptor(gateway);

        // Whitespace agent ID passes the null check but causes
        // ArgumentException inside InterceptToolCall (ThrowIfNullOrWhiteSpace).
        var headers = new Metadata
        {
            { McpGrpcInterceptor.AgentIdHeader, " " },
            { McpGrpcInterceptor.ToolNameHeader, "test_tool" }
        };
        var context = CreateContext(headers);
        var (continuation, wasInvoked) = CreateContinuation();

        var ex = await Assert.ThrowsAsync<RpcException>(() =>
            interceptor.UnaryServerHandler(new TestRequest(), context, continuation));

        Assert.Equal(StatusCode.Internal, ex.StatusCode);
        Assert.Contains("MCP governance evaluation failed", ex.Status.Detail);
        Assert.False(wasInvoked());
    }

    // ── Stage: Unary handler — tool params parsed from header ───────────

    [Fact]
    public async Task UnaryHandler_ToolParams_ParsedFromHeader()
    {
        var gateway = CreateGateway();
        var interceptor = CreateInterceptor(gateway);

        var headers = new Metadata
        {
            { McpGrpcInterceptor.AgentIdHeader, "did:mesh:agent1" },
            { McpGrpcInterceptor.ToolNameHeader, "read_file" },
            { McpGrpcInterceptor.ToolParamsHeader, "{\"path\":\"/etc/hosts\",\"encoding\":\"utf-8\"}" }
        };
        var context = CreateContext(headers);
        var (continuation, wasInvoked) = CreateContinuation();

        await interceptor.UnaryServerHandler(new TestRequest(), context, continuation);

        Assert.True(wasInvoked());

        // Verify the parameters were correctly parsed via the audit log
        var audit = gateway.AuditLog;
        Assert.NotEmpty(audit);

        var entry = audit[^1]; // last entry
        Assert.Equal("did:mesh:agent1", entry.AgentId);
        Assert.Equal("read_file", entry.ToolName);
        Assert.True(entry.Allowed);
        Assert.True(entry.Parameters.ContainsKey("path"));
        Assert.True(entry.Parameters.ContainsKey("encoding"));
    }

    // ── Stage: Unary handler — invalid JSON params → empty dict ─────────

    [Fact]
    public async Task UnaryHandler_InvalidJsonParams_UsesEmptyDict()
    {
        var gateway = CreateGateway();
        var interceptor = CreateInterceptor(gateway);

        var headers = new Metadata
        {
            { McpGrpcInterceptor.AgentIdHeader, "did:mesh:agent1" },
            { McpGrpcInterceptor.ToolNameHeader, "safe_tool" },
            { McpGrpcInterceptor.ToolParamsHeader, "NOT-VALID-JSON{{{" }
        };
        var context = CreateContext(headers);
        var (continuation, wasInvoked) = CreateContinuation();

        await interceptor.UnaryServerHandler(new TestRequest(), context, continuation);

        Assert.True(wasInvoked());

        // Verify the gateway received empty parameters despite invalid JSON
        var audit = gateway.AuditLog;
        Assert.NotEmpty(audit);

        var entry = audit[^1];
        Assert.Empty(entry.Parameters);
        Assert.True(entry.Allowed);
    }

    // ── Stage: Streaming handlers ───────────────────────────────────────

    [Fact]
    public async Task ServerStreamingHandler_DeniedTool_ThrowsPermissionDenied()
    {
        var gateway = CreateGateway(deniedTools: new[] { "exec_shell" });
        var interceptor = CreateInterceptor(gateway);

        var headers = new Metadata
        {
            { McpGrpcInterceptor.AgentIdHeader, "did:mesh:agent2" },
            { McpGrpcInterceptor.ToolNameHeader, "exec_shell" }
        };
        var context = CreateContext(headers);
        var writerInvoked = false;

        var ex = await Assert.ThrowsAsync<RpcException>(() =>
            interceptor.ServerStreamingServerHandler(
                new TestRequest(),
                new MockServerStreamWriter<TestResponse>(() => writerInvoked = true),
                context,
                (req, writer, ctx) => { writerInvoked = true; return Task.CompletedTask; }));

        Assert.Equal(StatusCode.PermissionDenied, ex.StatusCode);
        Assert.False(writerInvoked);
    }

    [Fact]
    public async Task ServerStreamingHandler_NoHeaders_PassesThrough()
    {
        var interceptor = CreateInterceptor();
        var context = CreateContext(); // No MCP headers
        var continuationInvoked = false;

        await interceptor.ServerStreamingServerHandler(
            new TestRequest(),
            new MockServerStreamWriter<TestResponse>(),
            context,
            (req, writer, ctx) => { continuationInvoked = true; return Task.CompletedTask; });

        Assert.True(continuationInvoked);
    }

    [Fact]
    public async Task DuplexStreamingHandler_DeniedTool_ThrowsPermissionDenied()
    {
        var gateway = CreateGateway(deniedTools: new[] { "drop_database" });
        var interceptor = CreateInterceptor(gateway);

        var headers = new Metadata
        {
            { McpGrpcInterceptor.AgentIdHeader, "did:mesh:agent3" },
            { McpGrpcInterceptor.ToolNameHeader, "drop_database" }
        };
        var context = CreateContext(headers);
        var continuationInvoked = false;

        var ex = await Assert.ThrowsAsync<RpcException>(() =>
            interceptor.DuplexStreamingServerHandler(
                new MockAsyncStreamReader<TestRequest>(),
                new MockServerStreamWriter<TestResponse>(),
                context,
                (reader, writer, ctx) => { continuationInvoked = true; return Task.CompletedTask; }));

        Assert.Equal(StatusCode.PermissionDenied, ex.StatusCode);
        Assert.False(continuationInvoked);
    }

    // ── Stage: Allow-list enforcement ───────────────────────────────────

    [Fact]
    public async Task UnaryHandler_ToolNotOnAllowList_ThrowsPermissionDenied()
    {
        var gateway = CreateGateway(allowedTools: new[] { "read_file", "list_files" });
        var interceptor = CreateInterceptor(gateway);

        var headers = new Metadata
        {
            { McpGrpcInterceptor.AgentIdHeader, "did:mesh:agent1" },
            { McpGrpcInterceptor.ToolNameHeader, "delete_file" }
        };
        var context = CreateContext(headers);
        var (continuation, wasInvoked) = CreateContinuation();

        var ex = await Assert.ThrowsAsync<RpcException>(() =>
            interceptor.UnaryServerHandler(new TestRequest(), context, continuation));

        Assert.Equal(StatusCode.PermissionDenied, ex.StatusCode);
        Assert.Contains("allow list", ex.Status.Detail);
        Assert.False(wasInvoked());
    }

    // ── Stage: Constructor validation ───────────────────────────────────

    [Fact]
    public void Constructor_NullGateway_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new McpGrpcInterceptor(null!));
    }

    // ── Mock helpers for streaming tests ────────────────────────────────

    /// <summary>
    /// Minimal <see cref="ServerCallContext"/> implementation for tests.
    /// Only <see cref="ServerCallContext.RequestHeaders"/> carries meaningful state;
    /// all other members return safe defaults.
    /// </summary>
    private sealed class FakeServerCallContext : ServerCallContext
    {
        private readonly Metadata _requestHeaders;

        public FakeServerCallContext(Metadata requestHeaders)
        {
            _requestHeaders = requestHeaders;
        }

        protected override string MethodCore => "/Test/Method";
        protected override string HostCore => "localhost";
        protected override string PeerCore => "ipv4:127.0.0.1:0";
        protected override DateTime DeadlineCore => DateTime.MaxValue;
        protected override Metadata RequestHeadersCore => _requestHeaders;
        protected override CancellationToken CancellationTokenCore => CancellationToken.None;
        protected override Metadata ResponseTrailersCore => new Metadata();
        protected override Status StatusCore { get; set; }
        protected override WriteOptions? WriteOptionsCore { get; set; }

        protected override AuthContext AuthContextCore =>
            new AuthContext(null, new Dictionary<string, List<AuthProperty>>());

        protected override Task WriteResponseHeadersAsyncCore(Metadata responseHeaders) =>
            Task.CompletedTask;

        protected override ContextPropagationToken CreatePropagationTokenCore(
            ContextPropagationOptions? options) => throw new NotSupportedException();
    }

    private sealed class MockAsyncStreamReader<T> : IAsyncStreamReader<T>
    {
        public T Current => default!;
        public Task<bool> MoveNext(CancellationToken cancellationToken) => Task.FromResult(false);
    }

    private sealed class MockServerStreamWriter<T> : IServerStreamWriter<T>
    {
        private readonly Action? _onWrite;

        public MockServerStreamWriter(Action? onWrite = null)
        {
            _onWrite = onWrite;
        }

        public WriteOptions? WriteOptions { get; set; }

        public Task WriteAsync(T message)
        {
            _onWrite?.Invoke();
            return Task.CompletedTask;
        }
    }
}
