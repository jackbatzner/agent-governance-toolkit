// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Mcp;
using Xunit;

namespace AgentGovernance.Tests;

public class McpSessionAuthenticatorTests
{
    private const string AgentId = "did:mesh:agent-001";
    private const string OtherAgentId = "did:mesh:agent-002";
    private const string UserId = "user@contoso.com";

    private static McpSessionAuthenticator CreateAuthenticator(
        TimeSpan? ttl = null,
        int maxSessions = 10)
    {
        var auth = new McpSessionAuthenticator { MaxSessionsPerAgent = maxSessions };
        if (ttl is not null)
        {
            auth = new McpSessionAuthenticator
            {
                SessionTtl = ttl.Value,
                MaxSessionsPerAgent = maxSessions
            };
        }
        return auth;
    }

    // ── CreateSession ────────────────────────────────────────────────────

    [Fact]
    public void CreateSession_ValidAgent_ReturnsToken()
    {
        var auth = CreateAuthenticator();

        var token = auth.CreateSession(AgentId);

        Assert.False(string.IsNullOrWhiteSpace(token));
        // Token should be valid base64 (32 bytes → 44 chars with padding)
        var bytes = Convert.FromBase64String(token);
        Assert.Equal(32, bytes.Length);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void CreateSession_NullOrWhitespaceAgent_Throws(string? agentId)
    {
        var auth = CreateAuthenticator();

        Assert.ThrowsAny<ArgumentException>(() => auth.CreateSession(agentId!));
    }

    [Fact]
    public void CreateSession_ExceedsMaxSessions_Throws()
    {
        var auth = CreateAuthenticator(maxSessions: 2);

        auth.CreateSession(AgentId);
        auth.CreateSession(AgentId);

        var ex = Assert.Throws<InvalidOperationException>(() => auth.CreateSession(AgentId));
        Assert.Contains("exceeded maximum concurrent sessions", ex.Message);
    }

    [Fact]
    public void CreateSession_WithUserId_BindsContext()
    {
        var auth = CreateAuthenticator();

        var token = auth.CreateSession(AgentId, userId: UserId);
        var session = auth.ValidateRequest(AgentId, token);

        Assert.NotNull(session);
        Assert.Equal(UserId, session.UserId);
        Assert.Equal($"{UserId}:{AgentId}", session.RateLimitKey);
    }

    [Fact]
    public void CreateSession_WithoutUserId_UsesAgentId()
    {
        var auth = CreateAuthenticator();

        var token = auth.CreateSession(AgentId);
        var session = auth.ValidateRequest(AgentId, token);

        Assert.NotNull(session);
        Assert.Null(session.UserId);
        Assert.Equal(AgentId, session.RateLimitKey);
    }

    [Fact]
    public void Session_TokensAreCryptographicallyRandom()
    {
        var auth = CreateAuthenticator();

        var token1 = auth.CreateSession(AgentId);
        var token2 = auth.CreateSession(AgentId);

        Assert.NotEqual(token1, token2);
    }

    // ── ValidateRequest ──────────────────────────────────────────────────

    [Fact]
    public void ValidateRequest_ValidToken_ReturnsSession()
    {
        var auth = CreateAuthenticator();
        var token = auth.CreateSession(AgentId);

        var session = auth.ValidateRequest(AgentId, token);

        Assert.NotNull(session);
        Assert.Equal(AgentId, session.AgentId);
        Assert.Equal(token, session.Token);
    }

    [Fact]
    public void ValidateRequest_WrongAgentId_ReturnsNull()
    {
        var auth = CreateAuthenticator();
        var token = auth.CreateSession(AgentId);

        // A different agent tries to use the same token → null (prevents token theft)
        var session = auth.ValidateRequest(OtherAgentId, token);

        Assert.Null(session);
    }

    [Fact]
    public void ValidateRequest_ExpiredSession_ReturnsNull()
    {
        // Use a very short TTL so the session expires immediately
        var auth = CreateAuthenticator(ttl: TimeSpan.FromMilliseconds(1));
        var token = auth.CreateSession(AgentId);

        // Wait for expiry
        Thread.Sleep(50);

        var session = auth.ValidateRequest(AgentId, token);
        Assert.Null(session);
    }

    [Fact]
    public void ValidateRequest_UnknownToken_ReturnsNull()
    {
        var auth = CreateAuthenticator();

        var session = auth.ValidateRequest(AgentId, "not-a-real-token");

        Assert.Null(session);
    }

    [Theory]
    [InlineData(null, "some-token")]
    [InlineData("", "some-token")]
    [InlineData("   ", "some-token")]
    [InlineData("did:mesh:a1", null)]
    [InlineData("did:mesh:a1", "")]
    [InlineData("did:mesh:a1", "   ")]
    public void ValidateRequest_EmptyInputs_ReturnsNull(string? agentId, string? token)
    {
        var auth = CreateAuthenticator();

        var session = auth.ValidateRequest(agentId!, token!);

        Assert.Null(session);
    }

    // ── RevokeSession ────────────────────────────────────────────────────

    [Fact]
    public void RevokeSession_ExistingToken_ReturnsTrue()
    {
        var auth = CreateAuthenticator();
        var token = auth.CreateSession(AgentId);

        Assert.True(auth.RevokeSession(token));
        // Subsequent validation fails
        Assert.Null(auth.ValidateRequest(AgentId, token));
    }

    [Fact]
    public void RevokeSession_UnknownToken_ReturnsFalse()
    {
        var auth = CreateAuthenticator();

        Assert.False(auth.RevokeSession("nonexistent-token"));
    }

    // ── RevokeAllSessions ────────────────────────────────────────────────

    [Fact]
    public void RevokeAllSessions_RemovesAllForAgent()
    {
        var auth = CreateAuthenticator();
        var token1 = auth.CreateSession(AgentId);
        var token2 = auth.CreateSession(AgentId);
        var otherToken = auth.CreateSession(OtherAgentId);

        var revoked = auth.RevokeAllSessions(AgentId);

        Assert.Equal(2, revoked);
        // Agent's sessions are gone
        Assert.Null(auth.ValidateRequest(AgentId, token1));
        Assert.Null(auth.ValidateRequest(AgentId, token2));
        // Other agent's session is untouched
        Assert.NotNull(auth.ValidateRequest(OtherAgentId, otherToken));
    }

    // ── CleanupExpiredSessions ───────────────────────────────────────────

    [Fact]
    public void CleanupExpiredSessions_RemovesExpiredOnly()
    {
        var auth = CreateAuthenticator(ttl: TimeSpan.FromMilliseconds(1));
        auth.CreateSession(AgentId);
        auth.CreateSession(AgentId);

        // Wait for those to expire
        Thread.Sleep(50);

        // Create a fresh session with a long TTL authenticator
        var freshAuth = CreateAuthenticator(ttl: TimeSpan.FromHours(1));
        var freshToken = freshAuth.CreateSession(AgentId);

        // On the short-TTL authenticator, both sessions should be expired
        var removed = auth.CleanupExpiredSessions();
        Assert.Equal(2, removed);

        // The fresh authenticator's session should remain valid
        Assert.NotNull(freshAuth.ValidateRequest(AgentId, freshToken));
    }

    // ── ActiveSessionCount ───────────────────────────────────────────────

    [Fact]
    public void ActiveSessionCount_ExcludesExpired()
    {
        var auth = CreateAuthenticator(ttl: TimeSpan.FromMilliseconds(1));
        auth.CreateSession(AgentId);
        auth.CreateSession(AgentId);

        // Wait for expiry
        Thread.Sleep(50);

        // Create one more with a long TTL — need a new authenticator for that
        // Instead, verify active count reflects the expired ones
        Assert.Equal(0, auth.ActiveSessionCount);
    }

    [Fact]
    public void ActiveSessionCount_CountsNonExpired()
    {
        var auth = CreateAuthenticator();
        auth.CreateSession(AgentId);
        auth.CreateSession(OtherAgentId);

        Assert.Equal(2, auth.ActiveSessionCount);
    }

    // ── Concurrent race condition ────────────────────────────────────────

    [Fact]
    public void CreateSession_ConcurrentCreation_RespectsMaxSessions()
    {
        var auth = new McpSessionAuthenticator
        {
            MaxSessionsPerAgent = 3,
            SessionTtl = TimeSpan.FromHours(1)
        };

        int successCount = 0;
        int failCount = 0;
        var tasks = Enumerable.Range(0, 20).Select(_ => Task.Run(() =>
        {
            try
            {
                auth.CreateSession("did:mesh:race-agent");
                Interlocked.Increment(ref successCount);
            }
            catch (InvalidOperationException)
            {
                Interlocked.Increment(ref failCount);
            }
        })).ToArray();

        Task.WaitAll(tasks);
        Assert.Equal(3, successCount);
        Assert.Equal(17, failCount);
    }
}
