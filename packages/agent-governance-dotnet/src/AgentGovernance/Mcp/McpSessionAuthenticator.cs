// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Collections.Concurrent;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace AgentGovernance.Mcp;

/// <summary>
/// Authenticates MCP sessions by binding agent identities to cryptographic session tokens.
/// Implements OWASP MCP Security Cheat Sheet §6: sessions are bound to user/agent context,
/// validated on each request, and expire after a configurable TTL.
/// <para>
/// Prevents rate-limiter bypass via agent ID spoofing by requiring authenticated sessions.
/// Session IDs are cryptographically random (not sequential or predictable).
/// </para>
/// </summary>
public sealed class McpSessionAuthenticator
{
    // Session storage: token → session info
    private readonly ConcurrentDictionary<string, McpSession> _sessions = new();
    private readonly object _sessionLock = new();

    /// <summary>Session TTL. Defaults to 1 hour.</summary>
    public TimeSpan SessionTtl { get; init; } = TimeSpan.FromHours(1);

    /// <summary>Maximum concurrent sessions per agent. Defaults to 10.</summary>
    public int MaxSessionsPerAgent { get; init; } = 10;

    /// <summary>
    /// Optional logger for recording session lifecycle events.
    /// When <c>null</c>, no logging occurs — the authenticator operates silently.
    /// </summary>
    public ILogger<McpSessionAuthenticator>? Logger { get; set; }

    /// <summary>
    /// Creates a new authenticated session for an agent.
    /// </summary>
    /// <param name="agentId">The agent's DID (e.g., "did:mesh:agent-001").</param>
    /// <param name="userId">Optional user context to bind the session to.</param>
    /// <returns>A session token that must be presented with each request.</returns>
    /// <exception cref="ArgumentException">If agentId is null or whitespace.</exception>
    /// <exception cref="InvalidOperationException">If agent has exceeded max concurrent sessions.</exception>
    public string CreateSession(string agentId, string? userId = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(agentId);

        // Lock to prevent TOCTOU race between count check and add
        lock (_sessionLock)
        {
            // Check max sessions per agent
            var agentSessionCount = _sessions.Count(kv => kv.Value.AgentId == agentId && !kv.Value.IsExpired);
            if (agentSessionCount >= MaxSessionsPerAgent)
                throw new InvalidOperationException($"Agent '{agentId}' has exceeded maximum concurrent sessions ({MaxSessionsPerAgent}).");

            // Generate cryptographic session token
            var tokenBytes = RandomNumberGenerator.GetBytes(32);
            var token = Convert.ToBase64String(tokenBytes);

            var session = new McpSession
            {
                Token = token,
                AgentId = agentId,
                UserId = userId,
                CreatedAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.Add(SessionTtl),
                // Composite key for rate limiting: userId:agentId or just agentId
                RateLimitKey = userId is not null ? $"{userId}:{agentId}" : agentId
            };

            _sessions.TryAdd(token, session);
            Logger?.LogInformation("MCP session created for {AgentId}, token: {TokenPrefix}...", agentId, token[..8]);
            return token;
        }
    }

    /// <summary>
    /// Validates a request against an existing session.
    /// </summary>
    /// <param name="agentId">The agent's DID claiming this session.</param>
    /// <param name="sessionToken">The session token to validate.</param>
    /// <returns>The authenticated session, or <c>null</c> if validation fails.</returns>
    public McpSession? ValidateRequest(string agentId, string sessionToken)
    {
        if (string.IsNullOrWhiteSpace(agentId) || string.IsNullOrWhiteSpace(sessionToken))
        {
            Logger?.LogWarning("MCP session validation failed for {AgentId}: {Reason}", agentId ?? "(null)", "missing agentId or sessionToken");
            return null;
        }

        if (!_sessions.TryGetValue(sessionToken, out var session))
        {
            Logger?.LogWarning("MCP session validation failed for {AgentId}: {Reason}", agentId, "session token not found");
            return null;
        }

        // Check agent ID matches (prevent token theft)
        if (!string.Equals(session.AgentId, agentId, StringComparison.Ordinal))
        {
            Logger?.LogWarning("MCP session validation failed for {AgentId}: {Reason}", agentId, "agent ID mismatch");
            return null;
        }

        // Check expiry
        if (session.IsExpired)
        {
            Logger?.LogWarning("MCP session validation failed for {AgentId}: {Reason}", agentId, "session expired");
            _sessions.TryRemove(sessionToken, out _);
            return null;
        }

        return session;
    }

    /// <summary>
    /// Revokes a session token immediately.
    /// </summary>
    /// <param name="sessionToken">The token to revoke.</param>
    /// <returns><c>true</c> if the session was found and removed; otherwise <c>false</c>.</returns>
    public bool RevokeSession(string sessionToken)
    {
        return _sessions.TryRemove(sessionToken, out _);
    }

    /// <summary>
    /// Revokes all sessions for an agent.
    /// </summary>
    /// <param name="agentId">The agent whose sessions should be revoked.</param>
    /// <returns>The number of sessions revoked.</returns>
    public int RevokeAllSessions(string agentId)
    {
        var toRemove = _sessions.Where(kv => kv.Value.AgentId == agentId).Select(kv => kv.Key).ToList();
        foreach (var token in toRemove)
            _sessions.TryRemove(token, out _);
        return toRemove.Count;
    }

    /// <summary>
    /// Removes expired sessions from the cache.
    /// </summary>
    /// <returns>The number of expired sessions removed.</returns>
    public int CleanupExpiredSessions()
    {
        var expired = _sessions.Where(kv => kv.Value.IsExpired).Select(kv => kv.Key).ToList();
        foreach (var token in expired)
        {
            if (_sessions.TryRemove(token, out var session))
            {
                Logger?.LogDebug("MCP session expired for {AgentId}", session.AgentId);
            }
        }
        return expired.Count;
    }

    /// <summary>
    /// Gets the count of active (non-expired) sessions.
    /// </summary>
    public int ActiveSessionCount => _sessions.Count(kv => !kv.Value.IsExpired);
}

/// <summary>
/// Represents an authenticated MCP session bound to an agent identity.
/// </summary>
public sealed class McpSession
{
    /// <summary>Cryptographic session token.</summary>
    public required string Token { get; init; }

    /// <summary>The agent's DID this session is bound to.</summary>
    public required string AgentId { get; init; }

    /// <summary>Optional user context (for user:agent binding).</summary>
    public string? UserId { get; init; }

    /// <summary>When the session was created.</summary>
    public DateTimeOffset CreatedAt { get; init; }

    /// <summary>When the session expires.</summary>
    public DateTimeOffset ExpiresAt { get; init; }

    /// <summary>
    /// Composite key for rate limiting. Format: "userId:agentId" or just "agentId".
    /// </summary>
    public required string RateLimitKey { get; init; }

    /// <summary>Whether this session has expired.</summary>
    public bool IsExpired => DateTimeOffset.UtcNow >= ExpiresAt;
}
