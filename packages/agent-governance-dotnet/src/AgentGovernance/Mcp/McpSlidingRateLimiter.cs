// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace AgentGovernance.Mcp;

/// <summary>
/// A thread-safe sliding window rate limiter for per-agent MCP tool call budgets.
/// </summary>
/// <remarks>
/// Each agent maintains a queue of call timestamps. When <see cref="TryAcquire"/>
/// is called, expired entries (older than <see cref="WindowSize"/>) are pruned and
/// the call is allowed only if the remaining count is below <see cref="MaxCallsPerWindow"/>.
/// <para>
/// Thread safety is achieved via per-agent locking — agents do not contend with each other.
/// </para>
/// </remarks>
public sealed class McpSlidingRateLimiter
{
    private readonly ConcurrentDictionary<string, AgentBucket> _buckets = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Maximum number of calls an agent may make within a single sliding window.
    /// Defaults to <c>100</c>.
    /// </summary>
    public int MaxCallsPerWindow { get; init; } = 100;

    /// <summary>
    /// The duration of the sliding window. Defaults to 5 minutes.
    /// </summary>
    public TimeSpan WindowSize { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Optional logger for recording rate limit events.
    /// When <c>null</c>, no logging occurs — the limiter operates silently.
    /// </summary>
    public ILogger<McpSlidingRateLimiter>? Logger { get; set; }

    /// <summary>
    /// Attempts to acquire a call permit for the specified agent.
    /// Returns <c>true</c> if the agent is under the rate limit (and records the call),
    /// or <c>false</c> if the agent has exhausted its budget for the current window.
    /// </summary>
    /// <param name="agentId">The agent's identifier (e.g., a DID).</param>
    /// <returns><c>true</c> if the call is permitted; <c>false</c> if rate-limited.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="agentId"/> is null or whitespace.</exception>
    public bool TryAcquire(string agentId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(agentId);

        var bucket = _buckets.GetOrAdd(agentId, _ => new AgentBucket());
        var now = DateTimeOffset.UtcNow;
        var cutoff = now - WindowSize;

        lock (bucket.Lock)
        {
            PruneExpired(bucket.Timestamps, cutoff);

            if (bucket.Timestamps.Count >= MaxCallsPerWindow)
            {
                Logger?.LogWarning("MCP rate limit exceeded for {AgentId}: {Used}/{Max} in window", agentId, bucket.Timestamps.Count, MaxCallsPerWindow);
                return false;
            }

            bucket.Timestamps.Enqueue(now);
            return true;
        }
    }

    /// <summary>
    /// Returns the number of calls the agent can still make within the current window.
    /// </summary>
    /// <param name="agentId">The agent's identifier.</param>
    /// <returns>Remaining call budget (≥ 0).</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="agentId"/> is null or whitespace.</exception>
    public int GetRemainingBudget(string agentId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(agentId);

        if (!_buckets.TryGetValue(agentId, out var bucket))
        {
            return MaxCallsPerWindow;
        }

        var cutoff = DateTimeOffset.UtcNow - WindowSize;

        lock (bucket.Lock)
        {
            PruneExpired(bucket.Timestamps, cutoff);
            return Math.Max(0, MaxCallsPerWindow - bucket.Timestamps.Count);
        }
    }

    /// <summary>
    /// Returns the number of calls recorded in the current window for the specified agent.
    /// </summary>
    /// <param name="agentId">The agent's identifier.</param>
    /// <returns>Current call count within the window.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="agentId"/> is null or whitespace.</exception>
    public int GetCallCount(string agentId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(agentId);

        if (!_buckets.TryGetValue(agentId, out var bucket))
        {
            return 0;
        }

        var cutoff = DateTimeOffset.UtcNow - WindowSize;

        lock (bucket.Lock)
        {
            PruneExpired(bucket.Timestamps, cutoff);
            return bucket.Timestamps.Count;
        }
    }

    /// <summary>
    /// Clears all recorded call timestamps for the specified agent.
    /// </summary>
    /// <param name="agentId">The agent's identifier.</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="agentId"/> is null or whitespace.</exception>
    public void Reset(string agentId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(agentId);

        if (_buckets.TryGetValue(agentId, out var bucket))
        {
            lock (bucket.Lock)
            {
                bucket.Timestamps.Clear();
            }
        }
    }

    /// <summary>
    /// Clears all recorded call timestamps for all agents.
    /// </summary>
    public void ResetAll()
    {
        // Snapshot keys to avoid mutation during iteration.
        var keys = _buckets.Keys.ToArray();
        foreach (var key in keys)
        {
            if (_buckets.TryGetValue(key, out var bucket))
            {
                lock (bucket.Lock)
                {
                    bucket.Timestamps.Clear();
                }
            }
        }
    }

    /// <summary>
    /// Removes expired timestamps from all agents and returns the total number removed.
    /// Call periodically to reclaim memory for long-lived limiter instances.
    /// </summary>
    /// <returns>The total number of expired entries removed across all agents.</returns>
    public int CleanupExpired()
    {
        var cutoff = DateTimeOffset.UtcNow - WindowSize;
        int totalRemoved = 0;

        foreach (var kvp in _buckets)
        {
            var bucket = kvp.Value;
            lock (bucket.Lock)
            {
                int before = bucket.Timestamps.Count;
                PruneExpired(bucket.Timestamps, cutoff);
                totalRemoved += before - bucket.Timestamps.Count;
            }
        }

        return totalRemoved;
    }

    /// <summary>
    /// Dequeues all timestamps that are older than <paramref name="cutoff"/>.
    /// Because timestamps are enqueued in order, we only need to dequeue from the front.
    /// </summary>
    private static void PruneExpired(Queue<DateTimeOffset> timestamps, DateTimeOffset cutoff)
    {
        while (timestamps.Count > 0 && timestamps.Peek() <= cutoff)
        {
            timestamps.Dequeue();
        }
    }

    /// <summary>
    /// Per-agent bucket holding the call timestamps and a dedicated lock object.
    /// </summary>
    private sealed class AgentBucket
    {
        public readonly object Lock = new();
        public readonly Queue<DateTimeOffset> Timestamps = new();
    }
}
