// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AgentGovernance.Mcp;

/// <summary>
/// SHA-256 fingerprint of an MCP tool definition, used for rug-pull detection.
/// Tracks changes to a tool's description and schema over time.
/// </summary>
public sealed class ToolFingerprint
{
    /// <summary>Name of the tool.</summary>
    public required string ToolName { get; init; }

    /// <summary>Name of the MCP server that hosts this tool.</summary>
    public required string ServerName { get; init; }

    /// <summary>SHA-256 hash of the tool's description.</summary>
    public required string DescriptionHash { get; set; }

    /// <summary>SHA-256 hash of the tool's input schema (JSON, sorted keys).</summary>
    public required string SchemaHash { get; set; }

    /// <summary>UTC timestamp when the tool was first registered.</summary>
    public DateTimeOffset FirstSeen { get; init; }

    /// <summary>UTC timestamp of the most recent observation.</summary>
    public DateTimeOffset LastSeen { get; set; }

    /// <summary>
    /// Monotonically increasing version counter. Incremented each time
    /// the description or schema hash changes.
    /// </summary>
    public int Version { get; set; }
}

/// <summary>
/// Thread-safe registry that computes and stores <see cref="ToolFingerprint"/>
/// records for MCP tools. Used by <see cref="McpSecurityScanner"/> to detect rug-pull attacks.
/// </summary>
public sealed class ToolFingerprintRegistry
{
    private readonly ConcurrentDictionary<string, ToolFingerprint> _registry = new(StringComparer.Ordinal);

    /// <summary>
    /// Registers or updates a tool fingerprint. Returns the current fingerprint.
    /// </summary>
    /// <param name="toolName">Name of the tool.</param>
    /// <param name="description">The tool's description text.</param>
    /// <param name="schema">The tool's input schema (may be <c>null</c>).</param>
    /// <param name="serverName">Name of the hosting MCP server.</param>
    /// <returns>The registered or updated <see cref="ToolFingerprint"/>.</returns>
    public ToolFingerprint Register(
        string toolName,
        string description,
        Dictionary<string, object>? schema,
        string serverName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(toolName);
        ArgumentException.ThrowIfNullOrWhiteSpace(serverName);

        var key = $"{serverName}::{toolName}";
        var now = DateTimeOffset.UtcNow;
        var descHash = ComputeHash(description ?? string.Empty);
        var schemaHash = ComputeSchemaHash(schema);

        return _registry.AddOrUpdate(
            key,
            _ => new ToolFingerprint
            {
                ToolName = toolName,
                ServerName = serverName,
                DescriptionHash = descHash,
                SchemaHash = schemaHash,
                FirstSeen = now,
                LastSeen = now,
                Version = 1
            },
            (_, existing) =>
            {
                var changed = !string.Equals(existing.DescriptionHash, descHash, StringComparison.Ordinal)
                           || !string.Equals(existing.SchemaHash, schemaHash, StringComparison.Ordinal);

                existing.LastSeen = now;

                if (changed)
                {
                    existing.DescriptionHash = descHash;
                    existing.SchemaHash = schemaHash;
                    existing.Version++;
                }

                return existing;
            });
    }

    /// <summary>
    /// Retrieves the fingerprint for a tool, if one exists.
    /// </summary>
    /// <param name="toolName">Name of the tool.</param>
    /// <param name="serverName">Name of the MCP server.</param>
    /// <returns>The fingerprint, or <c>null</c> if the tool is not registered.</returns>
    public ToolFingerprint? Get(string toolName, string serverName)
    {
        var key = $"{serverName}::{toolName}";
        return _registry.TryGetValue(key, out var fp) ? fp : null;
    }

    /// <summary>
    /// Returns a snapshot of all registered fingerprints.
    /// </summary>
    public IReadOnlyList<ToolFingerprint> GetAll() =>
        _registry.Values.ToList().AsReadOnly();

    /// <summary>
    /// Removes all registered fingerprints. Useful for testing.
    /// </summary>
    public void Clear() => _registry.Clear();

    /// <summary>
    /// Computes the SHA-256 hash of a string value.
    /// </summary>
    public static string ComputeHash(string value)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    /// <summary>
    /// Computes the SHA-256 hash of a JSON schema dictionary.
    /// Keys are sorted for deterministic hashing.
    /// </summary>
    public static string ComputeSchemaHash(Dictionary<string, object>? schema)
    {
        if (schema is null || schema.Count == 0)
        {
            return ComputeHash(string.Empty);
        }

        // Sort keys for deterministic hashing regardless of insertion order
        var sorted = new SortedDictionary<string, object>(schema, StringComparer.Ordinal);
        var json = JsonSerializer.Serialize(sorted, new JsonSerializerOptions
        {
            WriteIndented = false,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        });

        return ComputeHash(json);
    }
}
