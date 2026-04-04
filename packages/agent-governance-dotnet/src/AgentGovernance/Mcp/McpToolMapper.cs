// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

namespace AgentGovernance.Mcp;

/// <summary>
/// Action types that an MCP tool call can be classified as.
/// Used to map tool names to governance policy categories.
/// </summary>
public enum ActionType
{
    /// <summary>Reading a file or document.</summary>
    FileRead,

    /// <summary>Writing or creating a file or document.</summary>
    FileWrite,

    /// <summary>Querying a database (read-only).</summary>
    DatabaseQuery,

    /// <summary>Writing to a database (insert, update, delete).</summary>
    DatabaseWrite,

    /// <summary>Making an HTTP/API call.</summary>
    ApiCall,

    /// <summary>Executing code or a command.</summary>
    CodeExecution,

    /// <summary>Unknown or unclassified action.</summary>
    Unknown
}

/// <summary>
/// Maps MCP tool names and resource URIs to <see cref="ActionType"/> categories
/// using a three-stage resolution strategy: exact match → pattern heuristics → deny-by-default.
/// </summary>
/// <remarks>
/// Ported from the Python MCPAdapter's <c>_map_tool_to_action</c> logic.
/// </remarks>
public sealed class McpToolMapper
{
    private readonly Dictionary<string, ActionType> _toolMapping;

    /// <summary>
    /// Default mappings for well-known MCP operations and tool names.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, ActionType> DefaultMapping =
        new Dictionary<string, ActionType>(StringComparer.OrdinalIgnoreCase)
        {
            // MCP method-level operations
            ["tools/call"] = ActionType.CodeExecution,
            ["resources/read"] = ActionType.FileRead,
            ["resources/write"] = ActionType.FileWrite,

            // Common tool name patterns
            ["file_read"] = ActionType.FileRead,
            ["file_write"] = ActionType.FileWrite,
            ["database_query"] = ActionType.DatabaseQuery,
            ["database_write"] = ActionType.DatabaseWrite,
            ["api_call"] = ActionType.ApiCall,
            ["http_request"] = ActionType.ApiCall,
        };

    /// <summary>
    /// Initializes a new <see cref="McpToolMapper"/> with optional custom mappings
    /// merged on top of the defaults.
    /// </summary>
    /// <param name="customMappings">
    /// Additional tool-name-to-action mappings. These override default mappings
    /// for the same key (case-insensitive).
    /// </param>
    public McpToolMapper(IReadOnlyDictionary<string, ActionType>? customMappings = null)
    {
        _toolMapping = new Dictionary<string, ActionType>(DefaultMapping, StringComparer.OrdinalIgnoreCase);

        if (customMappings is not null)
        {
            foreach (var (key, value) in customMappings)
            {
                _toolMapping[key] = value;
            }
        }
    }

    /// <summary>
    /// Maps a tool name to an <see cref="ActionType"/> using three-stage resolution:
    /// <list type="number">
    ///   <item>Exact match in the mapping table (case-insensitive).</item>
    ///   <item>Pattern-based heuristics on the tool name.</item>
    ///   <item>Returns <c>null</c> (deny-by-default) if no match is found.</item>
    /// </list>
    /// </summary>
    /// <param name="toolName">The MCP tool name to classify.</param>
    /// <returns>The classified <see cref="ActionType"/>, or <c>null</c> if unresolvable.</returns>
    public ActionType? MapTool(string toolName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(toolName);

        // Stage 1: Exact match
        if (_toolMapping.TryGetValue(toolName, out var action))
        {
            return action;
        }

        // Stage 2: Pattern-based heuristics
        var lower = toolName.ToLowerInvariant();

        if (ContainsAny(lower, "read", "get", "fetch", "load") && ContainsAny(lower, "file", "document"))
        {
            return ActionType.FileRead;
        }

        if (ContainsAny(lower, "write", "save", "create", "update") && ContainsAny(lower, "file", "document"))
        {
            return ActionType.FileWrite;
        }

        if (ContainsAny(lower, "sql", "query", "database", "db"))
        {
            return ContainsAny(lower, "insert", "update", "delete", "drop")
                ? ActionType.DatabaseWrite
                : ActionType.DatabaseQuery;
        }

        if (ContainsAny(lower, "api", "http", "request"))
        {
            return ActionType.ApiCall;
        }

        if (ContainsAny(lower, "exec", "run", "execute", "code", "python", "bash"))
        {
            return ActionType.CodeExecution;
        }

        // Stage 3: Deny-by-default (unclassified)
        return null;
    }

    /// <summary>
    /// Maps a resource URI to an <see cref="ActionType"/> based on its scheme.
    /// </summary>
    /// <param name="uri">The resource URI (e.g., "file://…", "db://…", "https://…").</param>
    /// <returns>The classified <see cref="ActionType"/>.</returns>
    public static ActionType MapResource(string uri)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(uri);

        if (uri.StartsWith("file://", StringComparison.OrdinalIgnoreCase))
            return ActionType.FileRead;

        if (uri.StartsWith("db://", StringComparison.OrdinalIgnoreCase)
            || uri.StartsWith("postgres://", StringComparison.OrdinalIgnoreCase)
            || uri.StartsWith("mysql://", StringComparison.OrdinalIgnoreCase))
            return ActionType.DatabaseQuery;

        if (uri.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            || uri.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            return ActionType.ApiCall;

        // Default: treat unknown URIs as file reads (safest classification).
        return ActionType.FileRead;
    }

    private static bool ContainsAny(string text, params string[] keywords) =>
        keywords.Any(k => text.Contains(k, StringComparison.Ordinal));
}
