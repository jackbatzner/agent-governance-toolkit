// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

namespace AgentGovernance.Mcp;

/// <summary>
/// Marks a method as an MCP tool that can be auto-discovered by <see cref="McpToolRegistry"/>.
/// Methods must be static or instance (on a class registered in DI) and return
/// <see cref="Dictionary{TKey, TValue}"/> or <see cref="Task{TResult}"/> of the same.
/// </summary>
[AttributeUsage(AttributeTargets.Method, AllowMultiple = false, Inherited = false)]
public sealed class McpToolAttribute : Attribute
{
    /// <summary>
    /// The MCP tool name. If not specified, the method name is converted to snake_case.
    /// </summary>
    public string? Name { get; set; }

    /// <summary>
    /// Human-readable description of what the tool does.
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Whether this tool requires human approval before execution.
    /// </summary>
    public bool RequiresApproval { get; set; }

    /// <summary>
    /// The governance action type for this tool (e.g., "FileRead", "DatabaseWrite").
    /// If not specified, <see cref="McpToolMapper"/> heuristics are used.
    /// </summary>
    public string? ActionType { get; set; }
}
