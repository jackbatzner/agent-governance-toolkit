// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Text.RegularExpressions;

namespace AgentGovernance.Mcp;

/// <summary>
/// MCP-specific threat types aligned with the OWASP MCP threat taxonomy.
/// </summary>
public enum McpThreatType
{
    /// <summary>Malicious instructions hidden in tool descriptions or schemas.</summary>
    ToolPoisoning,

    /// <summary>Tool definition changed after initial registration (bait-and-switch).</summary>
    RugPull,

    /// <summary>Tool from one server impersonating or shadowing another server's tool.</summary>
    CrossServerAttack,

    /// <summary>Prompt injection hidden in tool description text.</summary>
    DescriptionInjection,

    /// <summary>Overly permissive or suspicious schema definitions.</summary>
    SchemaAbuse,

    /// <summary>Protocol-level attacks targeting the JSON-RPC transport.</summary>
    ProtocolAttack
}

/// <summary>
/// Severity level for MCP security threats.
/// </summary>
public enum McpSeverity
{
    /// <summary>Informational finding, not necessarily a threat.</summary>
    Info,

    /// <summary>Low-severity finding that warrants monitoring.</summary>
    Warning,

    /// <summary>High-severity threat that should be investigated.</summary>
    High,

    /// <summary>Critical threat requiring immediate action.</summary>
    Critical
}

/// <summary>
/// Represents a single MCP security threat detected by the <see cref="McpSecurityScanner"/>.
/// </summary>
public sealed class McpThreat
{
    /// <summary>The type of threat detected.</summary>
    public McpThreatType ThreatType { get; init; }

    /// <summary>The severity of the threat.</summary>
    public McpSeverity Severity { get; init; }

    /// <summary>Name of the tool that triggered the finding.</summary>
    public required string ToolName { get; init; }

    /// <summary>Name of the MCP server hosting the tool.</summary>
    public required string ServerName { get; init; }

    /// <summary>Human-readable description of the threat.</summary>
    public required string Message { get; init; }

    /// <summary>The pattern or indicator that matched, if applicable.</summary>
    public string? MatchedPattern { get; init; }

    /// <summary>Additional structured details about the finding.</summary>
    public Dictionary<string, object> Details { get; init; } = new();
}

/// <summary>
/// Aggregated result of scanning one or more tools on an MCP server.
/// </summary>
public sealed class ScanResult
{
    /// <summary>Name of the server that was scanned.</summary>
    public required string ServerName { get; init; }

    /// <summary>Number of tools scanned.</summary>
    public int ToolsScanned { get; init; }

    /// <summary>All threats discovered during the scan.</summary>
    public List<McpThreat> Threats { get; init; } = new();

    /// <summary>Whether any critical-severity threats were found.</summary>
    public bool HasCritical => Threats.Any(t => t.Severity == McpSeverity.Critical);

    /// <summary>Whether any threats were found at all.</summary>
    public bool HasThreats => Threats.Count > 0;
}

/// <summary>
/// MCP JSON-RPC message types as defined by the Model Context Protocol.
/// </summary>
public enum McpMessageType
{
    /// <summary>List available tools.</summary>
    ToolsList,

    /// <summary>Invoke a tool.</summary>
    ToolsCall,

    /// <summary>List available resources.</summary>
    ResourcesList,

    /// <summary>Read a resource.</summary>
    ResourcesRead,

    /// <summary>List available prompts.</summary>
    PromptsList,

    /// <summary>Get a specific prompt.</summary>
    PromptsGet,

    /// <summary>Completion request (reserved for future use).</summary>
    CompletionComplete
}

/// <summary>
/// Maps <see cref="McpMessageType"/> values to their JSON-RPC method strings.
/// </summary>
public static class McpMessageTypeExtensions
{
    private static readonly Dictionary<string, McpMessageType> MethodToType = new(StringComparer.OrdinalIgnoreCase)
    {
        ["tools/list"] = McpMessageType.ToolsList,
        ["tools/call"] = McpMessageType.ToolsCall,
        ["resources/list"] = McpMessageType.ResourcesList,
        ["resources/read"] = McpMessageType.ResourcesRead,
        ["prompts/list"] = McpMessageType.PromptsList,
        ["prompts/get"] = McpMessageType.PromptsGet,
        ["completion/complete"] = McpMessageType.CompletionComplete,
    };

    private static readonly Dictionary<McpMessageType, string> TypeToMethod = MethodToType
        .ToDictionary(kv => kv.Value, kv => kv.Key);

    /// <summary>
    /// Parses a JSON-RPC method string into an <see cref="McpMessageType"/>.
    /// Returns <c>null</c> if the method is not recognised.
    /// </summary>
    public static McpMessageType? FromMethod(string method) =>
        MethodToType.TryGetValue(method, out var type) ? type : null;

    /// <summary>
    /// Converts an <see cref="McpMessageType"/> to its JSON-RPC method string.
    /// </summary>
    public static string ToMethod(this McpMessageType type) =>
        TypeToMethod.TryGetValue(type, out var method) ? method : type.ToString();
}

/// <summary>
/// Approval status for human-in-the-loop governance on sensitive MCP tool calls.
/// </summary>
public enum ApprovalStatus
{
    /// <summary>Awaiting human review.</summary>
    Pending,

    /// <summary>Approved by a human reviewer.</summary>
    Approved,

    /// <summary>Denied by a human reviewer.</summary>
    Denied
}

/// <summary>
/// Default sanitization patterns for parameter inspection in the MCP gateway.
/// Mirrors the built-in dangerous patterns from the Python MCPGateway.
/// </summary>
public static class SanitizationDefaults
{
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(200);

    /// <summary>SSN pattern (###-##-####).</summary>
    public static readonly Regex SsnPattern =
        new(@"\b\d{3}-\d{2}-\d{4}\b", RegexOptions.Compiled, RegexTimeout);

    /// <summary>Credit card pattern (4 groups of 4 digits, optional separators).</summary>
    public static readonly Regex CreditCardPattern =
        new(@"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b", RegexOptions.Compiled, RegexTimeout);

    /// <summary>Shell destructive commands after command separators (; &amp;&amp; &amp; |).</summary>
    public static readonly Regex ShellDestructivePattern =
        new(@"[;&|]\s*(rm|del|format|mkfs)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout);

    /// <summary>Command substitution via <c>$(…)</c>.</summary>
    public static readonly Regex CommandSubstitutionPattern =
        new(@"\$\(.*\)", RegexOptions.Compiled, RegexTimeout);

    /// <summary>Backtick execution.</summary>
    public static readonly Regex BacktickExecutionPattern =
        new(@"`[^`]+`", RegexOptions.Compiled, RegexTimeout);

    /// <summary>Path traversal sequences (<c>../</c> or <c>..\</c>).</summary>
    public static readonly Regex PathTraversalPattern =
        new(@"\.\.[/\\]", RegexOptions.Compiled, RegexTimeout);

    /// <summary>SSRF targeting cloud metadata endpoints.</summary>
    public static readonly Regex SsrfMetadataPattern =
        new(@"169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200", RegexOptions.Compiled, RegexTimeout);

    /// <summary>SSRF targeting internal/private IP ranges.</summary>
    public static readonly Regex SsrfInternalIpPattern =
        new(@"\b(127\.\d{1,3}\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b", RegexOptions.Compiled, RegexTimeout);

    /// <summary>SSRF via dangerous URI schemes (gopher, dict, file, jar, ldap).</summary>
    public static readonly Regex SsrfDangerousSchemePattern =
        new(@"(gopher|dict|file|jar|ldap|netdoc)://", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout);

    /// <summary>Common SQL injection patterns.</summary>
    public static readonly Regex SqlInjectionPattern =
        new(@"(\bunion\s+select\b|;\s*(drop|delete|truncate|update)\s+|'\s*or\s+'|--\s)", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout);

    /// <summary>API keys and tokens (OpenAI, GitHub PAT, AWS access key, Bearer tokens).</summary>
    public static readonly Regex ApiKeyPattern =
        new(@"(sk[-_](live|test)[-_]\w{20,}|ghp_[A-Za-z0-9]{36,}|AKIA[A-Z0-9]{16}|Bearer\s+[A-Za-z0-9._\-]{20,})", RegexOptions.Compiled, RegexTimeout);

    /// <summary>Process spawning function calls.</summary>
    public static readonly Regex ProcessSpawnPattern =
        new(@"\b(exec|system|popen|Runtime\.exec|Process\.Start|subprocess)\s*\(", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout);

    /// <summary>Pipe and redirection operators that could chain commands.</summary>
    public static readonly Regex PipeRedirectPattern =
        new(@"[|]\s*\w|>\s*[/\w]|>>\s*[/\w]", RegexOptions.Compiled, RegexTimeout);

    /// <summary>Template injection patterns (Jinja2, Handlebars, etc.).</summary>
    public static readonly Regex TemplateInjectionPattern =
        new(@"\{\{.*\}\}|\{%.*%\}", RegexOptions.Compiled, RegexTimeout);

    /// <summary>Null byte injection.</summary>
    public static readonly Regex NullBytePattern =
        new(@"\x00|%00", RegexOptions.Compiled, RegexTimeout);

    /// <summary>
    /// All built-in dangerous patterns with human-readable names.
    /// </summary>
    public static IReadOnlyList<(Regex Pattern, string Name)> AllPatterns { get; } = new List<(Regex, string)>
    {
        (SsnPattern, "SSN"),
        (CreditCardPattern, "Credit card number"),
        (ShellDestructivePattern, "Shell destructive command"),
        (CommandSubstitutionPattern, "Command substitution"),
        (BacktickExecutionPattern, "Backtick execution"),
        (PathTraversalPattern, "Path traversal"),
        (SsrfMetadataPattern, "SSRF cloud metadata"),
        (SsrfInternalIpPattern, "SSRF internal IP"),
        (SsrfDangerousSchemePattern, "SSRF dangerous scheme"),
        (SqlInjectionPattern, "SQL injection"),
        (ApiKeyPattern, "API key / token"),
        (ProcessSpawnPattern, "Process spawning"),
        (PipeRedirectPattern, "Pipe / redirection"),
        (TemplateInjectionPattern, "Template injection"),
        (NullBytePattern, "Null byte injection"),
    };
}
