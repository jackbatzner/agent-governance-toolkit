// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace AgentGovernance.Mcp;

/// <summary>
/// Scans MCP tool response content for injection attacks before returning results to the LLM.
/// Implements OWASP MCP Security Cheat Sheet §5 (Output Validation) and §12 (Prompt Injection via Tool Return Values).
/// <para>
/// Treats every tool response as <b>untrusted input</b>. Detects instruction-like patterns,
/// credential leakage, and data exfiltration indicators in tool outputs.
/// </para>
/// </summary>
public sealed class McpResponseScanner
{
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(200);

    /// <summary>
    /// Optional logger for recording response scan results.
    /// When <c>null</c>, no logging occurs — the scanner operates silently.
    /// </summary>
    public ILogger<McpResponseScanner>? Logger { get; set; }

    // ── Instruction tag patterns (HTML-like injection) ───────────────────
    // Detect: <IMPORTANT>, <system>, <instructions>, <admin>, <override>
    // Also bracket variants: [SYSTEM], [ADMIN], [INSTRUCTIONS]
    private static readonly Regex[] InstructionTagPatterns =
    {
        new(@"<(IMPORTANT|system|instructions?|admin|override|prompt|context|role)\b[^>]*>",
            RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
        new(@"\[(SYSTEM|ADMIN|INSTRUCTIONS?)\]",
            RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
    };

    // ── Imperative instruction patterns ──────────────────────────────────
    // Detect: "ignore previous", "forget all", "override instructions",
    // "you are now", "new role:", "from now on", "don't follow"
    private static readonly Regex[] ImperativePatterns =
    {
        new(@"ignore\s+(all\s+)?previous\s+(instructions?|context|rules?)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
        new(@"(forget|disregard|override)\s+(all\s+)?(previous|above|prior|earlier)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
        new(@"you\s+are\s+now\s+",
            RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
        new(@"new\s+(role|instruction|directive|persona)\s*:",
            RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
        new(@"from\s+now\s+on\s*,?\s*(you|ignore|forget|act)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
        new(@"(do\s+not|don'?t)\s+(follow|obey|listen)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
    };

    // ── Credential patterns in responses ─────────────────────────────────
    // Detect: API keys, tokens, AWS keys, Bearer tokens, PEM private keys
    private static readonly Regex[] CredentialPatterns =
    {
        new(@"sk[-_](live|test)[-_]\w{20,}",
            RegexOptions.Compiled, RegexTimeout),
        new(@"ghp_[A-Za-z0-9]{36,}",
            RegexOptions.Compiled, RegexTimeout),
        new(@"AKIA[A-Z0-9]{16}",
            RegexOptions.Compiled, RegexTimeout),
        new(@"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
            RegexOptions.Compiled, RegexTimeout),
        new(@"Bearer\s+[A-Za-z0-9._\-]{20,}",
            RegexOptions.Compiled, RegexTimeout),
    };

    // ── Data exfiltration indicators ─────────────────────────────────────
    // Detect: large base64 blobs, hex-encoded blocks
    private static readonly Regex[] ExfiltrationPatterns =
    {
        new(@"[A-Za-z0-9+/]{100,}={0,2}",
            RegexOptions.Compiled, RegexTimeout),
        new(@"(\\x[0-9a-fA-F]{2}){10,}",
            RegexOptions.Compiled, RegexTimeout),
    };

    /// <summary>
    /// Scans a tool response string for threats.
    /// </summary>
    /// <param name="responseContent">The tool's response content.</param>
    /// <param name="toolName">Name of the tool that produced the response (for diagnostics).</param>
    /// <returns>A scan result with safety status and detected threats.</returns>
    public McpResponseScanResult ScanResponse(string? responseContent, string toolName = "unknown")
    {
        // Fail-closed: any exception → unsafe
        try
        {
            if (string.IsNullOrEmpty(responseContent))
            {
                return McpResponseScanResult.Safe(toolName);
            }

            var threats = new List<McpResponseThreat>();

            ScanPatterns(responseContent, InstructionTagPatterns, "instruction_injection", "Instruction tag detected in tool response", threats);
            ScanPatterns(responseContent, ImperativePatterns, "prompt_injection", "Imperative instruction detected in tool response", threats);
            ScanPatterns(responseContent, CredentialPatterns, "credential_leak", "Credential or secret detected in tool response", threats);
            ScanPatterns(responseContent, ExfiltrationPatterns, "data_exfiltration", "Data exfiltration indicator detected in tool response", threats);

            if (threats.Count == 0)
            {
                return McpResponseScanResult.Safe(toolName);
            }

            Logger?.LogWarning("MCP response scan found {IssueCount} issues in tool {ToolName}", threats.Count, toolName);

            return new McpResponseScanResult
            {
                IsSafe = false,
                ToolName = toolName,
                Threats = threats.AsReadOnly(),
            };
        }
        catch
        {
            return McpResponseScanResult.Unsafe(toolName, "Scanner error (fail-closed)");
        }
    }

    /// <summary>
    /// Sanitizes a tool response by stripping detected instruction tags.
    /// Returns the cleaned content and any threats that were stripped.
    /// </summary>
    /// <param name="responseContent">The tool's response content.</param>
    /// <param name="toolName">Name of the tool that produced the response (for diagnostics).</param>
    /// <returns>A tuple of the sanitized content and a list of threats that were stripped.</returns>
    public (string SanitizedContent, List<McpResponseThreat> StrippedThreats) SanitizeResponse(
        string? responseContent, string toolName = "unknown")
    {
        if (string.IsNullOrEmpty(responseContent))
        {
            return (responseContent ?? string.Empty, new List<McpResponseThreat>());
        }

        var stripped = new List<McpResponseThreat>();
        var sanitized = responseContent;

        foreach (var pattern in InstructionTagPatterns)
        {
            var matches = pattern.Matches(sanitized);
            foreach (Match match in matches)
            {
                stripped.Add(new McpResponseThreat
                {
                    Category = "instruction_injection",
                    Description = "Instruction tag stripped from tool response",
                    MatchedPattern = match.Value,
                });
            }

            sanitized = pattern.Replace(sanitized, string.Empty);
        }

        return (sanitized, stripped);
    }

    /// <summary>
    /// Scans content against an array of regex patterns and appends any matches as threats.
    /// </summary>
    private static void ScanPatterns(
        string content,
        Regex[] patterns,
        string category,
        string description,
        List<McpResponseThreat> threats)
    {
        foreach (var pattern in patterns)
        {
            var match = pattern.Match(content);
            if (match.Success)
            {
                threats.Add(new McpResponseThreat
                {
                    Category = category,
                    Description = description,
                    MatchedPattern = match.Value,
                });
            }
        }
    }
}

/// <summary>
/// Result of scanning an MCP tool response.
/// </summary>
public sealed class McpResponseScanResult
{
    /// <summary>Whether the response content is considered safe.</summary>
    public bool IsSafe { get; init; }

    /// <summary>Name of the tool that produced the response.</summary>
    public string ToolName { get; init; } = "";

    /// <summary>All threats detected in the response content.</summary>
    public IReadOnlyList<McpResponseThreat> Threats { get; init; } = Array.Empty<McpResponseThreat>();

    /// <summary>
    /// Creates a safe scan result for the specified tool.
    /// </summary>
    public static McpResponseScanResult Safe(string toolName) =>
        new() { IsSafe = true, ToolName = toolName };

    /// <summary>
    /// Creates an unsafe scan result with a single error-category threat.
    /// </summary>
    public static McpResponseScanResult Unsafe(string toolName, string reason) =>
        new()
        {
            IsSafe = false,
            ToolName = toolName,
            Threats = new[] { new McpResponseThreat { Category = "error", Description = reason } },
        };
}

/// <summary>
/// A threat detected in an MCP tool response.
/// </summary>
public sealed class McpResponseThreat
{
    /// <summary>Category of the threat (e.g. instruction_injection, credential_leak).</summary>
    public string Category { get; init; } = "";

    /// <summary>Human-readable description of the threat.</summary>
    public string Description { get; init; } = "";

    /// <summary>The pattern or indicator that matched, if applicable.</summary>
    public string? MatchedPattern { get; init; }
}
