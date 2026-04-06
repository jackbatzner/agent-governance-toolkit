// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using AgentGovernance.Telemetry;
using Microsoft.Extensions.Logging;

namespace AgentGovernance.Mcp;

/// <summary>
/// Scans MCP tool definitions for security threats including tool poisoning,
/// rug-pull attacks, cross-server impersonation, description injection,
/// schema abuse, and protocol-level attacks.
/// <para>
/// Uses SHA-256 fingerprinting to detect tool definition changes over time
/// (rug-pull detection) and pattern-based analysis for other threat types.
/// </para>
/// </summary>
/// <remarks>
/// Ported from the Python <c>MCPSecurityScanner</c> in <c>agent_os/mcp_security.py</c>.
/// </remarks>
public sealed class McpSecurityScanner
{
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(200);

    private readonly ToolFingerprintRegistry _fingerprints = new();
    private readonly ConcurrentBag<Dictionary<string, object>> _auditLog = new();

    // ── Invisible Unicode patterns ───────────────────────────────────────
    private static readonly Regex[] InvisibleUnicodePatterns =
    {
        new(@"[\u200b\u200c\u200d\ufeff]", RegexOptions.Compiled, RegexTimeout),
        new(@"[\u202a-\u202e]", RegexOptions.Compiled, RegexTimeout),
        new(@"[\u2066-\u2069]", RegexOptions.Compiled, RegexTimeout),
        new(@"[\u00ad]", RegexOptions.Compiled, RegexTimeout),
        new(@"[\u2060\u180e]", RegexOptions.Compiled, RegexTimeout),
    };

    // ── Hidden comment patterns ──────────────────────────────────────────
    private static readonly Regex[] HiddenCommentPatterns =
    {
        new(@"<!--.*?-->", RegexOptions.Compiled | RegexOptions.Singleline, RegexTimeout),
        new(@"\[//\]:\s*#\s*\(.*?\)", RegexOptions.Compiled | RegexOptions.Singleline, RegexTimeout),
        new(@"\[comment\]:\s*<>\s*\(.*?\)", RegexOptions.Compiled | RegexOptions.Singleline, RegexTimeout),
    };

    // ── Hidden instruction patterns ──────────────────────────────────────
    private static readonly Regex[] HiddenInstructionPatterns =
    {
        new(@"ignore\s+(all\s+)?previous", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
        new(@"override\s+(the\s+)?(previous|above|original)", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
        new(@"instead\s+of\s+(the\s+)?(above|previous|described)", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
        new(@"actually\s+do", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
        new(@"\bsystem\s*:", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
        new(@"\bassistant\s*:", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
        new(@"do\s+not\s+follow", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
        new(@"disregard\s+(all\s+)?(above|prior|previous)", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
    };

    // ── Encoded payload patterns ─────────────────────────────────────────
    private static readonly Regex Base64Pattern =
        new(@"[A-Za-z0-9+/]{40,}={0,2}", RegexOptions.Compiled, RegexTimeout);

    private static readonly Regex HexPattern =
        new(@"(?:\\x[0-9a-fA-F]{2}){4,}", RegexOptions.Compiled, RegexTimeout);

    // ── Excessive whitespace ─────────────────────────────────────────────
    private static readonly Regex ExcessiveWhitespacePattern =
        new(@"\n{5,}.+", RegexOptions.Compiled | RegexOptions.Singleline, RegexTimeout);

    // ── Data exfiltration patterns ───────────────────────────────────────
    private static readonly Regex[] ExfiltrationPatterns =
    {
        new(@"\bcurl\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
        new(@"\bwget\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
        new(@"\bfetch\s*\(", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
        new(@"https?://", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
        new(@"\bsend\s+email\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
        new(@"\bsend\s+to\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
        new(@"\bpost\s+to\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
        new(@"include\s+the\s+contents?\s+of\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
    };

    // ── Role override patterns ───────────────────────────────────────────
    private static readonly Regex[] RoleOverridePatterns =
    {
        new(@"you\s+are\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
        new(@"your\s+task\s+is\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
        new(@"respond\s+with\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
        new(@"always\s+return\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
        new(@"you\s+must\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
        new(@"your\s+role\s+is\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
    };

    // ── Suspicious schema field names ────────────────────────────────────
    private static readonly HashSet<string> SuspiciousFieldNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "system_prompt", "instructions", "override", "command", "exec",
        "eval", "callback_url", "webhook", "target_url"
    };

    /// <summary>
    /// The tool fingerprint registry used for rug-pull detection.
    /// </summary>
    public ToolFingerprintRegistry Fingerprints => _fingerprints;

    /// <summary>
    /// Returns a snapshot of the audit log.
    /// </summary>
    public IReadOnlyList<Dictionary<string, object>> AuditLog => _auditLog.ToArray();

    /// <summary>
    /// Optional <see cref="GovernanceMetrics"/> instance for recording
    /// telemetry from the security scanner.
    /// </summary>
    public GovernanceMetrics? Metrics { get; set; }

    /// <summary>
    /// Optional logger for recording threat detections and scan results.
    /// When <c>null</c>, no logging occurs — the scanner operates silently.
    /// </summary>
    public ILogger<McpSecurityScanner>? Logger { get; set; }

    /// <summary>
    /// Scans a single tool definition for all known threat types.
    /// </summary>
    /// <param name="toolName">Name of the tool.</param>
    /// <param name="description">The tool's description text.</param>
    /// <param name="schema">The tool's input schema, if available.</param>
    /// <param name="serverName">The name of the MCP server hosting the tool.</param>
    /// <returns>A list of threats found. Empty if the tool is clean.</returns>
    public List<McpThreat> ScanTool(
        string toolName,
        string description,
        Dictionary<string, object>? schema = null,
        string serverName = "unknown")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(toolName);

        var threats = new List<McpThreat>();

        // Register fingerprint for rug-pull tracking.
        _fingerprints.Register(toolName, description ?? string.Empty, schema, serverName);

        // Run all scanners.
        threats.AddRange(CheckHiddenInstructions(toolName, description ?? string.Empty, serverName));
        threats.AddRange(CheckDescriptionInjection(toolName, description ?? string.Empty, serverName));
        threats.AddRange(CheckSchemaAbuse(toolName, schema, serverName));

        RecordAudit(toolName, serverName, "scan_tool", threats);

        if (threats.Count > 0)
        {
            foreach (var threat in threats)
            {
                Logger?.LogWarning("MCP threat detected: {ThreatType} in tool {ToolName}", threat.ThreatType, toolName);
            }

            var tags = new KeyValuePair<string, object?>[]
            {
                new("tool_name", toolName),
                new("server_name", serverName)
            };
            Metrics?.McpThreatsDetected.Add(threats.Count, tags);
        }

        Logger?.LogDebug("MCP scan complete for {ToolName}: {ThreatCount} threats found", toolName, threats.Count);

        return threats;
    }

    /// <summary>
    /// Scans all tools on an MCP server, including cross-server analysis.
    /// </summary>
    /// <param name="serverName">Name of the MCP server.</param>
    /// <param name="tools">
    /// List of tool definitions. Each dictionary should contain "name", "description",
    /// and optionally "inputSchema" keys.
    /// </param>
    /// <returns>An aggregated <see cref="ScanResult"/>.</returns>
    public ScanResult ScanServer(string serverName, IReadOnlyList<Dictionary<string, object>> tools)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(serverName);
        ArgumentNullException.ThrowIfNull(tools);

        var allThreats = new List<McpThreat>();

        foreach (var tool in tools)
        {
            var name = tool.TryGetValue("name", out var n) ? n?.ToString() ?? "unknown" : "unknown";
            var desc = tool.TryGetValue("description", out var d) ? d?.ToString() ?? string.Empty : string.Empty;
            var schema = tool.TryGetValue("inputSchema", out var s) ? s as Dictionary<string, object> : null;

            allThreats.AddRange(ScanTool(name, desc, schema, serverName));
        }

        // Cross-server checks
        allThreats.AddRange(CheckCrossServer(serverName, tools));

        return new ScanResult
        {
            ServerName = serverName,
            ToolsScanned = tools.Count,
            Threats = allThreats
        };
    }

    /// <summary>
    /// Checks whether a tool definition has changed since last registration (rug-pull detection).
    /// </summary>
    /// <param name="toolName">Name of the tool.</param>
    /// <param name="description">Current description.</param>
    /// <param name="schema">Current schema.</param>
    /// <param name="serverName">Hosting server name.</param>
    /// <returns>A threat if a change was detected; otherwise <c>null</c>.</returns>
    public McpThreat? CheckRugPull(
        string toolName,
        string description,
        Dictionary<string, object>? schema,
        string serverName)
    {
        var existing = _fingerprints.Get(toolName, serverName);
        if (existing is null)
        {
            // First time seeing this tool — register and return clean.
            _fingerprints.Register(toolName, description ?? string.Empty, schema, serverName);
            return null;
        }

        var descHash = ToolFingerprintRegistry.ComputeHash(description ?? string.Empty);
        var schemaHash = ToolFingerprintRegistry.ComputeSchemaHash(schema);

        var changedFields = new List<string>();
        if (!string.Equals(existing.DescriptionHash, descHash, StringComparison.Ordinal))
            changedFields.Add("description");
        if (!string.Equals(existing.SchemaHash, schemaHash, StringComparison.Ordinal))
            changedFields.Add("schema");

        if (changedFields.Count == 0)
            return null;

        // Update fingerprint
        _fingerprints.Register(toolName, description ?? string.Empty, schema, serverName);

        var threat = new McpThreat
        {
            ThreatType = McpThreatType.RugPull,
            Severity = McpSeverity.Critical,
            ToolName = toolName,
            ServerName = serverName,
            Message = $"Tool definition changed since first registration: {string.Join(", ", changedFields)}",
            Details = new Dictionary<string, object>
            {
                ["changed_fields"] = changedFields,
                ["version"] = existing.Version + 1
            }
        };

        RecordAudit(toolName, serverName, "rug_pull_detected", new List<McpThreat> { threat });
        return threat;
    }

    // ── Private detection methods ────────────────────────────────────────

    private List<McpThreat> CheckHiddenInstructions(string toolName, string description, string serverName)
    {
        var threats = new List<McpThreat>();
        if (string.IsNullOrWhiteSpace(description)) return threats;

        // Invisible unicode
        foreach (var pattern in InvisibleUnicodePatterns)
        {
            if (pattern.IsMatch(description))
            {
                threats.Add(new McpThreat
                {
                    ThreatType = McpThreatType.ToolPoisoning,
                    Severity = McpSeverity.High,
                    ToolName = toolName,
                    ServerName = serverName,
                    Message = "Invisible Unicode characters detected in tool description",
                    MatchedPattern = pattern.ToString()
                });
                break; // One finding per category is sufficient.
            }
        }

        // Hidden comments
        foreach (var pattern in HiddenCommentPatterns)
        {
            if (pattern.IsMatch(description))
            {
                threats.Add(new McpThreat
                {
                    ThreatType = McpThreatType.ToolPoisoning,
                    Severity = McpSeverity.High,
                    ToolName = toolName,
                    ServerName = serverName,
                    Message = "Hidden comment detected in tool description",
                    MatchedPattern = pattern.ToString()
                });
                break;
            }
        }

        // Encoded payloads
        if (Base64Pattern.IsMatch(description))
        {
            threats.Add(new McpThreat
            {
                ThreatType = McpThreatType.ToolPoisoning,
                Severity = McpSeverity.High,
                ToolName = toolName,
                ServerName = serverName,
                Message = "Potential base64-encoded payload detected in tool description",
                MatchedPattern = "base64"
            });
        }

        if (HexPattern.IsMatch(description))
        {
            threats.Add(new McpThreat
            {
                ThreatType = McpThreatType.ToolPoisoning,
                Severity = McpSeverity.High,
                ToolName = toolName,
                ServerName = serverName,
                Message = "Hex-encoded payload detected in tool description",
                MatchedPattern = "hex_sequence"
            });
        }

        // Excessive whitespace hiding content
        if (ExcessiveWhitespacePattern.IsMatch(description))
        {
            threats.Add(new McpThreat
            {
                ThreatType = McpThreatType.ToolPoisoning,
                Severity = McpSeverity.Warning,
                ToolName = toolName,
                ServerName = serverName,
                Message = "Excessive whitespace detected — may be hiding instructions"
            });
        }

        // Hidden instruction-like patterns
        foreach (var pattern in HiddenInstructionPatterns)
        {
            if (pattern.IsMatch(description))
            {
                threats.Add(new McpThreat
                {
                    ThreatType = McpThreatType.ToolPoisoning,
                    Severity = McpSeverity.Critical,
                    ToolName = toolName,
                    ServerName = serverName,
                    Message = "Hidden instruction-like pattern detected in tool description",
                    MatchedPattern = pattern.ToString()
                });
                break;
            }
        }

        return threats;
    }

    private List<McpThreat> CheckDescriptionInjection(string toolName, string description, string serverName)
    {
        var threats = new List<McpThreat>();
        if (string.IsNullOrWhiteSpace(description)) return threats;

        // Role override patterns
        foreach (var pattern in RoleOverridePatterns)
        {
            if (pattern.IsMatch(description))
            {
                threats.Add(new McpThreat
                {
                    ThreatType = McpThreatType.DescriptionInjection,
                    Severity = McpSeverity.High,
                    ToolName = toolName,
                    ServerName = serverName,
                    Message = "Role override pattern detected in tool description",
                    MatchedPattern = pattern.ToString()
                });
                break;
            }
        }

        // Data exfiltration patterns
        foreach (var pattern in ExfiltrationPatterns)
        {
            if (pattern.IsMatch(description))
            {
                threats.Add(new McpThreat
                {
                    ThreatType = McpThreatType.DescriptionInjection,
                    Severity = McpSeverity.High,
                    ToolName = toolName,
                    ServerName = serverName,
                    Message = "Data exfiltration pattern detected in tool description",
                    MatchedPattern = pattern.ToString()
                });
                break;
            }
        }

        return threats;
    }

    private List<McpThreat> CheckSchemaAbuse(string toolName, Dictionary<string, object>? schema, string serverName)
    {
        var threats = new List<McpThreat>();
        if (schema is null || schema.Count == 0) return threats;

        // Overly permissive schema: type=object with no properties and additionalProperties not explicitly false.
        if (schema.TryGetValue("type", out var typeObj) && typeObj?.ToString() == "object"
            && !schema.ContainsKey("properties"))
        {
            var additionalProps = schema.TryGetValue("additionalProperties", out var ap) ? ap : null;
            if (additionalProps is not (bool and false))
            {
                threats.Add(new McpThreat
                {
                    ThreatType = McpThreatType.SchemaAbuse,
                    Severity = McpSeverity.High,
                    ToolName = toolName,
                    ServerName = serverName,
                    Message = "Overly permissive schema: object type with no defined properties"
                });
            }
        }

        // Suspicious required field names
        if (schema.TryGetValue("required", out var requiredObj) && requiredObj is IEnumerable<object> requiredList)
        {
            foreach (var field in requiredList)
            {
                var fieldName = field?.ToString() ?? string.Empty;
                if (SuspiciousFieldNames.Any(s => fieldName.Contains(s, StringComparison.OrdinalIgnoreCase)))
                {
                    threats.Add(new McpThreat
                    {
                        ThreatType = McpThreatType.SchemaAbuse,
                        Severity = McpSeverity.Critical,
                        ToolName = toolName,
                        ServerName = serverName,
                        Message = $"Suspicious required field name: '{fieldName}'",
                        MatchedPattern = fieldName
                    });
                }
            }
        }

        return threats;
    }

    private List<McpThreat> CheckCrossServer(
        string serverName,
        IReadOnlyList<Dictionary<string, object>> tools)
    {
        var threats = new List<McpThreat>();
        var allFingerprints = _fingerprints.GetAll();

        foreach (var tool in tools)
        {
            var name = tool.TryGetValue("name", out var n) ? n?.ToString() ?? string.Empty : string.Empty;
            if (string.IsNullOrWhiteSpace(name)) continue;

            foreach (var fp in allFingerprints)
            {
                if (string.Equals(fp.ServerName, serverName, StringComparison.Ordinal))
                    continue;

                // Exact name match from different server = impersonation.
                if (string.Equals(fp.ToolName, name, StringComparison.OrdinalIgnoreCase))
                {
                    threats.Add(new McpThreat
                    {
                        ThreatType = McpThreatType.CrossServerAttack,
                        Severity = McpSeverity.Critical,
                        ToolName = name,
                        ServerName = serverName,
                        Message = $"Tool impersonation: '{name}' already registered on server '{fp.ServerName}'",
                        Details = new Dictionary<string, object>
                        {
                            ["existing_server"] = fp.ServerName,
                            ["attack_type"] = "impersonation"
                        }
                    });
                }
                // Typosquatting: similar names (Levenshtein distance ≤ 2, names ≥ 4 chars).
                else if (name.Length >= 4 && fp.ToolName.Length >= 4 && IsTyposquat(name, fp.ToolName))
                {
                    threats.Add(new McpThreat
                    {
                        ThreatType = McpThreatType.CrossServerAttack,
                        Severity = McpSeverity.Warning,
                        ToolName = name,
                        ServerName = serverName,
                        Message = $"Potential typosquatting: '{name}' is similar to '{fp.ToolName}' on server '{fp.ServerName}'",
                        Details = new Dictionary<string, object>
                        {
                            ["existing_server"] = fp.ServerName,
                            ["similar_tool"] = fp.ToolName,
                            ["attack_type"] = "typosquatting"
                        }
                    });
                }
            }
        }

        return threats;
    }

    /// <summary>
    /// Determines whether two tool names are similar enough to constitute typosquatting.
    /// Uses Levenshtein distance ≤ 2.
    /// </summary>
    public static bool IsTyposquat(string a, string b)
    {
        if (string.Equals(a, b, StringComparison.OrdinalIgnoreCase))
            return false;

        return LevenshteinDistance(a.ToLowerInvariant(), b.ToLowerInvariant()) <= 2;
    }

    private static int LevenshteinDistance(string s, string t)
    {
        var n = s.Length;
        var m = t.Length;
        var d = new int[n + 1, m + 1];

        for (var i = 0; i <= n; i++) d[i, 0] = i;
        for (var j = 0; j <= m; j++) d[0, j] = j;

        for (var i = 1; i <= n; i++)
        {
            for (var j = 1; j <= m; j++)
            {
                var cost = s[i - 1] == t[j - 1] ? 0 : 1;
                d[i, j] = Math.Min(
                    Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1),
                    d[i - 1, j - 1] + cost);
            }
        }

        return d[n, m];
    }

    private void RecordAudit(string toolName, string serverName, string action, List<McpThreat> threats)
    {
        _auditLog.Add(new Dictionary<string, object>
        {
            ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            ["tool_name"] = toolName,
            ["server_name"] = serverName,
            ["action"] = action,
            ["threat_count"] = threats.Count,
            ["threats"] = threats.Select(t => t.ThreatType.ToString()).ToList()
        });
    }
}
