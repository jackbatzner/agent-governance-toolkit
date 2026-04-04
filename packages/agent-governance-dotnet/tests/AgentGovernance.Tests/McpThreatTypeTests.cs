// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Mcp;
using Xunit;

namespace AgentGovernance.Tests;

public class McpThreatTypeTests
{
    // ── McpMessageType parsing ───────────────────────────────────────────

    [Theory]
    [InlineData("tools/list", McpMessageType.ToolsList)]
    [InlineData("tools/call", McpMessageType.ToolsCall)]
    [InlineData("resources/list", McpMessageType.ResourcesList)]
    [InlineData("resources/read", McpMessageType.ResourcesRead)]
    [InlineData("prompts/list", McpMessageType.PromptsList)]
    [InlineData("prompts/get", McpMessageType.PromptsGet)]
    [InlineData("completion/complete", McpMessageType.CompletionComplete)]
    public void FromMethod_KnownMethods_ReturnsCorrectType(string method, McpMessageType expected)
    {
        var result = McpMessageTypeExtensions.FromMethod(method);
        Assert.NotNull(result);
        Assert.Equal(expected, result!.Value);
    }

    [Theory]
    [InlineData("unknown/method")]
    [InlineData("")]
    [InlineData("tools")]
    public void FromMethod_UnknownMethods_ReturnsNull(string method)
    {
        Assert.Null(McpMessageTypeExtensions.FromMethod(method));
    }

    [Theory]
    [InlineData(McpMessageType.ToolsList, "tools/list")]
    [InlineData(McpMessageType.ToolsCall, "tools/call")]
    [InlineData(McpMessageType.ResourcesRead, "resources/read")]
    public void ToMethod_ReturnsCorrectString(McpMessageType type, string expected)
    {
        Assert.Equal(expected, type.ToMethod());
    }

    [Fact]
    public void FromMethod_CaseInsensitive()
    {
        Assert.NotNull(McpMessageTypeExtensions.FromMethod("TOOLS/LIST"));
        Assert.NotNull(McpMessageTypeExtensions.FromMethod("Tools/Call"));
    }

    // ── SanitizationDefaults ─────────────────────────────────────────────

    [Theory]
    [InlineData("123-45-6789")]
    [InlineData("SSN is 999-88-7777")]
    public void SsnPattern_MatchesSsn(string input)
    {
        Assert.True(SanitizationDefaults.SsnPattern.IsMatch(input));
    }

    [Theory]
    [InlineData("1234567890123456")]
    [InlineData("1234-5678-9012-3456")]
    [InlineData("1234 5678 9012 3456")]
    public void CreditCardPattern_MatchesCreditCard(string input)
    {
        Assert.True(SanitizationDefaults.CreditCardPattern.IsMatch(input));
    }

    [Theory]
    [InlineData("; rm -rf /")]
    [InlineData("; del /q")]
    [InlineData("; format c:")]
    public void ShellDestructivePattern_MatchesDestructiveCommands(string input)
    {
        Assert.True(SanitizationDefaults.ShellDestructivePattern.IsMatch(input));
    }

    [Fact]
    public void CommandSubstitutionPattern_MatchesDollarParen()
    {
        Assert.True(SanitizationDefaults.CommandSubstitutionPattern.IsMatch("$(whoami)"));
    }

    [Fact]
    public void BacktickExecutionPattern_MatchesBackticks()
    {
        Assert.True(SanitizationDefaults.BacktickExecutionPattern.IsMatch("`whoami`"));
    }

    // ── Path traversal ─────────────────────────────────────────────────

    [Theory]
    [InlineData("../../etc/passwd")]
    [InlineData("..\\windows\\system32")]
    [InlineData("path/../../secret")]
    public void PathTraversal_MatchesDangerousPatterns(string input)
    {
        Assert.Matches(SanitizationDefaults.PathTraversalPattern, input);
    }

    [Theory]
    [InlineData("normal/path/file.txt")]
    [InlineData("file.name")]
    public void PathTraversal_DoesNotMatchSafePaths(string input)
    {
        Assert.DoesNotMatch(SanitizationDefaults.PathTraversalPattern, input);
    }

    // ── SSRF cloud metadata ──────────────────────────────────────────────

    [Theory]
    [InlineData("http://169.254.169.254/latest/meta-data/")]
    [InlineData("curl metadata.google.internal")]
    [InlineData("http://100.100.100.200/metadata")]
    public void SsrfMetadata_MatchesCloudEndpoints(string input)
    {
        Assert.Matches(SanitizationDefaults.SsrfMetadataPattern, input);
    }

    [Theory]
    [InlineData("http://example.com")]
    [InlineData("192.168.1.1")]
    public void SsrfMetadata_DoesNotMatchSafeUrls(string input)
    {
        Assert.DoesNotMatch(SanitizationDefaults.SsrfMetadataPattern, input);
    }

    // ── SSRF internal IP ─────────────────────────────────────────────────

    [Theory]
    [InlineData("http://127.0.0.1/admin")]
    [InlineData("http://10.0.0.1/secret")]
    [InlineData("http://172.16.0.1/internal")]
    [InlineData("http://192.168.1.1/config")]
    public void SsrfInternalIp_MatchesPrivateRanges(string input)
    {
        Assert.Matches(SanitizationDefaults.SsrfInternalIpPattern, input);
    }

    [Theory]
    [InlineData("http://8.8.8.8/dns")]
    [InlineData("http://example.com")]
    public void SsrfInternalIp_DoesNotMatchPublicIps(string input)
    {
        Assert.DoesNotMatch(SanitizationDefaults.SsrfInternalIpPattern, input);
    }

    // ── SSRF dangerous scheme ────────────────────────────────────────────

    [Theory]
    [InlineData("gopher://evil.com")]
    [InlineData("dict://attacker.com")]
    [InlineData("file:///etc/passwd")]
    [InlineData("ldap://evil.com/cn=foo")]
    public void SsrfDangerousScheme_MatchesDangerousProtocols(string input)
    {
        Assert.Matches(SanitizationDefaults.SsrfDangerousSchemePattern, input);
    }

    [Theory]
    [InlineData("https://example.com")]
    [InlineData("http://example.com")]
    public void SsrfDangerousScheme_DoesNotMatchSafeSchemes(string input)
    {
        Assert.DoesNotMatch(SanitizationDefaults.SsrfDangerousSchemePattern, input);
    }

    // ── SQL injection ────────────────────────────────────────────────────

    [Theory]
    [InlineData("1 UNION SELECT * FROM users")]
    [InlineData("; DROP TABLE students")]
    [InlineData("; delete from accounts")]
    [InlineData("' or '1'='1")]
    [InlineData("admin-- ")]
    public void SqlInjection_MatchesDangerousPatterns(string input)
    {
        Assert.Matches(SanitizationDefaults.SqlInjectionPattern, input);
    }

    [Theory]
    [InlineData("SELECT * FROM users WHERE id = 1")]
    [InlineData("normal text query")]
    public void SqlInjection_DoesNotMatchSafeQueries(string input)
    {
        Assert.DoesNotMatch(SanitizationDefaults.SqlInjectionPattern, input);
    }

    // ── API key / token ──────────────────────────────────────────────────

    [Theory]
    [InlineData("sk-live-abc12345678901234567890")]
    [InlineData("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")]
    [InlineData("AKIAIOSFODNN7EXAMPLE")]
    [InlineData("Bearer eyJhbGciOiJIUzI1NiJ9.payload")]
    public void ApiKey_MatchesDangerousTokens(string input)
    {
        Assert.Matches(SanitizationDefaults.ApiKeyPattern, input);
    }

    [Theory]
    [InlineData("my-api-key")]
    [InlineData("regular text")]
    public void ApiKey_DoesNotMatchSafeStrings(string input)
    {
        Assert.DoesNotMatch(SanitizationDefaults.ApiKeyPattern, input);
    }

    // ── Process spawning ─────────────────────────────────────────────────

    [Theory]
    [InlineData("exec(\"/bin/sh\")")]
    [InlineData("system(\"ls\")")]
    [InlineData("popen(\"cmd\")")]
    [InlineData("Runtime.exec(\"calc\")")]
    [InlineData("Process.Start(\"cmd.exe\")")]
    [InlineData("subprocess(\"whoami\")")]
    public void ProcessSpawn_MatchesDangerousCalls(string input)
    {
        Assert.Matches(SanitizationDefaults.ProcessSpawnPattern, input);
    }

    [Theory]
    [InlineData("execute the plan")]
    [InlineData("the system works")]
    public void ProcessSpawn_DoesNotMatchSafeText(string input)
    {
        Assert.DoesNotMatch(SanitizationDefaults.ProcessSpawnPattern, input);
    }

    // ── Pipe / redirection ───────────────────────────────────────────────

    [Theory]
    [InlineData("cat file | grep secret")]
    [InlineData("echo data > /tmp/out")]
    [InlineData("echo data >> /tmp/out")]
    public void PipeRedirect_MatchesDangerousOperators(string input)
    {
        Assert.Matches(SanitizationDefaults.PipeRedirectPattern, input);
    }

    [Theory]
    [InlineData("hello world")]
    [InlineData("normal text")]
    public void PipeRedirect_DoesNotMatchSafeText(string input)
    {
        Assert.DoesNotMatch(SanitizationDefaults.PipeRedirectPattern, input);
    }

    // ── Template injection ───────────────────────────────────────────────

    [Theory]
    [InlineData("{{7*7}}")]
    [InlineData("{% import os %}")]
    [InlineData("Hello {{user.name}}")]
    public void TemplateInjection_MatchesDangerousPatterns(string input)
    {
        Assert.Matches(SanitizationDefaults.TemplateInjectionPattern, input);
    }

    [Theory]
    [InlineData("normal text")]
    [InlineData("{single braces}")]
    public void TemplateInjection_DoesNotMatchSafeText(string input)
    {
        Assert.DoesNotMatch(SanitizationDefaults.TemplateInjectionPattern, input);
    }

    // ── Null byte injection ──────────────────────────────────────────────

    [Theory]
    [InlineData("file.txt%00.jpg")]
    [InlineData("path%00injection")]
    public void NullByte_MatchesDangerousPatterns(string input)
    {
        Assert.Matches(SanitizationDefaults.NullBytePattern, input);
    }

    [Theory]
    [InlineData("normal.txt")]
    [InlineData("safe file name")]
    public void NullByte_DoesNotMatchSafeText(string input)
    {
        Assert.DoesNotMatch(SanitizationDefaults.NullBytePattern, input);
    }

    // ── AllPatterns aggregate ────────────────────────────────────────────

    [Fact]
    public void AllPatterns_HasFifteenEntries()
    {
        Assert.Equal(15, SanitizationDefaults.AllPatterns.Count);
    }

    [Fact]
    public void SafeInput_NoPatternMatches()
    {
        var safeText = "Hello, this is a normal tool parameter.";
        foreach (var (pattern, _) in SanitizationDefaults.AllPatterns)
        {
            Assert.False(pattern.IsMatch(safeText));
        }
    }

    // ── McpThreat model ──────────────────────────────────────────────────

    [Fact]
    public void McpThreat_DefaultDetails_IsEmptyDictionary()
    {
        var threat = new McpThreat
        {
            ThreatType = McpThreatType.ToolPoisoning,
            Severity = McpSeverity.High,
            ToolName = "test_tool",
            ServerName = "test_server",
            Message = "Test threat"
        };

        Assert.NotNull(threat.Details);
        Assert.Empty(threat.Details);
        Assert.Null(threat.MatchedPattern);
    }

    // ── ScanResult model ─────────────────────────────────────────────────

    [Fact]
    public void ScanResult_NoThreats_HasCriticalIsFalse()
    {
        var result = new ScanResult { ServerName = "test" };
        Assert.False(result.HasCritical);
        Assert.False(result.HasThreats);
    }

    [Fact]
    public void ScanResult_WithCritical_HasCriticalIsTrue()
    {
        var result = new ScanResult
        {
            ServerName = "test",
            Threats = new List<McpThreat>
            {
                new()
                {
                    ThreatType = McpThreatType.RugPull,
                    Severity = McpSeverity.Critical,
                    ToolName = "evil_tool",
                    ServerName = "test",
                    Message = "Rug pull detected"
                }
            }
        };
        Assert.True(result.HasCritical);
        Assert.True(result.HasThreats);
    }

    // ── Expanded shell injection patterns ────────────────────────────────

    [Fact]
    public void ShellDestructive_DoubleAmpersand_Detected()
    {
        Assert.Matches(SanitizationDefaults.ShellDestructivePattern, "input && rm -rf /");
    }

    [Fact]
    public void ShellDestructive_Pipe_Detected()
    {
        Assert.Matches(SanitizationDefaults.ShellDestructivePattern, "input | rm something");
    }

    [Fact]
    public void ShellDestructive_SingleAmpersand_Detected()
    {
        Assert.Matches(SanitizationDefaults.ShellDestructivePattern, "input & del file.txt");
    }

    // ── Expanded SQL injection patterns ──────────────────────────────────

    [Fact]
    public void SqlInjection_Truncate_Detected()
    {
        Assert.Matches(SanitizationDefaults.SqlInjectionPattern, "; truncate users");
    }

    [Fact]
    public void SqlInjection_Update_Detected()
    {
        Assert.Matches(SanitizationDefaults.SqlInjectionPattern, "; update users set admin=1");
    }
}
