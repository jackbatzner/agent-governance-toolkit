// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Extensions;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace AgentGovernance.Tests;

public class McpConfigurationTests
{
    [Fact]
    public void BindFromConfiguration_MaxToolCallsPerAgent_Parsed()
    {
        var config = BuildConfig(new Dictionary<string, string?>
        {
            ["McpGovernance:MaxToolCallsPerAgent"] = "500"
        });

        var options = new McpGovernanceOptions().BindFromConfiguration(config);

        Assert.Equal(500, options.MaxToolCallsPerAgent);
    }

    [Fact]
    public void BindFromConfiguration_RateLimitWindow_Parsed()
    {
        var config = BuildConfig(new Dictionary<string, string?>
        {
            ["McpGovernance:RateLimitWindowMinutes"] = "10"
        });

        var options = new McpGovernanceOptions().BindFromConfiguration(config);

        Assert.Equal(TimeSpan.FromMinutes(10), options.RateLimitWindow);
    }

    [Fact]
    public void BindFromConfiguration_DeniedTools_Parsed()
    {
        var config = BuildConfig(new Dictionary<string, string?>
        {
            ["McpGovernance:DeniedTools:0"] = "drop_database",
            ["McpGovernance:DeniedTools:1"] = "rm_rf",
            ["McpGovernance:DeniedTools:2"] = "exec_shell"
        });

        var options = new McpGovernanceOptions().BindFromConfiguration(config);

        Assert.Equal(3, options.DeniedTools.Count);
        Assert.Contains("drop_database", options.DeniedTools);
        Assert.Contains("rm_rf", options.DeniedTools);
        Assert.Contains("exec_shell", options.DeniedTools);
    }

    [Fact]
    public void BindFromConfiguration_AllowedTools_Parsed()
    {
        var config = BuildConfig(new Dictionary<string, string?>
        {
            ["McpGovernance:AllowedTools:0"] = "read_file",
            ["McpGovernance:AllowedTools:1"] = "list_files"
        });

        var options = new McpGovernanceOptions().BindFromConfiguration(config);

        Assert.Equal(2, options.AllowedTools.Count);
        Assert.Contains("read_file", options.AllowedTools);
        Assert.Contains("list_files", options.AllowedTools);
    }

    [Fact]
    public void BindFromConfiguration_SensitiveTools_Parsed()
    {
        var config = BuildConfig(new Dictionary<string, string?>
        {
            ["McpGovernance:SensitiveTools:0"] = "send_email",
            ["McpGovernance:SensitiveTools:1"] = "deploy_production"
        });

        var options = new McpGovernanceOptions().BindFromConfiguration(config);

        Assert.Equal(2, options.SensitiveTools.Count);
        Assert.Contains("send_email", options.SensitiveTools);
        Assert.Contains("deploy_production", options.SensitiveTools);
    }

    [Fact]
    public void BindFromConfiguration_SessionTtl_Parsed()
    {
        var config = BuildConfig(new Dictionary<string, string?>
        {
            ["McpGovernance:SessionTtlMinutes"] = "120"
        });

        var options = new McpGovernanceOptions().BindFromConfiguration(config);

        Assert.Equal(TimeSpan.FromMinutes(120), options.SessionTtl);
    }

    [Fact]
    public void BindFromConfiguration_MaxSessionsPerAgent_Parsed()
    {
        var config = BuildConfig(new Dictionary<string, string?>
        {
            ["McpGovernance:MaxSessionsPerAgent"] = "3"
        });

        var options = new McpGovernanceOptions().BindFromConfiguration(config);

        Assert.Equal(3, options.MaxSessionsPerAgent);
    }

    [Fact]
    public void BindFromConfiguration_MessageReplayWindow_Parsed()
    {
        var config = BuildConfig(new Dictionary<string, string?>
        {
            ["McpGovernance:MessageReplayWindowSeconds"] = "600"
        });

        var options = new McpGovernanceOptions().BindFromConfiguration(config);

        Assert.Equal(TimeSpan.FromSeconds(600), options.MessageReplayWindow);
    }

    [Fact]
    public void BindFromConfiguration_MessageSigningKey_Base64Decoded()
    {
        var key = new byte[32];
        new Random(42).NextBytes(key);
        var base64Key = Convert.ToBase64String(key);

        var config = BuildConfig(new Dictionary<string, string?>
        {
            ["McpGovernance:MessageSigningKey"] = base64Key
        });

        var options = new McpGovernanceOptions().BindFromConfiguration(config);

        Assert.NotNull(options.MessageSigningKey);
        Assert.Equal(key, options.MessageSigningKey);
    }

    [Fact]
    public void BindFromConfiguration_MissingSection_ReturnsUnchangedOptions()
    {
        var config = BuildConfig(new Dictionary<string, string?>
        {
            ["SomeOtherSection:Key"] = "value"
        });

        var options = new McpGovernanceOptions().BindFromConfiguration(config);

        // Should retain all defaults
        Assert.Equal(1000, options.MaxToolCallsPerAgent);
        Assert.Equal(TimeSpan.FromMinutes(5), options.RateLimitWindow);
        Assert.False(options.RequireHumanApproval);
        Assert.True(options.EnableBuiltinSanitization);
        Assert.True(options.EnableResponseScanning);
        Assert.True(options.EnableCredentialRedaction);
        Assert.Equal(TimeSpan.FromHours(1), options.SessionTtl);
        Assert.Equal(10, options.MaxSessionsPerAgent);
        Assert.Null(options.MessageSigningKey);
        Assert.Empty(options.DeniedTools);
    }

    [Fact]
    public void BindFromConfiguration_InvalidBase64Key_IgnoredGracefully()
    {
        var config = BuildConfig(new Dictionary<string, string?>
        {
            ["McpGovernance:MessageSigningKey"] = "not-valid-base64!!!"
        });

        var options = new McpGovernanceOptions().BindFromConfiguration(config);

        // Invalid key should be ignored (null retained)
        Assert.Null(options.MessageSigningKey);
    }

    [Fact]
    public void BindFromConfiguration_Booleans_Parsed()
    {
        var config = BuildConfig(new Dictionary<string, string?>
        {
            ["McpGovernance:RequireHumanApproval"] = "true",
            ["McpGovernance:EnableBuiltinSanitization"] = "false",
            ["McpGovernance:EnableResponseScanning"] = "false",
            ["McpGovernance:EnableCredentialRedaction"] = "false"
        });

        var options = new McpGovernanceOptions().BindFromConfiguration(config);

        Assert.True(options.RequireHumanApproval);
        Assert.False(options.EnableBuiltinSanitization);
        Assert.False(options.EnableResponseScanning);
        Assert.False(options.EnableCredentialRedaction);
    }

    [Fact]
    public void BindFromConfiguration_CustomSectionName_Works()
    {
        var config = BuildConfig(new Dictionary<string, string?>
        {
            ["CustomSection:MaxToolCallsPerAgent"] = "250"
        });

        var options = new McpGovernanceOptions()
            .BindFromConfiguration(config, sectionName: "CustomSection");

        Assert.Equal(250, options.MaxToolCallsPerAgent);
    }

    [Fact]
    public void BindFromConfiguration_AllScalarValues_Parsed()
    {
        var config = BuildConfig(new Dictionary<string, string?>
        {
            ["McpGovernance:MaxToolCallsPerAgent"] = "750",
            ["McpGovernance:RateLimitWindowMinutes"] = "15",
            ["McpGovernance:RequireHumanApproval"] = "true",
            ["McpGovernance:EnableBuiltinSanitization"] = "false",
            ["McpGovernance:EnableResponseScanning"] = "false",
            ["McpGovernance:EnableCredentialRedaction"] = "false",
            ["McpGovernance:SessionTtlMinutes"] = "45",
            ["McpGovernance:MaxSessionsPerAgent"] = "8",
            ["McpGovernance:MessageReplayWindowSeconds"] = "120"
        });

        var options = new McpGovernanceOptions().BindFromConfiguration(config);

        Assert.Equal(750, options.MaxToolCallsPerAgent);
        Assert.Equal(TimeSpan.FromMinutes(15), options.RateLimitWindow);
        Assert.True(options.RequireHumanApproval);
        Assert.False(options.EnableBuiltinSanitization);
        Assert.False(options.EnableResponseScanning);
        Assert.False(options.EnableCredentialRedaction);
        Assert.Equal(TimeSpan.FromMinutes(45), options.SessionTtl);
        Assert.Equal(8, options.MaxSessionsPerAgent);
        Assert.Equal(TimeSpan.FromSeconds(120), options.MessageReplayWindow);
    }

    [Fact]
    public void BindFromConfiguration_InvalidIntegers_IgnoredGracefully()
    {
        var config = BuildConfig(new Dictionary<string, string?>
        {
            ["McpGovernance:MaxToolCallsPerAgent"] = "not-a-number",
            ["McpGovernance:MaxSessionsPerAgent"] = "abc"
        });

        var options = new McpGovernanceOptions().BindFromConfiguration(config);

        // Should retain defaults when parsing fails
        Assert.Equal(1000, options.MaxToolCallsPerAgent);
        Assert.Equal(10, options.MaxSessionsPerAgent);
    }

    // --- Helpers ---

    private static IConfiguration BuildConfig(Dictionary<string, string?> data)
    {
        return new ConfigurationBuilder()
            .AddInMemoryCollection(data)
            .Build();
    }
}
