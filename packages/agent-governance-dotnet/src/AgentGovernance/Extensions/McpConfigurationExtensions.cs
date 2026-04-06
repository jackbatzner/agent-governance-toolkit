// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using AgentGovernance.Mcp;
using Microsoft.Extensions.Configuration;

namespace AgentGovernance.Extensions;

/// <summary>
/// Extension methods for binding MCP governance options from IConfiguration (appsettings.json).
/// </summary>
public static class McpConfigurationExtensions
{
    /// <summary>
    /// Binds MCP governance options from a configuration section.
    /// 
    /// Example appsettings.json:
    /// {
    ///   "McpGovernance": {
    ///     "MaxToolCallsPerAgent": 500,
    ///     "RateLimitWindowMinutes": 10,
    ///     "RequireHumanApproval": false,
    ///     "EnableBuiltinSanitization": true,
    ///     "EnableResponseScanning": true,
    ///     "EnableCredentialRedaction": true,
    ///     "SessionTtlMinutes": 60,
    ///     "MaxSessionsPerAgent": 5,
    ///     "MessageReplayWindowSeconds": 300,
    ///     "DeniedTools": ["drop_database", "rm_rf", "exec_shell"],
    ///     "AllowedTools": [],
    ///     "SensitiveTools": ["send_email", "deploy_production"]
    ///   }
    /// }
    /// </summary>
    public static McpGovernanceOptions BindFromConfiguration(
        this McpGovernanceOptions options,
        IConfiguration configuration,
        string sectionName = "McpGovernance")
    {
        var section = configuration.GetSection(sectionName);
        if (!section.Exists()) return options;

        // Scalar values
        if (int.TryParse(section["MaxToolCallsPerAgent"], out var maxCalls))
            options.MaxToolCallsPerAgent = maxCalls;

        if (double.TryParse(section["RateLimitWindowMinutes"], out var windowMins))
            options.RateLimitWindow = TimeSpan.FromMinutes(windowMins);

        if (bool.TryParse(section["RequireHumanApproval"], out var requireApproval))
            options.RequireHumanApproval = requireApproval;

        if (bool.TryParse(section["EnableBuiltinSanitization"], out var enableSanitization))
            options.EnableBuiltinSanitization = enableSanitization;

        if (bool.TryParse(section["EnableResponseScanning"], out var enableResponse))
            options.EnableResponseScanning = enableResponse;

        if (bool.TryParse(section["EnableCredentialRedaction"], out var enableRedaction))
            options.EnableCredentialRedaction = enableRedaction;

        if (double.TryParse(section["SessionTtlMinutes"], out var sessionMins))
            options.SessionTtl = TimeSpan.FromMinutes(sessionMins);

        if (int.TryParse(section["MaxSessionsPerAgent"], out var maxSessions))
            options.MaxSessionsPerAgent = maxSessions;

        if (double.TryParse(section["MessageReplayWindowSeconds"], out var replaySeconds))
            options.MessageReplayWindow = TimeSpan.FromSeconds(replaySeconds);

        // List values
        var deniedSection = section.GetSection("DeniedTools");
        if (deniedSection.Exists())
        {
            foreach (var child in deniedSection.GetChildren())
            {
                if (child.Value is not null)
                    options.DeniedTools.Add(child.Value);
            }
        }

        var allowedSection = section.GetSection("AllowedTools");
        if (allowedSection.Exists())
        {
            foreach (var child in allowedSection.GetChildren())
            {
                if (child.Value is not null)
                    options.AllowedTools.Add(child.Value);
            }
        }

        var sensitiveSection = section.GetSection("SensitiveTools");
        if (sensitiveSection.Exists())
        {
            foreach (var child in sensitiveSection.GetChildren())
            {
                if (child.Value is not null)
                    options.SensitiveTools.Add(child.Value);
            }
        }

        // Message signing key (base64 encoded)
        var signingKey = section["MessageSigningKey"];
        if (!string.IsNullOrEmpty(signingKey))
        {
            try
            {
                options.MessageSigningKey = Convert.FromBase64String(signingKey);
            }
            catch (FormatException)
            {
                // Invalid base64 — ignore, let validation catch it
            }
        }

        return options;
    }
}
