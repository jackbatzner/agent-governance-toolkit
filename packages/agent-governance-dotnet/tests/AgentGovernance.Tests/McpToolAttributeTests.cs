// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Mcp;
using Xunit;

namespace AgentGovernance.Tests;

public class McpToolAttributeTests
{
    [Fact]
    public void Defaults_AreCorrect()
    {
        var attr = new McpToolAttribute();

        Assert.Null(attr.Name);
        Assert.Equal(string.Empty, attr.Description);
        Assert.False(attr.RequiresApproval);
        Assert.Null(attr.ActionType);
    }

    [Fact]
    public void Properties_AreSettable()
    {
        var attr = new McpToolAttribute
        {
            Name = "file_read",
            Description = "Reads a file",
            RequiresApproval = true,
            ActionType = "FileRead"
        };

        Assert.Equal("file_read", attr.Name);
        Assert.Equal("Reads a file", attr.Description);
        Assert.True(attr.RequiresApproval);
        Assert.Equal("FileRead", attr.ActionType);
    }

    [Fact]
    public void AttributeUsage_AllowsMethodsOnly()
    {
        var usage = (AttributeUsageAttribute)Attribute.GetCustomAttribute(
            typeof(McpToolAttribute), typeof(AttributeUsageAttribute))!;

        Assert.Equal(AttributeTargets.Method, usage.ValidOn);
        Assert.False(usage.AllowMultiple);
        Assert.False(usage.Inherited);
    }

    [Fact]
    public void CanBeRetrievedFromMethod()
    {
        var method = typeof(SampleToolClass).GetMethod(nameof(SampleToolClass.MyTool))!;
        var attr = (McpToolAttribute?)Attribute.GetCustomAttribute(method, typeof(McpToolAttribute));

        Assert.NotNull(attr);
        Assert.Equal("my_tool", attr.Name);
        Assert.Equal("A test tool", attr.Description);
        Assert.True(attr.RequiresApproval);
    }

    private class SampleToolClass
    {
        [McpTool(Name = "my_tool", Description = "A test tool", RequiresApproval = true)]
        public static Dictionary<string, object> MyTool() => new();
    }
}
