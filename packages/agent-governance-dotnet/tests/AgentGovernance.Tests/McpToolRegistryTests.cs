// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Reflection;
using AgentGovernance.Mcp;
using Xunit;

namespace AgentGovernance.Tests;

// ── Test tool stubs ──────────────────────────────────────────────────────

public static class TestTools
{
    [McpTool(Description = "Reads a file")]
    public static Dictionary<string, object> ReadFile(string path)
    {
        return new Dictionary<string, object> { ["content"] = $"content of {path}" };
    }

    [McpTool(Name = "custom_tool", Description = "Custom named tool", RequiresApproval = true)]
    public static Dictionary<string, object> MyCustomTool(string input, int count = 5)
    {
        return new Dictionary<string, object> { ["result"] = $"{input}:{count}" };
    }

    [McpTool(Description = "Gets user profile", ActionType = "ApiCall")]
    public static Task<Dictionary<string, object>> GetUserProfile(string userId)
    {
        var result = new Dictionary<string, object> { ["id"] = userId, ["name"] = "Test User" };
        return Task.FromResult(result);
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

public class McpToolRegistryTests
{
    private static (McpToolRegistry Registry, McpMessageHandler Handler) CreateRegistry()
    {
        var kernel = new GovernanceKernel();
        var gateway = new McpGateway(kernel);
        var mapper = new McpToolMapper();
        var handler = new McpMessageHandler(gateway, mapper, "did:mesh:test-agent");
        var registry = new McpToolRegistry(handler);
        return (registry, handler);
    }

    // ── DiscoverTools ────────────────────────────────────────────────────

    [Fact]
    public void DiscoverTools_FindsDecoratedMethods()
    {
        var (registry, _) = CreateRegistry();

        var count = registry.DiscoverTools(typeof(TestTools).Assembly);

        Assert.True(count >= 3, $"Expected at least 3 tools but found {count}");
        Assert.NotNull(registry.GetRegistration("read_file"));
        Assert.NotNull(registry.GetRegistration("custom_tool"));
        Assert.NotNull(registry.GetRegistration("get_user_profile"));
    }

    [Fact]
    public void DiscoverTools_UsesSnakeCaseForUnnamedTools()
    {
        var (registry, _) = CreateRegistry();
        registry.DiscoverTools(typeof(TestTools).Assembly);

        // ReadFile has no explicit Name → should be snake_cased to "read_file"
        var reg = registry.GetRegistration("read_file");
        Assert.NotNull(reg);
        Assert.Equal("read_file", reg.ToolName);
    }

    [Fact]
    public void DiscoverTools_UsesExplicitName_WhenProvided()
    {
        var (registry, _) = CreateRegistry();
        registry.DiscoverTools(typeof(TestTools).Assembly);

        // MyCustomTool has Name = "custom_tool"
        var reg = registry.GetRegistration("custom_tool");
        Assert.NotNull(reg);
        Assert.Equal("custom_tool", reg.ToolName);
        Assert.Equal("Custom named tool", reg.Description);
        Assert.True(reg.RequiresApproval);
    }

    // ── GetRegistration ──────────────────────────────────────────────────

    [Fact]
    public void GetRegistration_ReturnsNull_ForUnregistered()
    {
        var (registry, _) = CreateRegistry();
        registry.DiscoverTools(typeof(TestTools).Assembly);

        var reg = registry.GetRegistration("nonexistent_tool");

        Assert.Null(reg);
    }

    [Fact]
    public void GetRegistration_ReturnsRegistration_ForKnownTool()
    {
        var (registry, _) = CreateRegistry();
        registry.DiscoverTools(typeof(TestTools).Assembly);

        var reg = registry.GetRegistration("read_file");

        Assert.NotNull(reg);
        Assert.Equal("Reads a file", reg.Description);
        Assert.Equal(typeof(TestTools), reg.DeclaringType);
        Assert.False(reg.RequiresApproval);
        Assert.Null(reg.ActionType);
    }

    [Fact]
    public void GetRegistration_PreservesActionType()
    {
        var (registry, _) = CreateRegistry();
        registry.DiscoverTools(typeof(TestTools).Assembly);

        var reg = registry.GetRegistration("get_user_profile");

        Assert.NotNull(reg);
        Assert.Equal("ApiCall", reg.ActionType);
    }

    // ── InvokeToolAsync ──────────────────────────────────────────────────

    [Fact]
    public async Task InvokeToolAsync_StaticMethod_ExecutesSuccessfully()
    {
        var (registry, _) = CreateRegistry();
        registry.DiscoverTools(typeof(TestTools).Assembly);

        var result = await registry.InvokeToolAsync(
            "read_file",
            new Dictionary<string, object> { ["path"] = "/tmp/test.txt" });

        Assert.Equal("content of /tmp/test.txt", result["content"]);
    }

    [Fact]
    public async Task InvokeToolAsync_AsyncMethod_ExecutesSuccessfully()
    {
        var (registry, _) = CreateRegistry();
        registry.DiscoverTools(typeof(TestTools).Assembly);

        var result = await registry.InvokeToolAsync(
            "get_user_profile",
            new Dictionary<string, object> { ["userId"] = "user-42" });

        Assert.Equal("user-42", result["id"]);
        Assert.Equal("Test User", result["name"]);
    }

    [Fact]
    public async Task InvokeToolAsync_WithDefaultParameter_UsesDefault()
    {
        var (registry, _) = CreateRegistry();
        registry.DiscoverTools(typeof(TestTools).Assembly);

        var result = await registry.InvokeToolAsync(
            "custom_tool",
            new Dictionary<string, object> { ["input"] = "hello" });

        Assert.Equal("hello:5", result["result"]);
    }

    [Fact]
    public async Task InvokeToolAsync_WithExplicitOptionalParam_UsesProvided()
    {
        var (registry, _) = CreateRegistry();
        registry.DiscoverTools(typeof(TestTools).Assembly);

        var result = await registry.InvokeToolAsync(
            "custom_tool",
            new Dictionary<string, object> { ["input"] = "hello", ["count"] = 10 });

        Assert.Equal("hello:10", result["result"]);
    }

    [Fact]
    public async Task InvokeToolAsync_MissingRequiredParam_ThrowsArgumentException()
    {
        var (registry, _) = CreateRegistry();
        registry.DiscoverTools(typeof(TestTools).Assembly);

        await Assert.ThrowsAsync<ArgumentException>(() =>
            registry.InvokeToolAsync(
                "read_file",
                new Dictionary<string, object>()));
    }

    [Fact]
    public async Task InvokeToolAsync_UnknownTool_ThrowsInvalidOperationException()
    {
        var (registry, _) = CreateRegistry();

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            registry.InvokeToolAsync(
                "nonexistent_tool",
                new Dictionary<string, object>()));
    }

    // ── BuildSchemaFromMethod ────────────────────────────────────────────

    [Fact]
    public void BuildSchemaFromMethod_ExtractsParameterTypes()
    {
        var method = typeof(TestTools).GetMethod(nameof(TestTools.MyCustomTool))!;

        var schema = McpToolRegistry.BuildSchemaFromMethod(method);

        Assert.Equal("object", schema["type"]);

        var properties = (Dictionary<string, object>)schema["properties"];
        Assert.Equal(2, properties.Count);

        var inputSchema = (Dictionary<string, object>)properties["input"];
        Assert.Equal("string", inputSchema["type"]);

        var countSchema = (Dictionary<string, object>)properties["count"];
        Assert.Equal("number", countSchema["type"]);

        // Only "input" is required; "count" has a default value
        var required = (List<string>)schema["required"];
        Assert.Single(required);
        Assert.Contains("input", required);
    }

    [Fact]
    public void BuildSchemaFromMethod_NoParameters_ReturnsEmptySchema()
    {
        // Use a method with no parameters — just pick a parameterless method
        var method = typeof(object).GetMethod(nameof(object.GetHashCode))!;

        var schema = McpToolRegistry.BuildSchemaFromMethod(method);

        Assert.Equal("object", schema["type"]);
        var properties = (Dictionary<string, object>)schema["properties"];
        Assert.Empty(properties);
        Assert.False(schema.ContainsKey("required"));
    }

    // ── ToSnakeCase ──────────────────────────────────────────────────────

    [Theory]
    [InlineData("GetUserProfile", "get_user_profile")]
    [InlineData("ReadFile", "read_file")]
    [InlineData("MyCustomTool", "my_custom_tool")]
    [InlineData("HandleHTTPRequest", "handle_h_t_t_p_request")]
    public void ToSnakeCase_ConvertsCorrectly(string input, string expected)
    {
        Assert.Equal(expected, McpToolRegistry.ToSnakeCase(input));
    }

    [Fact]
    public void ToSnakeCase_SingleWord()
    {
        Assert.Equal("read", McpToolRegistry.ToSnakeCase("Read"));
    }

    [Fact]
    public void ToSnakeCase_EmptyString()
    {
        Assert.Equal("", McpToolRegistry.ToSnakeCase(""));
    }

    [Fact]
    public void ToSnakeCase_Null_ReturnsNull()
    {
        Assert.Null(McpToolRegistry.ToSnakeCase(null!));
    }

    [Fact]
    public void ToSnakeCase_AllLowerCase_Unchanged()
    {
        Assert.Equal("already_snake", McpToolRegistry.ToSnakeCase("already_snake"));
    }

    // ── Registrations property ───────────────────────────────────────────

    [Fact]
    public void Registrations_EmptyByDefault()
    {
        var (registry, _) = CreateRegistry();

        Assert.Empty(registry.Registrations);
    }

    [Fact]
    public void Registrations_ReturnsReadOnlyList()
    {
        var (registry, _) = CreateRegistry();
        registry.DiscoverTools(typeof(TestTools).Assembly);

        var registrations = registry.Registrations;

        Assert.True(registrations.Count >= 3);
        Assert.IsAssignableFrom<IReadOnlyList<ToolRegistration>>(registrations);
    }
}
