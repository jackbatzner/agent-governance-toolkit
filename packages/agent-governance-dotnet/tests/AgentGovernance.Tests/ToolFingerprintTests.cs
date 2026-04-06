// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Mcp;
using Xunit;

namespace AgentGovernance.Tests;

public class ToolFingerprintTests
{
    private readonly ToolFingerprintRegistry _registry = new();

    // ── Registration ─────────────────────────────────────────────────────

    [Fact]
    public void Register_NewTool_CreatesVersion1()
    {
        var fp = _registry.Register("read_file", "Reads a file from disk", null, "server1");

        Assert.Equal("read_file", fp.ToolName);
        Assert.Equal("server1", fp.ServerName);
        Assert.Equal(1, fp.Version);
        Assert.NotEmpty(fp.DescriptionHash);
        Assert.NotEmpty(fp.SchemaHash);
    }

    [Fact]
    public void Register_SameTool_DoesNotIncrementVersion()
    {
        _registry.Register("tool", "desc", null, "srv");
        var fp = _registry.Register("tool", "desc", null, "srv");

        Assert.Equal(1, fp.Version);
    }

    [Fact]
    public void Register_ChangedDescription_IncrementsVersion()
    {
        var original = _registry.Register("tool", "original description", null, "srv");
        var fp = _registry.Register("tool", "changed description", null, "srv");

        Assert.NotSame(original, fp);
        Assert.Equal(1, original.Version);
        Assert.Equal(2, fp.Version);
    }

    [Fact]
    public void Register_ChangedSchema_IncrementsVersion()
    {
        var schema1 = new Dictionary<string, object> { ["type"] = "string" };
        var schema2 = new Dictionary<string, object> { ["type"] = "integer" };

        var original = _registry.Register("tool", "desc", schema1, "srv");
        var fp = _registry.Register("tool", "desc", schema2, "srv");

        Assert.NotSame(original, fp);
        Assert.Equal(1, original.Version);
        Assert.Equal(2, fp.Version);
    }

    [Fact]
    public void Register_UpdatesLastSeen()
    {
        var fp1 = _registry.Register("tool", "desc", null, "srv");
        var firstSeen = fp1.LastSeen;

        // Small delay to ensure timestamp differs.
        Thread.Sleep(10);

        var fp2 = _registry.Register("tool", "desc", null, "srv");
        Assert.True(fp2.LastSeen >= firstSeen);
    }

    // ── Get ──────────────────────────────────────────────────────────────

    [Fact]
    public void Get_RegisteredTool_ReturnsFingerprint()
    {
        _registry.Register("tool", "desc", null, "srv");
        var fp = _registry.Get("tool", "srv");

        Assert.NotNull(fp);
        Assert.Equal("tool", fp!.ToolName);
    }

    [Fact]
    public void Get_UnregisteredTool_ReturnsNull()
    {
        Assert.Null(_registry.Get("nonexistent", "srv"));
    }

    [Fact]
    public void Get_DifferentServer_ReturnsNull()
    {
        _registry.Register("tool", "desc", null, "server1");
        Assert.Null(_registry.Get("tool", "server2"));
    }

    // ── GetAll ───────────────────────────────────────────────────────────

    [Fact]
    public void GetAll_ReturnsAllRegistered()
    {
        _registry.Register("tool1", "desc1", null, "srv");
        _registry.Register("tool2", "desc2", null, "srv");

        var all = _registry.GetAll();
        Assert.Equal(2, all.Count);
    }

    // ── Clear ────────────────────────────────────────────────────────────

    [Fact]
    public void Clear_RemovesAllEntries()
    {
        _registry.Register("tool1", "desc1", null, "srv");
        _registry.Clear();

        Assert.Empty(_registry.GetAll());
        Assert.Null(_registry.Get("tool1", "srv"));
    }

    // ── Hashing ──────────────────────────────────────────────────────────

    [Fact]
    public void ComputeHash_SameInput_SameOutput()
    {
        var hash1 = ToolFingerprintRegistry.ComputeHash("test input");
        var hash2 = ToolFingerprintRegistry.ComputeHash("test input");
        Assert.Equal(hash1, hash2);
    }

    [Fact]
    public void ComputeHash_DifferentInput_DifferentOutput()
    {
        var hash1 = ToolFingerprintRegistry.ComputeHash("input A");
        var hash2 = ToolFingerprintRegistry.ComputeHash("input B");
        Assert.NotEqual(hash1, hash2);
    }

    [Fact]
    public void ComputeHash_ReturnsLowercaseHex()
    {
        var hash = ToolFingerprintRegistry.ComputeHash("hello");
        Assert.Matches(@"^[0-9a-f]{64}$", hash); // SHA-256 = 64 hex chars
    }

    [Fact]
    public void ComputeSchemaHash_NullSchema_ReturnsConsistentHash()
    {
        var hash1 = ToolFingerprintRegistry.ComputeSchemaHash(null);
        var hash2 = ToolFingerprintRegistry.ComputeSchemaHash(null);
        Assert.Equal(hash1, hash2);
    }

    [Fact]
    public void ComputeSchemaHash_EmptySchema_SameAsNull()
    {
        var hashNull = ToolFingerprintRegistry.ComputeSchemaHash(null);
        var hashEmpty = ToolFingerprintRegistry.ComputeSchemaHash(new Dictionary<string, object>());
        Assert.Equal(hashNull, hashEmpty);
    }

    [Fact]
    public void ComputeSchemaHash_DifferentInsertionOrder_SameHash()
    {
        var schema1 = new Dictionary<string, object>
        {
            ["alpha"] = "first",
            ["beta"] = "second",
            ["gamma"] = "third"
        };
        var schema2 = new Dictionary<string, object>
        {
            ["gamma"] = "third",
            ["alpha"] = "first",
            ["beta"] = "second"
        };

        var hash1 = ToolFingerprintRegistry.ComputeSchemaHash(schema1);
        var hash2 = ToolFingerprintRegistry.ComputeSchemaHash(schema2);
        Assert.Equal(hash1, hash2);
    }
}
