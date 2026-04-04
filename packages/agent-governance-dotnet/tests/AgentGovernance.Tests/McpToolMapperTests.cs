// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Mcp;
using Xunit;

namespace AgentGovernance.Tests;

public class McpToolMapperTests
{
    private readonly McpToolMapper _mapper = new();

    // ── Stage 1: Exact match ─────────────────────────────────────────────

    [Theory]
    [InlineData("file_read", ActionType.FileRead)]
    [InlineData("file_write", ActionType.FileWrite)]
    [InlineData("database_query", ActionType.DatabaseQuery)]
    [InlineData("database_write", ActionType.DatabaseWrite)]
    [InlineData("api_call", ActionType.ApiCall)]
    [InlineData("http_request", ActionType.ApiCall)]
    [InlineData("tools/call", ActionType.CodeExecution)]
    [InlineData("resources/read", ActionType.FileRead)]
    public void MapTool_DefaultMappings_ReturnsCorrectType(string toolName, ActionType expected)
    {
        Assert.Equal(expected, _mapper.MapTool(toolName));
    }

    [Fact]
    public void MapTool_ExactMatch_CaseInsensitive()
    {
        Assert.Equal(ActionType.FileRead, _mapper.MapTool("FILE_READ"));
        Assert.Equal(ActionType.ApiCall, _mapper.MapTool("Http_Request"));
    }

    // ── Stage 2: Pattern heuristics ──────────────────────────────────────

    [Theory]
    [InlineData("read_file_content", ActionType.FileRead)]
    [InlineData("get_document_text", ActionType.FileRead)]
    [InlineData("fetch_file_info", ActionType.FileRead)]
    [InlineData("load_document_data", ActionType.FileRead)]
    public void MapTool_FileReadPatterns_ReturnsFileRead(string toolName, ActionType expected)
    {
        Assert.Equal(expected, _mapper.MapTool(toolName));
    }

    [Theory]
    [InlineData("write_file_content", ActionType.FileWrite)]
    [InlineData("save_document", ActionType.FileWrite)]
    [InlineData("create_file_entry", ActionType.FileWrite)]
    [InlineData("update_document_v2", ActionType.FileWrite)]
    public void MapTool_FileWritePatterns_ReturnsFileWrite(string toolName, ActionType expected)
    {
        Assert.Equal(expected, _mapper.MapTool(toolName));
    }

    [Theory]
    [InlineData("sql_query_runner", ActionType.DatabaseQuery)]
    [InlineData("query_database", ActionType.DatabaseQuery)]
    [InlineData("db_lookup", ActionType.DatabaseQuery)]
    public void MapTool_DatabaseQueryPatterns_ReturnsDatabaseQuery(string toolName, ActionType expected)
    {
        Assert.Equal(expected, _mapper.MapTool(toolName));
    }

    [Theory]
    [InlineData("sql_insert_record", ActionType.DatabaseWrite)]
    [InlineData("database_update_row", ActionType.DatabaseWrite)]
    [InlineData("db_delete_entry", ActionType.DatabaseWrite)]
    public void MapTool_DatabaseWritePatterns_ReturnsDatabaseWrite(string toolName, ActionType expected)
    {
        Assert.Equal(expected, _mapper.MapTool(toolName));
    }

    [Theory]
    [InlineData("call_api_endpoint", ActionType.ApiCall)]
    [InlineData("http_get_data", ActionType.ApiCall)]
    [InlineData("send_request", ActionType.ApiCall)]
    public void MapTool_ApiCallPatterns_ReturnsApiCall(string toolName, ActionType expected)
    {
        Assert.Equal(expected, _mapper.MapTool(toolName));
    }

    [Theory]
    [InlineData("exec_command", ActionType.CodeExecution)]
    [InlineData("run_python_script", ActionType.CodeExecution)]
    [InlineData("execute_bash", ActionType.CodeExecution)]
    [InlineData("code_interpreter", ActionType.CodeExecution)]
    public void MapTool_CodeExecutionPatterns_ReturnsCodeExecution(string toolName, ActionType expected)
    {
        Assert.Equal(expected, _mapper.MapTool(toolName));
    }

    // ── Stage 3: Deny-by-default ─────────────────────────────────────────

    [Theory]
    [InlineData("totally_unknown_tool")]
    [InlineData("mysteriousthing")]
    [InlineData("zxy123")]
    public void MapTool_UnknownTool_ReturnsNull(string toolName)
    {
        Assert.Null(_mapper.MapTool(toolName));
    }

    // ── Custom mappings ──────────────────────────────────────────────────

    [Fact]
    public void CustomMappings_OverrideDefaults()
    {
        var custom = new Dictionary<string, ActionType>
        {
            ["file_read"] = ActionType.CodeExecution // Override default
        };
        var mapper = new McpToolMapper(custom);

        Assert.Equal(ActionType.CodeExecution, mapper.MapTool("file_read"));
    }

    [Fact]
    public void CustomMappings_AddNewEntries()
    {
        var custom = new Dictionary<string, ActionType>
        {
            ["my_custom_tool"] = ActionType.FileWrite
        };
        var mapper = new McpToolMapper(custom);

        Assert.Equal(ActionType.FileWrite, mapper.MapTool("my_custom_tool"));
    }

    // ── Resource mapping ─────────────────────────────────────────────────

    [Theory]
    [InlineData("file:///tmp/data.txt", ActionType.FileRead)]
    [InlineData("db://mydb/table", ActionType.DatabaseQuery)]
    [InlineData("postgres://host/db", ActionType.DatabaseQuery)]
    [InlineData("mysql://host/db", ActionType.DatabaseQuery)]
    [InlineData("http://api.example.com", ActionType.ApiCall)]
    [InlineData("https://api.example.com", ActionType.ApiCall)]
    public void MapResource_KnownSchemes_ReturnsCorrectType(string uri, ActionType expected)
    {
        Assert.Equal(expected, McpToolMapper.MapResource(uri));
    }

    [Fact]
    public void MapResource_UnknownScheme_DefaultsToFileRead()
    {
        Assert.Equal(ActionType.FileRead, McpToolMapper.MapResource("custom://something"));
    }

    // ── Argument validation ──────────────────────────────────────────────

    [Fact]
    public void MapTool_NullOrEmpty_Throws()
    {
        Assert.ThrowsAny<ArgumentException>(() => _mapper.MapTool(""));
        Assert.ThrowsAny<ArgumentException>(() => _mapper.MapTool(null!));
    }

    [Fact]
    public void MapResource_NullOrEmpty_Throws()
    {
        Assert.ThrowsAny<ArgumentException>(() => McpToolMapper.MapResource(""));
        Assert.ThrowsAny<ArgumentException>(() => McpToolMapper.MapResource(null!));
    }
}
