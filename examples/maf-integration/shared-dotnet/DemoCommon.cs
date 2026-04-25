// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Text;
using AgentGovernance.Audit;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

namespace MafIntegration.Shared;

public static class Display
{
    private static readonly bool Enabled =
        !Console.IsOutputRedirected || Environment.GetEnvironmentVariable("FORCE_COLOR") != null;

    private static string Esc(string code) => Enabled ? code : "";

    public static string Reset => Esc("\x1b[0m");
    public static string Bold => Esc("\x1b[1m");
    public static string Dim => Esc("\x1b[2m");
    public static string Red => Esc("\x1b[91m");
    public static string Green => Esc("\x1b[92m");
    public static string Yellow => Esc("\x1b[93m");
    public static string Blue => Esc("\x1b[94m");
    public static string Magenta => Esc("\x1b[95m");
    public static string Cyan => Esc("\x1b[96m");
    public static string White => Esc("\x1b[97m");

    public static void Header(string title, string subtitle)
    {
        const int width = 60;
        Console.WriteLine($"{Cyan}{Bold}╔{"".PadRight(width, '═')}╗{Reset}");
        Console.WriteLine($"{Cyan}{Bold}║  {White}{title.PadRight(width - 2)}{Cyan}║{Reset}");
        Console.WriteLine($"{Cyan}{Bold}║  {Dim}{White}{subtitle.PadRight(width - 2)}{Cyan}{Bold}║{Reset}");
        Console.WriteLine($"{Cyan}{Bold}╚{"".PadRight(width, '═')}╝{Reset}");
    }

    public static void Section(string title)
    {
        var pad = Math.Max(0, 56 - title.Length);
        Console.WriteLine($"\n{Yellow}{Bold}{"".PadRight(3, '━')} {title} {"".PadRight(pad, '━')}{Reset}\n");
    }

    public static void Request(string message) => Console.WriteLine($"  {Blue}📨 Request:{Reset} \"{message}\"");

    public static void Allowed(string detail) => Console.WriteLine($"  {Green}✅ ALLOWED{Reset} — {detail}");

    public static void Denied(string detail) => Console.WriteLine($"  {Red}❌ DENIED{Reset} — {detail}");

    public static void Policy(string ruleName) => Console.WriteLine($"  {Dim}📋 Governance rule: {ruleName}{Reset}");

    public static void ToolCall(string name, IEnumerable<KeyValuePair<string, object?>>? arguments)
    {
        var formattedArgs = arguments is not null && arguments.Any()
            ? string.Join(", ", arguments.Select(pair => $"{pair.Key}: {pair.Value}"))
            : "(no arguments)";
        Console.WriteLine($"  {Yellow}🛠 Tool Call:{Reset} {name}({formattedArgs})");
    }

    public static void ToolResult(string text, bool blocked)
    {
        var color = blocked ? Red : Green;
        var icon = blocked ? "❌" : "✅";
        Console.WriteLine($"  {color}{icon} Tool Result:{Reset} {text}");
    }

    public static void LlmResponse(string text) => Console.WriteLine($"  {Magenta}🤖 Agent:{Reset} {text}");

    public static void Info(string text) => Console.WriteLine($"  {Cyan}{text}{Reset}");

    public static void Warning(string text) => Console.WriteLine($"  {Yellow}{text}{Reset}");

    public static void DimLine(string text) => Console.WriteLine($"  {Dim}{text}{Reset}");
}

public record AnomalyScore(double ZScore, double Entropy, double CapabilityDeviation, bool IsAnomalous, bool Quarantine);

public sealed class RogueDetectionMiddleware
{
    private readonly int _windowSize;
    private readonly double _zThreshold;
    private readonly List<double> _callTimestamps = new();
    private readonly Dictionary<string, int> _toolCounts = new(StringComparer.OrdinalIgnoreCase);

    public RogueDetectionMiddleware(int windowSize = 20, double zThreshold = 2.5)
    {
        _windowSize = windowSize;
        _zThreshold = zThreshold;
    }

    public AnomalyScore RecordCall(string toolName)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0;
        _callTimestamps.Add(now);
        _toolCounts[toolName] = _toolCounts.GetValueOrDefault(toolName) + 1;

        if (_callTimestamps.Count < 5)
        {
            return new AnomalyScore(0, 0, 0, false, false);
        }

        var recent = _callTimestamps.TakeLast(_windowSize).ToList();
        double zScore = 0;
        if (recent.Count >= 2)
        {
            var intervals = new List<double>();
            for (var index = 1; index < recent.Count; index++)
            {
                intervals.Add(recent[index] - recent[index - 1]);
            }

            var mean = intervals.Average();
            var standardDeviation = Math.Sqrt(intervals.Average(value => Math.Pow(value - mean, 2)));
            if (standardDeviation < 0.001)
            {
                standardDeviation = 0.001;
            }

            zScore = Math.Abs((intervals[^1] - mean) / standardDeviation);
        }

        var totalCalls = _toolCounts.Values.Sum();
        double entropy = 0;
        foreach (var count in _toolCounts.Values)
        {
            var probability = (double)count / totalCalls;
            if (probability > 0)
            {
                entropy -= probability * Math.Log2(probability);
            }
        }

        var maxCount = _toolCounts.Values.Max();
        var capabilityDeviation = (double)maxCount / totalCalls;

        var anomalous = zScore > _zThreshold || capabilityDeviation > 0.8;
        var quarantine = zScore > _zThreshold * 1.5 || (anomalous && capabilityDeviation > 0.85);

        return new AnomalyScore(
            Math.Round(zScore, 2),
            Math.Round(entropy, 3),
            Math.Round(capabilityDeviation, 3),
            anomalous,
            quarantine);
    }
}

public record AuditEntry(int Index, string Timestamp, string AgentId, string EventType, string Action, string Detail, string Hash, string PreviousHash);

public sealed class AuditTrail
{
    private readonly List<AuditEntry> _entries = new();
    private string _lastHash = new('0', 64);

    public IReadOnlyList<AuditEntry> Entries => _entries;

    public AuditEntry Log(string agentId, string eventType, string action, string detail)
    {
        var timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
        var payload = $"{_entries.Count}|{timestamp}|{agentId}|{eventType}|{action}|{detail}|{_lastHash}";
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(payload))).ToLowerInvariant();
        var entry = new AuditEntry(_entries.Count, timestamp, agentId, eventType, action, detail, hash, _lastHash);
        _entries.Add(entry);
        _lastHash = hash;
        return entry;
    }

    public void LogGovernanceEvent(GovernanceEvent governanceEvent)
    {
        var action = governanceEvent.Data.TryGetValue("action", out var actionValue)
            ? actionValue?.ToString() ?? "observe"
            : governanceEvent.Type switch
            {
                GovernanceEventType.PolicyViolation or GovernanceEventType.ToolCallBlocked => "deny",
                _ => "allow"
            };

        var detailParts = new List<string>();
        if (governanceEvent.Data.TryGetValue("message", out var message))
        {
            detailParts.Add($"message={message}");
        }

        if (governanceEvent.Data.TryGetValue("tool_name", out var toolName))
        {
            detailParts.Add($"tool={toolName}");
        }

        if (governanceEvent.Data.TryGetValue("reason", out var reason))
        {
            detailParts.Add($"reason={reason}");
        }

        Log(
            governanceEvent.AgentId,
            governanceEvent.Type.ToString(),
            action,
            string.Join(" | ", detailParts.Where(part => !string.IsNullOrWhiteSpace(part))));
    }

    public (bool IsValid, int VerifiedCount) VerifyIntegrity()
    {
        var previousHash = new string('0', 64);
        foreach (var entry in _entries)
        {
            var payload = $"{entry.Index}|{entry.Timestamp}|{entry.AgentId}|{entry.EventType}|{entry.Action}|{entry.Detail}|{previousHash}";
            var expected = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(payload))).ToLowerInvariant();
            if (!string.Equals(expected, entry.Hash, StringComparison.Ordinal))
            {
                return (false, entry.Index);
            }

            previousHash = entry.Hash;
        }

        return (true, _entries.Count);
    }
}

public record ToolCallPlan(string Prompt, string ToolName, Dictionary<string, object?> Arguments);

public sealed class DeterministicScenarioChatClient : IChatClient
{
    private readonly Dictionary<string, string> _directResponses;
    private readonly Dictionary<string, ToolCallPlan> _toolPlans;

    public DeterministicScenarioChatClient(
        IEnumerable<KeyValuePair<string, string>> directResponses,
        IEnumerable<ToolCallPlan> toolPlans)
    {
        _directResponses = new Dictionary<string, string>(directResponses, StringComparer.Ordinal);
        _toolPlans = toolPlans.ToDictionary(plan => plan.Prompt, StringComparer.Ordinal);
    }

    public Task<ChatResponse> GetResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var transcript = messages.ToList();
        var lastMessage = transcript.LastOrDefault();
        if (lastMessage is not null)
        {
            var toolResult = lastMessage.Contents.OfType<FunctionResultContent>().LastOrDefault();
            if (toolResult is not null)
            {
                var resultText = toolResult.Result?.ToString() ?? "Tool completed with no output.";
                return Task.FromResult(new ChatResponse(new ChatMessage(ChatRole.Assistant, resultText)));
            }
        }

        var prompt = transcript.LastOrDefault(message => message.Role == ChatRole.User)?.Text ?? string.Empty;
        if (_toolPlans.TryGetValue(prompt, out var plan))
        {
            var callId = Guid.NewGuid().ToString("N");
            var message = new ChatMessage(
                ChatRole.Assistant,
                [new FunctionCallContent(callId, plan.ToolName, plan.Arguments)]);
            return Task.FromResult(new ChatResponse(message));
        }

        if (_directResponses.TryGetValue(prompt, out var response))
        {
            return Task.FromResult(new ChatResponse(new ChatMessage(ChatRole.Assistant, response)));
        }

        return Task.FromResult(new ChatResponse(new ChatMessage(ChatRole.Assistant, "I can help within the scenario's governed operating boundaries.")));
    }

    public async IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var response = await GetResponseAsync(messages, options, cancellationToken).ConfigureAwait(false);
        foreach (var update in response.ToChatResponseUpdates())
        {
            yield return update;
        }
    }

    public object? GetService(Type serviceType, object? serviceKey = null)
        => serviceType.IsInstanceOfType(this) ? this : null;

    public void Dispose()
    {
    }
}

public static class DemoCommon
{
    public static bool IsBlockedResponse(AgentResponse response) =>
        response.Text.Contains("Blocked by governance policy", StringComparison.OrdinalIgnoreCase) ||
        response.Messages.SelectMany(message => message.Contents)
            .OfType<FunctionResultContent>()
            .Any(content => content.Result?.ToString()?.Contains("Blocked by governance policy", StringComparison.OrdinalIgnoreCase) == true);

    public static void PrintResponseDetails(AgentResponse response, AuditTrail audit, string agentName, ref int allowedCount, ref int deniedCount)
    {
        var blocked = IsBlockedResponse(response);

        foreach (var functionCall in response.Messages.SelectMany(message => message.Contents).OfType<FunctionCallContent>())
        {
            Display.ToolCall(functionCall.Name, functionCall.Arguments);
        }

        foreach (var functionResult in response.Messages.SelectMany(message => message.Contents).OfType<FunctionResultContent>())
        {
            var resultText = functionResult.Result?.ToString() ?? "(no output)";
            Display.ToolResult(resultText, blocked);
        }

        var assistantText = response.Messages
            .Where(message => message.Role == ChatRole.Assistant)
            .Select(message => message.Text)
            .LastOrDefault(text => !string.IsNullOrWhiteSpace(text));

        if (!string.IsNullOrWhiteSpace(assistantText))
        {
            if (blocked)
            {
                Display.Denied(assistantText);
                deniedCount++;
                audit.Log(agentName, "tool_decision", "deny", assistantText);
            }
            else
            {
                Display.Allowed("Tool execution completed");
                Display.LlmResponse(assistantText);
                allowedCount++;
                audit.Log(agentName, "tool_decision", "allow", assistantText);
            }
        }
    }
}
