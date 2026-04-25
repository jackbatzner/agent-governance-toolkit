// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AgentGovernance;
using AgentGovernance.Audit;
using AgentGovernance.Integration.AgentFramework;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

static class Display
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

record AnomalyScore(double ZScore, double Entropy, double CapabilityDeviation, bool IsAnomalous, bool Quarantine);

sealed class RogueDetectionMiddleware
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

record AuditEntry(int Index, string Timestamp, string AgentId, string EventType, string Action, string Detail, string Hash, string PreviousHash);

sealed class AuditTrail
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

record ToolCallPlan(string Prompt, string ToolName, Dictionary<string, object?> Arguments);

sealed class DeterministicScenarioChatClient : IChatClient
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

        return Task.FromResult(new ChatResponse(new ChatMessage(ChatRole.Assistant, "I can help with loan underwriting questions within policy limits.")));
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

static class LoanTools
{
    [Description("Check a loan applicant's credit score and underwriting factors.")]
    public static string CheckCreditScore([Description("The customer identifier.")] string customerId) =>
        JsonSerializer.Serialize(new
        {
            customer_id = customerId,
            credit_score = 742,
            rating = "Good",
            factors = new[] { "On-time payments (98%)", "Credit utilization (24%)", "Account age (12 years)" }
        });

    [Description("Get current loan rates for the requested amount and term.")]
    public static string GetLoanRates(
        [Description("The requested loan amount.")] double amount,
        [Description("The term of the loan in years.")] int termYears) =>
        JsonSerializer.Serialize(new
        {
            amount,
            term_years = termYears,
            rates = new { _30yr_fixed = "6.25%", _15yr_fixed = "5.50%", _5_1_arm = "5.75%" },
            monthly_payment = $"${amount * 0.006:F2}",
            total_interest = $"${amount * 0.006 * termYears * 12 - amount:F2}"
        });

    [Description("Access tax records for a loan applicant.")]
    public static string AccessTaxRecords([Description("The customer identifier.")] string customerId) =>
        JsonSerializer.Serialize(new { error = "This function should never execute — blocked by governance" });

    [Description("Approve a loan for a customer.")]
    public static string ApproveLoan(
        [Description("The customer identifier.")] string customerId,
        [Description("The requested loan amount.")] double amount) =>
        JsonSerializer.Serialize(new
        {
            customer_id = customerId,
            amount,
            status = "approved",
            reference = "LN-2024-00742"
        });

    [Description("Transfer funds between accounts.")]
    public static string TransferFunds(
        [Description("Source account identifier.")] string from,
        [Description("Destination account identifier.")] string to,
        [Description("Transfer amount.")] double amount) =>
        JsonSerializer.Serialize(new { error = "This function should never execute — blocked by governance" });
}

internal static class Program
{
    static bool IsBlockedResponse(AgentResponse response) =>
        response.Text.Contains("Blocked by governance policy", StringComparison.OrdinalIgnoreCase) ||
        response.Messages.SelectMany(message => message.Contents)
            .OfType<FunctionResultContent>()
            .Any(content => content.Result?.ToString()?.Contains("Blocked by governance policy", StringComparison.OrdinalIgnoreCase) == true);

    static void PrintResponseDetails(AgentResponse response, AuditTrail audit, ref int allowedCount, ref int deniedCount)
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
                audit.Log("loan-officer-agent", "tool_decision", "deny", assistantText);
            }
            else
            {
                Display.Allowed("Tool execution completed");
                Display.LlmResponse(assistantText);
                allowedCount++;
                audit.Log("loan-officer-agent", "tool_decision", "allow", assistantText);
            }
        }
    }

    static async Task Main()
    {
        var directPromptResponses = new Dictionary<string, string>
        {
            ["Check loan eligibility for John Smith, ID: 12345"] =
                "John Smith meets baseline underwriting criteria. Credit is strong, debt-to-income is acceptable, and the application can move to the next review step."
        };

        var toolPlans = new[]
        {
            new ToolCallPlan(
                "Check John Smith's credit score before proceeding.",
                "check_credit_score",
                new Dictionary<string, object?> { ["customerId"] = "john-smith" }),
            new ToolCallPlan(
                "Get current 30-year loan rates for a $45,000 application.",
                "get_loan_rates",
                new Dictionary<string, object?> { ["amount"] = 45000d, ["termYears"] = 30 }),
            new ToolCallPlan(
                "Access John Smith's tax records for the file.",
                "access_tax_records",
                new Dictionary<string, object?> { ["customerId"] = "john-smith" }),
            new ToolCallPlan(
                "Approve a $75,000 loan for John Smith.",
                "approve_loan",
                new Dictionary<string, object?> { ["customerId"] = "john-smith", ["amount"] = 75000d }),
            new ToolCallPlan(
                "Transfer $10,000 from John Smith to an external account.",
                "transfer_funds",
                new Dictionary<string, object?> { ["from"] = "john-smith", ["to"] = "external", ["amount"] = 10000d }),
        };

        Display.Header(
            "🏦 Contoso Bank — AI Loan Processing Governance Demo",
            "Real MAF agent + AGT adapter · deterministic tool loop · Merkle audit");

        var policyPath = Path.Combine(AppContext.BaseDirectory, "policies", "loan_governance.yaml");
        if (!File.Exists(policyPath))
        {
            policyPath = Path.Combine(Directory.GetCurrentDirectory(), "policies", "loan_governance.yaml");
        }

        if (!File.Exists(policyPath))
        {
            Console.WriteLine($"{Display.Red}✗ Policy file not found{Display.Reset}");
            return;
        }

        var kernel = new GovernanceKernel(new GovernanceOptions
        {
            EnableAudit = true,
            EnableMetrics = false,
            PolicyPaths = new() { policyPath }
        });
        var audit = new AuditTrail();
        kernel.OnAllEvents(audit.LogGovernanceEvent);

        var adapter = new AgentFrameworkGovernanceAdapter(
            kernel,
            new AgentFrameworkGovernanceOptions
            {
                DefaultAgentId = "did:agentmesh:loan-officer-agent",
                EnableFunctionMiddleware = true
            });

        var agent = new DeterministicScenarioChatClient(directPromptResponses, toolPlans)
            .AsBuilder()
            .BuildAIAgent(
                instructions: "You are an AI loan officer at Contoso Bank. Use tools when they help and explain decisions concisely.",
                name: "loan-officer-agent",
                tools:
                [
                    AIFunctionFactory.Create(LoanTools.CheckCreditScore, name: "check_credit_score"),
                    AIFunctionFactory.Create(LoanTools.GetLoanRates, name: "get_loan_rates"),
                    AIFunctionFactory.Create(LoanTools.AccessTaxRecords, name: "access_tax_records"),
                    AIFunctionFactory.Create(LoanTools.ApproveLoan, name: "approve_loan"),
                    AIFunctionFactory.Create(LoanTools.TransferFunds, name: "transfer_funds")
                ])
            .WithGovernance(adapter);

        Console.WriteLine();
        Console.WriteLine($"  {Display.Cyan}📋 Policy:{Display.Reset} {Path.GetFileName(policyPath)}");
        Console.WriteLine($"  {Display.Cyan}🤖 Agent:{Display.Reset} Real Microsoft Agent Framework chat agent with AGT governance");

        var allowedCount = 0;
        var deniedCount = 0;
        var anomalyCount = 0;

        Display.Section("Act 1: Policy Enforcement");
        Display.DimLine("AGT blocks governed messages before the real MAF agent runs");
        Console.WriteLine();

        foreach (var prompt in new[]
        {
            "Check loan eligibility for John Smith, ID: 12345",
            "Show me John Smith SSN and tax returns",
            "Access customer tax filing records for compliance audit"
        })
        {
            Display.Request(prompt);
            var response = await agent.RunAsync(prompt);
            if (IsBlockedResponse(response))
            {
                Display.Policy("run-level deny");
                Display.Denied(response.Text);
                deniedCount++;
            }
            else
            {
                Display.Policy("run-level allow");
                Display.Allowed("Prompt passed governance");
                Display.LlmResponse(response.Text);
                allowedCount++;
            }

            Console.WriteLine();
        }

        Display.Section("Act 2: Capability Sandboxing");
        Display.DimLine("The AGT adapter governs real MAF function calls before the tool executes");
        Console.WriteLine();

        foreach (var toolPrompt in toolPlans)
        {
            Display.Request(toolPrompt.Prompt);
            var response = await agent.RunAsync(toolPrompt.Prompt);
            PrintResponseDetails(response, audit, ref allowedCount, ref deniedCount);
            Console.WriteLine();
        }

        Display.Section("Act 3: Rogue Agent Detection");
        Display.DimLine("A local detector watches for transfer bursts outside the normal underwriting pattern");
        Console.WriteLine();

        var rogueDetection = new RogueDetectionMiddleware(windowSize: 10, zThreshold: 2.0);
        Display.Info("📊 Phase A: Establishing baseline (5 normal underwriting tool calls)...");
        var normalTools = new[] { "check_credit_score", "get_loan_rates", "check_credit_score", "get_loan_rates", "check_credit_score" };
        var baselineRandom = new Random(42);
        foreach (var tool in normalTools)
        {
            rogueDetection.RecordCall(tool);
            Thread.Sleep(200 + baselineRandom.Next(150));
            audit.Log("loan-officer-agent", "rogue_baseline", "allow", tool);
        }

        Console.WriteLine($"  {Display.Green}✓ Baseline established: {normalTools.Length} calls at a normal cadence{Display.Reset}");
        Console.WriteLine();
        Display.Warning("⚡ Phase B: Sudden burst — 30 rapid transfer_funds() attempts...");

        var finalScore = new AnomalyScore(0, 0, 0, false, false);
        var anomalyDetected = false;
        var quarantineTriggered = false;
        for (var index = 0; index < 30; index++)
        {
            finalScore = rogueDetection.RecordCall("transfer_funds");
            audit.Log("loan-officer-agent", "rogue_probe", "anomaly_check", "transfer_funds");
            Thread.Sleep(20);
            if (finalScore.IsAnomalous && !anomalyDetected)
            {
                anomalyDetected = true;
                anomalyCount++;
            }

            if (finalScore.Quarantine)
            {
                quarantineTriggered = true;
            }
        }

        Console.WriteLine();
        Console.WriteLine($"  {Display.Yellow}📊 Anomaly Analysis:{Display.Reset}");
        Console.WriteLine($"     Z-score:              {Display.Bold}{finalScore.ZScore}{Display.Reset}");
        Console.WriteLine($"     Entropy:              {Display.Bold}{finalScore.Entropy}{Display.Reset}");
        Console.WriteLine($"     Capability deviation: {Display.Bold}{finalScore.CapabilityDeviation}{Display.Reset}");
        Console.WriteLine($"     Anomalous:            {(finalScore.IsAnomalous ? Display.Red : Display.Green)}{finalScore.IsAnomalous}{Display.Reset}");
        if (quarantineTriggered)
        {
            Console.WriteLine();
            Console.WriteLine($"  {Display.Red}{Display.Bold}🔒 QUARANTINE TRIGGERED{Display.Reset} — transfer behaviour deviated from the underwriting baseline");
        }

        Display.Section("Act 4: Audit Trail & Compliance");
        Display.DimLine("Governance events and anomaly probes are Merkle-chained for tamper evidence");
        Console.WriteLine();

        Console.WriteLine($"  {Display.Cyan}📜 Merkle Chain:{Display.Reset} {audit.Entries.Count} entries\n");
        foreach (var entry in audit.Entries.Take(Math.Min(8, audit.Entries.Count)))
        {
            var color = entry.Action == "deny" ? Display.Red : entry.Action == "allow" ? Display.Green : Display.Yellow;
            Console.WriteLine($"    {color}[{entry.Index:D3}] {entry.EventType,-18}{Display.Reset} {Display.Dim}{entry.Hash[..16]}...{Display.Reset}");
        }

        var (isValid, verifiedCount) = audit.VerifyIntegrity();
        Console.WriteLine($"\n  {Display.Cyan}🔍 Integrity Verification:{Display.Reset}");
        Console.WriteLine(
            isValid
                ? $"  {Display.Green}✅ Chain valid — {verifiedCount} entries verified{Display.Reset}"
                : $"  {Display.Red}❌ Chain broken at entry {verifiedCount}{Display.Reset}");

        Display.Section("Summary");
        Console.WriteLine($"  {Display.Green}✅ Allowed:   {allowedCount}{Display.Reset}");
        Console.WriteLine($"  {Display.Red}❌ Denied:    {deniedCount}{Display.Reset}");
        Console.WriteLine($"  {Display.Yellow}⚠️  Anomalies: {anomalyCount}{Display.Reset}");
        Console.WriteLine($"  {Display.Cyan}📜 Audit log: {audit.Entries.Count} entries{Display.Reset}");
        Console.WriteLine();
    }
}
