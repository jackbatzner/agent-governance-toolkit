# 🎧 Contoso Support — Customer Service Governance Demo (.NET)

This example uses a **real Microsoft Agent Framework agent** with the shared
**AGT Agent Framework adapter** to demonstrate retail support governance.

## What it demonstrates

1. **Policy Enforcement** — large refunds, payment-card requests, and billing changes are denied before execution
2. **Capability Sandboxing** — governed MAF tools allow order/refund workflows and block sensitive account operations
3. **Rogue Agent Detection** — refund-farming behaviour triggers anomaly scoring and quarantine
4. **Audit Trail** — AGT events are mirrored into a Merkle-chained tamper-evident log

## Runtime model

- `Program.cs` builds the support agent with `BuildAIAgent(...).WithGovernance(adapter)`
- `policies/support_governance.yaml` uses the real AGT .NET policy expression format
- Output is deterministic and does not require GitHub Models or Azure OpenAI credentials

## Run it

```bash
dotnet run
```

## Files

- `Program.cs` — scenario walkthrough and support tool definitions
- `policies/support_governance.yaml` — AGT prompt and tool rules for the demo
- `CustomerServiceGovernance.csproj` — references `agent-governance-dotnet` plus shared demo support
