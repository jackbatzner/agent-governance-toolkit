# 🏦 Contoso Bank — Loan Processing Governance Demo (.NET)

This example shows a **real Microsoft Agent Framework agent** wrapped with the shared
**AGT Agent Framework adapter** from `agent-governance-dotnet`.

## What it demonstrates

1. **Policy Enforcement** — governed loan prompts are denied before the agent runs
2. **Capability Sandboxing** — governed MAF tool calls block tax-record access, large approvals, and fund transfers
3. **Rogue Agent Detection** — repeated transfer attempts trigger anomaly scoring
4. **Audit Trail** — AGT events are mirrored into a Merkle-chained compliance log

## Runtime model

- `Program.cs` builds a real MAF agent with `BuildAIAgent(...).WithGovernance(adapter)`
- `policies/loan_governance.yaml` uses the real AGT .NET expression syntax
- Output is deterministic: the demo uses a local MAF chat client instead of external model credentials

## Run it

```bash
dotnet run
```

## Files

- `Program.cs` — scenario walkthrough and domain tools
- `policies/loan_governance.yaml` — AGT policy rules for the walkthrough prompts and tools
- `LoanGovernance.csproj` — project reference to `agent-governance-dotnet`

## Example policy rule

```yaml
- name: block-fund-transfer
  condition: "tool_name == 'transfer_funds'"
  action: deny
  priority: 100
```
