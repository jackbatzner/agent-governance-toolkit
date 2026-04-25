# 🔐 SecureDesk — IT Helpdesk Governance Demo (.NET)

This example uses a **real Microsoft Agent Framework agent** with the shared
**AGT Agent Framework adapter** to demonstrate least-privilege IT helpdesk controls.

## What it demonstrates

1. **Policy Enforcement** — privilege-escalation and credential prompts are denied before the agent runs
2. **Capability Sandboxing** — governed MAF tools allow safe helpdesk actions and block admin or vault access
3. **Rogue Agent Detection** — repeated admin-command attempts trigger anomaly scoring and quarantine
4. **Audit Trail** — AGT events are mirrored into a Merkle-chained compliance log

## Runtime model

- `Program.cs` builds the helpdesk agent with `BuildAIAgent(...).WithGovernance(adapter)`
- `policies/helpdesk_governance.yaml` uses the real AGT .NET policy expression format
- Output is deterministic and requires no live LLM credentials

## Run it

```bash
dotnet run
```
