# 🚀 DeployBot — CI/CD Pipeline Safety Governance Demo (.NET)

This example uses a **real Microsoft Agent Framework agent** with the shared
**AGT Agent Framework adapter** to demonstrate governed DevOps automation.

## What it demonstrates

1. **Policy Enforcement** — production deploy, secret access, and destructive database prompts are denied before the agent runs
2. **Capability Sandboxing** — governed MAF tools allow safe CI/staging operations and block production-only controls
3. **Rogue Agent Detection** — deployment storms trigger anomaly scoring and quarantine
4. **Audit Trail** — AGT events are mirrored into a Merkle-chained compliance log

## Runtime model

- `Program.cs` builds the DevOps agent with `BuildAIAgent(...).WithGovernance(adapter)`
- `policies/devops_governance.yaml` uses the real AGT .NET policy expression format
- Output is deterministic and requires no live LLM credentials

## Run it

```bash
dotnet run
```
