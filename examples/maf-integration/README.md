# Agent Governance Toolkit × Microsoft Agent Framework — Demo Scenarios

End-to-end samples showing how the **Agent Governance Toolkit (AGT)** integrates
with [Microsoft Agent Framework (MAF)](https://github.com/microsoft/agent-framework)
middleware to enforce governance policies on AI agents in real-world scenarios.

Each scenario is **fully self-contained** — copy any folder, install dependencies,
and run. No shared code, no cross-folder imports.

## Integration Pattern

AGT plugs into your MAF agent pipeline as **deterministic middleware** — no extra
LLM calls, no latency surprises. Every check is pure rule evaluation:

```
Your MAF Agent Pipeline
    │
    ▼
┌─────────────────────────────────┐
│ AGT Governance Middleware       │  ← Deterministic, no LLM
│ (plugs into MAF middleware)     │
│                                 │
│  1. Policy Engine (YAML rules)  │
│  2. Capability Guard (tools)    │
│  3. Rogue Detector (behavior)   │
│  4. Audit Trail (Merkle chain)  │
└─────────────────────────────────┘
    │
    ▼  (only if governance passes)
Your LLM Call
```

### Add AGT to an existing MAF project in 3 steps

**Step 1 — Install the toolkit**

```bash
pip install agent-governance-toolkit[full]
```

**Step 2 — Define policies in YAML**

Create a file such as `policies/governance.yaml`:

```yaml
version: "1.0"
rules:
  - name: "block_pii"
    condition:
      field: "message"
      operator: "contains_any"
      value: "SSN,social security,credit card number"
    action: "deny"
    priority: 100
    message: "PII detected — request blocked before reaching the LLM"

  - name: "spending_limit"
    condition:
      field: "message"
      operator: "contains_any"
      value: "approve loan,loan approval"
    action: "deny"
    priority: 90
    message: "Loan approvals over $50,000 require human review"
```

**Step 3 — Add middleware to your MAF pipeline**

```python
from agent_governance_toolkit import PolicyEngine, GovernancePolicyMiddleware, AuditTrail

engine = PolicyEngine("policies/governance.yaml")
audit  = AuditTrail()
gov_mw = GovernancePolicyMiddleware(engine, audit)

# In your MAF pipeline, call governance before the LLM:
result = gov_mw.evaluate(user_message)
if result.denied:
    return result.message          # blocked — never reaches the LLM
# ... proceed to LLM call ...
```

That's it. Every request now passes through deterministic policy checks before
any LLM interaction, and every decision is recorded in a tamper-proof Merkle-
chained audit log.

## Two Ways to Run

Each scenario supports two execution modes so you can experiment with or without
an API key:

| Mode | How to run | What happens |
|------|-----------|--------------|
| **Simulated** (default) | `python main.py` | Uses built-in simulated LLM responses — no API key needed. Great for exploring governance behavior. |
| **Live LLM** | Set `GITHUB_TOKEN` or `OPENAI_API_KEY`, then `python main.py` | Sends real requests to an LLM. Governance middleware still runs identically. |

> **Tip:** Start with simulated mode to understand the governance pipeline, then
> switch to live LLM calls to see the same policies enforced on real model output.

## Scenarios

| # | Scenario | Industry | What it demonstrates |
|---|----------|----------|----------------------|
| 01 | [**Loan Processing**](./01-loan-processing/) | Banking | PII blocking, spending limits, API sandboxing, rogue detection |
| 02 | [**Customer Service**](./02-customer-service/) | Retail | Refund fraud prevention, payment PII protection, escalation rules |
| 03 | [**Healthcare**](./03-healthcare/) | Healthcare | HIPAA PHI blocking, prescription safety, cross-department isolation, data exfiltration detection |
| 04 | [**IT Helpdesk**](./04-it-helpdesk/) | Enterprise IT | Privilege escalation prevention, credential access blocking, infrastructure protection |
| 05 | [**DevOps Deploy**](./05-devops-deploy/) | DevOps | Production deployment gates, destructive operation blocking, deployment storm detection |

Each scenario includes both **Python** and **.NET** implementations with identical
governance behavior.

## Quick Start

### Python

```bash
cd 01-loan-processing/python
pip install -r requirements.txt

# Option A: Free LLM via GitHub Models (recommended)
export GITHUB_TOKEN=$(gh auth token)
python main.py

# Option B: No setup needed (simulated mode)
python main.py
```

### .NET

```bash
cd 01-loan-processing/dotnet
dotnet restore

# Option A: Free LLM via GitHub Models (recommended)
export GITHUB_TOKEN=$(gh auth token)
dotnet run

# Option B: No setup needed (simulated mode)
dotnet run
```

## What You'll See

Each demo runs a **4-act governance walkthrough** in your terminal:

```
╔══════════════════════════════════════════════════════════╗
║  🏦 Contoso Bank — AI Loan Processing Governance Demo   ║
╚══════════════════════════════════════════════════════════╝

━━━ Act 1: Policy Enforcement ━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ✅ Safe request → ALLOWED → LLM responds
  ❌ PII request → DENIED before reaching LLM

━━━ Act 2: Capability Sandboxing ━━━━━━━━━━━━━━━━━━━━━━━━
  ✅ Permitted tool calls execute normally
  ❌ Restricted tools blocked at middleware layer

━━━ Act 3: Rogue Agent Detection ━━━━━━━━━━━━━━━━━━━━━━━━
  📊 Baseline established → anomalous burst detected
  🔒 Agent auto-quarantined

━━━ Act 4: Audit Trail & Compliance ━━━━━━━━━━━━━━━━━━━━━
  📝 Merkle-chained audit log verified
  ✅ Integrity check passed — no tampered entries
```

## LLM Configuration

Demos auto-detect the LLM backend in this order:

| Priority | Backend | Setup | Cost |
|----------|---------|-------|------|
| 1 | **GitHub Models** | `export GITHUB_TOKEN=$(gh auth token)` | Free |
| 2 | **Azure OpenAI** | Set `AZURE_OPENAI_ENDPOINT` + `AZURE_OPENAI_API_KEY` | Pay-as-you-go |
| 3 | **Simulated** | No setup needed | Free |

> **Tip:** [GitHub Models](https://github.com/marketplace/models) provides free
> access to GPT-4o-mini, Llama, and other models using your GitHub account. No
> Azure subscription required.

## Governance Architecture

```
┌─────────────────────────────────────────────────────┐
│                   User Request                       │
└────────────────────┬────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────┐
│           1. Policy Enforcement Middleware            │
│  Loads YAML policy → evaluates rules → ALLOW / DENY │
└────────────────────┬────────────────────────────────┘
                     │ (if allowed)
                     ▼
┌─────────────────────────────────────────────────────┐
│           2. Capability Guard Middleware              │
│  Checks tool allow/deny lists → ALLOW / BLOCK        │
└────────────────────┬────────────────────────────────┘
                     │ (if allowed)
                     ▼
┌─────────────────────────────────────────────────────┐
│           3. Rogue Detection Middleware               │
│  Z-score frequency + entropy + capability deviation  │
│  Quarantines agent if anomaly score exceeds threshold │
└────────────────────┬────────────────────────────────┘
                     │ (if not quarantined)
                     ▼
┌─────────────────────────────────────────────────────┐
│           4. LLM / Tool Execution                    │
│  Agent processes request via MAF pipeline             │
└────────────────────┬────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────┐
│           5. Audit Trail Middleware                   │
│  SHA-256 Merkle chain → tamper-proof compliance log  │
└─────────────────────────────────────────────────────┘
```

## Customization

Edit the YAML policy files to change governance behavior:

```yaml
# policies/loan_governance.yaml
rules:
  - name: "spending_limit"
    condition:
      field: "message"
      operator: "contains_any"
      value: "approve loan,loan approval"
    action: "deny"
    priority: 90
    message: "Loan approvals over $50,000 require human review"
```

Re-run the demo and see your changes take effect immediately.

## Folder Structure

```
examples/maf-integration/
├── README.md                     ← You are here
├── 01-loan-processing/
│   ├── python/                   # Python implementation
│   │   ├── main.py               #   Complete standalone demo
│   │   ├── policies/             #   YAML governance rules
│   │   ├── requirements.txt      #   pip dependencies
│   │   ├── README.md             #   Detailed guide
│   │   └── sample_output.md      #   Expected output for blog
│   └── dotnet/                   # .NET implementation
│       ├── Program.cs            #   Complete standalone demo
│       ├── policies/             #   Same YAML governance rules
│       ├── *.csproj              #   .NET 8 project file
│       ├── README.md             #   Detailed guide
│       └── sample_output.md      #   Expected output
├── 02-customer-service/
│   ├── python/                   # Same structure as above
│   └── dotnet/
├── 03-healthcare/
│   ├── python/                   # HIPAA patient data governance
│   └── dotnet/
├── 04-it-helpdesk/
│   ├── python/                   # Privilege escalation prevention
│   └── dotnet/
└── 05-devops-deploy/
    ├── python/                   # CI/CD pipeline safety
    └── dotnet/
```

## Related Resources

- [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) — Full governance framework
- [Microsoft Agent Framework](https://github.com/microsoft/agent-framework) — Agent development SDK
- [GitHub Models](https://github.com/marketplace/models) — Free LLM access for developers
