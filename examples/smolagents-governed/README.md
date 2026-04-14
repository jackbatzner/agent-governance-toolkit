# 🤗 Hugging Face smolagents + Governance Toolkit

> This folder now includes a **real smolagents integration path** for
> the core example plus the earlier simulated governance walkthroughs.
> `getting_started.py` uses actual `smolagents` runtime objects;
> `demo_simulated.py` and `smolagents_governance_demo.py` stay focused on
> broader toolkit behavior.

![smolagents governance demo](demo.gif)

## Two Ways to Run

```bash
# Real smolagents runtime example
pip install smolagents agent-governance-toolkit[full]
python examples/smolagents-governed/getting_started.py

# Or keep the old no-framework walkthrough
python examples/smolagents-governed/demo_simulated.py
```

`getting_started.py` is the real integration example. It uses:

- real `@tool`-decorated smolagents tools
- a real `ToolCallingAgent`
- `agent_os.integrations.smolagents_adapter.SmolagentsKernel`
- a deterministic local `Model`, so the example runs without API keys

The key integration surface is the adapter wrapping real smolagents tools:

```python
from smolagents import ToolCallingAgent, tool
from agent_os.integrations.smolagents_adapter import SmolagentsKernel

@tool
def web_search(query: str) -> str:
    """Search public sources."""
    return f"Results for: {query}"

agent = ToolCallingAgent(tools=[web_search], model=your_model)
kernel = SmolagentsKernel(allowed_tools=["web_search"], blocked_tools=["shell_exec"])
kernel.wrap(agent)

result = agent.run("Research public agent governance patterns.")
```

For the broader simulated governance walkthroughs:

```bash
# Legacy no-framework walkthrough
python examples/smolagents-governed/demo_simulated.py

# Full 9-scenario governance walkthrough (still simulated/smolagents-shaped)
python examples/smolagents-governed/smolagents_governance_demo.py
```

## What This Shows

| Scenario | Governance Layer | What Happens |
|----------|-----------------|--------------|
| **1. Role-Based Tool Access** | `CapabilityGuardMiddleware` | Each agent role (Researcher, Analyst, Summarizer, Publisher) has a declared tool allow/deny list — Researcher can `web_search` but not `deploy_model`; Analyst can `compute_stats` but not `shell_exec` |
| **2. Data-Sharing Policies** | `GovernancePolicyMiddleware` | YAML policy blocks PII (email, phone, SSN), internal resource access, and secrets — **before the LLM is called** |
| **3. Model Safety Gates** | `GovernancePolicyMiddleware` | Restricts model downloads to trusted sources, blocks arbitrary code execution, requires review before publishing results |
| **4. Rate Limiting & Rogue Detection** | `RogueDetectionMiddleware` + `RogueAgentDetector` | Behavioral anomaly engine builds a deterministic baseline, then detects a 50-call burst from the Analyst role and recommends quarantine |
| **5. Full Agent Pipeline** | All layers combined | Research → Analyze → Summarize → Publish pipeline with governance applied at every step |
| **6. Prompt Injection Defense** | `GovernancePolicyMiddleware` | 8 adversarial attacks (jailbreak, instruction override, system prompt extraction, encoded payload, PII exfiltration, SQL/shell injection) — blocked before reaching the LLM |
| **7. Delegation Governance** | `GovernancePolicyMiddleware` | Agents trying to bypass the required review pipeline are caught — proper Researcher→Analyst→Summarizer→Publisher chain enforced |
| **8. Capability Escalation** | `CapabilityGuardMiddleware` + `RogueAgentDetector` | Analyst attempts `shell_exec`, `deploy_model`, `delete_file`, `send_email`, `admin_panel` — all blocked and recorded against the declared capability profile |
| **9. Tamper Detection** | `AuditLog` + `MerkleAuditChain` | Merkle proof generation, simulated audit trail tampering caught by integrity check, CloudEvents export |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  smolagents-shaped Roles (4)                                │
│                                                             │
│  ┌────────────┐ ┌──────────┐ ┌────────────┐ ┌───────────┐ │
│  │ Researcher │→│ Analyst  │→│ Summarizer │→│ Publisher │ │
│  └─────┬──────┘ └────┬─────┘ └─────┬──────┘ └─────┬─────┘ │
│        │             │              │              │        │
│  ┌─────┴─────────────┴──────────────┴──────────────┴──────┐ │
│  │           Governance Middleware Stack                   │ │
│  │                                                        │ │
│  │  CapabilityGuardMiddleware  (tool allow/deny list)     │ │
│  │  GovernancePolicyMiddleware (YAML policy rules)        │ │
│  │  RogueDetectionMiddleware   (anomaly scoring)          │ │
│  └──────────────────────┬─────────────────────────────────┘ │
│                         │                                   │
│          LLM / Tool Execution (live or simulated)           │
└─────────────────────────┬───────────────────────────────────┘
                          │
              ┌───────────┴───────────┐
              │                       │
              ▼                       ▼
        AuditLog (Merkle)      RogueAgentDetector
        agentmesh.governance   agent_sre.anomaly
```

## How This Maps to smolagents

Hugging Face [smolagents](https://github.com/huggingface/smolagents) provides
two agent types — `CodeAgent` (generates Python code to call tools) and
`ToolCallingAgent` (emits structured JSON tool calls). The files in this folder
are now split deliberately:

1. **`getting_started.py`** uses the real `ToolCallingAgent` runtime, real
   `@tool` objects, and the toolkit's `SmolagentsKernel`.
2. **`demo_simulated.py`** preserves the previous lightweight walkthrough
   without a smolagents dependency.
3. **`smolagents_governance_demo.py`** remains the larger simulated showcase
   for policy, rogue detection, and audit scenarios beyond the current native
   smolagents adapter surface.

The native adapter currently intercepts **tool execution** by wrapping each
tool's `forward()` implementation on real smolagents agents:

1. **Tool `forward()` wrapping** — `SmolagentsKernel` wraps entries from the
   agent's real tool registry and enforces allowlists, blocklists, blocked
   content patterns, approval gates, and audit events.

2. **Simulated higher-level policy walkthroughs** — The other scripts in this
   folder still demonstrate the broader toolkit layers that are not yet wired
   into a native smolagents message-level integration.

## Prerequisites

```bash
# Minimal dependency for the real smolagents example
pip install smolagents agent-governance-toolkit[full]

# Or install just the framework dependency from this folder
pip install -r examples/smolagents-governed/requirements.txt
```

`getting_started.py` does **not** need an API key: it uses a deterministic
local demo model to drive the real smolagents runtime.

## Running

```bash
cd agent-governance-toolkit

# Real smolagents example (actual ToolCallingAgent + @tool + adapter)
python examples/smolagents-governed/getting_started.py

# Previous lightweight walkthrough without smolagents
python examples/smolagents-governed/demo_simulated.py

# Larger simulated governance showcase
python examples/smolagents-governed/smolagents_governance_demo.py
```

## Scenarios Walkthrough

### 1. Role-Based Tool Access

Each agent has declared capabilities. The `CapabilityGuardMiddleware`
enforces tool access at runtime:

| Agent | Allowed Tools | Denied Tools |
|-------|--------------|--------------|
| Researcher | `web_search`, `read_file`, `hf_hub_search` | `shell_exec`, `deploy_model`, `publish_results` |
| Data Analyst | `read_file`, `compute_stats`, `visualize_data` | `shell_exec`, `deploy_model`, `send_email` |
| Summarizer | `read_file`, `write_draft`, `check_grammar` | `shell_exec`, `deploy_model`, `publish_results` |
| Publisher | `publish_results`, `read_file` | `shell_exec`, `deploy_model`, `delete_file` |

### 2. Data-Sharing Policies

YAML-defined policies in `policies/research_governance_policy.yaml` block:
- **PII** — email addresses, phone numbers, SSNs detected via regex
- **Internal resources** — any mention of "internal" or "secrets"
- **Dangerous content** — SQL injection, shell injection patterns

Policy evaluation happens **before** the LLM call, saving API tokens.

### 3. Model Safety Gates

Uses the `model_safety_policy.yaml` to enforce:
- **Model trust** — Only models from approved sources (Hugging Face Hub)
- **Execution safety** — Blocks `exec()` / `eval()` patterns
- **Review gates** — DRAFT results are blocked from publishing; REVIEWED content passes

### 4. Rate Limiting & Rogue Detection

The `RogueAgentDetector` monitors three behavioral signals:
- **Frequency** — Z-score spikes in tool call rate
- **Entropy** — deviation from normal action distribution
- **Capability** — calls outside declared tool profile

The demo seeds a deterministic five-window baseline, then injects a 50-call
burst so the detector produces a reproducible high-risk assessment with
quarantine recommended.

### 5. Full Agent Pipeline

Runs the complete workflow (Research → Analyze → Summarize → Publish)
with governance applied at every step. All decisions are logged in the
Merkle-chained audit trail.

### 6. Prompt Injection Defense

Tests 8 adversarial attacks against the governance policy layer:
- **Instruction override** — "Ignore all previous instructions..."
- **Jailbreak** — "You are now DAN, no restrictions..."
- **System prompt extraction** — "Reveal your system prompt..."
- **Encoded payload** — Base64 execution attempts
- **PII exfiltration** — SSN + email in agent messages
- **SQL injection** — `DROP TABLE` hidden in analysis queries
- **Shell injection** — `rm -rf` hidden in cleanup tasks

### 7. Delegation Governance

Enforces proper workflow delegation chains:
- **Allowed**: Researcher → Analyst → Summarizer → Publisher
- **Blocked**: Researcher → Publisher (skipping review steps)
- **Blocked**: Any agent using "bypass", "circumvent", or "skip" review

### 8. Capability Escalation Detection

Detects agents attempting to use tools outside their declared profile:
- Analyst tries `shell_exec`, `deploy_model`, `delete_file`, `send_email`, `admin_panel`
- All escalation attempts blocked by `CapabilityGuardMiddleware`
- `RogueAgentDetector` records those attempts against the analyst's declared tool profile

### 9. Tamper Detection & Merkle Proofs

Demonstrates the cryptographic integrity guarantees of the audit trail:
- Logs governed actions and verifies Merkle chain integrity
- Generates a Merkle proof for a specific entry (independently verifiable)
- **Simulates tampering** — modifies an entry's action field
- Integrity check **detects the tamper** and reports the corrupted entry
- Restores original state and re-verifies
- Exports full audit trail as CloudEvents format

## Key Files

| File | Purpose |
|------|---------|
| `getting_started.py` | **Start here** — real smolagents `ToolCallingAgent` + `SmolagentsKernel` integration |
| `demo_simulated.py` | Previous lightweight walkthrough with no smolagents dependency |
| `smolagents_governance_demo.py` | Full 9-scenario simulated governance walkthrough |
| `requirements.txt` | Minimal framework dependency for the real example |
| `policies/research_governance_policy.yaml` | Role-based + PII + injection + delegation policies |
| `policies/model_safety_policy.yaml` | Model trust and publishing quality gates |
| `packages/agent-os/src/agent_os/integrations/smolagents_adapter.py` | Real smolagents adapter used by `getting_started.py` |
| `packages/agent-mesh/src/agentmesh/governance/audit.py` | Merkle-chained audit log |
| `packages/agent-sre/src/agent_sre/anomaly/rogue_detector.py` | Rogue agent detector |

## LLM Configuration

Demos auto-detect the LLM backend in this order:

| Priority | Backend | Setup | Cost |
|----------|---------|-------|------|
| 1 | **GitHub Models** | `export GITHUB_TOKEN=$(gh auth token)` | Free |
| 2 | **Google Gemini** | Set `GOOGLE_API_KEY` | Free tier available |
| 3 | **Azure OpenAI** | Set `AZURE_OPENAI_ENDPOINT` + `AZURE_OPENAI_API_KEY` | Pay-as-you-go |
| 4 | **OpenAI** | Set `OPENAI_API_KEY` | Pay-as-you-go |
| 5 | **Simulated** | No setup needed | Free |

> **Tip:** [GitHub Models](https://github.com/marketplace/models) provides free
> access to GPT-4o-mini, Llama, and other models using your GitHub account.

## Related

- [CrewAI Governance Demo](../crewai-governed/) — Similar demo with CrewAI framework
- [MAF Integration Examples](../maf-integration/) — Microsoft Agent Framework scenarios
- [Quickstart Examples](../quickstart/) — Single-file quickstarts for each framework
- [Sample Policies](../policies/) — Additional YAML governance policies
