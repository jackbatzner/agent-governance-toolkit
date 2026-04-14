# OpenAI Agents Governed

This folder now uses the **real OpenAI Agents SDK runtime**:

- `agents.Agent`
- `agents.Runner.run`
- real `InputGuardrail` / `OutputGuardrail`
- `GovernanceHooks` from `openai_agents_trust`

It is scoped to a repo checkout and keeps the dependency story honest:

- **Required:** install `openai-agents`
- **Repo-local:** the example imports `openai_agents_trust` from this checkout
- **Optional:** `--live` uses a real OpenAI model when `OPENAI_API_KEY` is set

## Install

```bash
python -m pip install openai-agents
```

Run the example from this repository checkout. The scripts add the local
`packages/agentmesh-integrations/openai-agents-trust/src` path automatically.

If you prefer an installed package instead of repo-local imports:

```bash
python -m pip install -e packages/agentmesh-integrations/openai-agents-trust
```

## Quick Start

Offline mode exercises the real SDK runtime without network calls by using a
deterministic local `Model` implementation:

```bash
python examples/openai-agents-governed/getting_started.py
```

That run still goes through:

1. `Agent(...)`
2. `Runner.run(...)`
3. `trust_input_guardrail(...)`
4. `policy_input_guardrail(...)`
5. `content_output_guardrail(...)`
6. `GovernanceHooks(...)`

## Full Demo

```bash
python examples/openai-agents-governed/openai_agents_governance_demo.py
```

The demo shows three real SDK-native flows:

- **Allowed tool-assisted run** through `Runner.run`
- **Blocked input** via input guardrail tripwire
- **Blocked output** via output guardrail tripwire

Use `--verbose` to print the audit trail.

## Live OpenAI Run

To swap the offline model for a live OpenAI call, set `OPENAI_API_KEY` and use
`--live`:

```bash
set OPENAI_API_KEY=sk-...
python examples/openai-agents-governed/openai_agents_governance_demo.py --live --model gpt-4.1-mini
```

Notes:

- Live mode is **optional**
- The offline default is what we validate locally in this repo
- This example is currently wired for the standard OpenAI API path only

## What This Example Is

- A **real OpenAI Agents SDK** example
- A **contained** example scoped to this folder
- An example of governed tool execution, audit logging, and guardrail tripwires

## What This Example Is Not

- Not a broad repo-wide framework rewrite
- Not an Azure OpenAI example
- Not a claim that `agent-governance-toolkit[full]` alone installs the OpenAI
  Agents SDK stack
