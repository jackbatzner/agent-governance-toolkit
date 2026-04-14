# CrewAI + Governance Toolkit

This folder now contains a **real CrewAI-native quickstart** plus a larger
supplemental governance showcase:

- `getting_started.py` — **native CrewAI runtime**
  - imports `crewai.Agent`, `crewai.Task`, `crewai.Crew`, and `crewai.Process`
  - wraps the real crew with `agent_os.integrations.CrewAIKernel`
  - runs locally with a deterministic `DemoLLM`, so no hosted-model API key is
    required
- `crewai_governance_demo.py` — broader **simulated CrewAI-style** scenario
  walkthrough kept for the larger governance surface area

If you need the smallest credible integration path, start with
`getting_started.py`.

## Quick Start

Run from the repository root:

```bash
pip install agent-governance-toolkit[full]
pip install -r examples/crewai-governed/requirements.txt
python examples/crewai-governed/getting_started.py
```

Expected behavior:

1. A governed native CrewAI kickoff is blocked because the input matches a
   policy deny pattern.
2. A second governed native CrewAI kickoff succeeds and returns a deterministic
   local result.

## What the Native Example Exercises

The quickstart is intentionally narrow and reviewable. It proves the integration
path without introducing broader framework design changes:

- native `crewai.Agent`
- native `crewai.Task`
- native `crewai.Crew`
- native `Crew.kickoff(...)`
- toolkit governance via `CrewAIKernel.wrap(...)`
- policy enforcement before CrewAI execution begins

## Native Example Shape

```python
from crewai import Agent, Crew, Process, Task
from crewai.llms.base_llm import BaseLLM

from agent_os.integrations import CrewAIKernel
from agent_os.integrations.base import GovernancePolicy


class DemoLLM(BaseLLM):
    def call(self, messages, **kwargs):
        return "Final Answer: Safe CrewAI summary."


reviewer = Agent(
    role="Compliance reviewer",
    goal="Produce concise, policy-compliant summaries.",
    backstory="A deterministic reviewer used for local integration demos.",
    llm=DemoLLM(model="demo"),
    allow_delegation=False,
)

task = Task(
    description="Summarize {topic} for the compliance bulletin.",
    expected_output="A concise safe summary.",
    agent=reviewer,
)

crew = Crew(agents=[reviewer], tasks=[task], process=Process.sequential)
governed = CrewAIKernel(
    policy=GovernancePolicy(blocked_patterns=["DROP TABLE"])
).wrap(crew)
```

## Dependency Notes

`examples/crewai-governed/requirements.txt` is intentionally narrow:

```text
crewai>=1.14,<2.0
```

The repo-local quickstart still imports toolkit packages from this checkout via
`sys.path`, so you do **not** need repo-wide packaging changes to run it.

## About the Larger Demo

`crewai_governance_demo.py` remains useful for the broader governance story
(trust scoring, rogue detection, Merkle audit checks, prompt-injection samples,
and tamper detection), but it is **not** the primary native CrewAI integration
path. Treat it as a supplemental showcase, not the minimal framework-native
example.

## Files

| File | Purpose |
|------|---------|
| `getting_started.py` | Real CrewAI-native quickstart using `Agent`, `Task`, `Crew`, and `CrewAIKernel.wrap()` |
| `requirements.txt` | Minimal example-specific dependency declaration |
| `crewai_governance_demo.py` | Supplemental simulated CrewAI-style governance showcase |
| `policies/content_creation_policy.yaml` | Policy data used by the supplemental showcase |
| `policies/quality_gate_policy.yaml` | Publishing quality gate policy for the supplemental showcase |

## Validation

Suggested checks from the repo root:

```bash
python examples/crewai-governed/getting_started.py
pytest packages/agent-os/tests/test_crewai_logging.py \
       packages/agent-os/tests/test_crewai_native_runtime.py -q
```
