# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
CrewAI + Governance Toolkit — Native Getting Started
====================================================

This example uses native CrewAI constructs (`Agent`, `Task`, `Crew`) and wraps
the real CrewAI runtime with `agent_os.integrations.CrewAIKernel`.

Run from a repo checkout:

    pip install agent-governance-toolkit[full]
    pip install -r examples/crewai-governed/requirements.txt
    python examples/crewai-governed/getting_started.py

No external API key is required for this walkthrough. It uses a small
deterministic local `DemoLLM` so the CrewAI runtime is exercised without
calling a hosted model.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

try:
    from crewai import Agent, Crew, Process, Task
    from crewai.llms.base_llm import BaseLLM
except ImportError as exc:  # pragma: no cover - user-facing guard
    raise SystemExit(
        "CrewAI is required for this example. Run "
        "`pip install -r examples/crewai-governed/requirements.txt` first."
    ) from exc

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_REPO_ROOT / "packages" / "agent-os" / "src"))

from agent_os.integrations import CrewAIKernel
from agent_os.integrations.base import GovernancePolicy, PolicyViolationError


class DemoLLM(BaseLLM):
    """Deterministic local LLM used to keep the example reproducible."""

    def call(
        self,
        messages: Any,
        tools: Any = None,
        callbacks: Any = None,
        available_functions: Any = None,
        from_task: Any = None,
        from_agent: Any = None,
        response_model: Any = None,
    ) -> str:
        task_text = str(messages)
        match = re.search(
            r"Current Task:\s*Summarize (.+?) for the compliance bulletin\.",
            task_text,
            re.DOTALL,
        )
        topic = match.group(1).strip() if match else "the requested topic"
        return f"Final Answer: Safe CrewAI summary for {topic}."


def build_governed_crew() -> object:
    """Create a native CrewAI crew wrapped by the governance kernel."""
    reviewer = Agent(
        role="Compliance reviewer",
        goal="Produce concise, policy-compliant summaries.",
        backstory="A deterministic reviewer used for local integration demos.",
        llm=DemoLLM(model="demo"),
        allow_delegation=False,
        verbose=False,
    )

    summary_task = Task(
        description="Summarize {topic} for the compliance bulletin.",
        expected_output="A concise safe summary.",
        agent=reviewer,
    )

    native_crew = Crew(
        name="governed-native-crewai-crew",
        agents=[reviewer],
        tasks=[summary_task],
        process=Process.sequential,
        tracing=False,
        verbose=False,
    )

    policy = GovernancePolicy(
        name="native-crewai-demo-policy",
        blocked_patterns=["DROP TABLE", "rm -rf", "exfiltrate secrets"],
    )
    kernel = CrewAIKernel(policy=policy)
    return kernel.wrap(native_crew)


def run_blocked_scenario() -> None:
    """Show governance stopping a native CrewAI kickoff before the LLM runs."""
    governed_crew = build_governed_crew()
    print("[1] Native CrewAI kickoff with blocked input...")
    try:
        governed_crew.kickoff({"topic": "DROP TABLE users"})
    except PolicyViolationError as exc:
        print(f"    BLOCKED -- {exc}")


def run_allowed_scenario() -> None:
    """Show a safe native CrewAI kickoff succeeding."""
    governed_crew = build_governed_crew()
    print("\n[2] Native CrewAI kickoff with safe input...")
    result = governed_crew.kickoff({"topic": "the regulated release"})
    print(f"    ALLOWED -- {result}")


def main() -> None:
    print("=" * 64)
    print("  CrewAI + Governance Toolkit — Native Getting Started")
    print("=" * 64)
    print("  Uses real CrewAI Agent/Task/Crew objects plus CrewAIKernel.wrap().")
    print("  DemoLLM keeps the example local and reproducible (no API key needed).")

    run_blocked_scenario()
    run_allowed_scenario()

    print("\nDone! For the broader non-native scenario showcase, see")
    print("`examples/crewai-governed/crewai_governance_demo.py`.")


if __name__ == "__main__":
    main()
