# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Native CrewAI runtime smoke tests for the governed adapter."""

from __future__ import annotations

import re

import pytest

from agent_os.integrations import CrewAIKernel
from agent_os.integrations.base import GovernancePolicy, PolicyViolationError

crewai = pytest.importorskip("crewai")
from crewai import Agent, Crew, Process, Task  # type: ignore[attr-defined]
from crewai.llms.base_llm import BaseLLM  # type: ignore[attr-defined]


class DemoLLM(BaseLLM):
    """Deterministic local LLM for native CrewAI adapter tests."""

    def call(
        self,
        messages,
        tools=None,
        callbacks=None,
        available_functions=None,
        from_task=None,
        from_agent=None,
        response_model=None,
    ) -> str:
        text = str(messages)
        match = re.search(
            r"Current Task:\s*Summarize (.+?) for the compliance bulletin\.",
            text,
            re.DOTALL,
        )
        topic = match.group(1).strip() if match else "the requested topic"
        return f"Final Answer: Safe CrewAI summary for {topic}."


def _build_governed_crew() -> object:
    agent = Agent(
        role="Compliance reviewer",
        goal="Produce concise safe summaries.",
        backstory="A deterministic native CrewAI test agent.",
        llm=DemoLLM(model="demo"),
        allow_delegation=False,
        verbose=False,
    )
    task = Task(
        description="Summarize {topic} for the compliance bulletin.",
        expected_output="A concise safe summary.",
        agent=agent,
    )
    crew = Crew(
        name="native-governed-crew",
        agents=[agent],
        tasks=[task],
        process=Process.sequential,
        tracing=False,
        verbose=False,
    )
    kernel = CrewAIKernel(
        policy=GovernancePolicy(
            name="native-crewai-test-policy",
            blocked_patterns=["DROP TABLE", "rm -rf"],
        )
    )
    return kernel.wrap(crew)


def test_native_crewai_kickoff_is_blocked_by_policy():
    governed = _build_governed_crew()

    with pytest.raises(PolicyViolationError, match="DROP TABLE"):
        governed.kickoff({"topic": "DROP TABLE users"})


def test_native_crewai_kickoff_runs_with_safe_input():
    governed = _build_governed_crew()

    result = governed.kickoff({"topic": "the regulated release"})

    assert "regulated release" in str(result)
