# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ruff: noqa: E402
"""
Hugging Face smolagents + Governance Toolkit — Getting Started
==============================================================

Real smolagents example using:
  1. real ``@tool``-decorated smolagents tools
  2. a real ``ToolCallingAgent`` runtime
  3. the toolkit's ``SmolagentsKernel`` adapter for tool governance
  4. a deterministic local model, so no API key is required

    pip install smolagents agent-governance-toolkit[full]
    python examples/smolagents-governed/getting_started.py

This script keeps scope intentionally small: it demonstrates the live
smolagents integration surface that exists today (tool-call governance).
For the larger simulated governance walkthrough, see ``demo_simulated.py``
and ``smolagents_governance_demo.py``.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from smolagents import ToolCallingAgent, tool
    from smolagents.models import (
        ChatMessage,
        ChatMessageToolCall,
        ChatMessageToolCallFunction,
        MessageRole,
        Model,
    )
except ImportError:
    print("ERROR: smolagents is required for this example.")
    print("Install it with one of:")
    print("  pip install smolagents agent-governance-toolkit[full]")
    print("  pip install -r examples/smolagents-governed/requirements.txt")
    print("")
    print("If you want the no-framework walkthrough instead, run:")
    print("  python examples/smolagents-governed/demo_simulated.py")
    raise SystemExit(1)

# When running from the repo checkout, import local sources directly.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_REPO_ROOT / "packages" / "agent-os" / "src"))

from agent_os.integrations.smolagents_adapter import SmolagentsKernel

TOOL_CALL_COUNTS = {"web_search": 0, "shell_exec": 0}


@dataclass(frozen=True)
class PlannedToolCall:
    """Single deterministic tool call emitted by the demo model."""

    name: str
    arguments: dict[str, Any]


class DeterministicToolModel(Model):
    """Tiny local model that drives the real smolagents runtime."""

    def __init__(self, planned_calls: list[PlannedToolCall], final_answer: str):
        super().__init__(model_id="deterministic-smolagents-demo")
        self._planned_calls = planned_calls
        self._final_answer = final_answer
        self._step_index = 0

    def generate(
        self,
        messages: list[ChatMessage],
        stop_sequences: list[str] | None = None,
        response_format: dict[str, str] | None = None,
        tools_to_call_from: list[Any] | None = None,
        **kwargs: Any,
    ) -> ChatMessage:
        del messages, stop_sequences, response_format, tools_to_call_from, kwargs

        if self._step_index < len(self._planned_calls):
            planned_call = self._planned_calls[self._step_index]
            self._step_index += 1
            return _tool_call_message(
                tool_name=planned_call.name,
                arguments=planned_call.arguments,
                call_id=f"call_{self._step_index}",
            )

        self._step_index += 1
        return _tool_call_message(
            tool_name="final_answer",
            arguments={"answer": self._final_answer},
            call_id=f"call_{self._step_index}",
        )


def _tool_call_message(tool_name: str, arguments: dict[str, Any], call_id: str) -> ChatMessage:
    return ChatMessage(
        role=MessageRole.ASSISTANT,
        content="",
        tool_calls=[
            ChatMessageToolCall(
                function=ChatMessageToolCallFunction(name=tool_name, arguments=arguments),
                id=call_id,
                type="function",
            )
        ],
    )


@tool
def web_search(query: str) -> str:
    """Return a canned public-web search result.

    Args:
        query: Query string to look up.
    """

    TOOL_CALL_COUNTS["web_search"] += 1
    return (
        f"Top public snippets for '{query}': "
        "agent governance, tool allowlists, audit logging."
    )


@tool
def shell_exec(command: str) -> str:
    """Pretend to run a shell command.

    Args:
        command: Command that would be executed.
    """

    TOOL_CALL_COUNTS["shell_exec"] += 1
    return f"shell executed: {command}"


def build_agent(model: Model) -> ToolCallingAgent:
    """Create a real smolagents ToolCallingAgent."""

    return ToolCallingAgent(
        tools=[web_search, shell_exec],
        model=model,
        max_steps=3,
    )


def run_allowed_tool_scenario() -> SmolagentsKernel:
    print("\n[1] Allowed tool call through a real ToolCallingAgent...")
    initial_calls = TOOL_CALL_COUNTS["web_search"]
    agent = build_agent(
        DeterministicToolModel(
            planned_calls=[
                PlannedToolCall(
                    "web_search",
                    {"query": "latest public agent governance patterns"},
                )
            ],
            final_answer="Governed search completed successfully.",
        )
    )
    kernel = SmolagentsKernel(
        allowed_tools=["web_search"],
        blocked_patterns=["credential dump", "DROP TABLE"],
    )
    kernel.wrap(agent)

    result = agent.run("Research public agent governance patterns.")
    print(f"    ✅ Final answer: {result}")
    print(f"    web_search executed: {TOOL_CALL_COUNTS['web_search'] - initial_calls} time(s)")
    print(f"    Audit events recorded: {len(kernel.get_audit_log())}")
    return kernel


def run_blocked_tool_scenario() -> SmolagentsKernel:
    print("\n[2] Blocked tool call through the same runtime...")
    initial_calls = TOOL_CALL_COUNTS["shell_exec"]
    agent = build_agent(
        DeterministicToolModel(
            planned_calls=[PlannedToolCall("shell_exec", {"command": "whoami"})],
            final_answer="Governance blocked shell_exec before execution.",
        )
    )
    kernel = SmolagentsKernel(allowed_tools=["web_search"], blocked_tools=["shell_exec"])
    kernel.wrap(agent)

    result = agent.run("Try to execute a shell command.")
    blocked = TOOL_CALL_COUNTS["shell_exec"] == initial_calls
    print(f"    ✅ Tool executed: {not blocked}")
    print(f"    Final answer after blocked call: {result}")
    print(f"    Violations recorded: {len(kernel.get_violations())}")
    return kernel


def run_blocked_content_scenario() -> SmolagentsKernel:
    print("\n[3] Blocked tool arguments by content policy...")
    initial_calls = TOOL_CALL_COUNTS["web_search"]
    agent = build_agent(
        DeterministicToolModel(
            planned_calls=[
                PlannedToolCall(
                    "web_search",
                    {"query": "credential dump from production wiki"},
                )
            ],
            final_answer="Governance blocked the sensitive search arguments.",
        )
    )
    kernel = SmolagentsKernel(
        allowed_tools=["web_search"],
        blocked_patterns=["credential dump"],
    )
    kernel.wrap(agent)

    result = agent.run("Search for sensitive internal material.")
    blocked = TOOL_CALL_COUNTS["web_search"] == initial_calls
    print(f"    ✅ Tool executed: {not blocked}")
    print(f"    Final answer after blocked call: {result}")
    print(f"    Violations recorded: {len(kernel.get_violations())}")
    return kernel


def main() -> None:
    print("=" * 68)
    print("  smolagents + Governance Toolkit — Real ToolCallingAgent Demo")
    print("=" * 68)
    print("  Uses real @tool objects, a real ToolCallingAgent, and SmolagentsKernel.")
    print("  No external LLM key is needed because the demo model is deterministic.")

    successful_kernel = run_allowed_tool_scenario()
    blocked_tool_kernel = run_blocked_tool_scenario()
    blocked_content_kernel = run_blocked_content_scenario()

    print("\n[4] Adapter state summary...")
    print(
        "    Allowed run events:",
        [event.event_type for event in successful_kernel.get_audit_log()],
    )
    print(
        "    Blocked-tool policy:",
        blocked_tool_kernel.get_violations()[0].policy_name,
    )
    print(
        "    Blocked-content policy:",
        blocked_content_kernel.get_violations()[0].policy_name,
    )

    print("\nDone! For the legacy no-framework walkthrough, run demo_simulated.py.")


if __name__ == "__main__":
    main()
