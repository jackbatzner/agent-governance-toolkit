# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Live smolagents integration tests for the governance adapter."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

pytest.importorskip("smolagents")

from smolagents import ToolCallingAgent, tool
from smolagents.models import (
    ChatMessage,
    ChatMessageToolCall,
    ChatMessageToolCallFunction,
    MessageRole,
    Model,
)

from agent_os.integrations.smolagents_adapter import SmolagentsKernel

TOOL_CALL_COUNTS = {"web_search": 0, "shell_exec": 0}


@dataclass(frozen=True)
class PlannedToolCall:
    name: str
    arguments: dict[str, Any]


class DeterministicToolModel(Model):
    """Minimal local model that drives real smolagents agents in tests."""

    def __init__(self, planned_calls: list[PlannedToolCall], final_answer: str = "done"):
        super().__init__(model_id="deterministic-test-model")
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
            call = self._planned_calls[self._step_index]
            self._step_index += 1
            return build_tool_call_message(call.name, call.arguments, f"call_{self._step_index}")

        self._step_index += 1
        return build_tool_call_message(
            "final_answer",
            {"answer": self._final_answer},
            f"call_{self._step_index}",
        )


def build_tool_call_message(tool_name: str, arguments: dict[str, Any], call_id: str) -> ChatMessage:
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
    """Search public sources.

    Args:
        query: Search query text.
    """

    TOOL_CALL_COUNTS["web_search"] += 1
    return f"search results for {query}"


@tool
def shell_exec(command: str) -> str:
    """Pretend to execute a command.

    Args:
        command: Command string.
    """

    TOOL_CALL_COUNTS["shell_exec"] += 1
    return f"executed {command}"


def build_agent(model: Model) -> ToolCallingAgent:
    return ToolCallingAgent(
        tools=[web_search, shell_exec],
        model=model,
        max_steps=3,
    )


def test_wrap_real_toolcalling_agent_allows_tool_call():
    initial_calls = TOOL_CALL_COUNTS["web_search"]
    kernel = SmolagentsKernel(allowed_tools=["web_search"])
    agent = build_agent(
        DeterministicToolModel(
            [PlannedToolCall("web_search", {"query": "agent governance"})],
            final_answer="success",
        )
    )

    kernel.wrap(agent)
    result = agent.run("Research agent governance.")

    assert result == "success"
    assert TOOL_CALL_COUNTS["web_search"] - initial_calls == 1
    assert kernel.get_stats()["tool_calls"] == 1
    assert kernel.get_violations() == []
    assert [event.event_type for event in kernel.get_audit_log()] == [
        "agent_wrapped",
        "before_tool",
        "after_tool",
    ]


def test_wrap_real_toolcalling_agent_blocks_disallowed_tool():
    initial_calls = TOOL_CALL_COUNTS["shell_exec"]
    kernel = SmolagentsKernel(allowed_tools=["web_search"], blocked_tools=["shell_exec"])
    agent = build_agent(
        DeterministicToolModel(
            [PlannedToolCall("shell_exec", {"command": "whoami"})],
            final_answer="blocked",
        )
    )

    kernel.wrap(agent)
    result = agent.run("Run a command.")

    assert result == "blocked"
    assert TOOL_CALL_COUNTS["shell_exec"] == initial_calls
    assert len(kernel.get_violations()) == 1
    assert kernel.get_violations()[0].policy_name == "tool_filter"


def test_wrap_real_toolcalling_agent_blocks_content_pattern():
    initial_calls = TOOL_CALL_COUNTS["web_search"]
    kernel = SmolagentsKernel(
        allowed_tools=["web_search"],
        blocked_patterns=["credential dump"],
    )
    agent = build_agent(
        DeterministicToolModel(
            [PlannedToolCall("web_search", {"query": "credential dump from wiki"})],
            final_answer="blocked-content",
        )
    )

    kernel.wrap(agent)
    result = agent.run("Search for internal secrets.")

    assert result == "blocked-content"
    assert TOOL_CALL_COUNTS["web_search"] == initial_calls
    assert len(kernel.get_violations()) == 1
    assert kernel.get_violations()[0].policy_name == "content_filter"
