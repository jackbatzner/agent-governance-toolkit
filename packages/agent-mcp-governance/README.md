<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# agent-mcp-governance

`agent-mcp-governance` is a standalone **Public Preview** package that exposes
the MCP governance primitives used in this repository:

- `MCPGateway` for policy enforcement and audit logging
- `MCPSlidingRateLimiter` for per-agent call budgets
- `MCPSessionAuthenticator` for short-lived MCP sessions
- `MCPMessageSigner`, `MCPSecurityScanner`, and `MCPResponseScanner` for
  message integrity and security scanning

This package is intentionally thin. It exists as a focused MCP governance
surface for enterprise packaging and reuse scenarios without pulling in the
full Agent Governance Toolkit as an install-time dependency.

## Installation

```bash
pip install agent-mcp-governance
```

## Quick usage

```python
from agent_mcp_governance import (
    CredentialRedactor,
    MCPGateway,
    MCPMessageSigner,
    MCPSessionAuthenticator,
    MCPSlidingRateLimiter,
)


class DemoPolicy:
    name = "demo"
    allowed_tools = ["read_file", "web_search"]
    max_tool_calls = 10
    log_all_calls = True
    require_human_approval = False

    def matches_pattern(self, _text: str) -> list[str]:
        return []


policy = DemoPolicy()
gateway = MCPGateway(policy)
rate_limiter = MCPSlidingRateLimiter(max_calls_per_window=5, window_size=60.0)
session_auth = MCPSessionAuthenticator()
signer = MCPMessageSigner(MCPMessageSigner.generate_key())

token = session_auth.create_session("agent-123", user_id="alice@example.com")
session = session_auth.validate_session("agent-123", token)
if session is None:
    raise PermissionError("Invalid or expired MCP session token")

envelope = signer.sign_message('{"tool":"read_file"}', sender_id=session.agent_id)
verification = signer.verify_message(envelope)
if not verification.is_valid:
    raise PermissionError(verification.failure_reason or "Invalid MCP envelope")

if not rate_limiter.try_acquire(session.rate_limit_key):
    raise RuntimeError("MCP rate limit exceeded")

allowed, reason = gateway.intercept_tool_call(
    session.agent_id,
    "read_file",
    {"path": "docs/architecture.md"},
)
safe_output = CredentialRedactor.redact("API key: sk-example-secret")
print(allowed, reason, safe_output)
```

The package is intentionally thin and depends on
[`agent-os-kernel`](https://pypi.org/project/agent-os-kernel/) for the
underlying implementations.

## Security guidance

Use the standalone package with the same transport assumptions as the full Agent OS integration:

1. Treat `MCPSessionAuthenticator` tokens and `MCPMessageSigner` keys as secrets. Do not write raw values to logs, prompts, traces, or persisted audit records.
2. Keep MCP checks fail-closed. If session validation, signature verification, or response scanning fails, deny the request and force the caller to re-establish trust.
3. Redact tool output before returning it to an LLM or storing it. `CredentialRedactor` is included for secret scrubbing, while `MCPResponseScanner` handles instruction-tag removal and hostile-output detection.

For deployment guidance and hardening recommendations, see the
[OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html).

## License

[MIT](../../LICENSE) — Copyright (c) Microsoft Corporation.
