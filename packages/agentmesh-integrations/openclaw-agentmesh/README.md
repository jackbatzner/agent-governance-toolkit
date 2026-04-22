# @microsoft/agentmesh-openclaw

Governance adapter for OpenClaw built on [`@microsoft/agentmesh-sdk`](../../agent-mesh/sdks/typescript/).

This package is the **in-process** OpenClaw integration path:

- **OpenClaw** remains the runtime and tool-execution plane.
- **Agent Governance Toolkit (AGT)** evaluates policy before a tool runs, scans MCP tool definitions, and records audit events.
- **Your OpenClaw deployment** decides how to load policies, route human approvals, persist audits, and apply runtime isolation.

For broader deployment guidance, see:

- [OpenClaw adapter guide](../../../docs/integrations/openclaw-adapter.md)
- [OpenClaw end-to-end tutorial](../../../docs/tutorials/34-openclaw-end-to-end.md)
- [OpenClaw AKS protection guidance](../../../docs/deployment/openclaw-aks-protection.md)
- [OpenClaw sidecar pattern](../../../docs/deployment/openclaw-sidecar.md)

## Install

```bash
openclaw plugins install @microsoft/agentmesh-openclaw
```

If you are developing locally or installing without the OpenClaw plugin installer:

```bash
npm install @microsoft/agentmesh-openclaw @microsoft/agentmesh-sdk
```

## What this package gives you

- a **native OpenClaw plugin entry** that registers `before_tool_call` and `after_tool_call` hooks
- `createOpenClawGovernanceAdapter()` — reusable adapter instance for OpenClaw tool governance
- `createOpenClawGovernanceAdapterFromPluginConfig()` — adapter construction from native plugin config
- `registerOpenClawGovernanceHooks()` — manual hook registration for advanced/custom plugin setups
- `evaluateBeforeToolCall()` — policy evaluation before OpenClaw executes a tool
- `recordAfterToolCall()` — post-execution audit logging for success/error outcomes
- `scanMcpToolDefinition()` / `scanMcpToolDefinitions()` — MCP tool-definition scanning before tool registration or use

## What this package does not do for you

- It does **not** patch OpenClaw automatically.
- It does **not** provide a built-in approval UI or approval queue.
- It does **not** persist audits outside process memory unless you supply that behavior.
- It does **not** sandbox tool execution; OpenClaw, your container runtime, and AKS still own runtime isolation.

## Preferred setup path

For most developers, the easiest setup is:

1. install `@microsoft/agentmesh-openclaw` into the OpenClaw app
2. point the plugin at a policy bundle with `plugins.entries.agentmesh-openclaw.config.policyFile`
3. let the native plugin entry register `before_tool_call` and `after_tool_call`
4. route OpenClaw approvals and audit export the same way you already operate the host runtime

### Runtime flow

```text
OpenClaw tool request
    |
    v
before_tool_call hook
    |
    v
@microsoft/agentmesh-openclaw
    |
    +--> normalize tool-call context
    +--> call AGT policy engine
    +--> map result to allow | deny | review
    |
    v
OpenClaw enforces the result
    |
    +--> allow  -> execute tool
    +--> deny   -> block tool
    +--> review -> native approval flow
    |
    v
after_tool_call hook (when audit is enabled)
    |
    v
AGT audit logging
```

Truthful boundary:

- the native plugin **does** register `before_tool_call` and `after_tool_call`
- the native plugin **does not** auto-scan every tool catalog; use `scanMcpToolDefinition()` / `scanMcpToolDefinitions()` explicitly where you assemble tools
- OpenClaw still owns execution, approval UX, retries, and sandboxing

### Underlying hook references

If you maintain OpenClaw itself or need a source-level fallback, the known underlying interception points are:

- `src/agents/pi-tools.ts`
- `src/agents/pi-tools.before-tool-call.ts`
- `wrapToolWithBeforeToolCallHook(...)`

The adapter is designed to fit that same interception model even when registration happens through an SDK surface instead of direct source edits.

---

## Setup checklist

1. Define a governance policy bundle for the tools you expose.
2. Install and enable the native OpenClaw plugin entry.
3. Configure `policyFile` and optional audit settings in `plugins.entries.agentmesh-openclaw.config`.
4. Treat the source-level hook path as a maintainer fallback, not the normal app-developer path.
5. Route `review` decisions into your approval workflow.
6. Scan MCP tool definitions before registration.
7. Export post-call audits to a durable sink.

---

## 1. Define a policy bundle

The adapter accepts `Policy[]` objects directly. A simple customer-facing pattern is to keep the policies in a JSON file that ships with your OpenClaw deployment.

**`config/openclaw-governance.policies.json`**

```json
[
  {
    "name": "openclaw-tool-policy",
    "agents": ["*"],
    "default_action": "deny",
    "rules": [
      {
        "name": "allow-read-only-tools",
        "condition": "tool.name in ['read_file', 'search_web']",
        "ruleAction": "allow",
        "description": "Read-only tools are allowed by default."
      },
      {
        "name": "review-shell",
        "condition": "tool.name == 'shell'",
        "ruleAction": "require_approval",
        "approvers": ["ops@contoso.com"],
        "description": "Shell access requires human review."
      },
      {
        "name": "deny-secrets-write",
        "condition": "tool.name == 'write_file' and params.path.startswith('/secrets/')",
        "ruleAction": "deny",
        "description": "Never let the agent write into mounted secret paths."
      }
    ]
  }
]
```

### Loading policies at startup

```ts
import { readFileSync } from "node:fs";
import type { Policy } from "@microsoft/agentmesh-sdk/types";

export function loadPolicies(): Policy[] {
  const raw = readFileSync(
    new URL("./config/openclaw-governance.policies.json", import.meta.url),
    "utf8",
  );

  return JSON.parse(raw) as Policy[];
}
```

If your team stores policy in YAML or a database, load and parse it before adapter creation, then pass the resulting `Policy[]` into `createOpenClawGovernanceAdapter()`. The adapter itself does not ship a YAML loader.

---

## 2. Enable the native OpenClaw plugin

The package now ships a real OpenClaw plugin entry and manifest, so the default path no longer needs a custom bootstrap module.

Add plugin config in your OpenClaw configuration:

```json
{
  "plugins": {
    "entries": {
      "agentmesh-openclaw": {
        "config": {
          "policyFile": "./config/openclaw-governance.policies.json",
          "agentId": "openclaw-main-agent",
          "agentDid": "did:agentmesh:openclaw-main-agent",
          "audit": {
            "enabled": true,
            "stdout": true,
            "maxEntries": 5000
          }
        }
      }
    }
  }
}
```

What the native plugin entry does:

- loads the configured JSON policy bundle
- registers `before_tool_call` and `after_tool_call` hooks
- maps AGT policy actions into OpenClaw `allow | deny | review` behavior
- emits audit records to stdout when `audit.stdout` is enabled

---

## 3. Advanced: register hooks manually

If you are building a custom OpenClaw plugin package and want direct control over hook registration, use the exported helper instead of reimplementing the mapping yourself:

```ts
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { registerOpenClawGovernanceHooks } from "@microsoft/agentmesh-openclaw";

export default definePluginEntry({
  id: "custom-governance-wrapper",
  name: "Custom Governance Wrapper",
  description: "Registers AGT governance hooks through a custom plugin entry.",
  register(api) {
    registerOpenClawGovernanceHooks(api, {
      policyFile: "./config/openclaw-governance.policies.json",
      audit: {
        enabled: true,
        stdout: true,
      },
    });
  },
});
```

### Source-level fallback

If your OpenClaw deployment does **not** expose a native SDK/plugin registration surface yet, wire the same callback into the underlying hook path in:

- `src/agents/pi-tools.before-tool-call.ts`
- `src/agents/pi-tools.ts`

### Decision mapping

This package intentionally normalizes AGT policy actions into the smaller decision surface OpenClaw already knows how to act on:

| AGT policy action | OpenClaw adapter decision |
|---|---|
| `allow` | `allow` |
| `deny` | `deny` |
| `require_approval` | `review` |
| `warn` | `review` |
| `log` | `allow` |

---

## 5. Wire review and approval handling

When the adapter returns `review`, AGT is telling OpenClaw that the call should stop until a human or approval service responds.

Recommended flow:

1. `beforeToolCallHook()` returns `requiresApproval: true`.
2. OpenClaw stores the pending request and shows its native approval surface.
3. Your approval system notifies the listed approvers.
4. Only after approval do you re-run or resume the tool call.

What AGT provides:

- the policy decision
- the matched rule and policy name
- the list of approvers

What OpenClaw or your platform must provide:

- approval queue or ticketing
- reviewer identity checks
- resume/retry behavior after approval
- denial messaging back to the operator or user

---

## 6. Enable MCP tool-definition scanning before registration

OpenClaw assembles tools centrally in `src/agents/pi-tools.ts`, which is also the right place to scan tool definitions before they are wrapped and exposed:

```ts
import { governance } from "./governance";

export function validateAndWrapTools(
  tools: Array<{ name: string; description: string }>,
) {
  for (const tool of tools) {
    const scan = governance.scanMcpToolDefinition({
      name: tool.name,
      description: tool.description,
    });

    if (scan.recommendedDecision === "deny") {
      throw new Error(
        `Refusing to register tool "${tool.name}" because MCP scanning found high-risk content.`,
      );
    }

    if (scan.recommendedDecision === "review") {
      console.warn(
        `Tool "${tool.name}" should be reviewed before enablement.`,
        scan.findings,
      );
    }
  }

  return tools.map((tool) =>
    wrapToolWithBeforeToolCallHook(tool, beforeToolCallHook),
  );
}
```

Use `scanMcpToolDefinitions()` instead if you want to evaluate the full catalog in one pass during process startup.

---

## 7. Record post-call audit events

The native plugin entry registers `after_tool_call` automatically when audit logging is enabled.

If you need to override that behavior in a custom entry, call `recordAfterToolCall()` yourself from your own `after_tool_call` hook implementation.

### Production note on audit persistence

The default SDK `AuditLogger` keeps a hash-chained log in process memory. For production OpenClaw deployments, forward those audit entries somewhere durable:

- emit structured JSON to stdout and collect it with your AKS log pipeline
- wrap the SDK logger and forward each entry to Event Hub, Kafka, or your SIEM
- replace the logger entirely with an implementation of `OpenClawAuditLogger`

---

## Deployment choices

| Choice | Use when | Notes |
|---|---|---|
| **In-process adapter only** | You want the shortest path from OpenClaw's hook to policy evaluation | Lowest latency. OpenClaw still owns approval UX, audit export, and runtime isolation. |
| **Adapter + sidecar** | You want in-process policy gating and a nearby governance HTTP service for other checks or separation of duties | Not automatic. Your deployment must wire both pieces intentionally. |
| **Adapter + shared governance service** | You want centrally managed policy, audit, or approval backends across many OpenClaw instances | Operational pattern, not a one-command package feature. Typically implemented through custom `policyEngine` and `audit.logger` integrations. |

See the repo docs for the full operational guidance:

- [OpenClaw adapter guide](../../../docs/integrations/openclaw-adapter.md)
- [OpenClaw AKS protection guidance](../../../docs/deployment/openclaw-aks-protection.md)
- [OpenClaw sidecar pattern](../../../docs/deployment/openclaw-sidecar.md)

## Error behavior

- Missing adapter configuration (for example, no policies and no `policyEngine`) throws an `OpenClawGovernanceConfigError`.
- Before-tool-call policy or audit failures **fail closed by default** and return a `deny` result with a reason.
- If you explicitly set `failClosed: false`, runtime governance failures are thrown as `OpenClawGovernanceError`.
- `recordAfterToolCall()` throws `OpenClawGovernanceAuditError` if post-execution audit logging cannot be recorded.

## API

### `createOpenClawGovernanceAdapter(config)`

Creates a reusable adapter instance with:

- `evaluateBeforeToolCall(input)`
- `recordAfterToolCall(input)`
- `scanMcpToolDefinition(tool)`
- `scanMcpToolDefinitions(tools)`

### `evaluateBeforeToolCall(input, adapterOrConfig)`

Standalone helper if you prefer not to hold the adapter instance yourself.

### `recordAfterToolCall(input, adapterOrConfig)`

Records the post-call outcome with the configured audit logger.

## Notes

- Use this package when you want **native in-process enforcement** inside OpenClaw's existing tool hook.
- Use the sidecar docs when you want **HTTP-accessible governance infrastructure** next to or near OpenClaw.
- Use the AKS protection guide when you need to decide how to mount policies, export audits, and set network and identity boundaries in production.
