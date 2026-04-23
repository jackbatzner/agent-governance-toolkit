# @microsoft/agentmesh-openclaw

Governance adapter for OpenClaw built on [`@microsoft/agentmesh-sdk`](../../agent-mesh/sdks/typescript/).

This package is the **in-process** OpenClaw integration path:

- **OpenClaw** remains the runtime and tool-execution plane.
- **Agent Governance Toolkit (AGT)** evaluates policy before a tool runs, scans MCP tool definitions, and records audit events.
- **Your OpenClaw deployment** owns approval UX, audit export, and runtime isolation. This package now ships both a native OpenClaw plugin entry and lower-level hook helpers.

For broader deployment guidance, see:

- [OpenClaw adapter guide](../../../docs/integrations/openclaw-adapter.md)
- [OpenClaw end-to-end tutorial](../../../docs/tutorials/34-openclaw-end-to-end.md)
- [OpenClaw AKS protection guidance](../../../docs/deployment/openclaw-aks-protection.md)
- [OpenClaw sidecar pattern](../../../docs/deployment/openclaw-sidecar.md)

## Install

```bash
npm install @microsoft/agentmesh-openclaw @microsoft/agentmesh-sdk
```

If you want OpenClaw to install it through the plugin system:

```bash
openclaw plugins install @microsoft/agentmesh-openclaw
```

Or install it directly with npm:

```bash
npm install @microsoft/agentmesh-openclaw @microsoft/agentmesh-sdk
```

## What this package gives you

- `createOpenClawGovernanceAdapter()` — reusable adapter instance for OpenClaw tool governance
- `createOpenClawGovernanceAdapterFromConfig()` — adapter construction from a file-backed or inline hook config
- a **native OpenClaw plugin entry** at `@microsoft/agentmesh-openclaw/plugin`
- `registerOpenClawPluginHooks()` — hook registration through the real OpenClaw plugin API
- `createOpenClawBeforeToolCallInputFromHookEvent()` — best-effort mapping from OpenClaw `InternalHookEvent` into AGT before-call input
- `createOpenClawAfterToolCallInputFromHookEvent()` — best-effort mapping from OpenClaw `InternalHookEvent` into AGT after-call input
- `applyBeforeToolCallResultToHookEvent()` — writes allow/deny/review outcomes back onto the mutable hook event
- `processOpenClawHookEvent()` / `createOpenClawHookEventHandler()` — one-call helpers for common hook handlers
- `evaluateBeforeToolCall()` — policy evaluation before OpenClaw executes a tool
- `recordAfterToolCall()` — post-execution audit logging for success/error outcomes
- `scanMcpToolDefinition()` / `scanMcpToolDefinitions()` — MCP tool-definition scanning before tool registration or use

## What this package does not do for you

- It does **not** patch OpenClaw automatically.
- It does **not** provide a built-in approval UI or approval queue.
- It does **not** persist audits outside process memory unless you supply that behavior.
- It does **not** sandbox tool execution; OpenClaw, your container runtime, and AKS still own runtime isolation.

## Preferred setup path

For most developers, the best setup is:

1. install `@microsoft/agentmesh-openclaw` into the OpenClaw app
2. keep a JSON policy bundle in the OpenClaw repo
3. let the native plugin entry register the `before_tool_call` and `after_tool_call` hooks
4. route `allow | deny | review` into the same OpenClaw runtime flow you already operate

### Runtime flow

```text
OpenClaw plugin runtime
    |
    +--> @microsoft/agentmesh-openclaw/plugin
            |
            +--> api.registerHook("before_tool_call", ...)
            +--> api.registerHook("after_tool_call", ...)
            |
            v
        AGT adapter core
            |
            +--> normalize hook payload
            +--> call AGT policy engine
            +--> map result to allow | deny | review
            |
            v
        OpenClaw enforces the result
```

Truthful boundary:

- the package **does** ship a real OpenClaw plugin entry and manifest
- the package **does** also expose lower-level helpers for direct hook processing when you need them
- the package **does not** auto-discover every tool catalog
- OpenClaw still owns execution, approval UX, retries, and sandboxing

### Underlying hook references

If you maintain OpenClaw itself, the known underlying interception points are:

- `src/agents/pi-tools.ts`
- `src/agents/pi-tools.before-tool-call.ts`
- `wrapToolWithBeforeToolCallHook(...)`

This package is designed to fit that interception model directly.

---

## Setup checklist

1. Define a governance policy bundle for the tools you expose.
2. Install `@microsoft/agentmesh-openclaw` and `@microsoft/agentmesh-sdk`.
3. Wire your OpenClaw hook code to call the adapter helpers.
4. Route `review` decisions into your approval workflow.
5. Scan MCP tool definitions before registration.
6. Export post-call audits to a durable sink.

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

## 2. Wire the OpenClaw hook

The tested OpenClaw surface is the generic hook event shape:

```ts
export interface InternalHookEvent {
  type: string;
  action: string;
  sessionKey: string;
  context: Record<string, unknown>;
  timestamp: Date;
  messages: string[];
}
```

That means the normal integration path is **explicit hook wiring**, not native plugin auto-registration.

### Minimal hook wiring

```ts
import {
  createOpenClawGovernanceAdapterFromConfig,
  createOpenClawHookEventHandler,
} from "@microsoft/agentmesh-openclaw";

const governance = createOpenClawGovernanceAdapterFromConfig({
  policyFile: "./config/openclaw-governance.policies.json",
  agentId: "openclaw-main-agent",
  agentDid: "did:agentmesh:openclaw-main-agent",
  audit: {
    enabled: true,
    stdout: true,
    maxEntries: 5000,
  },
});

export const onInternalHookEvent = createOpenClawHookEventHandler(governance);
```

### Explicit before/after wiring

Use this shape when you want full control over mapping and enforcement:

```ts
import {
  applyBeforeToolCallResultToHookEvent,
  createOpenClawAfterToolCallInputFromHookEvent,
  createOpenClawBeforeToolCallInputFromHookEvent,
  createOpenClawGovernanceAdapterFromConfig,
} from "@microsoft/agentmesh-openclaw";
import type { InternalHookEvent } from "./hooks";

const governance = createOpenClawGovernanceAdapterFromConfig({
  policyFile: "./config/openclaw-governance.policies.json",
  audit: {
    enabled: true,
    stdout: true,
  },
});

export async function onInternalHookEvent(event: InternalHookEvent) {
  const beforeInput = createOpenClawBeforeToolCallInputFromHookEvent(event);
  if (beforeInput) {
    const result = await governance.evaluateBeforeToolCall(beforeInput);
    applyBeforeToolCallResultToHookEvent(event, result);
    return;
  }

  const afterInput = createOpenClawAfterToolCallInputFromHookEvent(event);
  if (afterInput && governance.auditLogger) {
    await governance.recordAfterToolCall(afterInput);
  }
}
```

### What the helper expects in `event.context`

The default hook mappers look for common fields in `event.context`:

- `toolName` (or `tool.name` / `name`)
- `params` (or `arguments`, `args`, `input`)
- optional `agentId`, `agentDid`, `toolCallId`, `requestId`, `runId`
- optional `result`, `error`, `durationMs` on after-tool events

If your OpenClaw deployment uses different context field names, build `OpenClawBeforeToolCallInput` and `OpenClawAfterToolCallInput` yourself and call `evaluateBeforeToolCall()` / `recordAfterToolCall()` directly.

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

## 3. Wire review and approval handling

When the adapter returns `review`, AGT is telling OpenClaw that the call should stop until a human or approval service responds.

Recommended flow:

1. your hook writes approval metadata onto the mutable event context
2. OpenClaw stores the pending request and shows its native approval surface
3. your approval system notifies the listed approvers
4. only after approval do you re-run or resume the tool call

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

## 4. Enable MCP tool-definition scanning before registration

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

  return tools;
}
```

Use `scanMcpToolDefinitions()` instead if you want to evaluate the full catalog in one pass during process startup.

---

## 5. Record post-call audit events

If audit logging is enabled, call `recordAfterToolCall()` from your `after_tool_call` hook path or use `createOpenClawHookEventHandler()`.

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

### `createOpenClawGovernanceAdapterFromConfig(config)`

Creates the adapter from a hook-oriented config object that can include `policyFile`, inline `policies`, `agentId`, `agentDid`, and audit settings.

### `processOpenClawHookEvent(event, adapterOrConfig)`

Processes an OpenClaw `InternalHookEvent` directly. It recognizes `before_tool_call` and `after_tool_call`, applies before-call decisions back onto the mutable event, and records after-call audits when enabled.

### `createOpenClawHookEventHandler(adapterOrConfig)`

Returns an async `(event) => ...` handler you can drop into your own OpenClaw hook pipeline.

## Notes

- Use this package when you want **in-process enforcement** inside OpenClaw's existing tool hook.
- Use the sidecar docs when you want **HTTP-accessible governance infrastructure** next to or near OpenClaw.
- Use the AKS protection guide when you need to decide how to mount policies, export audits, and set network and identity boundaries in production.
