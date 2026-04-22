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
npm install @microsoft/agentmesh-openclaw @microsoft/agentmesh-sdk
```

## What this package gives you

- `createOpenClawGovernanceAdapter()` — reusable adapter instance for OpenClaw tool governance
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

1. install `@microsoft/agentmesh-openclaw` and `@microsoft/agentmesh-sdk`
2. create one shared governance adapter instance
3. register it with the OpenClaw SDK or plugin surface that exposes `before_tool_call`
4. route `allow | deny | review` back into normal OpenClaw execution or approval behavior

### Underlying hook references

If you maintain OpenClaw itself or need a source-level fallback, the known underlying interception points are:

- `src/agents/pi-tools.ts`
- `src/agents/pi-tools.before-tool-call.ts`
- `wrapToolWithBeforeToolCallHook(...)`

The adapter is designed to fit that same interception model even when registration happens through an SDK surface instead of direct source edits.

---

## Setup checklist

1. Define a governance policy bundle for the tools you expose.
2. Load the policy bundle during OpenClaw startup.
3. Create one shared adapter instance.
4. Register `evaluateBeforeToolCall()` with the OpenClaw SDK `before_tool_call` surface.
5. Treat the source-level hook path as a maintainer fallback, not the normal app-developer path.
6. Route `review` decisions into your approval workflow.
7. Scan MCP tool definitions before registration.
8. Call `recordAfterToolCall()` after execution so audits contain the final outcome.

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

## 2. Create one shared adapter instance

Create the adapter near your OpenClaw startup or tool assembly code:

```ts
import { createOpenClawGovernanceAdapter } from "@microsoft/agentmesh-openclaw";
import { AuditLogger } from "@microsoft/agentmesh-sdk/audit";
import { loadPolicies } from "./load-policies";

const auditLogger = new AuditLogger({ maxEntries: 5_000 });

export const governance = createOpenClawGovernanceAdapter({
  agentId: "openclaw-main-agent",
  agentDid: "did:agentmesh:openclaw-main-agent",
  policies: loadPolicies(),
  audit: {
    enabled: true,
    logger: {
      log(entry) {
        const auditEntry = auditLogger.log(entry);
        process.stdout.write(
          `${JSON.stringify({ event: "agt.openclaw.audit", ...auditEntry })}\n`,
        );
        return auditEntry;
      },
    },
  },
});
```

### Why share one adapter instance?

- The policy engine is loaded once at startup.
- Audit hashes remain in sequence for that process.
- MCP scan decisions stay consistent for the same tool catalog.

---

## 3. Register the adapter with the OpenClaw SDK hook

Use the adapter anywhere the OpenClaw SDK exposes a `before_tool_call` registration surface:

```ts
import { governance } from "./governance";

export function registerGovernanceWithOpenClaw(openclawSdk: {
  registerBeforeToolCallHook: (
    hook: (input: {
      tool: { name: string; description?: string };
      args: Record<string, unknown>;
      requestId?: string;
      sessionId?: string;
      userId?: string;
    }) => Promise<unknown>,
  ) => void;
}) {
  openclawSdk.registerBeforeToolCallHook(async ({ tool, args, requestId, sessionId, userId }) => {
    const result = await governance.evaluateBeforeToolCall({
      toolName: tool.name,
      toolDescription: tool.description,
      params: args,
      requestId,
      sessionId,
      userId,
    });

    if (result.decision === "deny") {
      return {
        block: true,
        reason: result.reason ?? "Blocked by governance policy.",
      };
    }

    if (result.decision === "review") {
      return {
        block: true,
        requiresApproval: true,
        reason: result.reason ?? "Approval required by governance policy.",
        metadata: {
          approvers: result.approvers,
          matchedRule: result.matchedRule,
          policyName: result.policyName,
        },
      };
    }

    return {
      args: result.rewrittenParams ?? args,
    };
  });
}
```

> **Note:** `registerBeforeToolCallHook(...)` is illustrative. Use the actual registration API exposed by your OpenClaw SDK version. The important part is the adapter callback shape and the returned `allow | deny | review` handling.

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
2. OpenClaw stores the pending request, tool name, arguments, and `approvers`.
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

Record the final outcome around the wrapped tool execution path:

```ts
import { governance } from "./governance";

export async function executeGovernedTool(
  tool: {
    name: string;
    execute: (args: Record<string, unknown>) => Promise<unknown>;
  },
  args: Record<string, unknown>,
  requestId?: string,
  sessionId?: string,
) {
  const startedAt = Date.now();

  try {
    const output = await tool.execute(args);

    await governance.recordAfterToolCall({
      toolName: tool.name,
      params: args,
      result: output,
      requestId,
      sessionId,
      durationMs: Date.now() - startedAt,
    });

    return output;
  } catch (error) {
    await governance.recordAfterToolCall({
      toolName: tool.name,
      params: args,
      error,
      requestId,
      sessionId,
      durationMs: Date.now() - startedAt,
    });

    throw error;
  }
}
```

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
