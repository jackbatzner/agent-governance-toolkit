# OpenClaw Adapter Integration Guide

Use [`@microsoft/agentmesh-openclaw`](../../packages/agentmesh-integrations/openclaw-agentmesh/README.md) when you want AGT to run **inside** OpenClaw's existing tool interception path.

This is the TypeScript adapter path for OpenClaw operators and platform teams. It is different from the [OpenClaw sidecar pattern](../deployment/openclaw-sidecar.md), which exposes governance over HTTP.

## What ships vs. what you own

| Area | Shipped in repo | You still own in your OpenClaw deployment |
|---|---|---|
| Before-tool governance | `evaluateBeforeToolCall()` | Calling it from OpenClaw's hook and acting on the result |
| Post-tool audit | `recordAfterToolCall()` | Persisting or exporting audit data outside process memory |
| MCP scan | `scanMcpToolDefinition()` / `scanMcpToolDefinitions()` | Deciding whether review findings block registration |
| Approval signal | `review` decision + `approvers` list | Approval UX, queueing, reviewer identity, and resume behavior |
| Runtime isolation | Not part of the adapter | OpenClaw sandboxing, container policy, network policy, secrets handling |

## Known OpenClaw integration points

The adapter is meant to plug into the OpenClaw hook points already used for tool interception:

- `src/agents/pi-tools.ts`
- `src/agents/pi-tools.before-tool-call.ts`
- `wrapToolWithBeforeToolCallHook(...)`

See the package README for the concrete code snippets:

- [Install and load policy bundles](../../packages/agentmesh-integrations/openclaw-agentmesh/README.md#1-define-a-policy-bundle)
- [Create the shared adapter instance](../../packages/agentmesh-integrations/openclaw-agentmesh/README.md#2-create-one-shared-adapter-instance)
- [Wire `before_tool_call`](../../packages/agentmesh-integrations/openclaw-agentmesh/README.md#3-wire-before_tool_call-into-srcagentspi-toolsbefore-tool-callts)
- [Enable MCP scanning](../../packages/agentmesh-integrations/openclaw-agentmesh/README.md#6-enable-mcp-tool-definition-scanning-before-registration)
- [Record post-call audits](../../packages/agentmesh-integrations/openclaw-agentmesh/README.md#7-record-post-call-audit-events)

If you want one follow-along guide that starts with installation and ends with AKS validation, use the [OpenClaw end-to-end tutorial](../tutorials/34-openclaw-end-to-end.md).

## Deployment choices

Choose the topology that matches how much separation you need between OpenClaw and AGT.

| Choice | What AGT protects | What OpenClaw still owns | Best fit |
|---|---|---|---|
| **In-process adapter only** | Tool-call policy evaluation in the `before_tool_call` path, MCP tool-definition review, post-call audit hooks | Tool execution, runtime/container isolation, approval workflow, audit export | Lowest-latency deployment where OpenClaw can embed governance directly |
| **Adapter + sidecar** | Same in-process decision point plus optional nearby governance HTTP APIs for adjacent checks or operational separation | Orchestration between adapter and sidecar, runtime isolation, ingress design | Teams that want OpenClaw-native hooks and a local governance service in the same pod or namespace |
| **Adapter + shared governance service** | Same in-process decision point with centrally managed policy/audit backends via custom integrations | Network path to the shared service, service auth, approval UX, runtime isolation | Multi-tenant or multi-cluster fleets that want centralized governance operations |

### Important boundary

The adapter is an **integration library**, not a full OpenClaw control plane. It does not automatically discover your sidecar, talk to a shared governance API, or create approval workflows for you. Those are deployment decisions you wire around the adapter.

## Practical integration model

### 1. Load policies at startup

The adapter accepts `Policy[]` or a custom `policyEngine`. A common operator pattern is:

1. Store the policy bundle alongside the OpenClaw deployment image or mounted config.
2. Load it during OpenClaw startup.
3. Recreate or refresh the adapter only when policy changes.

If you already have a central policy service, implement `policyEngine.evaluatePolicy(...)` with that backend instead of passing inline `policies`.

### 2. Fail closed before a tool runs

`evaluateBeforeToolCall()` should be the last gate before OpenClaw calls the tool implementation.

- `allow` means OpenClaw can continue.
- `deny` means OpenClaw should block the call and return the reason.
- `review` means OpenClaw should stop and route the request to a human or approval service.

That makes AGT a **protective control before tool execution**, not just a logging layer after the fact.

### 3. Keep approvals explicit

When AGT returns `review`, the adapter includes:

- the matched rule
- the policy name
- the list of `approvers`

OpenClaw should treat that as a pending request. AGT does not currently ship an approval inbox, resume token service, or OpenClaw-specific reviewer UI.

### 4. Scan tools before they reach operators

Run MCP scanning before registering or exposing tool definitions. That catches risky descriptions or capability declarations before the tool is available to the agent.

This is especially useful when:

- tool definitions come from MCP servers or plugins
- multiple teams publish tools into the same OpenClaw deployment
- you want a review gate for new tools before they are enabled

### 5. Export audits somewhere durable

The default SDK audit logger keeps a hash-chained audit log in memory. For customer-facing deployments, emit those records to a durable sink:

- stdout/stderr collected by the platform
- a SIEM or message bus
- a custom audit service

The package README shows one pattern: wrap the SDK `AuditLogger` and also write structured JSON to stdout.

## How the adapter relates to the sidecar

The [sidecar pattern](../deployment/openclaw-sidecar.md) is useful when you want a network-accessible governance surface next to OpenClaw. The adapter is useful when you want policy enforcement directly in the OpenClaw process.

You can use both, but they solve different problems:

- **adapter**: native hook integration before a tool executes
- **sidecar**: local HTTP governance service and separation of duties

Using both is an architecture choice, not an automatic behavior in the adapter package.

## AKS operators

For production guidance on ConfigMaps vs. Secrets, mounted policy bundles, network boundaries, workload identity, audit export, and runtime hardening, use the [OpenClaw AKS protection guide](../deployment/openclaw-aks-protection.md).

## Related

- [Package README](../../packages/agentmesh-integrations/openclaw-agentmesh/README.md)
- [OpenClaw AKS protection guidance](../deployment/openclaw-aks-protection.md)
- [OpenClaw sidecar pattern](../deployment/openclaw-sidecar.md)
