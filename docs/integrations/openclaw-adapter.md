# OpenClaw Advanced Integration and Operations Guide

> **Use this guide after Tutorial 34** when you want to understand the hook model, extend the baseline integration, or add sidecar-backed patterns.

Use [`@microsoft/agentmesh-openclaw`](../../packages/agentmesh-integrations/openclaw-agentmesh/README.md) when you want AGT to run **inside** OpenClaw's existing tool interception path.

This is the TypeScript adapter path for OpenClaw operators and platform teams. It is different from the [OpenClaw sidecar pattern](../deployment/openclaw-sidecar.md), which exposes governance over HTTP.

## Prerequisites

Before using this guide, you should have:

- completed or at least skimmed [Tutorial 34](../tutorials/34-openclaw-end-to-end.md)
- a working OpenClaw deployment or checkout
- a decision on which existing OpenClaw hook path you are wiring into
- a policy bundle strategy for local files, mounted config, or a custom policy backend

## What you'll learn

| Section | What you'll learn |
|---|---|
| [What ships vs. what you own](#what-ships-vs-what-you-own) | Which parts the package gives you and which parts still belong to your OpenClaw deployment |
| [Preferred integration model](#preferred-integration-model-hook-integration-first) | Why explicit hook integration is the default path |
| [Deployment choices](#deployment-choices) | When to choose in-process only, sidecar, or shared service |
| [Practical integration model](#practical-integration-model) | How to load policy, fail closed, keep approvals explicit, scan MCP tools, and export audits |
| [Extension path](#extension-path-after-the-baseline-tutorial) | What to add after the baseline tutorial is working |

## Contoso baseline

The baseline assumption for this page is the same Contoso scenario used in Tutorial 34:

- OpenClaw powers a customer support assistant
- AGT governs tool calls before execution
- AKS hosts the final deployment

Start with the tutorial if you want the full end-to-end walkthrough. Use this page when you want to understand or extend the integration model behind that walkthrough.

## Use this page for

Use this page when one of these is true:

1. the baseline tutorial already works and you want to extend it
2. you need to understand the adapter contract without reading the whole end-to-end walkthrough
3. you are deciding between in-process only, sidecar, or shared-service architectures

If you still need to provision ACR, AKS, manifests, or run the Contoso validation prompts, go back to [Tutorial 34](../tutorials/34-openclaw-end-to-end.md).

## Choose your follow-on path

Use the sections in this guide based on your audience or goal:

| Audience | Start here |
|---|---|
| **OpenClaw maintainer** | [Preferred integration model](#preferred-integration-model-hook-integration-first) and [Practical integration model](#practical-integration-model) |
| **AKS creator / platform engineer** | [Deployment choices](#deployment-choices), [AKS operators](#aks-operators), and the [AKS protection appendix](../deployment/openclaw-aks-protection.md) |
| **AGT creator / security owner** | [What ships vs. what you own](#what-ships-vs-what-you-own), [Fail closed before a tool runs](#2-fail-closed-before-a-tool-runs), and [Export audits somewhere durable](#5-export-audits-somewhere-durable) |
| **OpenClaw operator new to AGT** | Re-read [Tutorial 34](../tutorials/34-openclaw-end-to-end.md), then come back to [Practical integration model](#practical-integration-model) |
| **Leadership / architecture reviewer** | [What ships vs. what you own](#what-ships-vs-what-you-own) and [Deployment choices](#deployment-choices) |

## What ships vs. what you own

| Area | Shipped in repo | You still own in your OpenClaw deployment |
|---|---|---|
| Before-tool governance | Native plugin entry + `evaluateBeforeToolCall()` | Supplying policy config and acting on the result |
| Post-tool audit | Native plugin entry + `recordAfterToolCall()` | Persisting or exporting audit data outside process memory |
| MCP scan | `scanMcpToolDefinition()` / `scanMcpToolDefinitions()` | Deciding whether review findings block registration |
| Approval signal | `review` decision + `approvers` list | Approval UX, queueing, reviewer identity, and resume behavior |
| Runtime isolation | Not part of the adapter | OpenClaw sandboxing, container policy, network policy, secrets handling |

## Honest boundary

Use this adapter when you want a **governance gate in front of tool execution**. That is valuable, but it is not the same as owning the whole runtime security story.

What the adapter does well:

1. evaluate tool calls before execution
2. block or review risky actions
3. rewrite parameters when policy allows that pattern
4. emit audit evidence around tool execution
5. scan MCP tool definitions before registration

What the adapter does not do by itself:

1. sandbox OpenClaw
2. isolate the container or pod
3. provide a full approval product for operators
4. guarantee protection if another execution path bypasses the governed hook
5. prove an MCP tool is safe just because scanning found no issue

That is why this guide keeps separating **adapter responsibilities** from **OpenClaw and platform responsibilities**.

## Preferred integration model: native plugin first

For most developers, the best path is:

1. install the package with `openclaw plugins install @microsoft/agentmesh-openclaw`
2. configure `plugins.entries.agentmesh-openclaw.config.policyFile`
3. let the shipped plugin entry register `before_tool_call` and `after_tool_call`
4. route `allow | deny | review` into normal OpenClaw behavior

The adapter is still designed around OpenClaw's existing interception path, but **source-file edits should be treated as a fallback path**, not the default onboarding flow for application developers.

```text
OpenClaw runtime
    |
    +--> plugin entry loads config
    +--> before_tool_call
            |
            v
        AGT adapter
            |
            +--> evaluate policy
            +--> return allow | deny | review
    |
    +--> OpenClaw enforces result
    |
    +--> after_tool_call
            |
            v
        AGT audit logging
```

What is true today:

- the package ships a native OpenClaw plugin entry and manifest
- it uses AGT for policy evaluation and post-call audit logging
- MCP scan helpers are available, but you still choose where to call them in tool registration code

### Underlying hook path

If you are self-hosting or maintaining OpenClaw itself, the known underlying interception points are:

- `src/agents/pi-tools.ts`
- `src/agents/pi-tools.before-tool-call.ts`
- `wrapToolWithBeforeToolCallHook(...)`

See the package README for the concrete snippets and fallback source-level examples:

- [Install and load policy bundles](../../packages/agentmesh-integrations/openclaw-agentmesh/README.md#1-define-a-policy-bundle)
- [Wire the OpenClaw hook](../../packages/agentmesh-integrations/openclaw-agentmesh/README.md#2-wire-the-openclaw-hook)
- [Wire review handling](../../packages/agentmesh-integrations/openclaw-agentmesh/README.md#3-wire-review-and-approval-handling)
- [Enable MCP scanning](../../packages/agentmesh-integrations/openclaw-agentmesh/README.md#4-enable-mcp-tool-definition-scanning-before-registration)
- [Record post-call audits](../../packages/agentmesh-integrations/openclaw-agentmesh/README.md#5-record-post-call-audit-events)

If you want one follow-along guide that starts with installation and ends with AKS validation, use the [OpenClaw end-to-end tutorial](../tutorials/34-openclaw-end-to-end.md). This page is intentionally narrower and more architectural.

## Deployment choices

Choose the topology that matches how much separation you need between OpenClaw and AGT.

| Choice | What AGT protects | What OpenClaw still owns | Best fit |
|---|---|---|---|
| **In-process adapter only** | Tool-call policy evaluation in the `before_tool_call` path, MCP tool-definition review, post-call audit hooks | Tool execution, runtime/container isolation, approval workflow, audit export | Lowest-latency deployment where OpenClaw can embed governance directly |
| **Adapter + sidecar** | Same in-process decision point plus optional nearby governance HTTP APIs for adjacent checks or operational separation | Orchestration between adapter and sidecar, runtime isolation, ingress design | Teams that want OpenClaw-native hooks and a local governance service in the same pod or namespace |
| **Adapter + shared governance service** | Same in-process decision point with centrally managed policy/audit backends via custom integrations | Network path to the shared service, service auth, approval UX, runtime isolation | Multi-tenant or multi-cluster fleets that want centralized governance operations |

### Important boundary

The adapter is an **integration library**, not a full OpenClaw control plane. It does not automatically discover your sidecar, talk to a shared governance API, or create approval workflows for you. Those are deployment decisions you wire around the adapter.

## What still needs to be done after the baseline works

Most teams should expect follow-on work in these areas:

1. verify that all sensitive tools really flow through the governed `before_tool_call` path
2. define a real approval operating model, not just a technical `review` signal
3. export audits to durable logging and retention systems
4. reduce tool privileges and credential scope so an allowed action still has limited blast radius
5. test failure modes such as policy-engine errors, audit-export outages, and prompt-driven abuse attempts

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

### Hook helper fallback

The default package path is now the native plugin entry. The lower-level hook helpers remain available when you need to wire the adapter into a custom or source-level interception path.

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

## Extension path after the baseline tutorial

Once the Contoso baseline walkthrough is working, the usual next extensions are:

### 1. Add extra governance surfaces

The baseline integration already covers the most important path:

- `before_tool_call` for allow / deny / review
- `after_tool_call` for outcome audit logging
- MCP definition scanning before registration

That means you usually do **not** need a second governance mechanism immediately. Start by making those three surfaces trustworthy.

### 2. Add a sidecar when you want a local governance service boundary

Choose a sidecar when you want:

- a pod-local HTTP endpoint for adjacent governance checks
- cleaner separation between OpenClaw runtime code and a governance service
- an easier path to reusing the same local governance service for multiple runtimes in the same pod or namespace

The adapter remains the pre-execution gate. The sidecar is an **additional architecture layer**, not a replacement for `before_tool_call`.

### 3. Add a shared governance service when you want central operations

Choose a shared service when you want:

- centrally managed policy backends
- centralized audit export or review workflows
- governance consistency across many OpenClaw deployments

Do this only after the in-process path is already clear, because a shared service adds network and tenancy complexity.

## How the adapter relates to the sidecar

The [sidecar pattern](../deployment/openclaw-sidecar.md) is useful when you want a network-accessible governance surface next to OpenClaw. The adapter is useful when you want policy enforcement directly in the OpenClaw process.

You can use both, but they solve different problems:

- **adapter**: native hook integration before a tool executes
- **sidecar**: local HTTP governance service and separation of duties

Using both is an architecture choice, not an automatic behavior in the adapter package.

## AKS operators

For production guidance on ConfigMaps vs. Secrets, mounted policy bundles, network boundaries, workload identity, audit export, and runtime hardening, use the [OpenClaw AKS protection appendix](../deployment/openclaw-aks-protection.md).

## Reference links

- [Tutorial 34](../tutorials/34-openclaw-end-to-end.md)
- [OpenClaw package README](../../packages/agentmesh-integrations/openclaw-agentmesh/README.md)
- [Package API](../../packages/agentmesh-integrations/openclaw-agentmesh/README.md#api)
- [Error behavior](../../packages/agentmesh-integrations/openclaw-agentmesh/README.md#error-behavior)
- [Public types](../../packages/agentmesh-integrations/openclaw-agentmesh/src/types.ts)
- [Hook wiring examples](../../packages/agentmesh-integrations/openclaw-agentmesh/README.md#2-wire-the-openclaw-hook)

## Related

- [Package README](../../packages/agentmesh-integrations/openclaw-agentmesh/README.md)
- [OpenClaw AKS protection appendix](../deployment/openclaw-aks-protection.md)
- [OpenClaw sidecar pattern](../deployment/openclaw-sidecar.md)
