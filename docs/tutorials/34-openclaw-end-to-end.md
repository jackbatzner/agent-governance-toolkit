# Tutorial 34: OpenClaw End-to-End with the TypeScript SDK

Build and test a full OpenClaw + AGT flow using the OpenClaw adapter package, then carry the same shape into AKS.

This tutorial is the **follow-along path** for platform engineers and OpenClaw developers who want one place to cover:

1. installing the adapter and SDK
2. registering the adapter with the OpenClaw SDK `before_tool_call` surface
3. scanning MCP tool definitions
4. exporting audits
5. building the OpenClaw deployment artifact
6. testing allow / deny / review behavior locally and on AKS

Use this with:

- the [OpenClaw adapter package README](../../packages/agentmesh-integrations/openclaw-agentmesh/README.md)
- the [OpenClaw adapter integration guide](../integrations/openclaw-adapter.md)
- the [OpenClaw AKS protection guide](../deployment/openclaw-aks-protection.md)

## What you are building

The integration flow looks like this:

```text
OpenClaw request
  -> before_tool_call hook
  -> @microsoft/agentmesh-openclaw
  -> @microsoft/agentmesh-sdk policy / audit / MCP scan
  -> allow | deny | review
  -> OpenClaw executes or blocks
  -> post-call audit
```

The key boundary is:

- **`@microsoft/agentmesh-sdk`** provides generic governance primitives.
- **`@microsoft/agentmesh-openclaw`** translates those primitives into OpenClaw-shaped inputs and outputs.
- **OpenClaw** still owns execution, approvals, and runtime isolation.

## Before you start

You need:

- a working OpenClaw checkout
- Node.js 18+
- access to the OpenClaw SDK or plugin surface that lets you intercept tool calls before execution
- only if you are maintaining OpenClaw itself: access to the underlying interception files and wrappers

If you are also testing on AKS, you additionally need:

- an AKS cluster
- a container image build path for your OpenClaw deployment
- a place to store non-secret policy config and secret runtime credentials separately

## Choose an install mode

There are three practical ways to test this integration.

### Option A: published packages only

Use this when you want the cleanest customer-like path.

```bash
npm install @microsoft/agentmesh-openclaw @microsoft/agentmesh-sdk
```

### Option B: local source for both SDK and adapter

Use this when you are developing against a local AGT checkout alongside OpenClaw.

```bash
npm install \
  ../agent-governance-toolkit/packages/agent-mesh/sdks/typescript \
  ../agent-governance-toolkit/packages/agentmesh-integrations/openclaw-agentmesh
```

### Option C: published adapter + local SDK

Use this when the adapter package is fine but you want to try local SDK changes underneath it.

```bash
npm install @microsoft/agentmesh-openclaw
npm install ../agent-governance-toolkit/packages/agent-mesh/sdks/typescript
```

> **Important:** the adapter expects the SDK to be installed too. Even in source mode, keep both packages present in the OpenClaw dependency graph.

## Step 1: add a policy bundle to the OpenClaw repo

Create a policy file in your OpenClaw checkout.

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
        "name": "deny-secret-path-write",
        "condition": "tool.name == 'write_file' and params.path.startswith('/secrets/')",
        "ruleAction": "deny",
        "description": "Never write into mounted secret locations."
      }
    ]
  }
]
```

## Step 2: create a governance bootstrap module

Create one shared adapter instance during OpenClaw startup.

**`src/agents/governance.ts`**

```ts
import { readFileSync } from "node:fs";
import { AuditLogger } from "@microsoft/agentmesh-sdk/audit";
import type { Policy } from "@microsoft/agentmesh-sdk/types";
import { createOpenClawGovernanceAdapter } from "@microsoft/agentmesh-openclaw";

function loadPolicies(): Policy[] {
  const raw = readFileSync(
    new URL("../../config/openclaw-governance.policies.json", import.meta.url),
    "utf8",
  );

  return JSON.parse(raw) as Policy[];
}

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

## Step 3: register the adapter with the OpenClaw SDK

Use the adapter anywhere the OpenClaw SDK exposes a `before_tool_call` registration surface.

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

> **Note:** `registerBeforeToolCallHook(...)` is illustrative. Use the actual registration API exposed by your OpenClaw SDK version.

## Step 4: keep source edits as a fallback only

If your OpenClaw SDK does **not** expose a native registration surface yet, the same callback can be wired into the underlying interception path used by OpenClaw maintainers:

- `src/agents/pi-tools.ts`
- `src/agents/pi-tools.before-tool-call.ts`
- `wrapToolWithBeforeToolCallHook(...)`

## Step 5: scan MCP tool definitions before registration

Use the adapter to vet MCP tool definitions before they reach the tool catalog.

```ts
import { governance } from "./governance";

export function validateMcpTools(
  tools: Array<{ name: string; description?: string; inputSchema?: unknown }>,
) {
  for (const tool of tools) {
    const scan = governance.scanMcpToolDefinition({
      name: tool.name,
      description: tool.description ?? "",
      inputSchema: tool.inputSchema,
    });

    if (scan.recommendedDecision === "deny") {
      throw new Error(
        `Rejected MCP tool '${tool.name}': ${scan.findings.map((f) => f.message).join("; ")}`
      );
    }
  }
}
```

## Step 6: record post-call audit events

Call the post-execution hook wherever OpenClaw records tool outcomes.

```ts
import { governance } from "./governance";

export async function recordGovernedToolOutcome(params: {
  toolName: string;
  requestId?: string;
  sessionId?: string;
  userId?: string;
  error?: Error;
}) {
  await governance.recordAfterToolCall({
    toolName: params.toolName,
    requestId: params.requestId,
    sessionId: params.sessionId,
    userId: params.userId,
    outcome: params.error
      ? {
          status: "error",
          error: params.error.message,
        }
      : {
          status: "complete",
        },
  });
}
```

## Step 7: run local validation

Validate both layers.

### Validate the adapter package itself

If you are working from the AGT source tree:

```bash
cd packages/agentmesh-integrations/openclaw-agentmesh
npm install --legacy-peer-deps
npm run lint
npm test
npm run build
```

### Validate the OpenClaw checkout

After wiring the files in your OpenClaw repo:

1. run the package manager install step your OpenClaw checkout already uses
2. run the existing OpenClaw build command
3. run the existing OpenClaw test command or smoke test flow

This guide intentionally does **not** invent a fake OpenClaw build command because that depends on the checkout you are testing against.

## Step 8: test the governance outcomes locally

Use a small validation matrix before you build a container:

| Scenario | Expected result |
|---|---|
| `read_file` on a normal path | `allow` |
| `shell` | `review` |
| `write_file` into `/secrets/...` | `deny` |
| poisoned MCP tool description | `review` or `deny`, depending on your handling policy |

## Step 9: build the OpenClaw image

Use your existing OpenClaw Docker build, but make sure it includes:

- the adapter and SDK dependencies
- the policy bundle file or mounted path
- any environment variables you use for policy path or audit export

Typical build flow:

```bash
docker build -t contoso/openclaw-governed:dev .
docker run --rm -p 3000:3000 contoso/openclaw-governed:dev
```

If your OpenClaw repo already has a working Dockerfile, prefer updating that image rather than creating a second parallel image definition.

## Step 10: carry the same shape into AKS

For AKS, keep the local shape but move configuration into Kubernetes objects.

### ConfigMap for policy

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: openclaw-governance-policies
data:
  openclaw-governance.policies.json: |
    [
      {
        "name": "openclaw-tool-policy",
        "agents": ["*"],
        "default_action": "deny",
        "rules": [
          {
            "name": "allow-read-only-tools",
            "condition": "tool.name in ['read_file', 'search_web']",
            "ruleAction": "allow"
          }
        ]
      }
    ]
```

### Deployment patch

Merge the policy mount and any audit-related environment variables into your existing OpenClaw Deployment:

```yaml
volumeMounts:
  - name: governance-policies
    mountPath: /app/config/governance
    readOnly: true
env:
  - name: OPENCLAW_GOVERNANCE_POLICY_PATH
    value: /app/config/governance/openclaw-governance.policies.json
volumes:
  - name: governance-policies
    configMap:
      name: openclaw-governance-policies
```

For the full AKS operational guidance, use the [OpenClaw AKS protection guide](../deployment/openclaw-aks-protection.md).

## Step 11: validate on AKS

Before calling this production-ready, confirm:

1. the OpenClaw pod starts with the adapter enabled
2. the policy bundle is mounted read-only
3. `allow`, `deny`, and `review` behavior still matches local tests
4. audit output leaves the pod and reaches your log sink
5. any governance sidecar or shared service stays internal-only
6. workload identity or service auth works for any Azure dependencies

## When to use each install mode

| Goal | Best install mode |
|---|---|
| Customer-like validation | Published packages only |
| Branch testing for both packages | Local source for both SDK and adapter |
| Test local SDK changes with stable adapter | Published adapter + local SDK |

## Useful source references while integrating

- [OpenClaw adapter package README](../../packages/agentmesh-integrations/openclaw-agentmesh/README.md)
- [OpenClaw adapter implementation](../../packages/agentmesh-integrations/openclaw-agentmesh/src/adapter.ts)
- [OpenClaw public types](../../packages/agentmesh-integrations/openclaw-agentmesh/src/types.ts)
- [OpenClaw MCP scan helper](../../packages/agentmesh-integrations/openclaw-agentmesh/src/mcp-scan.ts)
- [OpenClaw consumer smoke test](../../packages/agentmesh-integrations/openclaw-agentmesh/tests/consumer-smoke.test.ts)
- [OpenClaw adapter guide](../integrations/openclaw-adapter.md)
- [OpenClaw AKS protection guide](../deployment/openclaw-aks-protection.md)

## What this tutorial does not automate

This tutorial gives you the integration shape, but you still own:

- the exact OpenClaw build command for your checkout
- the approval UX and resume flow
- durable audit export
- final AKS manifest structure, ingress, and runtime hardening

That is intentional. AGT acts as the governance layer in front of tool execution, but OpenClaw and your platform still own the rest of the runtime.
