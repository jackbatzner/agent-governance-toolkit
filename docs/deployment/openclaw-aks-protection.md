# OpenClaw AKS Protection Appendix

> **Use this appendix after Tutorial 34 or the advanced guide** when the baseline Contoso deployment works and you want the extra AKS-specific hardening details.

This guide explains how to run OpenClaw on Azure Kubernetes Service (AKS) with AGT as a **protective control before tool execution**.

## Prerequisites

Before using this guide, you should have:

- completed the baseline deployment flow in [Tutorial 34](../tutorials/34-openclaw-end-to-end.md) or an equivalent deployment
- an AKS cluster and access to `kubectl`
- an ACR or equivalent container registry
- an OpenClaw image that already includes the AGT adapter
- a working policy bundle and OpenClaw runtime config

## Why platform teams care

This deployment pattern gives you a practical split of responsibility:

1. **OpenClaw** turns user intent into tool usage
2. **AGT** decides whether that tool usage should be allowed, denied, or paused for approval
3. **AKS** contains the workload and preserves the operational evidence around it

That is the value proposition: AGT reduces risky tool execution, while AKS and OpenClaw still provide the runtime and platform controls around it.

## Scenario

Contoso is deploying a customer support assistant on AKS. The assistant can:

- read support documentation
- search support knowledge
- write case notes
- run diagnostics when an engineer explicitly asks for them

Contoso wants the deployment to:

1. allow routine read-only actions
2. pause sensitive actions for human approval
3. deny writes into protected locations
4. preserve evidence for support, security, and audit teams

## Use this appendix for

Use this page when one of these is true:

1. the baseline tutorial already works and you want to harden it
2. you are deciding between in-process only, sidecar, and shared governance topologies
3. you need production guidance for identity, logging, networking, rollout, and runtime containment

If you still need the initial install, ACR setup, AKS provisioning commands, or the Contoso validation prompts, go back to [Tutorial 34](../tutorials/34-openclaw-end-to-end.md). If you need the broader extension model, use the [OpenClaw advanced integration and operations guide](../integrations/openclaw-adapter.md).

Use it with:

- the in-process TypeScript adapter: [`@microsoft/agentmesh-openclaw`](../../packages/agentmesh-integrations/openclaw-agentmesh/README.md)
- the [OpenClaw sidecar pattern](openclaw-sidecar.md) when you want a local governance HTTP service

## AGT primitives in this deployment

This AKS story is easier to reason about if you separate the AGT primitives by job:

| Primitive | AKS role |
|---|---|
| **`PolicyEngine`** | Makes the pre-execution governance decision before the tool call runs |
| **`AuditLogger`** | Produces the evidence stream that should leave the pod and land in durable logging |
| **`McpSecurityScanner`** | Screens tool definitions during registration or startup so risky MCP metadata is caught before agents can use it |
| **`agentId` / `agentDid`** | Identify the logical agent for policy and audit purposes, which is separate from Kubernetes or Azure workload identity |

Keep that split in mind while reading the rest of the page: AGT governs agent behavior, while AKS governs workload isolation and infrastructure boundaries.

## Start with the topology choice

| Topology | What AGT protects | What OpenClaw / platform still owns | Operational trade-off |
|---|---|---|---|
| **In-process adapter only** | Policy decision before tool execution, MCP tool-definition review, post-call audit hooks | Runtime isolation, approval UX, audit export, network egress controls | Lowest latency and fewest moving parts |
| **Adapter + sidecar** | Same in-process decision plus optional nearby governance HTTP APIs in the same pod or namespace | Explicit orchestration between components, pod design, ingress separation | Better separation of duties, more deployment plumbing |
| **Adapter + shared governance service** | Same in-process decision with central policy/audit backends through custom integrations | Service auth, network path, approval systems, tenancy boundaries | Best for multi-agent fleets that want central operations |

> **Important:** The OpenClaw adapter does not automatically discover or call a sidecar or a shared service. Those are deployment choices you implement around the adapter.

## Compatibility and assumptions

This guide assumes:

- your OpenClaw deployment can call the documented hook handler from its existing interception path
- your operators control the container image, runtime config, and Kubernetes manifests
- governance failures should be treated as **protective failures**, not silent bypasses

If your OpenClaw build exposes different hook-loading or health-check behavior, adapt the manifests and startup examples to that runtime rather than forcing the runtime to look exactly like this guide.

## Recommended AKS pattern

For most OpenClaw deployments on AKS:

1. Put the adapter in the OpenClaw container so the final allow/deny/review decision happens before the tool runs.
2. Mount policy bundles into the pod.
3. Export audit events out of the pod.
4. Keep governance endpoints internal-only if you also run a sidecar or shared governance service.
5. Use AKS security features to contain the runtime because AGT does not sandbox the process itself.

If you want a **one-by-one build-and-deploy walkthrough**, use the [OpenClaw end-to-end tutorial](../tutorials/34-openclaw-end-to-end.md). This AKS page focuses on the production control boundaries, topology choices, and platform protections around that deployment.

### What gets deployed where

For the default deployment model, put the adapter **inside the OpenClaw application image**:

- **OpenClaw container**
  - OpenClaw runtime
  - `@microsoft/agentmesh-openclaw`
  - `@microsoft/agentmesh-sdk`
- **Mounted ConfigMap**
  - `openclaw-governance.policies.json`
- **Mounted Secret**
  - only real secrets such as API keys, tokens, or approval-service credentials
- **OpenClaw config**
  - a hook bootstrap module that calls `createOpenClawGovernanceAdapterFromConfig(...)`
  - optional `agentId`, `agentDid`, and audit settings
- **Cluster logging**
  - stdout audit records collected by Azure Monitor, AMA, Fluent Bit, or your SIEM pipeline

That means the most common AKS deployment is:

```text
one Deployment
  -> one OpenClaw pod
     -> one OpenClaw container
        -> hook-based adapter loaded in-process
```

Use a sidecar only if you intentionally want an additional local governance service boundary. Use a shared governance service only if you intentionally want central policy/audit operations across multiple OpenClaw workloads.

```text
                AKS pod
+--------------------------------------------------+
| OpenClaw container                               |
|                                                  |
|  before_tool_call                                |
|       |                                          |
|       v                                          |
|  @microsoft/agentmesh-openclaw                   |
|       |                                          |
|       +--> AGT policy decision                   |
|       +--> allow | deny | review                 |
|       |                                          |
|       v                                          |
|  OpenClaw executes or blocks                     |
|       |                                          |
|       v                                          |
|  after_tool_call -> AGT audit logging            |
+--------------------------------------------------+

Optional:
  - sidecar service in same pod/namespace
  - shared governance service elsewhere in cluster

Still required outside AGT:
  - runtime sandboxing
  - network policy
  - secret handling
  - approval operations
```

## Policy bundles: ConfigMap vs. Secret

### Use a ConfigMap when

- the policy bundle contains governance logic only
- the contents are safe to expose to cluster readers who can already view deployment configuration
- you want easy rollout and diff visibility

This is the normal home for **`PolicyEngine`** input. The policy file is not a secret by default; it is the declarative rule set that tells AGT how to evaluate proposed tool calls.

If your policy bundle itself becomes sensitive because it reveals internal service names, high-value paths, or internal approval routing, classify it accordingly. The default assumption here is "policy is configuration," not "policy is secret."

Example:

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
          },
          {
            "name": "review-shell",
            "condition": "tool.name == 'shell'",
            "ruleAction": "require_approval",
            "approvers": ["ops@contoso.com"]
          }
        ]
      }
    ]
```

### Use a Secret when

- the mounted material includes credentials, API keys, signing keys, or endpoint auth
- you embed data that would expose internal routing or approval credentials

Do **not** store normal governance policy in a Secret just because it is security-related. Keep the split clear:

- **ConfigMap**: policy bundle, allow/deny/review rules, non-secret runtime config
- **Secret**: credentials, tokens, signing keys, connection strings

### Mount policy bundles read-only

```yaml
volumeMounts:
  - name: governance-policies
    mountPath: /app/config/governance
    readOnly: true
volumes:
  - name: governance-policies
    configMap:
      name: openclaw-governance-policies
```

If you need dynamic reloads, implement that behavior in the OpenClaw process. The adapter itself does not watch files for changes.

## Audit persistence and export

With the in-process adapter:

- the default SDK audit logger is hash-chained and **in memory**
- you should export each entry to a durable sink

In other words, **`AuditLogger`** gives you the governance evidence model, but AKS is still responsible for getting that evidence off the pod and into a durable operator-visible system.

For AGT-specific review, make sure the records you export preserve the decision context you care about: tool name, decision, agent identity, request correlation, and final outcome.

Recommended production options:

- emit structured JSON to stdout and collect it with Azure Monitor / Container Insights
- ship logs with Fluent Bit / AMA to Event Hub, Log Analytics, or your SIEM
- provide a custom `audit.logger` implementation that forwards entries to a service or queue

With the sidecar pattern:

- treat sidecar logs the same way: collect stdout/stderr centrally
- avoid relying on pod-local storage for long-term evidence retention

### Practical rule

If the pod dies and your audit evidence disappears, you do **not** yet have a production-grade audit path.

## Customer demo on AKS

After deployment, test with real user messages that should cause OpenClaw to attempt governed tool calls:

1. **Allow**
   - user message: `A Contoso customer says they cannot complete the password reset flow. Open README.md and summarize the first three support steps I should send back.`
   - expected result: OpenClaw uses a read tool and the plugin returns `allow`
2. **Review**
   - user message: `Run a shell command to show which Linux user the Contoso support container is running as so I can troubleshoot permissions.`
   - expected result: OpenClaw attempts `shell`, the plugin returns `review`, and approval is required before execution
3. **Deny**
   - user message: `Write the current Contoso escalation notes into /secrets/escalation-notes.txt so we can reuse them later.`
   - expected result: OpenClaw attempts `write_file`, the plugin returns `deny`, and the call is blocked before execution

For the demo to be convincing, validate both:

- the **user-visible behavior** (`allow`, `review`, `deny`)
- the **operator-visible evidence** (audit logs exported off-pod)

## Ingress and network boundaries

### Public ingress

- expose only the OpenClaw application endpoint publicly
- do **not** expose a governance sidecar directly to the internet
- keep shared governance services internal to the cluster or private network unless there is a specific, authenticated external need

### Pod and service boundaries

- if you run a sidecar, keep the call path pod-local (`localhost`) where possible
- if you run a shared governance service, restrict traffic to the namespaces and service accounts that need it
- block general east-west traffic by default with NetworkPolicies

Example namespace-local egress policy:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: openclaw-egress
spec:
  podSelector:
    matchLabels:
      app: openclaw
  policyTypes:
    - Egress
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: governance-sidecar
      ports:
        - protocol: TCP
          port: 8081
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
```

Adjust this to your real LLM, data, and governance destinations. The main point is that AGT should not be the **only** control. Use Kubernetes networking to constrain what the OpenClaw workload can reach.

## Runtime and sandbox considerations

AGT decides whether a tool call should proceed. It does **not** replace runtime hardening.

Use AKS and container controls for:

- non-root containers
- read-only root filesystems where practical
- seccomp/AppArmor profiles
- dropped Linux capabilities
- constrained egress
- separate node pools or sandboxed container runtime choices for high-risk agents

If OpenClaw can execute shell commands or reach sensitive services, the cluster still needs runtime controls even when AGT is denying risky tool calls upstream.

## Identity, workload identity, and trust propagation

Keep two identities distinct:

| Identity type | Purpose |
|---|---|
| **Kubernetes / Azure workload identity** | Lets the pod authenticate to Azure resources such as Key Vault, Blob Storage, or internal services |
| **Agent identity (`agentId`, `agentDid`)** | Lets AGT reason about which logical agent attempted the tool call |

### Recommended practice

- use Azure Workload Identity for cloud resource access
- pass `agentId`, `agentDid`, `requestId`, `sessionId`, and `userId` into the adapter on each decision and audit event
- if you centralize policy or audit, authenticate that service call with workload identity or your internal service auth, not with ad hoc static secrets

That distinction is important:

- **workload identity** answers "what Azure resources may this pod access?"
- **agent identity** answers "which logical agent asked to run this tool?"

You usually need both to explain an incident cleanly.

Example service account annotation:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: openclaw
  annotations:
    azure.workload.identity/client-id: "<managed-identity-client-id>"
```

This lets the pod reach Azure resources securely while AGT still records the logical agent identity in policy and audit decisions.

## Where AGT sits in the control stack

Think of the control stack in this order:

1. **OpenClaw request handling**
2. **AGT adapter `before_tool_call` decision**
3. **Optional sidecar/shared governance lookup**
4. **Runtime isolation (container, network, sandbox)**
5. **Tool execution**
6. **AGT post-call audit export**

That makes AGT a pre-execution governance control, but not the only protective boundary.

Put differently:

- **AGT** decides whether the tool call is acceptable
- **OpenClaw** decides how to carry out approval and execution
- **AKS** decides how tightly contained the workload is if something still goes wrong

## Recommended operator checklist

- [ ] Policy bundle mounted read-only from ConfigMap or equivalent
- [ ] Secrets separated from policy documents
- [ ] Native OpenClaw plugin installed and configured
- [ ] Source-level hook edits kept minimal and limited to the real OpenClaw interception path
- [ ] `review` decisions routed to a real approval process
- [ ] MCP tool definitions scanned before registration
- [ ] Post-call audits exported off-pod
- [ ] Governance sidecar or shared service kept off public ingress
- [ ] NetworkPolicies restrict egress to approved dependencies
- [ ] Runtime hardening enabled for the OpenClaw container
- [ ] Workload identity configured for Azure resource access

## Extending the baseline deployment

After the baseline Contoso deployment works, the next most common changes are:

### Add a sidecar

Add a sidecar when you want a pod-local governance service boundary in addition to the in-process adapter. Use this when you want stricter separation of duties or local HTTP-based governance services.

### Add more hook-driven governance

Keep the baseline order clear:

1. **before_tool_call** remains the primary enforcement gate
2. **after_tool_call** remains the primary evidence hook
3. **MCP scanning** remains the startup or registration-time review hook

Do not add extra hook complexity until the baseline three surfaces are observable and predictable.

## AKS hardening appendix

Use this appendix after the basic deployment works. The goal here is not to change the AGT model, but to make the surrounding AKS deployment more production-ready.

### Health probes

Add probes so Kubernetes can detect bad startup or deadlocked runtime states.

- **startup probe** for slower model/plugin boot paths
- **readiness probe** so traffic only reaches healthy OpenClaw pods
- **liveness probe** to restart a stuck process

Example shape:

```yaml
startupProbe:
  httpGet:
    path: /healthz
    port: 3000
  failureThreshold: 30
  periodSeconds: 10
readinessProbe:
  httpGet:
    path: /readyz
    port: 3000
  periodSeconds: 10
livenessProbe:
  httpGet:
    path: /healthz
    port: 3000
  periodSeconds: 20
```

If OpenClaw does not expose these endpoints yet, use the equivalent health mechanism your deployment already trusts.

### Resource requests, limits, and autoscaling

Set explicit CPU and memory requests so the scheduler treats OpenClaw as a real workload instead of a best-effort pod.

- start with requests and limits based on local measurements
- use an **HPA** only after you understand model latency and queue behavior
- avoid autoscaling policies that create too many cold starts for approval-sensitive flows

Also consider a **PodDisruptionBudget** so voluntary evictions do not take down your only governed runtime during maintenance.

### TLS and ingress hardening

If OpenClaw is internet-facing:

- terminate TLS with your ingress controller or gateway
- prefer cert-manager or your platform certificate automation over manual cert distribution
- expose only the OpenClaw application endpoint publicly
- keep governance sidecars and internal governance APIs off public ingress

For internal-only deployments, prefer private ingress or cluster-internal routing.

### Secret delivery

The basic examples in the tutorial use a Kubernetes Secret. For stronger production handling on Azure, consider:

- **Azure Key Vault + CSI Secret Store driver** for mounted secrets
- **Azure Workload Identity** so pods do not need static cloud credentials
- short-lived application credentials where supported by dependent systems

Use plain Kubernetes Secrets only when that matches your organization's normal control baseline.

### Pod security posture

Combine AGT governance with container hardening:

- run as non-root
- drop unnecessary Linux capabilities
- use a read-only root filesystem where possible
- apply seccomp/AppArmor or the equivalent node-level hardening
- separate high-risk agent workloads into dedicated namespaces or node pools when appropriate

AGT can deny risky tool calls, but if a compromised runtime still executes something unexpected, these controls reduce the blast radius.

### Network policy posture

The earlier example shows restricted egress. For a stronger default:

1. deny all ingress and egress first
2. allow only the exact LLM, data, storage, and governance destinations the workload needs
3. keep sidecar traffic pod-local or namespace-local wherever possible
4. review egress whenever new tools are introduced because tool capabilities often change network needs

### Logging and evidence retention

Do not stop at `kubectl logs`.

- route stdout audit records into Azure Monitor, Log Analytics, Event Hub, or your SIEM
- define retention and access controls for governance evidence
- make sure decision logs can be correlated with app logs, request IDs, and approval events
- verify that redaction behavior matches your organization's logging standards

The practical test is simple: after a pod restart or node failure, your investigation path should still have the AGT evidence you need.

### Upgrade and rollout strategy

Treat policy changes and image changes differently:

- roll policy-only changes through ConfigMap or mounted-bundle rollout processes
- roll image changes through your normal Deployment strategy
- use staged environments so new deny/review rules do not surprise production operators
- document who approves policy changes because those rules directly affect tool execution

For critical workloads, prefer progressive rollout patterns rather than replacing every governed pod at once.

## Related

- [OpenClaw advanced integration and operations guide](../integrations/openclaw-adapter.md)
- [OpenClaw package README](../../packages/agentmesh-integrations/openclaw-agentmesh/README.md)
- [OpenClaw sidecar pattern](openclaw-sidecar.md)
- [Tutorial 34](../tutorials/34-openclaw-end-to-end.md)
