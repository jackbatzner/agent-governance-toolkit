# OpenClaw AKS Protection Guidance

This guide explains how to run OpenClaw on Azure Kubernetes Service (AKS) with AGT as a **protective control before tool execution**.

Use it with:

- the in-process TypeScript adapter: [`@microsoft/agentmesh-openclaw`](../../packages/agentmesh-integrations/openclaw-agentmesh/README.md)
- the [OpenClaw sidecar pattern](openclaw-sidecar.md) when you want a local governance HTTP service

## Start with the topology choice

| Topology | What AGT protects | What OpenClaw / platform still owns | Operational trade-off |
|---|---|---|---|
| **In-process adapter only** | Policy decision before tool execution, MCP tool-definition review, post-call audit hooks | Runtime isolation, approval UX, audit export, network egress controls | Lowest latency and fewest moving parts |
| **Adapter + sidecar** | Same in-process decision plus optional nearby governance HTTP APIs in the same pod or namespace | Explicit orchestration between components, pod design, ingress separation | Better separation of duties, more deployment plumbing |
| **Adapter + shared governance service** | Same in-process decision with central policy/audit backends through custom integrations | Service auth, network path, approval systems, tenancy boundaries | Best for multi-agent fleets that want central operations |

> **Important:** The OpenClaw adapter does not automatically discover or call a sidecar or a shared service. Those are deployment choices you implement around the adapter.

## Recommended AKS pattern

For most OpenClaw deployments on AKS:

1. Put the adapter in the OpenClaw container so the final allow/deny/review decision happens before the tool runs.
2. Mount policy bundles into the pod.
3. Export audit events out of the pod.
4. Keep governance endpoints internal-only if you also run a sidecar or shared governance service.
5. Use AKS security features to contain the runtime because AGT does not sandbox the process itself.

## Policy bundles: ConfigMap vs. Secret

### Use a ConfigMap when

- the policy bundle contains governance logic only
- the contents are safe to expose to cluster readers who can already view deployment configuration
- you want easy rollout and diff visibility

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

Recommended production options:

- emit structured JSON to stdout and collect it with Azure Monitor / Container Insights
- ship logs with Fluent Bit / AMA to Event Hub, Log Analytics, or your SIEM
- provide a custom `audit.logger` implementation that forwards entries to a service or queue

With the sidecar pattern:

- treat sidecar logs the same way: collect stdout/stderr centrally
- avoid relying on pod-local storage for long-term evidence retention

### Practical rule

If the pod dies and your audit evidence disappears, you do **not** yet have a production-grade audit path.

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

## Recommended operator checklist

- [ ] Policy bundle mounted read-only from ConfigMap or equivalent
- [ ] Secrets separated from policy documents
- [ ] Adapter wired into `src/agents/pi-tools.before-tool-call.ts`
- [ ] `wrapToolWithBeforeToolCallHook(...)` path used consistently for governed tools
- [ ] `review` decisions routed to a real approval process
- [ ] MCP tool definitions scanned before registration
- [ ] Post-call audits exported off-pod
- [ ] Governance sidecar or shared service kept off public ingress
- [ ] NetworkPolicies restrict egress to approved dependencies
- [ ] Runtime hardening enabled for the OpenClaw container
- [ ] Workload identity configured for Azure resource access

## Related

- [OpenClaw adapter guide](../integrations/openclaw-adapter.md)
- [OpenClaw package README](../../packages/agentmesh-integrations/openclaw-agentmesh/README.md)
- [OpenClaw sidecar pattern](openclaw-sidecar.md)
