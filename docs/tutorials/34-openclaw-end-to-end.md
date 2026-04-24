# Tutorial 34 — Govern OpenClaw on AKS with Agent Governance Toolkit

> **Scenario:** Contoso customer support on AKS · **Packages:** `@microsoft/agentmesh-openclaw`, `@microsoft/agentmesh-sdk` · **Prerequisites:** OpenClaw checkout, Node.js 22+, Docker, Azure CLI, AKS access

Build and validate a full OpenClaw + AGT flow for a simulated Contoso support agent, then carry the same shape into AKS.

## Why this matters

In one sentence: this integration lets OpenClaw keep doing agent orchestration while AGT adds a governance gate in front of tool execution.

For a real team, that means you can:

1. allow low-risk tool calls automatically
2. require human approval for sensitive actions
3. block obviously unsafe actions before they run
4. keep audit evidence that explains what happened

This tutorial is the **follow-along path** for platform engineers and OpenClaw developers who want one place to cover:

1. installing the adapter and SDK
2. wiring the OpenClaw hook integration
3. scanning MCP tool definitions
4. exporting audits
5. building the OpenClaw deployment artifact
6. testing allow / deny / review behavior locally and on AKS

Use this with:

- the [OpenClaw adapter package README](../../packages/agentmesh-integrations/openclaw-agentmesh/README.md)
- the [OpenClaw advanced integration and operations guide](../integrations/openclaw-adapter.md)
- the [OpenClaw AKS protection appendix](../deployment/openclaw-aks-protection.md)

## What this integration helps with

This integration is useful when you want to add a governance decision point **before** OpenClaw executes a tool.

That gives you practical benefits:

1. one place to express allow / deny / review rules
2. a consistent way to pause sensitive actions for human approval
3. an audit trail around proposed and completed tool usage
4. early screening of MCP tool definitions before they are enabled

## What this integration does not do by itself

This guide is intentionally honest about the boundary:

1. AGT does **not** sandbox OpenClaw
2. AGT does **not** replace Kubernetes, network policy, secret management, or workload identity
3. AGT does **not** make a dangerous tool safe if the runtime still has another way to execute it
4. AGT does **not** ship a complete approval inbox or reviewer workflow for OpenClaw
5. MCP scanning is a **risk signal**, not a proof that a tool is safe

Treat AGT here as a **protective control in front of tool execution**, not as the only security boundary.

## What still needs to be done in a real deployment

Before calling this production-ready for your environment, most teams still need to:

1. prove the governed hook path is the only path to tool execution
2. put least-privilege credentials behind the tools OpenClaw can call
3. export audit records to a durable sink outside process memory
4. define who approves `review` decisions and how approval resumes execution
5. add runtime containment with container policy, filesystem controls, and network restrictions
6. run scenario tests for prompt injection, risky tool combinations, and policy bypass attempts

## Prerequisites

You need:

- a **runnable OpenClaw checkout**, which means you can install dependencies and start OpenClaw locally before adding AGT
- Node.js 22+
- an OpenClaw deployment where you can wire a hook handler into the existing tool interception path
- access to the underlying OpenClaw interception files and wrappers if your deployment does not already expose a hook registration point

In this tutorial:

- **runnable OpenClaw checkout** means "you can clone OpenClaw, install its dependencies, and start it locally"
- **maintaining OpenClaw itself** means "you are editing OpenClaw source code to add or change hook wiring"

Most readers only need a runnable checkout. You only need to maintain OpenClaw itself if your deployment does not already expose the hook path you need and you must wire it manually.

If you are also testing on AKS, you additionally need:

- either an existing AKS cluster **or** permission to create one in Step 6 of this tutorial
- Azure CLI installed and logged in with `az login`
- `kubectl` installed; if you are using an existing cluster, `kubectl config current-context` should already point to it
- Docker installed and a known image-build path for OpenClaw, such as an existing `Dockerfile` or container build command in the OpenClaw repo
- a place to store non-secret policy config and secret runtime credentials separately

### Before you continue

Complete these quick prerequisite checks first:

1. from your OpenClaw repo, run the normal install and start flow your checkout already uses
2. confirm OpenClaw starts before AGT is added
3. if you are using AKS, run `az login`
4. if you are using an **existing** AKS cluster, run `kubectl config current-context` and confirm it points to the cluster you expect
5. if you are using an existing AKS cluster, run `kubectl get nodes` to confirm cluster access
6. from your OpenClaw repo, confirm you know how the container image is built before you reach Step 5

Helpful follow-on guides:

- if you want the package-level setup details, use the [OpenClaw adapter package README](../../packages/agentmesh-integrations/openclaw-agentmesh/README.md)
- if you want the advanced hook and extension model, use the [OpenClaw advanced integration and operations guide](../integrations/openclaw-adapter.md)
- if you want the AKS hardening details after deployment works, use the [OpenClaw AKS protection appendix](../deployment/openclaw-aks-protection.md)

### OpenClaw setup for this tutorial

Start with the official OpenClaw docs if you still need to install or run OpenClaw itself:

- [OpenClaw getting started](https://docs.openclaw.ai/start/getting-started)
- [OpenClaw plugin guide](https://docs.openclaw.ai/plugins/building-plugins)

For this tutorial, the OpenClaw-specific changes are:

1. install the AGT plugin package into OpenClaw
2. add `config/openclaw-governance.policies.json`
3. add a hook bootstrap module that loads the AGT adapter and processes OpenClaw hook events
4. add the AKS manifests under `deploy/aks/` if you are deploying to Kubernetes

This tutorial assumes you start OpenClaw using the normal command for your checkout. Do that first, confirm it runs, then come back and add the AGT-specific files in this guide.

### Where to run commands

- run the OpenClaw install, config, and Docker commands from your **OpenClaw repo**
- run the `kubectl apply -f deploy/aks/...` commands from the **OpenClaw repo root** if you copy the manifest layout from this tutorial
- if you run `kubectl` from another directory, use full paths to the manifest files instead of the relative `deploy/aks/...` paths shown here

### Suggested local folder layout

If you are new to this, keep the repos side by side so the source-install examples work cleanly:

```text
workspace/
  openclaw/
  agent-governance-toolkit/
```

Then run the local package-install commands from the `openclaw/` repo.

## What you'll learn

| Section | What you'll do |
|---|---|
| [Scenario](#scenario) | Understand the Contoso support-agent story used across all OpenClaw docs |
| [Guide map](#guide-map) | Follow the docs in the right order |
| [Architecture](#architecture) | Understand where OpenClaw, AGT, and AKS each fit |
| [Steps 1-4](#step-1-install-the-package) | Install the package, add policy, wire the hook handler, and validate governance locally |
| [Steps 5-10](#step-5-build-the-openclaw-image) | Build the image, provision ACR and AKS, deploy, and validate with natural-language prompts |
| [Next steps](#next-steps) | Extend the baseline with sidecars, extra hooks, and AKS hardening |

## Scenario

Contoso runs an OpenClaw-based customer support assistant. The assistant helps support engineers:

1. read internal runbooks
2. search support knowledge sources
3. write case summaries
4. run limited diagnostics when an engineer explicitly asks for them

Contoso wants three things before putting that assistant on AKS:

1. **safe defaults** so normal read-only actions can continue
2. **human approval** for sensitive actions such as shell access
3. **hard blocks** for actions that should never run, such as writing into secret-mounted paths

That is the story this tutorial implements from start to finish.

## Guide map

Use the OpenClaw docs in this order:

1. **This tutorial** for the golden path: install, configure, build, deploy, test, and validate.
2. [**OpenClaw advanced integration and operations guide**](../integrations/openclaw-adapter.md) when you want follow-on guidance by audience: OpenClaw maintainers, platform engineers, AGT owners, and advanced operators.
3. [**OpenClaw AKS protection appendix**](../deployment/openclaw-aks-protection.md) only when you need the extra AKS hardening details referenced by the advanced guide.

If you only want one document to follow from start to finish, stay in this tutorial first and use the other two pages as sub-guides when this tutorial points to them.

## Architecture

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

## AGT primitives used in this tutorial

These are the main AGT building blocks you are wiring into OpenClaw:

| Primitive | What it does in this flow |
|---|---|
| **`PolicyEngine`** | Evaluates the proposed tool call against your policy bundle and decides whether the call should be allowed, denied, or sent for approval |
| **`AuditLogger`** | Records governance evidence before and after tool execution so operators can explain what happened later |
| **`McpSecurityScanner`** | Reviews MCP tool definitions before they are registered so obviously risky tool metadata can be flagged early |
| **`AgentIdentity`**-style fields (`agentId`, `agentDid`) | Give AGT a stable logical actor identity so decisions and audits are tied to the right agent, not just the pod or process |

That means AGT is not replacing OpenClaw's runtime. It is supplying the governance layer that evaluates the tool call, emits evidence, and adds pre-registration scanning.

## Terms in plain English

| Term | Plain-English meaning |
|---|---|
| **tool call** | The concrete action OpenClaw is about to run, such as `read_file`, `shell`, or `write_file` |
| **policy bundle** | The JSON rules that tell AGT what to allow, deny, or send for approval |
| **review** | AGT decided the tool call should pause for human approval instead of running immediately |
| **MCP tool definition** | The metadata that describes a tool before the agent starts using it |
| **agentId / agentDid** | The logical identity of the agent making the request, used for policy and audit records |
| **workload identity** | The Kubernetes/Azure identity the pod uses to reach cloud resources |

## Step 1: install the package

For the primary walkthrough, install the package into the OpenClaw app:

```bash
npm install @microsoft/agentmesh-openclaw @microsoft/agentmesh-sdk
```

> **Note:** If you are doing local source development against the AGT repo, use the package README for the alternate install shapes. The main tutorial keeps a single installation path so the walkthrough stays linear.

### Quick success check

You are done with this step when:

1. the package is installed into the OpenClaw environment
2. the OpenClaw runtime can resolve the package
3. you are ready to configure the plugin against a real policy file

What you should see:

- the install command completes without package-resolution errors
- the package is available to the runtime before you start configuration

## Step 2: add a policy bundle to the OpenClaw repo

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

What AGT is doing here:

- the adapter loads this bundle into **`PolicyEngine`**
- `default_action: "deny"` makes the integration fail closed when no rule explicitly allows the tool call
- each rule evaluates the **proposed tool call** that OpenClaw is about to execute, not the raw user message
- the result is later translated into OpenClaw's native `allow`, `deny`, or `review` flow

### Quick success check

You are done with this step when:

1. the file exists in your OpenClaw checkout at the path you intend to mount or reference
2. the JSON parses cleanly
3. you can point at one rule that should **allow**, one that should **review**, and one that should **deny**

What you should see:

- no parser errors
- a file path you can reuse unchanged in local config and AKS manifests

## Step 3: configure the OpenClaw plugin

The package now ships a real OpenClaw plugin entry and manifest. Point the plugin at the policy bundle in your OpenClaw config:

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

The native plugin entry then:

1. loads the configured JSON policy bundle
2. registers `before_tool_call`
3. maps AGT decisions into OpenClaw `allow | deny | review`
4. registers `after_tool_call` for audit logging when audit is enabled

What AGT is doing here:

- `policyFile` tells the adapter where to load the policy bundle for **`PolicyEngine`**
- `agentId` and `agentDid` give AGT a stable logical identity for policy evaluation and audit records
- `audit.enabled` turns on **`AuditLogger`** so the plugin can record both the decision point and the final outcome
- `audit.stdout` is the simplest production handoff because AKS and other platforms already know how to collect stdout centrally
- the plugin is intended to **fail closed** if policy evaluation cannot complete cleanly; do not treat governance errors as implicit allows

Compatibility note:

- use the native plugin path first
- if your checkout needs source edits, fall back to the underlying `before_tool_call` / `after_tool_call` interception point rather than inventing a second governance path
- the lower-level hook helpers are still available for custom runtimes and tests

### Quick success check

You are done with this step when:

1. the OpenClaw config includes the `agentmesh-openclaw` plugin entry
2. `policyFile` points to the same policy file you created in Step 2
3. you have intentionally chosen values for `agentId`, `agentDid`, and audit settings instead of leaving them ambiguous

What you should see:

- OpenClaw starts without plugin-load errors
- the plugin can find the policy file at runtime

## Step 4: validate governance locally

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

### Quick success check

You are done with this step when:

1. the adapter package builds and tests successfully in the AGT repo
2. your OpenClaw checkout installs with the adapter present
3. the OpenClaw app starts without hook-loading or module-resolution errors

What you should see:

- a clean AGT package test/build run
- no module-resolution errors in OpenClaw startup

### Test the governance outcomes locally

Use a small validation matrix before you build a container:

| Scenario | Expected result |
|---|---|
| `read_file` on a normal path | `allow` |
| `shell` | `review` |
| `write_file` into `/secrets/...` | `deny` |
| poisoned MCP tool description | `review` or `deny`, depending on your handling policy |

### Contoso support prompts to send

OpenClaw translates user messages into tool calls. That means you should test by sending **user requests that are likely to cause the governed tool call**, not by trying to call the plugin directly.

Use a simple customer-support scenario where the agent has access to tools such as `read_file`, `search_web`, `write_file`, and `shell`.

This matters because AGT is sitting on the **tool boundary**:

1. the user sends a normal natural-language message
2. OpenClaw decides which tool it wants to invoke
3. AGT evaluates that proposed tool call
4. OpenClaw either executes, pauses for approval, or blocks the call

So the correct demo is always "send a user message and watch the governed tool decision," not "call AGT directly."

### How to send the Contoso prompts

Use the same user-input path you normally use to talk to OpenClaw:

1. if you are testing locally through the default OpenClaw dashboard, start OpenClaw and open `http://127.0.0.1:18789/`
2. open the chat or session surface that talks to your configured agent
3. paste the Contoso prompt exactly as written and send it like a normal user message

If your OpenClaw deployment is using another surface, such as WebChat, a messaging channel, or a custom API client, send the same natural-language text through that surface. The important thing is that OpenClaw receives a normal user message and decides which tool to call.

#### Demo 1: summarize the Contoso password reset runbook

Send a message like:

```text
A Contoso customer says they cannot complete the password reset flow. Open the support runbook in README.md and summarize the first three steps I should send back.
```

Expected behavior:

- OpenClaw should decide to use a read-oriented tool such as `read_file`
- the plugin should return `allow`
- the tool should run normally

#### Demo 2: request a diagnostic shell command

Send a message like:

```text
I think this is a permissions issue. Run a shell command to show which Linux user the Contoso support container is running as.
```

Expected behavior:

- OpenClaw should decide to use `shell`
- the plugin should return `review`
- OpenClaw should stop execution and route into its native approval flow instead of running the command immediately

#### Demo 3: attempt to write into a protected path

Send a message like:

```text
Write the current Contoso escalation notes into /secrets/escalation-notes.txt so we can reuse them later.
```

Expected behavior:

- OpenClaw should decide to use `write_file`
- the plugin should evaluate the proposed tool call
- because the path starts with `/secrets/`, the plugin should return `deny`
- OpenClaw should block the tool call and surface the deny reason

#### Demo 4: write a normal case summary

Send a message like:

```text
Write today's Contoso case summary into ./notes/case-4821-summary.txt.
```

Expected behavior depends on your policy:

- with the sample policy in this tutorial, the default is `deny` unless you add an allow rule for normal writes
- this is a good sanity check that your rules are doing what you think, instead of accidentally allowing all writes

### What you should verify in the demo

For each prompt, verify all of the following:

1. the user message causes the expected OpenClaw tool selection
2. the plugin decision matches the policy (`allow`, `deny`, or `review`)
3. approval-required calls do not execute before approval
4. audit output includes the tool name and final decision

## Step 5: build the OpenClaw image

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

### Quick success check

You are done with this step when:

1. the container image builds successfully
2. the built image includes both `@microsoft/agentmesh-openclaw` and `@microsoft/agentmesh-sdk`
3. a local container run can still start OpenClaw with the plugin enabled

What you should see:

- the container starts the same way your local app did
- no missing dependency or missing config-file errors

## Step 6: provision Azure resources for AKS

If you do not already have an AKS environment, create one first.

### 10.1 Create the resource group

```bash
az group create \
  --name rg-openclaw-demo \
  --location eastus
```

### 10.2 Create Azure Container Registry

```bash
az acr create \
  --resource-group rg-openclaw-demo \
  --name openclawdemoregistry \
  --sku Basic
```

### 10.3 Create the AKS cluster

```bash
az aks create \
  --resource-group rg-openclaw-demo \
  --name aks-openclaw-demo \
  --node-count 2 \
  --enable-managed-identity \
  --attach-acr openclawdemoregistry \
  --generate-ssh-keys
```

### 10.4 Get cluster credentials

```bash
az aks get-credentials \
  --resource-group rg-openclaw-demo \
  --name aks-openclaw-demo
```

At this point you have:

- a resource group
- an ACR registry for your OpenClaw image
- an AKS cluster that can pull from that registry

### Quick success check

You are done with this step when:

1. `az group show`, `az acr show`, and `az aks show` all succeed for the names you created
2. `kubectl config current-context` points at the AKS cluster you intend to use
3. you know which subscription, region, and resource group own this demo environment

What you should see:

- Azure resources in the expected region
- `kubectl get nodes` returning your AKS nodes

## Step 7: push the OpenClaw image to ACR

Tag the image you built locally:

```bash
docker tag contoso/openclaw-governed:dev \
  openclawdemoregistry.azurecr.io/openclaw-governed:demo
```

Log in to ACR:

```bash
az acr login --name openclawdemoregistry
```

Push the image:

```bash
docker push openclawdemoregistry.azurecr.io/openclaw-governed:demo
```

If you prefer cloud builds, replace the local push flow with `az acr build`.

### Quick success check

You are done with this step when:

1. the image tag you plan to deploy exists in ACR
2. the image name in Kubernetes manifests matches the image you pushed
3. the AKS cluster has permission to pull from that registry

What you should see:

- the pushed tag visible in ACR
- no image-pull failures during later deployment

## Step 8: prepare Kubernetes configuration

For AKS, keep the local shape but move configuration into Kubernetes objects.

Create a manifest folder in your OpenClaw repo so the examples stay organized:

```text
deploy/
  aks/
    namespace.yaml
    serviceaccount.yaml
    openclaw-governance-policies.yaml
    openclaw-config.yaml
    openclaw-secrets.yaml
    openclaw-deployment.yaml
    openclaw-service.yaml
    openclaw-ingress.yaml
```

### 12.1 What gets deployed where

For the simplest production-style deployment:

- **OpenClaw container image** contains:
  - your normal OpenClaw application
  - `@microsoft/agentmesh-openclaw`
  - `@microsoft/agentmesh-sdk`
- **ConfigMap** contains:
  - `openclaw-governance.policies.json`
- **OpenClaw runtime config** contains:
  - the hook bootstrap module path or startup wiring your OpenClaw build already uses
  - optional `agentId`, `agentDid`, and audit settings
- **Log pipeline** collects:
  - stdout audit events when `audit.stdout` is enabled

That means the adapter is usually deployed **inside the same OpenClaw pod and container**, not as a separate AKS workload.

If you later choose a sidecar or central governance service, that is an additional architecture choice on top of the in-process hook integration, not a replacement for the basic deployment shape.

What AGT is doing in this pod:

- **`PolicyEngine`** runs in-process before OpenClaw executes the tool
- **`AuditLogger`** emits decision and outcome records from the same workload
- **`McpSecurityScanner`** is something you run during tool registration or startup, not as a separate long-running service by default
- `agentId` / `agentDid` identify the logical OpenClaw agent, while AKS identity still controls the pod's access to Azure resources

### Quick success check

You are done with this step when:

1. policy JSON, runtime config, and secrets are split into the right Kubernetes object types
2. the deployment mounts the policy file read-only
3. the runtime config still points at the mounted policy path inside the container

What you should see:

- one clear home for policy, one for runtime config, and one for secrets
- mounted paths that match the values in the config examples exactly

### 12.2 Namespace

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: openclaw-demo
```

### 12.3 ConfigMap for policy

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

### 12.4 ConfigMap for OpenClaw hook settings

The exact OpenClaw bootstrap file varies by deployment. The important part is that the running workload passes the policy path and identity settings into the hook module you wired in Step 3.

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: openclaw-config
  namespace: openclaw-demo
data:
  AGT_POLICY_FILE: /app/config/governance/openclaw-governance.policies.json
  AGT_AGENT_ID: openclaw-main-agent
  AGT_AGENT_DID: did:agentmesh:openclaw-main-agent
  AGT_AUDIT_STDOUT: "true"
  AGT_AUDIT_MAX_ENTRIES: "5000"
```

### 12.5 Secret for real credentials

This is where API keys or approval-service secrets go. Do **not** put normal policy rules in a Secret.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: openclaw-secrets
  namespace: openclaw-demo
type: Opaque
stringData:
  OPENAI_API_KEY: "<replace-me>"
```

### 12.5a ServiceAccount for workload identity

If you plan to use Azure Workload Identity, create a ServiceAccount now and reuse it in the Deployment:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: openclaw
  namespace: openclaw-demo
  annotations:
    azure.workload.identity/client-id: "<managed-identity-client-id>"
```

### 12.6 Deployment

This example assumes your OpenClaw image loads a hook module that can read governance settings from environment variables. Adjust the startup command or bootstrap path if your OpenClaw image expects a different mechanism.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: openclaw
  namespace: openclaw-demo
spec:
  replicas: 1
  selector:
    matchLabels:
      app: openclaw
  template:
    metadata:
      labels:
        app: openclaw
    spec:
      serviceAccountName: openclaw
      securityContext:
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: openclaw
          image: openclawdemoregistry.azurecr.io/openclaw-governed:demo
          ports:
            - containerPort: 3000
          resources:
            requests:
              cpu: "250m"
              memory: "512Mi"
            limits:
              cpu: "1"
              memory: "1Gi"
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            capabilities:
              drop:
                - ALL
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
          env:
            - name: OPENAI_API_KEY
              valueFrom:
                secretKeyRef:
                  name: openclaw-secrets
                  key: OPENAI_API_KEY
            - name: NODE_ENV
              value: "production"
            - name: AGT_POLICY_FILE
              valueFrom:
                configMapKeyRef:
                  name: openclaw-config
                  key: AGT_POLICY_FILE
            - name: AGT_AGENT_ID
              valueFrom:
                configMapKeyRef:
                  name: openclaw-config
                  key: AGT_AGENT_ID
            - name: AGT_AGENT_DID
              valueFrom:
                configMapKeyRef:
                  name: openclaw-config
                  key: AGT_AGENT_DID
            - name: AGT_AUDIT_STDOUT
              valueFrom:
                configMapKeyRef:
                  name: openclaw-config
                  key: AGT_AUDIT_STDOUT
            - name: AGT_AUDIT_MAX_ENTRIES
              valueFrom:
                configMapKeyRef:
                  name: openclaw-config
                  key: AGT_AUDIT_MAX_ENTRIES
          volumeMounts:
            - name: governance-policies
              mountPath: /app/config/governance
              readOnly: true
      volumes:
        - name: governance-policies
          configMap:
            name: openclaw-governance-policies
```

If your OpenClaw runtime does not expose `/healthz` and `/readyz`, replace those probe paths with whatever health mechanism your deployment already supports.

### 12.7 Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: openclaw
  namespace: openclaw-demo
spec:
  selector:
    app: openclaw
  ports:
    - port: 80
      targetPort: 3000
  type: ClusterIP
```

### 12.8 Optional ingress

Only add ingress if your OpenClaw deployment should be reachable externally.

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: openclaw
  namespace: openclaw-demo
spec:
  rules:
    - host: openclaw-demo.contoso.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: openclaw
                port:
                  number: 80
```

For the full AKS operational guidance, use the [OpenClaw AKS protection appendix](../deployment/openclaw-aks-protection.md).

## Step 9: deploy to AKS

Apply the manifests in order:

```bash
kubectl apply -f deploy/aks/namespace.yaml
kubectl apply -f deploy/aks/serviceaccount.yaml
kubectl apply -f deploy/aks/openclaw-governance-policies.yaml
kubectl apply -f deploy/aks/openclaw-config.yaml
kubectl apply -f deploy/aks/openclaw-secrets.yaml
kubectl apply -f deploy/aks/openclaw-deployment.yaml
kubectl apply -f deploy/aks/openclaw-service.yaml
```

If you are exposing the service publicly:

```bash
kubectl apply -f deploy/aks/openclaw-ingress.yaml
```

Wait for rollout:

```bash
kubectl rollout status deployment/openclaw -n openclaw-demo
```

Check pods:

```bash
kubectl get pods -n openclaw-demo
```

Inspect logs:

```bash
kubectl logs deployment/openclaw -n openclaw-demo
```

### Quick success check

You are done with this step when:

1. the Deployment rolls out successfully
2. the pod reaches a healthy running state
3. the logs show OpenClaw starting with the governance plugin instead of failing on config or module load

What you should see:

- `kubectl get pods` shows the pod as running
- `kubectl describe pod` does not show repeated restart or image-pull failures

## Step 10: validate on AKS

Before calling this production-ready, confirm:

1. the OpenClaw pod starts with the adapter enabled
2. the policy bundle is mounted read-only
3. `allow`, `deny`, and `review` behavior still matches local tests
4. audit output leaves the pod and reaches your log sink
5. any governance sidecar or shared service stays internal-only
6. workload identity or service auth works for any Azure dependencies

### 14.1 AKS demo path

Use the same Contoso support prompts from **Step 4** after deployment:

1. send the safe read-only request and confirm `allow`
2. send the shell request and confirm `review`
3. send the `/secrets/...` write request and confirm `deny`
4. inspect pod logs or your central log sink to confirm the audit trail appears off-pod

### 14.2 What success looks like

At the end of the demo, you should be able to show:

1. **User-visible allow**  
   OpenClaw completes the safe read-only request.
2. **User-visible review**  
   OpenClaw pauses the shell request and requires approval.
3. **User-visible deny**  
   OpenClaw blocks the `/secrets/...` write request before execution.
4. **Operator-visible evidence**  
   Kubernetes logs or your central logging system show the audit trail.
5. **Platform-visible controls**  
   The policy file is mounted read-only and secrets are separated from governance rules.

If you want to productionize the AKS side after the demo, continue with the [AKS hardening appendix](../deployment/openclaw-aks-protection.md#aks-hardening-appendix).

## Troubleshooting

Use this table when the baseline Contoso walkthrough does not behave as expected.

| Symptom | Likely cause | What to check |
|---|---|---|
| OpenClaw starts without governance behavior | Hook handler not loaded or not called from the real interception path | Confirm your OpenClaw hook bootstrap module is loaded and that `onInternalHookEvent(...)` is wired into the real tool hook |
| OpenClaw fails at startup with module or hook errors | Missing package or wrong runtime path | Re-run install, confirm Node.js version, and verify the hook module path your OpenClaw runtime expects |
| Every tool call is denied | Policy bundle not found, malformed, or too restrictive | Confirm `policyFile` path, validate JSON, and check whether `default_action: "deny"` has any matching allow rules |
| Review never happens for shell calls | Policy rule mismatch or wrong tool name | Confirm the actual OpenClaw tool name and match it against the `review-shell` rule |
| Writes to `/secrets/...` are not denied | Rule condition does not match the real parameter shape | Inspect the actual tool-call payload and verify the path field is really `params.path` |
| MCP scanning does nothing | Scan helper is not wired into registration | Confirm `scanMcpToolDefinition()` runs before the tool is added to the catalog |
| Pod starts but restarts repeatedly | Probe paths, startup command, or mounted config path mismatch | Check `kubectl describe pod`, probe endpoints, and whether `/app/config/openclaw.config.json` exists in the container |
| Image pull fails on AKS | ACR auth or image tag mismatch | Confirm the pushed tag exists and the cluster is attached to the registry |
| No audit evidence after a tool call | Audit enabled but not exported or not wired after execution | Confirm `audit.enabled`, `audit.stdout`, and that `after_tool_call` or `recordAfterToolCall()` is actually invoked |

## Reference links

Use these when you need the underlying contract instead of the walkthrough:

- [OpenClaw package README](../../packages/agentmesh-integrations/openclaw-agentmesh/README.md)
- [Package install and setup checklist](../../packages/agentmesh-integrations/openclaw-agentmesh/README.md#setup-checklist)
- [Native plugin enablement](../../packages/agentmesh-integrations/openclaw-agentmesh/README.md#2-enable-the-native-openclaw-plugin)
- [Manual hook registration](../../packages/agentmesh-integrations/openclaw-agentmesh/README.md#3-advanced-register-hooks-manually)
- [Review and approval handling](../../packages/agentmesh-integrations/openclaw-agentmesh/README.md#5-wire-review-and-approval-handling)
- [MCP scanning](../../packages/agentmesh-integrations/openclaw-agentmesh/README.md#6-enable-mcp-tool-definition-scanning-before-registration)
- [Post-call audit](../../packages/agentmesh-integrations/openclaw-agentmesh/README.md#7-record-post-call-audit-events)
- [Package API](../../packages/agentmesh-integrations/openclaw-agentmesh/README.md#api)
- [Public types](../../packages/agentmesh-integrations/openclaw-agentmesh/src/types.ts)
- [Hook wiring examples](../../packages/agentmesh-integrations/openclaw-agentmesh/README.md#2-wire-the-openclaw-hook)

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
- [OpenClaw advanced integration and operations guide](../integrations/openclaw-adapter.md)
- [OpenClaw AKS protection appendix](../deployment/openclaw-aks-protection.md)

## What this tutorial does not automate

This tutorial now gives you a full step-by-step deployment shape, but you still own:

- the exact OpenClaw startup command for your image
- the approval UX and resume flow
- durable audit export
- final production manifest hardening, ingress, scaling, and network controls

That is intentional. AGT acts as the governance layer in front of tool execution, but OpenClaw and your platform still own the rest of the runtime.

## Next steps

After you complete the baseline Contoso walkthrough:

1. use the [OpenClaw advanced integration and operations guide](../integrations/openclaw-adapter.md) to add **manual hook wrappers**, **MCP registration scanning**, **post-call audit customization**, or a **sidecar-backed architecture**
2. use the [OpenClaw AKS protection appendix](../deployment/openclaw-aks-protection.md) when you need the extra **hardening**, **network policy**, **secret-delivery**, and **progressive rollout** details
3. if you want a pod-local governance API in addition to in-process enforcement, continue to the [OpenClaw sidecar pattern](../deployment/openclaw-sidecar.md)
