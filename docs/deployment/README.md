# Deployment Guides

Deploy the Agent Governance Toolkit on any cloud or on-premises infrastructure.

> **No vendor lock-in** — AGT is pure Python/TypeScript/.NET/Rust/Go with zero cloud-vendor
> dependencies. It runs anywhere containers run.
>
> **Quick start:** `pip install agent-governance-toolkit[full]` — see the [main README](../../README.md) for local development.

---

## Choose Your Platform

### Azure

| Scenario | Guide | Best For |
|----------|-------|----------|
| **Azure Kubernetes Service (AKS)** | [AKS Sidecar Deployment](../../packages/agent-mesh/docs/deployment/azure.md) | Production multi-agent systems, enterprise HA |
| **Azure AI Foundry Agent Service** | [Foundry Integration](azure-foundry-agent-service.md) | Agents built with Azure AI Foundry |
| **Azure Container Apps** | [Container Apps](azure-container-apps.md) | Serverless, scale-to-zero scenarios |
| **OpenClaw on AKS** | [OpenClaw AKS Protection](openclaw-aks-protection.md) | Governing OpenClaw autonomous agents on AKS |
| **OpenClaw Sidecar Pattern** | [OpenClaw Sidecar](openclaw-sidecar.md) | HTTP sidecar deployment model for OpenClaw |

### AWS

| Scenario | Guide | Best For |
|----------|-------|----------|
| **AWS ECS / Fargate** | [ECS Deployment](aws-ecs.md) | Serverless containers, simple agent deployments |

### Google Cloud

| Scenario | Guide | Best For |
|----------|-------|----------|
| **Google Kubernetes Engine (GKE)** | [GKE Deployment](gcp-gke.md) | Production multi-agent on GKE |

### Self-Hosted / On-Premises

| Scenario | Guide | Best For |
|----------|-------|----------|
| **Docker Compose** | [OpenClaw Sidecar](openclaw-sidecar.md#quick-start-with-docker-compose) | Local development, testing |
| **Private Endpoints** | [Private Endpoints](private-endpoints.md) | Air-gapped / regulated environments |

---

## Architecture Overview

The toolkit supports three primary deployment patterns on any cloud:

```
┌────────────────────────────────────────────────────────────────────────┐
│  Any Cloud (Azure / AWS / GCP / On-Prem)                              │
│                                                                        │
│  ┌──────────────────┐  ┌──────────────────┐  ┌─────────────────────┐  │
│  │ Kubernetes (AKS/ │  │ Serverless (ACA/ │  │ Agent Framework     │  │
│  │ EKS/GKE)         │  │ Fargate/CloudRun)│  │ (Foundry/Bedrock/   │  │
│  │                  │  │                  │  │  Vertex)            │  │
│  │ ┌─────┐┌─────┐  │  │ ┌─────┐┌──────┐ │  │                     │  │
│  │ │Agent││Gov  │  │  │ │Agent││Gov   │ │  │  ┌─────────────┐   │  │
│  │ │     ││Side-│  │  │ │     ││Init/ │ │  │  │ Governance  │   │  │
│  │ │     ││car  │  │  │ │     ││Side  │ │  │  │ Middleware   │   │  │
│  │ └─────┘└─────┘  │  │ └─────┘└──────┘ │  │  └─────────────┘   │  │
│  │  Pod / Task      │  │  Container Group │  │   In-Process       │  │
│  └──────────────────┘  └──────────────────┘  └─────────────────────┘  │
│                                                                        │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ Shared: Secret Store │ Monitoring │ Identity Provider           │   │
│  │ (Key Vault / Secrets │ (CloudWatch│ (Managed ID / IAM Role /   │   │
│  │  Manager / Secret Mgr│  / Monitor)│  Workload Identity)        │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Which Option Should I Choose?

**Choose Kubernetes (AKS/EKS/GKE) if:**
- You need full control over networking, scaling, and pod configuration
- You're running multi-agent systems with sidecar-per-agent governance
- You require enterprise features: managed identity, secret stores, zone-redundant HA

**Choose Serverless (Container Apps/Fargate/Cloud Run) if:**
- You want scale-to-zero and simpler operational overhead
- You're running single-agent or small-scale scenarios
- You're prototyping before moving to Kubernetes for production

**Choose In-Process Middleware if:**
- You're using a managed agent framework (Azure AI Foundry, Bedrock, Vertex)
- You want zero sidecar overhead
- Your agents run as functions, not long-lived containers
