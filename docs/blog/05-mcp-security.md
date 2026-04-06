# MCP Security — Why Your AI Agent's Tool Calls Need a Firewall

The Model Context Protocol is becoming the standard for how AI agents interact with tools. Claude, GPT, LangChain, CrewAI, and dozens of other frameworks have adopted MCP as their tool integration layer. The protocol standardizes what was previously a fragmented landscape of custom adapters — agents discover tools from MCP servers, read their schemas, and invoke them through a common interface.

But MCP was designed for interoperability, not security. The protocol itself provides no authentication between clients and servers, no validation of tool parameters, no integrity checking of tool definitions, and no audit trail of what happened. Every tool call passes through unmediated — the equivalent of running network services without a firewall.

As adoption accelerated through 2025 and into 2026, the gap between MCP's capability and its security posture became increasingly clear — not through theoretical analysis, but through real incidents.

## The attack surface is real and growing

In July 2025, [CVE-2025-49596](https://thehackernews.com/2025/07/critical-vulnerability-in-anthropics.html) demonstrated that Anthropic's MCP Inspector — a developer tool used to test MCP servers — allowed remote code execution on developer machines through a CSRF exploit, scoring CVSS 9.4. A separate vulnerability in `mcp-remote` ([CVE-2025-6514](https://cybersecuritynews.com/critical-mcp-remote-vulnerability-exposes-llm-clients/)) allowed a malicious MCP server to compromise a client's host machine through command injection. Path traversal in the MCP Filesystem Server ([CVE-2025-53110](https://www.sentinelone.com/vulnerability-database/cve-2025-53110/)) enabled access to files outside intended directories.

The pattern continued into 2026. The TypeScript SDK ([CVE-2026-25536](https://www.cvedetails.com/cve/CVE-2026-25536/)) leaked data between clients when a server instance was shared. FastMCP ([CVE-2026-32871](https://www.wiz.io/vulnerability-database/cve/cve-2026-32871/)) exposed a server-side request forgery that allowed attackers to reach any backend endpoint through MCP's trusted network access. Both the Python and Go SDKs ([CVE-2025-66416](https://nvd.nist.gov/vuln/detail/CVE-2025-66416), [CVE-2026-34742](https://app.opencve.io/cve/CVE-2026-34742)) shipped without DNS rebinding protection, allowing browsers to issue requests to local MCP servers.

Beyond CVEs, [Invariant Labs documented](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) tool poisoning attacks where hidden instructions embedded in MCP tool descriptions exfiltrated enterprise credentials and SSH keys — the first such malicious package went undetected for two weeks. [Microsoft Defender research](https://techcommunity.microsoft.com/blog/microsoftdefendercloudblog/plug-play-and-prey-the-security-risks-of-the-model-context-protocol/4410829) ("Plug, Play, and Prey") identified over 1,800 MCP servers running without any authentication. An [Authzed breach timeline](https://authzed.com/blog/timeline-mcp-breaches) confirmed exposed customer data and production file systems.

The [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) now formalizes these risks into a standard taxonomy. Regulatory frameworks are adding pressure as well — the European Union AI Act's high-risk obligations take effect in August 2026, and many of its requirements around auditability and access control apply directly to agent-tool interactions.

## What a firewall for MCP looks like

Network firewalls solved a similar problem decades ago: untrusted traffic reaching services without mediation. The solution was to intercept every packet, apply rules, and deny by default. MCP tool calls need the same treatment — every call intercepted, every parameter validated, every tool definition verified, every action logged.

When we [introduced the Agent Governance Toolkit](https://opensource.microsoft.com/blog/2026/04/02/introducing-the-agent-governance-toolkit-open-source-runtime-security-for-ai-agents/) earlier this month, we described an OS-inspired architecture for governing autonomous AI agents. MCP security is a natural extension of that architecture — the same patterns that govern agent actions apply directly to the tool call path: intercept before execution, enforce deterministically, audit everything.

The [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) defines ten risk categories specific to MCP deployments. Our governance layers fully cover nine of the ten. The tenth — shadow MCP servers (MCP09) — is partially addressed through the governance proxy and trust scoring, with deeper server-discovery controls on the roadmap. The [full compliance mapping](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/MCP-OWASP-COMPLIANCE.md) documents coverage risk by risk. Here is how the ten risks break down by the type of defense they require:

**Risks in tool definitions — what the agent sees before it acts:**

- **Tool poisoning (MCP03)** — Adversarial modifications to tool descriptions using invisible unicode, HTML comments, or encoded payloads that redirect agent behavior. The LLM follows hidden instructions that human reviewers cannot see. A related pattern is the "rug pull," where a tool definition changes silently after initial review — the tool that was safe on Monday behaves differently on Wednesday.
- **Intent flow subversion (MCP06)** — Prompt injection patterns embedded in tool descriptions or responses that override agent instructions or redirect workflows. The security scanner detects these patterns in definitions, and the trust proxy's injection scanning catches them in tool arguments at runtime.
- **Context injection and over-sharing (MCP10)** — Tool responses that leak sensitive context, system prompts, or internal data back to the agent, which may then expose them downstream.

**Risks in tool execution — what happens when the agent acts:**

- **Command injection and execution (MCP05)** — Unsanitized tool parameters that reach server-side shell execution. Without parameter validation at the firewall layer, a filename parameter can become arbitrary code execution.
- **Privilege escalation via scope creep (MCP02)** — Agents accumulating tool access beyond their intended role over time, or tools granting broader permissions than declared.
- **Token mismanagement and secret exposure (MCP01)** — Hardcoded credentials in MCP server configurations, long-lived tokens in tool parameters, or secrets leaking through tool responses into logs. The credential redactor strips secrets from responses before they reach audit trails, and the response scanner detects credential patterns in tool outputs.

**Risks in the trust model — who is calling what, and can we verify it:**

- **Insufficient authentication and authorization (MCP07)** — MCP servers accepting connections without verifying client identity, or agents calling tools without scoped authorization.
- **Lack of audit and telemetry (MCP08)** — No structured record of which agent called which tool with what parameters, making incident investigation and compliance evidence impossible.
- **Shadow MCP servers (MCP09)** — Unauthorized or unregistered MCP servers operating outside governance controls, often introduced through development tooling or third-party integrations.
- **Software supply chain attacks (MCP04)** — Malicious MCP server packages distributed through registries, or compromised dependencies in the tool-serving infrastructure.

## Three layers of defense

The toolkit addresses these risks through three composable layers, each operating independently or together for defense in depth — the same layered approach that makes network security effective:

**Static analysis** inspects tool definitions before any tool is called. The security scanner detects poisoning, hidden instructions, prompt injection, schema abuse, and cross-server typosquatting. Tool fingerprinting with SHA-256 hashes enables rug-pull detection by comparing definitions across sessions — any change to a description or schema triggers a critical alert.

**Runtime gateway** intercepts every tool call through a five-stage evaluation pipeline: deny-list filtering, allow-list enforcement, parameter sanitization, per-agent rate limiting, and human-in-the-loop approval for sensitive operations. The gateway is fail-closed by design — an unexpected exception during evaluation denies the call rather than allowing it through.

**Trust-based authorization** gates tool access on decentralized identifier (DID) based agent identity and dynamic trust scores. Agents earn trust through successful operations and lose it on failures, with configurable per-tool score thresholds. When an agent's behavior degrades, its access to sensitive tools is revoked automatically without manual intervention.

## Native packages for every language

We are shipping MCP governance as standalone packages across all major ecosystems, bringing the same security model to teams regardless of their language:

- **Python** — `agent-mcp-governance` on PyPI
- **TypeScript** — `@microsoft/agentmesh-mcp-governance` on npm
- **.NET** — `Microsoft.AgentGovernance.Mcp` on NuGet
- **Rust** — `agentmesh-mcp` on crates.io
- **Go** — `mcp-governance-go` as a Go module

Each package includes the full security scanner, runtime gateway, trust proxy, rug-pull fingerprinting, and OWASP MCP Top 10 coverage. No framework dependency is required — the packages integrate with any MCP client or server. A CLI tool, `mcp-scan`, enables teams to integrate MCP security checks into CI pipelines and generate audit reports.

## Get started

The MCP governance components are part of the [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit), available on GitHub under the MIT license. The [MCP + Trust Verification Guide](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/integrations/mcp-trust-guide.md) walks through all four governance layers. [Tutorial 07](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/tutorials/07-mcp-security-gateway.md) provides a hands-on walkthrough of the security gateway, and [Tutorial 27](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/tutorials/27-mcp-scan-cli.md) covers the `mcp-scan` CLI. The [OWASP MCP Top 10 compliance mapping](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/MCP-OWASP-COMPLIANCE.md) documents risk-by-risk coverage.

For teams adopting incrementally: start with `mcp-scan` in CI to catch configuration issues, add the runtime gateway for parameter sanitization and rate limiting, and layer in trust-based authorization as multi-agent scenarios emerge.

MCP is the right standard for agent-tool communication. Standardization means the community can build security tooling that works across frameworks rather than per-vendor. But just as network services needed firewalls before they were safe to expose, MCP tool calls need a governance layer before they are safe to use in production. We built it in the open, and we welcome contributions.
