# @agentmesh/sdk

> [!IMPORTANT]
> **Public Preview** — This npm package is a Microsoft-signed public preview release.
> APIs may change before GA.

TypeScript SDK for [AgentMesh](../../README.md) — a governance-first framework for multi-agent systems.

Provides agent identity (Ed25519 DIDs), trust scoring, policy evaluation, hash-chain audit logging, and a unified `AgentMeshClient`.

## Installation

```bash
npm install @microsoft/agentmesh-sdk
```

For MCP-only workloads, install the standalone governance package instead:

```bash
npm install @microsoft/agentmesh-mcp-governance
```

## Quick Start

```typescript
import { AgentMeshClient } from '@microsoft/agentmesh-sdk';

const client = AgentMeshClient.create('my-agent', {
  capabilities: ['data.read', 'data.write'],
  policyRules: [
    { action: 'data.read', effect: 'allow' },
    { action: 'data.write', effect: 'allow', conditions: { role: 'admin' } },
    { action: '*', effect: 'deny' },
  ],
});

// Execute an action through the governance pipeline
const result = await client.executeWithGovernance('data.read');
console.log(result.decision);   // 'allow'
console.log(result.trustScore); // { overall: 0.5, tier: 'Provisional', ... }

// Verify the audit chain
console.log(client.audit.verify()); // true
```

## API Reference

### `AgentIdentity`

Manage agent identities built on Ed25519 key pairs.

```typescript
import { AgentIdentity } from '@microsoft/agentmesh-sdk';

const identity = AgentIdentity.generate('agent-1', ['read']);
const signature = identity.sign(new TextEncoder().encode('hello'));
identity.verify(new TextEncoder().encode('hello'), signature); // true

// Serialization
const json = identity.toJSON();
const restored = AgentIdentity.fromJSON(json);
```

### `TrustManager`

Track and score trust for peer agents.

```typescript
import { TrustManager } from '@microsoft/agentmesh-sdk';

const tm = new TrustManager({ initialScore: 0.5, decayFactor: 0.95 });

tm.recordSuccess('peer-1', 0.05);
tm.recordFailure('peer-1', 0.1);

const score = tm.getTrustScore('peer-1');
// { overall: 0.45, tier: 'Provisional', dimensions: { ... } }
```

### `PolicyEngine`

Rule-based policy evaluation with conditions and YAML support.

```typescript
import { PolicyEngine } from '@microsoft/agentmesh-sdk';

const engine = new PolicyEngine([
  { action: 'data.*', effect: 'allow' },
  { action: 'admin.*', effect: 'deny' },
]);

engine.evaluate('data.read');  // 'allow'
engine.evaluate('admin.nuke'); // 'deny'
engine.evaluate('unknown');    // 'deny' (default)

// Load additional rules from YAML
await engine.loadFromYAML('./policy.yaml');
```

### `AuditLogger`

Append-only audit log with hash-chain integrity verification.

```typescript
import { AuditLogger } from '@microsoft/agentmesh-sdk';

const logger = new AuditLogger();

logger.log({ agentId: 'agent-1', action: 'data.read', decision: 'allow' });
logger.log({ agentId: 'agent-1', action: 'data.write', decision: 'deny' });

logger.verify();  // true — chain is intact
logger.getEntries({ agentId: 'agent-1' }); // filtered results
logger.exportJSON(); // full log as JSON string
```

### `AgentMeshClient`

Unified client tying identity, trust, policy, and audit together.

```typescript
import { AgentMeshClient } from '@microsoft/agentmesh-sdk';

const client = AgentMeshClient.create('my-agent', {
  policyRules: [{ action: 'data.*', effect: 'allow' }],
});

const result = await client.executeWithGovernance('data.read', { user: 'alice' });
// result: { decision, trustScore, auditEntry, executionTime }
```

### MCP Security

Use the MCP security primitives to govern both tool definitions and runtime traffic.
You can access the same governance surface either from the full SDK or from the standalone MCP package.

#### Full SDK install

```typescript
import {
  ApprovalStatus,
  CredentialRedactor,
  MCPGateway,
  MCPMessageSigner,
  MCPResponseScanner,
  MCPSecurityScanner,
  MCPSessionAuthenticator,
  MCPSlidingRateLimiter,
} from '@microsoft/agentmesh-sdk';
```

#### Standalone MCP governance install

```typescript
import {
  ApprovalStatus,
  CredentialRedactor,
  MCPGateway,
  MCPMessageSigner,
  MCPResponseScanner,
  MCPSecurityScanner,
  MCPSessionAuthenticator,
  MCPSlidingRateLimiter,
} from '@microsoft/agentmesh-mcp-governance';
```

Both entry points expose the same MCP governance primitives; the standalone package has zero dependency on the rest of the AGT SDK.

```typescript
import {
  ApprovalStatus,
  CredentialRedactor,
  MCPGateway,
  MCPMessageSigner,
  MCPResponseScanner,
  MCPSecurityScanner,
  MCPSessionAuthenticator,
  MCPSlidingRateLimiter,
} from '@microsoft/agentmesh-sdk';

const responseScanner = new MCPResponseScanner();
const redactor = new CredentialRedactor();
const sessionAuth = new MCPSessionAuthenticator({
  secret: process.env.MCP_SESSION_SECRET!,
});
const messageSigner = new MCPMessageSigner({
  secret: process.env.MCP_SIGNING_SECRET!,
});
const rateLimiter = new MCPSlidingRateLimiter({
  maxRequests: 60,
  windowMs: 60_000,
});
const securityScanner = new MCPSecurityScanner();

const gateway = new MCPGateway({
  allowedTools: ['read_file', 'search_docs'],
  sensitiveTools: ['deploy'],
  rateLimiter,
  approvalHandler: async ({ toolName }) =>
    toolName === 'deploy'
      ? ApprovalStatus.Approved
      : ApprovalStatus.Pending,
});

const toolDecision = await gateway.evaluateToolCall('agent-1', 'read_file', {
  path: '/workspace/README.md',
});
const issuedSession = await sessionAuth.issueToken('agent-1');
const verifiedSession = await sessionAuth.verifyToken(
  issuedSession.token,
  'agent-1',
);
const signedMessage = messageSigner.sign({
  tool: 'read_file',
  args: { path: '/workspace/README.md' },
});
const verifiedMessage = await messageSigner.verify(signedMessage);
const toolThreats = securityScanner.scanTool(
  'read_file',
  'Read the contents of a file at the specified path.',
  {
    type: 'object',
    properties: { path: { type: 'string' } },
    required: ['path'],
    additionalProperties: false,
  },
  'filesystem-server',
);
const scannedResponse = responseScanner.scan({
  text: 'Search completed successfully.',
});
const redactedSecrets = redactor.redact({
  bearerToken: 'Bearer abcdefghijklmnop',
});
```

The MCP surface adds:

- **MCPResponseScanner** — strips and flags prompt-injection tags, imperative phrasing, credential leaks, and exfiltration URLs before tool output reaches an LLM
- **MCPSessionAuthenticator** — HMAC-backed session tokens bound to agent identity with TTL expiry and concurrent-session enforcement
- **MCPMessageSigner** — HMAC-SHA256 request signing with timestamps and nonce replay protection
- **CredentialRedactor** — secret redaction for strings and nested object graphs
- **MCPSlidingRateLimiter** — per-agent sliding-window rate limiting
- **MCPSecurityScanner** — tool metadata scanning for poisoning, rug pulls, cross-server attacks, description injection, and schema abuse
- **MCPGateway** — deny-list, allow-list, sanitization, rate limiting, and approval orchestration

> [!NOTE]
> The built-in nonce and session stores are in-memory and intended for single-process development or tests.
> In multi-replica or enterprise deployments, implement the provided store interfaces against durable shared storage and inject shared clock/nonce providers for deterministic behavior.

## Development

```bash
npm install
npm run build    # Compile TypeScript
npm test         # Run Jest tests
npm run lint     # Lint with ESLint
```

## License

Apache-2.0 — see [LICENSE](../../LICENSE).
