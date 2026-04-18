// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
export { AgentIdentity, IdentityRegistry, stripKeyPrefix, safeBase64Decode } from './identity';
export { TrustManager } from './trust';
export { PolicyEngine, PolicyConflictResolver } from './policy';
export type { PolicyDecision } from './policy';
export { AuditLogger } from './audit';
export { AgentMeshClient } from './client';
export { GovernanceMetrics } from './metrics';
/**
 * @deprecated Use `McpSecurityScannerV2` (7 threat types) instead. This legacy export
 * only detects 4 threat types. Will be removed in the next major version.
 */
export { McpSecurityScanner, McpThreatType } from './mcp';
/** @deprecated Use `McpThreatV2` / `McpScanResultV2` / `McpToolDefinitionV2` instead. */
export type { McpScanResult, McpThreat, McpToolDefinition } from './mcp';
export { LifecycleManager, LifecycleState } from './lifecycle';
export type { LifecycleEvent } from './lifecycle';

export {
  ConflictResolutionStrategy,
  PolicyScope,
} from './types';

export type {
  AgentIdentityJSON,
  IdentityStatus,
  TrustConfig,
  TrustScore,
  TrustTier,
  TrustVerificationResult,
  PolicyRule,
  Policy,
  PolicyAction,
  LegacyPolicyDecision,
  PolicyDecisionResult,
  CandidateDecision,
  ResolutionResult,
  AuditConfig,
  AuditEntry,
  AgentMeshConfig,
  GovernanceResult,
} from './types';

// ── MCP Governance Primitives ──

// Clock & nonce abstractions
export { SystemClock, FixedClock } from './mcp/clock';
export type { Clock } from './mcp/clock';
export { SystemNonceGenerator, DeterministicNonceGenerator } from './mcp/nonce';
export type { NonceGenerator } from './mcp/nonce';

// Persistence interfaces
export type {
  McpSessionStore,
  McpSessionRecord,
  McpNonceStore,
  McpRateLimitStore,
  McpRateLimitBucket,
  McpAuditSink,
  McpAuditRecord,
} from './mcp/stores';

// In-memory implementations
export {
  InMemorySessionStore,
  InMemoryNonceStore,
  InMemoryRateLimitStore,
  InMemoryAuditSink,
} from './mcp/memory-stores';

// Credential redactor
export { CredentialRedactor, CredentialKind } from './mcp/redactor';
export type { CredentialMatch, CredentialMatchRaw, RedactionResult } from './mcp/redactor';

// Response scanner
export { McpResponseScanner, McpResponseThreatType } from './mcp/response';
export type { McpResponseFinding, McpSanitizedResponse } from './mcp/response';

// Metrics
export {
  McpMetricsCollector,
  McpDecisionLabel,
  McpThreatLabel,
  McpScanLabel,
} from './mcp/metrics';
export type { McpMetricsSnapshot } from './mcp/metrics';