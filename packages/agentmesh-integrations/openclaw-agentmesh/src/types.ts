// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import type {
  AuditConfig,
  AuditEntry,
  ConflictResolutionStrategy,
  Policy,
  PolicyDecisionResult,
} from "@microsoft/agentmesh-sdk/types";
import type {
  McpScanResult,
  McpThreat,
  McpToolDefinition,
} from "@microsoft/agentmesh-sdk/mcp";

export interface OpenClawAgentIdentity {
  did?: string;
  name?: string;
}

export type OpenClawGovernanceDecision = "allow" | "deny" | "review";

export interface OpenClawPolicyEngine {
  evaluatePolicy(agentDid: string, context: Record<string, unknown>): PolicyDecisionResult;
  loadPolicy?(policy: Policy): void;
}

export interface OpenClawAuditLogger {
  log(entry: Omit<AuditEntry, "timestamp" | "hash" | "previousHash">): AuditEntry;
}

export interface OpenClawMcpScanner {
  scan(toolDefinition: McpToolDefinition): McpScanResult;
  scanAll?(tools: McpToolDefinition[]): McpScanResult[];
}

export interface OpenClawBeforeToolCallInput {
  toolName: string;
  params: Record<string, unknown>;
  toolDescription?: string;
  requestId?: string;
  sessionId?: string;
  userId?: string;
  agentId?: string;
  agentDid?: string;
  metadata?: Record<string, unknown>;
  runtimeContext?: Record<string, unknown>;
}

export interface OpenClawAfterToolCallInput {
  toolName: string;
  params?: Record<string, unknown>;
  result?: unknown;
  error?: unknown;
  durationMs?: number;
  requestId?: string;
  sessionId?: string;
  userId?: string;
  agentId?: string;
  agentDid?: string;
  metadata?: Record<string, unknown>;
}

export interface OpenClawBeforeToolCallResult {
  decision: OpenClawGovernanceDecision;
  allowed: boolean;
  reason?: string;
  matchedRule?: string;
  policyName?: string;
  approvers: string[];
  rewrittenParams?: Record<string, unknown>;
  auditEntry?: AuditEntry;
  policyDecision?: PolicyDecisionResult;
  source: "policy" | "policy_error" | "audit_error";
}

export interface OpenClawAfterToolCallResult {
  decision: OpenClawGovernanceDecision;
  action: "complete" | "error";
  logged: boolean;
  auditEntry: AuditEntry;
}

export interface OpenClawMcpScanResult extends McpScanResult {
  recommendedDecision: OpenClawGovernanceDecision;
  findings: McpThreat[];
}

export interface OpenClawGovernanceAdapterConfig {
  agentId?: string;
  agentDid?: string;
  agentIdentity?: OpenClawAgentIdentity;
  policies?: Policy[];
  policyEngine?: OpenClawPolicyEngine;
  conflictStrategy?: ConflictResolutionStrategy;
  audit?: {
    enabled?: boolean;
    logger?: OpenClawAuditLogger;
    config?: AuditConfig;
  };
  mcpScanner?: OpenClawMcpScanner;
  failClosed?: boolean;
  rewriteParams?: (
    input: OpenClawBeforeToolCallInput,
    policyDecision: PolicyDecisionResult,
  ) =>
    | Promise<Record<string, unknown> | undefined>
    | Record<string, unknown>
    | undefined;
}

export interface OpenClawGovernanceAdapter {
  readonly policyEngine: OpenClawPolicyEngine;
  readonly auditLogger: OpenClawAuditLogger | null;
  readonly mcpScanner: OpenClawMcpScanner;
  evaluateBeforeToolCall(input: OpenClawBeforeToolCallInput): Promise<OpenClawBeforeToolCallResult>;
  recordAfterToolCall(input: OpenClawAfterToolCallInput): Promise<OpenClawAfterToolCallResult>;
  scanMcpToolDefinition(toolDefinition: McpToolDefinition): OpenClawMcpScanResult;
  scanMcpToolDefinitions(toolDefinitions: McpToolDefinition[]): OpenClawMcpScanResult[];
}
