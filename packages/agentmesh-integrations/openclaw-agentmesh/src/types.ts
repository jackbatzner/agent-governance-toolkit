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

export interface OpenClawNativePluginLogger {
  info?(message: string, ...args: unknown[]): void;
  warn?(message: string, ...args: unknown[]): void;
  error?(message: string, ...args: unknown[]): void;
}

export interface OpenClawNativePluginHookOptions {
  priority?: number;
}

export interface OpenClawNativeBeforeToolCallEvent {
  toolName: string;
  params: Record<string, unknown>;
  runId?: string;
  toolCallId?: string;
}

export interface OpenClawNativeAfterToolCallEvent {
  toolName: string;
  params: Record<string, unknown>;
  runId?: string;
  toolCallId?: string;
  result?: unknown;
  error?: string;
  durationMs?: number;
}

export interface OpenClawNativeToolHookContext {
  agentId?: string;
  sessionKey?: string;
  sessionId?: string;
  runId?: string;
  toolName: string;
  toolCallId?: string;
}

export interface OpenClawNativeApprovalRequest {
  title: string;
  description: string;
  severity?: "info" | "warning" | "critical";
  timeoutMs?: number;
  timeoutBehavior?: "allow" | "deny";
  pluginId?: string;
  onResolution?: (decision: string) => Promise<void> | void;
}

export interface OpenClawNativeBeforeToolCallResult {
  params?: Record<string, unknown>;
  block?: boolean;
  blockReason?: string;
  requireApproval?: OpenClawNativeApprovalRequest;
}

export interface OpenClawNativePluginApi {
  pluginConfig?: Record<string, unknown>;
  logger?: OpenClawNativePluginLogger;
  registerHook: (
    events: string | string[],
    handler: (event: unknown, ctx: unknown) => Promise<unknown> | unknown,
    opts?: OpenClawNativePluginHookOptions,
  ) => void;
}

export interface OpenClawNativePluginConfig {
  policyFile?: string;
  policies?: Policy[];
  agentId?: string;
  agentDid?: string;
  failClosed?: boolean;
  audit?: {
    enabled?: boolean;
    stdout?: boolean;
    maxEntries?: number;
  };
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
