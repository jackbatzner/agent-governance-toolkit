// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { AuditLogger } from "@microsoft/agentmesh-sdk/audit";
import { McpSecurityScanner, type McpToolDefinition } from "@microsoft/agentmesh-sdk/mcp";
import { PolicyEngine } from "@microsoft/agentmesh-sdk/policy";
import type { PolicyDecisionResult } from "@microsoft/agentmesh-sdk/types";
import { recordAuditEntry } from "./audit";
import {
  OpenClawGovernanceAuditError,
  OpenClawGovernanceConfigError,
  OpenClawGovernanceError,
} from "./errors";
import { scanMcpToolDefinition, scanMcpToolDefinitions } from "./mcp-scan";
import { isExecutionAllowed, mapPolicyDecisionToOpenClawDecision } from "./policy-mapping";
import type {
  OpenClawAfterToolCallInput,
  OpenClawAfterToolCallResult,
  OpenClawBeforeToolCallInput,
  OpenClawBeforeToolCallResult,
  OpenClawGovernanceAdapter,
  OpenClawGovernanceAdapterConfig,
  OpenClawGovernanceDecision,
  OpenClawMcpScanResult,
  OpenClawPolicyEngine,
} from "./types";

interface ResolvedAdapterRuntime {
  agentId?: string;
  agentDid?: string;
  policyEngine: OpenClawPolicyEngine;
  auditLogger: OpenClawGovernanceAdapter["auditLogger"];
  mcpScanner: OpenClawGovernanceAdapter["mcpScanner"];
  failClosed: boolean;
  rewriteParams?: OpenClawGovernanceAdapterConfig["rewriteParams"];
}

export function createOpenClawGovernanceAdapter(
  config: OpenClawGovernanceAdapterConfig,
): OpenClawGovernanceAdapter {
  const runtime = resolveRuntime(config);

  return {
    policyEngine: runtime.policyEngine,
    auditLogger: runtime.auditLogger,
    mcpScanner: runtime.mcpScanner,
    evaluateBeforeToolCall: (input) => evaluateBeforeToolCallInternal(input, runtime),
    recordAfterToolCall: (input) => recordAfterToolCallInternal(input, runtime),
    scanMcpToolDefinition: (toolDefinition) => scanMcpToolDefinition(toolDefinition, runtime.mcpScanner),
    scanMcpToolDefinitions: (toolDefinitions) =>
      scanMcpToolDefinitions(toolDefinitions, runtime.mcpScanner),
  };
}

export async function evaluateBeforeToolCall(
  input: OpenClawBeforeToolCallInput,
  adapterOrConfig: OpenClawGovernanceAdapter | OpenClawGovernanceAdapterConfig,
): Promise<OpenClawBeforeToolCallResult> {
  return resolveAdapter(adapterOrConfig).evaluateBeforeToolCall(input);
}

export async function recordAfterToolCall(
  input: OpenClawAfterToolCallInput,
  adapterOrConfig: OpenClawGovernanceAdapter | OpenClawGovernanceAdapterConfig,
): Promise<OpenClawAfterToolCallResult> {
  return resolveAdapter(adapterOrConfig).recordAfterToolCall(input);
}

export function scanOpenClawMcpToolDefinition(
  toolDefinition: McpToolDefinition,
  adapterOrConfig: OpenClawGovernanceAdapter | OpenClawGovernanceAdapterConfig,
): OpenClawMcpScanResult {
  return resolveAdapter(adapterOrConfig).scanMcpToolDefinition(toolDefinition);
}

export function scanOpenClawMcpToolDefinitions(
  toolDefinitions: McpToolDefinition[],
  adapterOrConfig: OpenClawGovernanceAdapter | OpenClawGovernanceAdapterConfig,
): OpenClawMcpScanResult[] {
  return resolveAdapter(adapterOrConfig).scanMcpToolDefinitions(toolDefinitions);
}

async function evaluateBeforeToolCallInternal(
  input: OpenClawBeforeToolCallInput,
  runtime: ResolvedAdapterRuntime,
): Promise<OpenClawBeforeToolCallResult> {
  const agentId = resolveAgentId(input, runtime);
  const agentDid = resolveAgentDid(input, runtime, agentId);
  const context = buildPolicyContext(input, agentId, agentDid);

  let policyDecision: PolicyDecisionResult;
  try {
    policyDecision = runtime.policyEngine.evaluatePolicy(agentDid, context);
  } catch (error) {
    return handleEvaluationFailure(input.toolName, agentId, runtime, "policy_error", error);
  }

  const decision = mapPolicyDecisionToOpenClawDecision(policyDecision);
  let rewrittenParams: Record<string, unknown> | undefined;

  if (decision === "allow" && runtime.rewriteParams) {
    rewrittenParams = await runtime.rewriteParams(input, policyDecision);
  }

  const result: OpenClawBeforeToolCallResult = {
    decision,
    allowed: isExecutionAllowed(decision),
    reason: policyDecision.reason,
    matchedRule: policyDecision.matchedRule,
    policyName: policyDecision.policyName,
    approvers: policyDecision.approvers,
    rewrittenParams,
    policyDecision,
    source: "policy",
  };

  if (!runtime.auditLogger) {
    return result;
  }

  try {
    return {
      ...result,
      auditEntry: recordAuditEntry(runtime.auditLogger, {
        agentId,
        toolName: input.toolName,
        decision,
        stage: "before_tool_call",
      }),
    };
  } catch (error) {
    return handleEvaluationFailure(input.toolName, agentId, runtime, "audit_error", error, result);
  }
}

async function recordAfterToolCallInternal(
  input: OpenClawAfterToolCallInput,
  runtime: ResolvedAdapterRuntime,
): Promise<OpenClawAfterToolCallResult> {
  if (!runtime.auditLogger) {
    throw new OpenClawGovernanceAuditError(
      "recordAfterToolCall() requires audit logging to be enabled.",
    );
  }

  const agentId = resolveAgentId(input, runtime);
  const decision: OpenClawGovernanceDecision = input.error ? "deny" : "allow";
  const action = input.error ? "error" : "complete";

  try {
    return {
      decision,
      action,
      logged: true,
      auditEntry: recordAuditEntry(runtime.auditLogger, {
        agentId,
        toolName: input.toolName,
        decision,
        stage: "after_tool_call",
        outcome: action,
      }),
    };
  } catch (error) {
    throw new OpenClawGovernanceAuditError(
      formatError(
        `Audit logging failed after tool "${input.toolName}" ${action}`,
        error,
      ),
    );
  }
}

function resolveRuntime(config: OpenClawGovernanceAdapterConfig): ResolvedAdapterRuntime {
  const policyEngine = resolvePolicyEngine(config);
  const auditEnabled = config.audit?.enabled !== false;

  return {
    agentId: config.agentId ?? config.agentIdentity?.name,
    agentDid: config.agentDid ?? config.agentIdentity?.did,
    policyEngine,
    auditLogger: auditEnabled
      ? config.audit?.logger ?? new AuditLogger(config.audit?.config)
      : null,
    mcpScanner: config.mcpScanner ?? new McpSecurityScanner(),
    failClosed: config.failClosed ?? true,
    rewriteParams: config.rewriteParams,
  };
}

function resolvePolicyEngine(
  config: OpenClawGovernanceAdapterConfig,
): OpenClawPolicyEngine {
  if (config.policyEngine) {
    return config.policyEngine;
  }
  if (!config.policies || config.policies.length === 0) {
    throw new OpenClawGovernanceConfigError(
      "Provide either policyEngine or at least one policy in policies.",
    );
  }

  const engine = new PolicyEngine([], config.conflictStrategy);
  for (const policy of config.policies) {
    engine.loadPolicy(policy);
  }
  return engine;
}

function resolveAdapter(
  adapterOrConfig: OpenClawGovernanceAdapter | OpenClawGovernanceAdapterConfig,
): OpenClawGovernanceAdapter {
  if ("evaluateBeforeToolCall" in adapterOrConfig) {
    return adapterOrConfig;
  }
  return createOpenClawGovernanceAdapter(adapterOrConfig);
}

function resolveAgentId(
  input: Pick<OpenClawBeforeToolCallInput, "agentId"> | Pick<OpenClawAfterToolCallInput, "agentId">,
  runtime: ResolvedAdapterRuntime,
): string {
  return input.agentId ?? runtime.agentId ?? "openclaw-agent";
}

function resolveAgentDid(
  input:
    | Pick<OpenClawBeforeToolCallInput, "agentDid" | "agentId">
    | Pick<OpenClawAfterToolCallInput, "agentDid" | "agentId">,
  runtime: ResolvedAdapterRuntime,
  agentId: string,
): string {
  return input.agentDid ?? runtime.agentDid ?? `did:agentmesh:${input.agentId ?? agentId}`;
}

function buildPolicyContext(
  input: OpenClawBeforeToolCallInput,
  agentId: string,
  agentDid: string,
): Record<string, unknown> {
  return {
    toolName: input.toolName,
    params: input.params,
    tool: {
      name: input.toolName,
      description: input.toolDescription,
    },
    action: {
      type: input.toolName,
      params: input.params,
    },
    agent: {
      id: agentId,
      did: agentDid,
    },
    request: {
      id: input.requestId,
      sessionId: input.sessionId,
      userId: input.userId,
    },
    metadata: input.metadata ?? {},
    runtime: input.runtimeContext ?? {},
  };
}

function handleEvaluationFailure(
  toolName: string,
  agentId: string,
  runtime: ResolvedAdapterRuntime,
  source: "policy_error" | "audit_error",
  error: unknown,
  priorResult?: OpenClawBeforeToolCallResult,
): OpenClawBeforeToolCallResult {
  const reason = formatError(
    source === "policy_error"
      ? `Policy evaluation failed for tool "${toolName}"`
      : `Audit logging failed before tool "${toolName}"`,
    error,
  );

  if (!runtime.failClosed) {
    throw new OpenClawGovernanceError(reason);
  }

  const fallback: OpenClawBeforeToolCallResult = {
    decision: "deny",
    allowed: false,
    reason,
    matchedRule: priorResult?.matchedRule,
    policyName: priorResult?.policyName,
    approvers: priorResult?.approvers ?? [],
    rewrittenParams: undefined,
    policyDecision: priorResult?.policyDecision,
    source,
  };

  if (!runtime.auditLogger || source === "audit_error") {
    return fallback;
  }

  try {
    return {
      ...fallback,
      auditEntry: recordAuditEntry(runtime.auditLogger, {
        agentId,
        toolName,
        decision: "deny",
        stage: "before_tool_call",
      }),
    };
  } catch {
    return fallback;
  }
}

function formatError(prefix: string, error: unknown): string {
  if (error instanceof Error && error.message) {
    return `${prefix}: ${error.message}`;
  }
  return `${prefix}: ${String(error)}`;
}
