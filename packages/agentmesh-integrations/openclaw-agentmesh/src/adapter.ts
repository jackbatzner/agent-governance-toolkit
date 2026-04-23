// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { readFileSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import { AuditLogger } from "@microsoft/agentmesh-sdk/audit";
import { McpSecurityScanner, type McpToolDefinition } from "@microsoft/agentmesh-sdk/mcp";
import { PolicyEngine } from "@microsoft/agentmesh-sdk/policy";
import type { AuditConfig, Policy, PolicyDecisionResult } from "@microsoft/agentmesh-sdk/types";
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
  OpenClawAuditLogger,
  OpenClawBeforeToolCallHookDecision,
  OpenClawBeforeToolCallInput,
  OpenClawBeforeToolCallResult,
  OpenClawGovernanceAdapter,
  OpenClawGovernanceAdapterConfig,
  OpenClawGovernanceDecision,
  OpenClawHookConfig,
  OpenClawHookProcessingResult,
  OpenClawInternalHookEvent,
  OpenClawMcpScanResult,
  OpenClawPluginApi,
  OpenClawPolicyEngine,
} from "./types";

const OPENCLAW_HOOK_PLUGIN_ID = "agentmesh-openclaw";
const BEFORE_TOOL_CALL_ACTIONS = new Set(["before_tool_call", "before-tool-call", "beforeToolCall"]);
const AFTER_TOOL_CALL_ACTIONS = new Set(["after_tool_call", "after-tool-call", "afterToolCall"]);

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

export function createOpenClawGovernanceAdapterFromConfig(
  config: OpenClawHookConfig,
  options?: {
    cwd?: string;
  },
): OpenClawGovernanceAdapter {
  const resolved = resolveHookConfig(config, options?.cwd);
  return createOpenClawGovernanceAdapter({
    agentId: resolved.agentId,
    agentDid: resolved.agentDid,
    policies: resolved.policies,
    failClosed: resolved.failClosed,
    audit: resolved.audit,
  });
}

export function createOpenClawGovernanceAdapterFromPluginConfig(
  pluginConfig: Record<string, unknown> | undefined,
  options?: {
    cwd?: string;
  },
): OpenClawGovernanceAdapter {
  return createOpenClawGovernanceAdapterFromConfig(
    normalizeNativePluginConfig(pluginConfig),
    options,
  );
}

export async function evaluateBeforeToolCall(
  input: OpenClawBeforeToolCallInput,
  adapterOrConfig:
    | OpenClawGovernanceAdapter
    | OpenClawGovernanceAdapterConfig
    | OpenClawHookConfig,
): Promise<OpenClawBeforeToolCallResult> {
  return resolveAdapter(adapterOrConfig).evaluateBeforeToolCall(input);
}

export async function recordAfterToolCall(
  input: OpenClawAfterToolCallInput,
  adapterOrConfig:
    | OpenClawGovernanceAdapter
    | OpenClawGovernanceAdapterConfig
    | OpenClawHookConfig,
): Promise<OpenClawAfterToolCallResult> {
  return resolveAdapter(adapterOrConfig).recordAfterToolCall(input);
}

export function scanOpenClawMcpToolDefinition(
  toolDefinition: McpToolDefinition,
  adapterOrConfig:
    | OpenClawGovernanceAdapter
    | OpenClawGovernanceAdapterConfig
    | OpenClawHookConfig,
): OpenClawMcpScanResult {
  return resolveAdapter(adapterOrConfig).scanMcpToolDefinition(toolDefinition);
}

export function scanOpenClawMcpToolDefinitions(
  toolDefinitions: McpToolDefinition[],
  adapterOrConfig:
    | OpenClawGovernanceAdapter
    | OpenClawGovernanceAdapterConfig
    | OpenClawHookConfig,
): OpenClawMcpScanResult[] {
  return resolveAdapter(adapterOrConfig).scanMcpToolDefinitions(toolDefinitions);
}

export function createOpenClawBeforeToolCallInputFromHookEvent(
  event: OpenClawInternalHookEvent | Record<string, unknown>,
): OpenClawBeforeToolCallInput | null {
  if (isInternalHookEvent(event)) {
    if (!BEFORE_TOOL_CALL_ACTIONS.has(event.action)) {
      return null;
    }

    const toolName = readToolName(event.context);
    if (!toolName) {
      return null;
    }

    return {
      toolName,
      params: readParams(event.context),
      toolDescription: readStringFromContext(event.context, ["toolDescription", "description"]),
      requestId: readStringFromContext(event.context, ["toolCallId", "requestId", "runId", "id"]),
      sessionId: event.sessionKey,
      userId: readStringFromContext(event.context, ["userId"]),
      agentId: readStringFromContext(event.context, ["agentId"]),
      agentDid: readStringFromContext(event.context, ["agentDid"]),
      metadata: {
        hookType: event.type,
        hookAction: event.action,
        hookTimestamp: event.timestamp.toISOString(),
      },
      runtimeContext: { ...event.context },
    };
  }

  const toolName = readToolName(event);
  if (!toolName) {
    return null;
  }

  return {
    toolName,
    params: readParams(event),
    toolDescription: readStringFromContext(event, ["toolDescription", "description"]),
    requestId: readStringFromContext(event, ["toolCallId", "requestId", "runId", "id"]),
    sessionId: readStringFromContext(event, ["sessionId", "sessionKey"]),
    userId: readStringFromContext(event, ["userId"]),
    agentId: readStringFromContext(event, ["agentId"]),
    agentDid: readStringFromContext(event, ["agentDid"]),
    metadata: {
      hookType: "before_tool_call",
      hookAction: "before_tool_call",
    },
    runtimeContext: { ...event },
  };
}

export function createOpenClawAfterToolCallInputFromHookEvent(
  event: OpenClawInternalHookEvent | Record<string, unknown>,
): OpenClawAfterToolCallInput | null {
  if (isInternalHookEvent(event)) {
    if (!AFTER_TOOL_CALL_ACTIONS.has(event.action)) {
      return null;
    }

    const toolName = readToolName(event.context);
    if (!toolName) {
      return null;
    }

    return {
      toolName,
      params: readOptionalRecordFromContext(event.context, ["params", "arguments", "args", "input"]),
      result: event.context.result,
      error: event.context.error,
      durationMs: readNumberFromContext(event.context, ["durationMs", "duration_ms"]),
      requestId: readStringFromContext(event.context, ["toolCallId", "requestId", "runId", "id"]),
      sessionId: event.sessionKey,
      userId: readStringFromContext(event.context, ["userId"]),
      agentId: readStringFromContext(event.context, ["agentId"]),
      agentDid: readStringFromContext(event.context, ["agentDid"]),
      metadata: {
        hookType: event.type,
        hookAction: event.action,
        hookTimestamp: event.timestamp.toISOString(),
      },
    };
  }

  const toolName = readToolName(event);
  if (!toolName) {
    return null;
  }

  return {
    toolName,
    params: readOptionalRecordFromContext(event, ["params", "arguments", "args", "input"]),
    result: event.result,
    error: event.error,
    durationMs: readNumberFromContext(event, ["durationMs", "duration_ms"]),
    requestId: readStringFromContext(event, ["toolCallId", "requestId", "runId", "id"]),
    sessionId: readStringFromContext(event, ["sessionId", "sessionKey"]),
    userId: readStringFromContext(event, ["userId"]),
    agentId: readStringFromContext(event, ["agentId"]),
    agentDid: readStringFromContext(event, ["agentDid"]),
    metadata: {
      hookType: "after_tool_call",
      hookAction: "after_tool_call",
    },
  };
}

export function applyBeforeToolCallResultToHookEvent(
  event: OpenClawInternalHookEvent,
  result: OpenClawBeforeToolCallResult,
): void {
  if (result.decision === "deny") {
    event.context.block = true;
    event.context.blockReason = result.reason ?? "Blocked by AGT policy.";
    pushHookMessage(event, event.context.blockReason as string);
    return;
  }

  if (result.decision === "review") {
    const description = buildApprovalDescription(result);
    event.context.requireApproval = {
      title: `Approval required for tool "${readToolName(event.context) ?? "unknown"}"`,
      description,
      severity: "warning",
      pluginId: OPENCLAW_HOOK_PLUGIN_ID,
      approvers: result.approvers,
    };
    pushHookMessage(event, description);
    return;
  }

  if (result.rewrittenParams) {
    event.context.params = result.rewrittenParams;
  }
}

export async function processOpenClawHookEvent(
  event: OpenClawInternalHookEvent,
  adapterOrConfig:
    | OpenClawGovernanceAdapter
    | OpenClawGovernanceAdapterConfig
    | OpenClawHookConfig,
): Promise<OpenClawHookProcessingResult | null> {
  const adapter = resolveAdapter(adapterOrConfig);
  const beforeInput = createOpenClawBeforeToolCallInputFromHookEvent(event);
  if (beforeInput) {
    const governanceResult = await adapter.evaluateBeforeToolCall(beforeInput);
    applyBeforeToolCallResultToHookEvent(event, governanceResult);
    return {
      kind: "before_tool_call",
      governanceResult,
    };
  }

  const afterInput = createOpenClawAfterToolCallInputFromHookEvent(event);
  if (afterInput && adapter.auditLogger) {
    try {
      return {
        kind: "after_tool_call",
        governanceResult: await adapter.recordAfterToolCall(afterInput),
      };
    } catch (error) {
      pushHookMessage(
        event,
        formatError(
          `AGT post-call audit logging failed for tool "${afterInput.toolName}"`,
          error,
        ),
      );
    }
  }

  return null;
}

export function mapBeforeToolCallResultToHookDecision(
  result: OpenClawBeforeToolCallResult,
): OpenClawBeforeToolCallHookDecision | undefined {
  if (result.decision === "deny") {
    return {
      block: true,
      blockReason: result.reason ?? "Blocked by AGT policy.",
    };
  }

  if (result.decision === "review") {
    return {
      requireApproval: true,
      blockReason: buildApprovalDescription(result),
    };
  }

  if (result.rewrittenParams) {
    return {
      params: result.rewrittenParams,
    };
  }

  return undefined;
}

export function registerOpenClawPluginHooks(
  api: OpenClawPluginApi,
  options?: {
    cwd?: string;
  },
): OpenClawGovernanceAdapter {
  const adapter = createOpenClawGovernanceAdapterFromPluginConfig(
    api.pluginConfig,
    options,
  );

  api.registerHook("before_tool_call", async (event) => {
    const input = createOpenClawBeforeToolCallInputFromHookEvent(asRecord(event));
    if (!input) {
      return undefined;
    }

    const result = await adapter.evaluateBeforeToolCall(input);
    return mapBeforeToolCallResultToHookDecision(result);
  });

  if (adapter.auditLogger) {
    api.registerHook("after_tool_call", async (event) => {
      const input = createOpenClawAfterToolCallInputFromHookEvent(asRecord(event));
      if (!input) {
        return undefined;
      }

      try {
        await adapter.recordAfterToolCall(input);
      } catch (error) {
        api.logger?.error?.(
          formatError(
            `AGT post-call audit logging failed for tool "${input.toolName}"`,
            error,
          ),
        );
      }

      return undefined;
    });
  }

  api.logger?.info?.(
    `Registered AGT OpenClaw plugin hooks with ${countPolicies(api.pluginConfig)} configured policy source(s).`,
  );

  return adapter;
}

export function createOpenClawHookEventHandler(
  adapterOrConfig:
    | OpenClawGovernanceAdapter
    | OpenClawGovernanceAdapterConfig
    | OpenClawHookConfig,
): (event: OpenClawInternalHookEvent) => Promise<OpenClawHookProcessingResult | null> {
  return async (event) => processOpenClawHookEvent(event, adapterOrConfig);
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
  adapterOrConfig:
    | OpenClawGovernanceAdapter
    | OpenClawGovernanceAdapterConfig
    | OpenClawHookConfig,
): OpenClawGovernanceAdapter {
  if ("evaluateBeforeToolCall" in adapterOrConfig) {
    return adapterOrConfig;
  }
  if ("policyFile" in adapterOrConfig || "policies" in adapterOrConfig) {
    return createOpenClawGovernanceAdapterFromConfig(adapterOrConfig);
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

function resolveHookConfig(
  config: OpenClawHookConfig,
  cwd = process.cwd(),
): {
  agentId?: string;
  agentDid?: string;
  failClosed?: boolean;
  policies: Policy[];
  audit: {
    enabled?: boolean;
    logger?: OpenClawAuditLogger;
    config?: AuditConfig;
  };
} {
  const filePolicies = config.policyFile
    ? loadPoliciesFromFile(config.policyFile, cwd)
    : [];
  const inlinePolicies = config.policies ?? [];
  const policies = [...filePolicies, ...inlinePolicies];

  if (policies.length === 0) {
    throw new OpenClawGovernanceConfigError(
      'OpenClaw hook configuration requires "policyFile" and/or non-empty "policies".',
    );
  }

  const auditEnabled = config.audit?.enabled !== false;
  const auditLogger =
    auditEnabled && config.audit?.stdout
      ? createStdoutAuditLogger(config.audit.maxEntries)
      : undefined;

  return {
    agentId: config.agentId,
    agentDid: config.agentDid,
    failClosed: config.failClosed,
    policies,
    audit: {
      enabled: auditEnabled,
      logger: auditLogger,
      config: config.audit?.stdout ? undefined : resolveAuditConfig(config.audit?.maxEntries),
    },
  };
}

function loadPoliciesFromFile(policyFile: string, cwd: string): Policy[] {
  const resolvedPath = isAbsolute(policyFile) ? policyFile : resolve(cwd, policyFile);
  const raw = readFileSync(resolvedPath, "utf8");
  const parsed = JSON.parse(raw) as unknown;

  if (!Array.isArray(parsed)) {
    throw new OpenClawGovernanceConfigError(
      `Policy file "${resolvedPath}" must contain a JSON array of policy objects.`,
    );
  }

  return parsed as Policy[];
}

function createStdoutAuditLogger(maxEntries?: number) {
  const logger = new AuditLogger(resolveAuditConfig(maxEntries));
  return {
    log(entry: Parameters<AuditLogger["log"]>[0]) {
      const auditEntry = logger.log(entry);
      process.stdout.write(
        `${JSON.stringify({ event: "agt.openclaw.audit", ...auditEntry })}\n`,
      );
      return auditEntry;
    },
  };
}

function resolveAuditConfig(maxEntries?: number): AuditConfig | undefined {
  return typeof maxEntries === "number" ? { maxEntries } : undefined;
}

function isInternalHookEvent(
  value: OpenClawInternalHookEvent | Record<string, unknown>,
): value is OpenClawInternalHookEvent {
  return (
    "type" in value &&
    "action" in value &&
    "sessionKey" in value &&
    "context" in value &&
    "messages" in value
  );
}

function readToolName(context: Record<string, unknown>): string | undefined {
  const direct = readStringFromContext(context, ["toolName", "tool_name", "name"]);
  if (direct) {
    return direct;
  }

  const nestedTool = readOptionalRecordFromContext(context, ["tool"]);
  if (!nestedTool) {
    return undefined;
  }

  return readStringFromContext(nestedTool, ["name"]);
}

function readParams(context: Record<string, unknown>): Record<string, unknown> {
  return readOptionalRecordFromContext(context, ["params", "arguments", "args", "input"]) ?? {};
}

function readOptionalRecordFromContext(
  context: Record<string, unknown>,
  fieldNames: string[],
): Record<string, unknown> | undefined {
  for (const fieldName of fieldNames) {
    const value = context[fieldName];
    if (value && typeof value === "object" && !Array.isArray(value)) {
      return value as Record<string, unknown>;
    }
  }
  return undefined;
}

function readStringFromContext(
  context: Record<string, unknown>,
  fieldNames: string[],
): string | undefined {
  for (const fieldName of fieldNames) {
    const value = context[fieldName];
    if (typeof value === "string") {
      return value;
    }
  }
  return undefined;
}

function asRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }
  return value as Record<string, unknown>;
}

function readNumberFromContext(
  context: Record<string, unknown>,
  fieldNames: string[],
): number | undefined {
  for (const fieldName of fieldNames) {
    const value = context[fieldName];
    if (typeof value === "number") {
      return value;
    }
  }
  return undefined;
}

function buildApprovalDescription(result: OpenClawBeforeToolCallResult): string {
  return [
    result.reason ?? "Approval required by AGT policy.",
    result.policyName ? `Policy: ${result.policyName}` : undefined,
    result.matchedRule ? `Rule: ${result.matchedRule}` : undefined,
    result.approvers.length > 0
      ? `Suggested approvers: ${result.approvers.join(", ")}`
      : undefined,
  ]
    .filter((value): value is string => Boolean(value))
    .join("\n");
}

function pushHookMessage(event: OpenClawInternalHookEvent, message: string): void {
  if (!event.messages.includes(message)) {
    event.messages.push(message);
  }
}

function normalizeNativePluginConfig(
  pluginConfig: Record<string, unknown> | undefined,
): OpenClawHookConfig {
  if (!pluginConfig) {
    return {};
  }

  const auditConfig = readOptionalRecord(pluginConfig.audit, "audit");

  return {
    policyFile: readOptionalString(pluginConfig.policyFile, "policyFile"),
    policies: readOptionalPolicies(pluginConfig.policies),
    agentId: readOptionalString(pluginConfig.agentId, "agentId"),
    agentDid: readOptionalString(pluginConfig.agentDid, "agentDid"),
    failClosed: readOptionalBoolean(pluginConfig.failClosed, "failClosed"),
    audit: auditConfig
      ? {
          enabled: readOptionalBoolean(auditConfig.enabled, "audit.enabled"),
          stdout: readOptionalBoolean(auditConfig.stdout, "audit.stdout"),
          maxEntries: readOptionalNumber(auditConfig.maxEntries, "audit.maxEntries"),
        }
      : undefined,
  };
}

function countPolicies(pluginConfig: Record<string, unknown> | undefined): number {
  if (!pluginConfig) {
    return 0;
  }

  const policies = pluginConfig.policies;
  return Array.isArray(policies) ? policies.length : 0;
}

function readOptionalRecord(
  value: unknown,
  fieldName: string,
): Record<string, unknown> | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new OpenClawGovernanceConfigError(`"${fieldName}" must be an object when provided.`);
  }
  return value as Record<string, unknown>;
}

function readOptionalString(value: unknown, fieldName: string): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "string") {
    throw new OpenClawGovernanceConfigError(`"${fieldName}" must be a string when provided.`);
  }
  return value;
}

function readOptionalBoolean(value: unknown, fieldName: string): boolean | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "boolean") {
    throw new OpenClawGovernanceConfigError(`"${fieldName}" must be a boolean when provided.`);
  }
  return value;
}

function readOptionalNumber(value: unknown, fieldName: string): number | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "number") {
    throw new OpenClawGovernanceConfigError(`"${fieldName}" must be a number when provided.`);
  }
  return value;
}

function readOptionalPolicies(value: unknown): Policy[] | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!Array.isArray(value)) {
    throw new OpenClawGovernanceConfigError('"policies" must be an array when provided.');
  }
  return value as Policy[];
}
