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
  OpenClawBeforeToolCallInput,
  OpenClawBeforeToolCallResult,
  OpenClawGovernanceAdapter,
  OpenClawGovernanceAdapterConfig,
  OpenClawGovernanceDecision,
  OpenClawMcpScanResult,
  OpenClawNativeAfterToolCallEvent,
  OpenClawNativeBeforeToolCallEvent,
  OpenClawNativeBeforeToolCallResult,
  OpenClawNativePluginApi,
  OpenClawNativePluginConfig,
  OpenClawNativeToolHookContext,
  OpenClawPolicyEngine,
} from "./types";

const OPENCLAW_NATIVE_PLUGIN_ID = "agentmesh-openclaw";

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

export function createOpenClawGovernanceAdapterFromPluginConfig(
  config: OpenClawNativePluginConfig,
  options?: {
    cwd?: string;
  },
): OpenClawGovernanceAdapter {
  const resolved = resolveNativePluginConfig(config, options?.cwd);
  return createOpenClawGovernanceAdapter({
    agentId: resolved.agentId,
    agentDid: resolved.agentDid,
    policies: resolved.policies,
    failClosed: resolved.failClosed,
    audit: resolved.audit,
  });
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

export function registerOpenClawGovernanceHooks(
  api: OpenClawNativePluginApi,
  config?: OpenClawNativePluginConfig,
): OpenClawGovernanceAdapter {
  const resolvedConfig = resolveNativePluginConfig(config ?? normalizeNativePluginConfig(api.pluginConfig));
  const adapter = createOpenClawGovernanceAdapter({
    agentId: resolvedConfig.agentId,
    agentDid: resolvedConfig.agentDid,
    policies: resolvedConfig.policies,
    failClosed: resolvedConfig.failClosed,
    audit: resolvedConfig.audit,
  });

  api.registerHook(
    "before_tool_call",
    async (event, ctx) => {
      const beforeToolCallEvent = event as OpenClawNativeBeforeToolCallEvent;
      return mapBeforeToolCallResult(
        await adapter.evaluateBeforeToolCall(
          mapBeforeToolCallEvent(
            beforeToolCallEvent,
            ctx as OpenClawNativeToolHookContext,
          ),
        ),
        beforeToolCallEvent.toolName,
      );
    },
  );

  if (resolvedConfig.audit.enabled !== false) {
    api.registerHook("after_tool_call", async (event, ctx) => {
      try {
        await adapter.recordAfterToolCall(
          mapAfterToolCallEvent(
            event as OpenClawNativeAfterToolCallEvent,
            ctx as OpenClawNativeToolHookContext,
          ),
        );
      } catch (error) {
        api.logger?.error?.(
          `AGT post-call audit logging failed for tool "${(event as OpenClawNativeAfterToolCallEvent).toolName}": ${formatError("audit error", error)}`,
        );
      }
    });
  }

  api.logger?.info?.(
    `Registered AGT OpenClaw governance hooks with ${resolvedConfig.policies.length} loaded policy set(s).`,
  );

  return adapter;
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

function mapBeforeToolCallEvent(
  event: OpenClawNativeBeforeToolCallEvent,
  ctx: OpenClawNativeToolHookContext,
): OpenClawBeforeToolCallInput {
  return {
    toolName: event.toolName,
    params: event.params,
    requestId: event.toolCallId ?? ctx.toolCallId ?? ctx.runId,
    sessionId: ctx.sessionId ?? ctx.sessionKey,
    agentId: ctx.agentId,
    metadata: {
      runId: event.runId ?? ctx.runId,
      toolCallId: event.toolCallId ?? ctx.toolCallId,
    },
    runtimeContext: {
      sessionKey: ctx.sessionKey,
    },
  };
}

function mapAfterToolCallEvent(
  event: OpenClawNativeAfterToolCallEvent,
  ctx: OpenClawNativeToolHookContext,
): OpenClawAfterToolCallInput {
  return {
    toolName: event.toolName,
    params: event.params,
    result: event.result,
    error: event.error,
    durationMs: event.durationMs,
    requestId: event.toolCallId ?? ctx.toolCallId ?? ctx.runId,
    sessionId: ctx.sessionId ?? ctx.sessionKey,
    agentId: ctx.agentId,
    metadata: {
      runId: event.runId ?? ctx.runId,
      toolCallId: event.toolCallId ?? ctx.toolCallId,
    },
  };
}

function mapBeforeToolCallResult(
  result: OpenClawBeforeToolCallResult,
  toolName: string,
): OpenClawNativeBeforeToolCallResult {
  if (result.decision === "deny") {
    return {
      block: true,
      blockReason: result.reason ?? "Blocked by AGT policy.",
    };
  }

  if (result.decision === "review") {
    const details = [
      result.reason ?? "Approval required by AGT policy.",
      result.policyName ? `Policy: ${result.policyName}` : undefined,
      result.matchedRule ? `Rule: ${result.matchedRule}` : undefined,
      result.approvers.length > 0
        ? `Suggested approvers: ${result.approvers.join(", ")}`
        : undefined,
    ].filter((value): value is string => Boolean(value));

    return {
      requireApproval: {
        title: `Approval required for tool "${toolName}"`,
        description: details.join("\n"),
        severity: "warning",
        pluginId: OPENCLAW_NATIVE_PLUGIN_ID,
      },
    };
  }

  return {
    params: result.rewrittenParams,
  };
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

function resolveNativePluginConfig(
  config: OpenClawNativePluginConfig,
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
      'Native OpenClaw plugin configuration requires "policyFile" and/or non-empty "policies".',
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

function normalizeNativePluginConfig(
  pluginConfig: Record<string, unknown> | undefined,
): OpenClawNativePluginConfig {
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
