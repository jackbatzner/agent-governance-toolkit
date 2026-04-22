// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import type { AuditEntry } from "@microsoft/agentmesh-sdk/types";
import type { OpenClawAuditLogger, OpenClawGovernanceDecision } from "./types";

type AuditStage = "before_tool_call" | "after_tool_call";

export function recordAuditEntry(
  logger: OpenClawAuditLogger,
  params: {
    agentId: string;
    toolName: string;
    decision: OpenClawGovernanceDecision;
    stage: AuditStage;
    outcome?: "complete" | "error";
  },
): AuditEntry {
  return logger.log({
    agentId: params.agentId,
    action: buildAuditAction(params.stage, params.toolName, params.outcome),
    decision: params.decision,
  });
}

function buildAuditAction(
  stage: AuditStage,
  toolName: string,
  outcome?: "complete" | "error",
): string {
  const parts = [stage, sanitizeAuditSegment(toolName)];
  if (outcome) {
    parts.push(outcome);
  }
  return parts.join(":");
}

function sanitizeAuditSegment(value: string): string {
  return value.replace(/[:\s]+/g, "_");
}
