// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import type { PolicyDecisionResult } from "@microsoft/agentmesh-sdk";
import type { OpenClawGovernanceDecision } from "./types";

export function mapPolicyDecisionToOpenClawDecision(
  decision: PolicyDecisionResult,
): OpenClawGovernanceDecision {
  switch (decision.action) {
    case "allow":
      return "allow";
    case "deny":
      return "deny";
    case "require_approval":
    case "warn":
      return "review";
    case "log":
      return "allow";
    default:
      return decision.allowed ? "allow" : "deny";
  }
}

export function isExecutionAllowed(decision: OpenClawGovernanceDecision): boolean {
  return decision === "allow";
}
