// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import {
  McpSecurityScanner,
  type McpToolDefinition,
} from "@microsoft/agentmesh-sdk/mcp";
import type { OpenClawGovernanceDecision, OpenClawMcpScanResult, OpenClawMcpScanner } from "./types";

const DENY_SCAN_THRESHOLD = 80;

export function scanMcpToolDefinition(
  toolDefinition: McpToolDefinition,
  scanner: OpenClawMcpScanner = new McpSecurityScanner(),
): OpenClawMcpScanResult {
  const result = scanner.scan(toolDefinition);

  return {
    ...result,
    recommendedDecision: getRecommendedDecision(result.risk_score, result.safe),
    findings: result.threats,
  };
}

export function scanMcpToolDefinitions(
  toolDefinitions: McpToolDefinition[],
  scanner: OpenClawMcpScanner = new McpSecurityScanner(),
): OpenClawMcpScanResult[] {
  if (scanner.scanAll) {
    return scanner.scanAll(toolDefinitions).map((result) => ({
      ...result,
      recommendedDecision: getRecommendedDecision(result.risk_score, result.safe),
      findings: result.threats,
    }));
  }

  return toolDefinitions.map((toolDefinition) => scanMcpToolDefinition(toolDefinition, scanner));
}

function getRecommendedDecision(
  riskScore: number,
  safe: boolean,
): OpenClawGovernanceDecision {
  if (safe) {
    return "allow";
  }
  if (riskScore >= DENY_SCAN_THRESHOLD) {
    return "deny";
  }
  return "review";
}
