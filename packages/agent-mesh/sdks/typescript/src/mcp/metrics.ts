// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// ── Label enums ──

export enum McpDecisionLabel {
  Allowed = 'allowed',
  Denied = 'denied',
  RateLimited = 'rate_limited',
  ApprovalRequired = 'approval_required',
  Sanitized = 'sanitized',
}

export enum McpThreatLabel {
  ToolPoisoning = 'tool_poisoning',
  Typosquatting = 'typosquatting',
  HiddenInstruction = 'hidden_instruction',
  RugPull = 'rug_pull',
  SchemaAbuse = 'schema_abuse',
  CrossServerAttack = 'cross_server_attack',
  DescriptionInjection = 'description_injection',
  PromptInjection = 'prompt_injection',
  CredentialLeak = 'credential_leak',
  ExfiltrationUrl = 'exfiltration_url',
}

export enum McpScanLabel {
  Response = 'response',
  ToolMetadata = 'tool_metadata',
  Gateway = 'gateway',
}

// ── Snapshot ──

export interface McpMetricsSnapshot {
  decisions: Record<string, number>;
  threats_detected: Record<string, number>;
  rate_limit_hits: number;
  scans: Record<string, number>;
}

// ── McpMetricsCollector ──

/**
 * Categorical metrics collector for MCP governance operations.
 * Matches Python MCPMetrics and Rust McpMetricsCollector.
 */
export class McpMetricsCollector {
  private readonly decisions = new Map<string, number>();
  private readonly threats = new Map<string, number>();
  private rateLimitHitCount = 0;
  private readonly scans = new Map<string, number>();

  /** Record a gateway decision. */
  recordDecision(label: McpDecisionLabel): void {
    this.decisions.set(label, (this.decisions.get(label) ?? 0) + 1);
  }

  /** Record detected threats. */
  recordThreatsDetected(count: number, label: McpThreatLabel): void {
    this.threats.set(label, (this.threats.get(label) ?? 0) + count);
  }

  /** Record a rate-limit hit. */
  recordRateLimitHit(): void {
    this.rateLimitHitCount++;
  }

  /** Record a scan operation. */
  recordScan(label: McpScanLabel): void {
    this.scans.set(label, (this.scans.get(label) ?? 0) + 1);
  }

  /** Get a snapshot of all metrics. */
  getSnapshot(): McpMetricsSnapshot {
    return {
      decisions: Object.fromEntries(this.decisions),
      threats_detected: Object.fromEntries(this.threats),
      rate_limit_hits: this.rateLimitHitCount,
      scans: Object.fromEntries(this.scans),
    };
  }

  /** Reset all metrics to zero. */
  reset(): void {
    this.decisions.clear();
    this.threats.clear();
    this.rateLimitHitCount = 0;
    this.scans.clear();
  }
}
