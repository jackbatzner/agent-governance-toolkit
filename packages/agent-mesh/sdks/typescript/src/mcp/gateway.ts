// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { McpResponseScanner } from './response';
import type { McpResponseFinding } from './response';
import { McpSlidingRateLimiter } from './rate-limiter';
import type { McpAuditSink } from './stores';
import type { Clock } from './clock';
import { SystemClock } from './clock';

// ── Types ──

export enum McpGatewayStatus {
  Allowed = 'allowed',
  Denied = 'denied',
  RateLimited = 'rate_limited',
  RequiresApproval = 'requires_approval',
}

export interface McpGatewayConfig {
  deny_list?: string[];
  allow_list?: string[];
  approval_required_tools?: string[];
  auto_approve?: boolean;
  block_on_suspicious_payload?: boolean;
}

export interface McpGatewayRequest {
  agent_id: string;
  tool_name: string;
  payload: string;
}

export interface McpGatewayDecision {
  status: McpGatewayStatus;
  allowed: boolean;
  sanitized_payload: string;
  findings: McpResponseFinding[];
  retry_after_ms: number;
}

// ── McpGateway ──

/**
 * MCP security gateway enforcing deny-list → allow-list → sanitization →
 * rate-limit → approval pipeline.
 */
export class McpGateway {
  private readonly config: McpGatewayConfig;
  private readonly scanner: McpResponseScanner;
  private readonly rateLimiter: McpSlidingRateLimiter;
  private readonly auditSink?: McpAuditSink;
  private readonly clock: Clock;

  constructor(
    config: McpGatewayConfig,
    options?: {
      scanner?: McpResponseScanner;
      rateLimiter?: McpSlidingRateLimiter;
      auditSink?: McpAuditSink;
      clock?: Clock;
    },
  ) {
    this.config = config;
    this.scanner = options?.scanner ?? new McpResponseScanner();
    this.rateLimiter = options?.rateLimiter ?? new McpSlidingRateLimiter();
    this.auditSink = options?.auditSink;
    this.clock = options?.clock ?? new SystemClock();
  }

  /** Process an MCP tool call request through the governance pipeline. */
  processRequest(request: McpGatewayRequest): McpGatewayDecision {
    if (!request.agent_id) throw new Error('agent_id must not be empty');
    if (!request.tool_name) throw new Error('tool_name must not be empty');

    const toolLower = request.tool_name.toLowerCase();

    // 1. Deny-list check
    if (this.config.deny_list?.some((t) => t.toLowerCase() === toolLower)) {
      return this.decide(request, McpGatewayStatus.Denied, request.payload, []);
    }

    // 2. Allow-list check (if configured, only listed tools pass)
    if (this.config.allow_list && this.config.allow_list.length > 0) {
      if (!this.config.allow_list.some((t) => t.toLowerCase() === toolLower)) {
        return this.decide(request, McpGatewayStatus.Denied, request.payload, []);
      }
    }

    // 3. Payload sanitization
    const scanResult = this.scanner.scanText(request.payload);
    if (this.config.block_on_suspicious_payload && scanResult.findings.length > 0) {
      return this.decide(request, McpGatewayStatus.Denied, scanResult.sanitized, scanResult.findings);
    }

    // 4. Rate limiting
    if (!this.rateLimiter.tryAcquire(request.agent_id)) {
      return this.decide(request, McpGatewayStatus.RateLimited, scanResult.sanitized, scanResult.findings, 1000);
    }

    // 5. Approval check
    if (
      this.config.approval_required_tools?.includes(request.tool_name) &&
      !this.config.auto_approve
    ) {
      return this.decide(request, McpGatewayStatus.RequiresApproval, scanResult.sanitized, scanResult.findings);
    }

    return this.decide(request, McpGatewayStatus.Allowed, scanResult.sanitized, scanResult.findings);
  }

  private decide(
    request: McpGatewayRequest,
    status: McpGatewayStatus,
    sanitizedPayload: string,
    findings: McpResponseFinding[],
    retryAfterMs = 0,
  ): McpGatewayDecision {
    const decision: McpGatewayDecision = {
      status,
      allowed: status === McpGatewayStatus.Allowed,
      sanitized_payload: sanitizedPayload,
      findings,
      retry_after_ms: retryAfterMs,
    };

    this.auditSink?.record({
      timestamp: this.clock.now(),
      agent_id: request.agent_id,
      action: `gateway:${request.tool_name}`,
      decision: status,
      details: {
        tool_name: request.tool_name,
        findingCount: findings.length,
      },
    });

    return decision;
  }
}
