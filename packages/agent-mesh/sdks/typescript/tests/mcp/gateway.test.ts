// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import {
  McpGateway,
  McpGatewayStatus,
  type McpGatewayConfig,
} from '../../src/mcp/gateway';
import { FixedClock } from '../../src/mcp/clock';
import { InMemoryAuditSink } from '../../src/mcp/memory-stores';
import { McpSlidingRateLimiter } from '../../src/mcp/rate-limiter';

const BASE_TIME = 1_000_000;

function buildGateway(
  config: McpGatewayConfig,
  opts?: { maxCalls?: number },
) {
  const clock = new FixedClock(BASE_TIME);
  const auditSink = new InMemoryAuditSink();
  const rateLimiter = new McpSlidingRateLimiter({
    maxCallsPerWindow: opts?.maxCalls ?? 100,
    windowSizeMs: 60_000,
    clock,
  });
  const gateway = new McpGateway(config, { rateLimiter, auditSink, clock });
  return { gateway, clock, auditSink };
}

describe('McpGateway', () => {
  // ── Deny list ──

  it('deny-list blocks tools', () => {
    const { gateway } = buildGateway({ deny_list: ['dangerous_tool'] });
    const result = gateway.processRequest({
      agent_id: 'agent-1',
      tool_name: 'dangerous_tool',
      payload: 'hello',
    });
    expect(result.status).toBe(McpGatewayStatus.Denied);
    expect(result.allowed).toBe(false);
  });

  // ── Allow list ──

  it('allow-list only allows listed tools', () => {
    const { gateway } = buildGateway({ allow_list: ['safe_tool'] });

    const denied = gateway.processRequest({
      agent_id: 'agent-1',
      tool_name: 'other_tool',
      payload: 'hello',
    });
    expect(denied.status).toBe(McpGatewayStatus.Denied);

    const allowed = gateway.processRequest({
      agent_id: 'agent-1',
      tool_name: 'safe_tool',
      payload: 'hello',
    });
    expect(allowed.status).toBe(McpGatewayStatus.Allowed);
  });

  // ── Payload sanitization ──

  it('sanitizes suspicious payloads with credentials', () => {
    const { gateway } = buildGateway({});
    const result = gateway.processRequest({
      agent_id: 'agent-1',
      tool_name: 'read',
      payload: 'key is sk-abcdefghijklmnopqrstuvwx',
    });
    // Gateway allows but sanitizes
    expect(result.status).toBe(McpGatewayStatus.Allowed);
    expect(result.sanitized_payload).toContain('[REDACTED:openai_key]');
  });

  // ── blockOnSuspiciousPayload ──

  it('blocks requests when blockOnSuspiciousPayload=true and findings present', () => {
    const { gateway } = buildGateway({ block_on_suspicious_payload: true });
    const result = gateway.processRequest({
      agent_id: 'agent-1',
      tool_name: 'write',
      payload: 'key: sk-abcdefghijklmnopqrstuvwx',
    });
    expect(result.status).toBe(McpGatewayStatus.Denied);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  // ── Rate limiting ──

  it('returns RateLimited status when over limit', () => {
    const { gateway } = buildGateway({}, { maxCalls: 1 });

    const first = gateway.processRequest({
      agent_id: 'agent-1',
      tool_name: 'tool',
      payload: 'ok',
    });
    expect(first.status).toBe(McpGatewayStatus.Allowed);

    const second = gateway.processRequest({
      agent_id: 'agent-1',
      tool_name: 'tool',
      payload: 'ok',
    });
    expect(second.status).toBe(McpGatewayStatus.RateLimited);
    expect(second.allowed).toBe(false);
  });

  // ── Approval required ──

  it('returns RequiresApproval when autoApprove=false', () => {
    const { gateway } = buildGateway({
      approval_required_tools: ['deploy'],
      auto_approve: false,
    });
    const result = gateway.processRequest({
      agent_id: 'agent-1',
      tool_name: 'deploy',
      payload: 'go',
    });
    expect(result.status).toBe(McpGatewayStatus.RequiresApproval);
    expect(result.allowed).toBe(false);
  });

  it('allows approval-required tools when autoApprove=true', () => {
    const { gateway } = buildGateway({
      approval_required_tools: ['deploy'],
      auto_approve: true,
    });
    const result = gateway.processRequest({
      agent_id: 'agent-1',
      tool_name: 'deploy',
      payload: 'go',
    });
    expect(result.status).toBe(McpGatewayStatus.Allowed);
    expect(result.allowed).toBe(true);
  });

  // ── Full pipeline ──

  it('clean request passes full pipeline and returns Allowed', () => {
    const { gateway } = buildGateway({});
    const result = gateway.processRequest({
      agent_id: 'agent-1',
      tool_name: 'read',
      payload: 'Just a normal request.',
    });
    expect(result.status).toBe(McpGatewayStatus.Allowed);
    expect(result.allowed).toBe(true);
    expect(result.findings).toHaveLength(0);
    expect(result.sanitized_payload).toBe('Just a normal request.');
  });

  // ── Audit sink ──

  it('audit sink receives records for each request', () => {
    const { gateway, auditSink } = buildGateway({});
    gateway.processRequest({
      agent_id: 'agent-1',
      tool_name: 'read',
      payload: 'test',
    });
    const records = auditSink.getAll();
    expect(records.length).toBeGreaterThanOrEqual(1);
    expect(records[0].agent_id).toBe('agent-1');
    expect(records[0].action).toContain('read');
  });

  // --- Input-validation guards ---

  it('throws on empty agent_id in processRequest', () => {
    const { gateway } = buildGateway({});
    expect(() =>
      gateway.processRequest({ agent_id: '', tool_name: 'read', payload: '{}' }),
    ).toThrow('agent_id must not be empty');
  });

  it('throws on empty tool_name in processRequest', () => {
    const { gateway } = buildGateway({});
    expect(() =>
      gateway.processRequest({ agent_id: 'agent-1', tool_name: '', payload: '{}' }),
    ).toThrow('tool_name must not be empty');
  });
});
