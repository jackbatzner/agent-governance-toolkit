// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import {
  ApprovalStatus,
  InMemoryMCPAuditSink,
  MCPGateway,
  MCPSlidingRateLimiter,
} from '../src';

describe('MCPGateway', () => {
  it('blocks tools on the deny list', async () => {
    const gateway = new MCPGateway({
      deniedTools: ['exec'],
    });

    const result = await gateway.evaluateToolCall('agent-1', 'exec', {});

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('deny list');
  });

  it('blocks parameters matching dangerous patterns', async () => {
    const gateway = new MCPGateway();
    const result = await gateway.evaluateToolCall('agent-1', 'search', {
      command: '$(whoami)',
    });

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('dangerous pattern');
  });

  it('applies per-agent rate limiting', async () => {
    const gateway = new MCPGateway({
      rateLimiter: new MCPSlidingRateLimiter({
        maxRequests: 1,
        windowMs: 10_000,
      }),
    });

    expect((await gateway.evaluateToolCall('agent-1', 'search', {})).allowed).toBe(true);
    const blocked = await gateway.evaluateToolCall('agent-1', 'search', {});

    expect(blocked.allowed).toBe(false);
    expect(blocked.reason).toContain('rate limit');
  });

  it('requires approval for sensitive tools', async () => {
    const gateway = new MCPGateway({
      sensitiveTools: ['deploy'],
      approvalHandler: async () => ApprovalStatus.Approved,
    });

    const result = await gateway.evaluateToolCall('agent-1', 'deploy', {});

    expect(result.allowed).toBe(true);
    expect(result.approvalStatus).toBe(ApprovalStatus.Approved);
  });

  it('redacts secrets in audit entries', async () => {
    const auditSink = new InMemoryMCPAuditSink();
    const gateway = new MCPGateway({
      auditSink,
    });
    await gateway.evaluateToolCall('agent-1', 'search', {
      apiKey: 'sk-test1234567890123456',
    });

    expect(auditSink.getEntries()[0].params).toEqual({
      apiKey: '[REDACTED]',
    });
  });
});
