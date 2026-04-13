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

  it('continues blocking built-in dangerous patterns across repeated calls', async () => {
    const gateway = new MCPGateway();

    const first = await gateway.evaluateToolCall('agent-1', 'search', {
      command: '`whoami`',
    });
    const second = await gateway.evaluateToolCall('agent-1', 'search', {
      command: '`hostname`',
    });

    expect(first.allowed).toBe(false);
    expect(second.allowed).toBe(false);
    expect(first.reason).toContain('dangerous pattern');
    expect(second.reason).toContain('dangerous pattern');
  });

  it('continues blocking custom global regex patterns across repeated calls', async () => {
    const gateway = new MCPGateway({
      blockedPatterns: [/secret/gi],
    });

    const first = await gateway.evaluateToolCall('agent-1', 'search', {
      text: 'secret token',
    });
    const second = await gateway.evaluateToolCall('agent-1', 'search', {
      text: 'secret value',
    });

    expect(first.allowed).toBe(false);
    expect(second.allowed).toBe(false);
    expect(first.reason).toContain('blocked pattern');
    expect(second.reason).toContain('blocked pattern');
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

  it('rejects pathological blocked regex patterns', () => {
    expect(() => new MCPGateway({
      // codeql-suppress js/polynomial-redos -- Intentionally pathological regex to test validateRegex rejection
      blockedPatterns: [/(a+)+$/],
    })).toThrow('possible ReDoS');
  });

  it('logs when the security gate fails closed', async () => {
    const debug = jest.fn();
    const gateway = new MCPGateway({
      logger: { debug },
      rateLimiter: {
        consume: async () => {
          throw new Error('rate limit store failed');
        },
      },
    });

    const result = await gateway.evaluateToolCall('agent-1', 'search', {});

    expect(result.allowed).toBe(false);
    expect(debug).toHaveBeenCalledWith('Security gate failed closed', {
      gate: 'gateway.evaluateToolCall',
      error: 'rate limit store failed',
    });
  });
});
