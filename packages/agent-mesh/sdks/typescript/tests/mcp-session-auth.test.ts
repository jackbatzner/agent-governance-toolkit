// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { MCPSessionAuthenticator } from '../src';

describe('MCPSessionAuthenticator', () => {
  it('issues and verifies session tokens bound to an agent', async () => {
    const auth = new MCPSessionAuthenticator({
      secret: 'super-secret',
    });

    const issued = await auth.issueToken('agent-1');
    const verification = await auth.verifyToken(issued.token, 'agent-1');

    expect(verification.valid).toBe(true);
    expect(verification.payload?.agentId).toBe('agent-1');
  });

  it('rejects expired tokens', async () => {
    let now = 1_000;
    const clock = {
      now: () => new Date(now),
      monotonic: () => now,
    };
    const auth = new MCPSessionAuthenticator({
      secret: 'super-secret',
      ttlMs: 100,
      maxClockSkewMs: 0,
      clock,
    });

    const issued = await auth.issueToken('agent-1');
    now = 5_000;
    const verification = await auth.verifyToken(issued.token, 'agent-1');

    expect(verification.valid).toBe(false);
    expect(verification.reason).toContain('expired');
  });

  it('enforces concurrent session limits', async () => {
    const auth = new MCPSessionAuthenticator({
      secret: 'super-secret',
      maxConcurrentSessions: 1,
    });

    await auth.issueToken('agent-1');
    await expect(auth.issueToken('agent-1')).rejects.toThrow(
      'Concurrent session limit exceeded',
    );
  });

  it('invalidates revoked sessions', async () => {
    const auth = new MCPSessionAuthenticator({
      secret: 'super-secret',
    });

    const issued = await auth.issueToken('agent-1');
    await auth.revokeSession(issued.payload.sessionId);

    const verification = await auth.verifyToken(issued.token, 'agent-1');
    expect(verification.valid).toBe(false);
    expect(verification.reason).toContain('Session not found');
  });
});
