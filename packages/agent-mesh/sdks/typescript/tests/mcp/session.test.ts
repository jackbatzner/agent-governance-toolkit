// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { McpSessionAuthenticator } from '../../src/mcp/session';
import { FixedClock } from '../../src/mcp/clock';
import { InMemorySessionStore } from '../../src/mcp/memory-stores';

const BASE_TIME = 1_000_000;
const ONE_HOUR = 3_600_000;

function buildAuth(opts?: { maxConcurrent?: number; ttlMs?: number }) {
  const clock = new FixedClock(BASE_TIME);
  const store = new InMemorySessionStore();
  const auth = new McpSessionAuthenticator({
    store,
    clock,
    sessionTtlMs: opts?.ttlMs ?? ONE_HOUR,
    maxConcurrentSessions: opts?.maxConcurrent ?? 10,
  });
  return { auth, clock, store };
}

describe('McpSessionAuthenticator', () => {
  // ── createSession ──

  it('createSession returns a token string', () => {
    const { auth } = buildAuth();
    const token = auth.createSession('agent-1', 'user-1');
    expect(typeof token).toBe('string');
    expect(token.length).toBeGreaterThan(0);
  });

  // ── validateSession ──

  it('validateSession returns McpSession for valid token', () => {
    const { auth } = buildAuth();
    const token = auth.createSession('agent-1', 'user-1');
    const session = auth.validateSession('agent-1', token);
    expect(session).not.toBeNull();
    expect(session!.agent_id).toBe('agent-1');
    expect(session!.user_id).toBe('user-1');
    expect(session!.token).toBe(token);
    expect(session!.is_expired).toBe(false);
  });

  it('validateSession returns null for unknown token', () => {
    const { auth } = buildAuth();
    expect(auth.validateSession('agent-1', 'bogus-token')).toBeNull();
  });

  it('validateSession returns null for wrong agentId', () => {
    const { auth } = buildAuth();
    const token = auth.createSession('agent-1', 'user-1');
    expect(auth.validateSession('wrong-agent', token)).toBeNull();
  });

  // ── Expiration ──

  it('session returns null after advancing past TTL (fail-closed)', () => {
    const { auth, clock } = buildAuth({ ttlMs: 10_000 });
    const token = auth.createSession('agent-1', 'user-1');

    const before = auth.validateSession('agent-1', token);
    expect(before).not.toBeNull();
    expect(before!.is_expired).toBe(false);

    clock.advance(10_001);
    const after = auth.validateSession('agent-1', token);
    expect(after).toBeNull();
  });

  // ── revokeSession ──

  it('revokeSession removes session', () => {
    const { auth } = buildAuth();
    const token = auth.createSession('agent-1', 'user-1');
    expect(auth.revokeSession(token)).toBe(true);
    expect(auth.validateSession('agent-1', token)).toBeNull();
  });

  // ── revokeAllSessions ──

  it('revokeAllSessions removes all sessions for an agent', () => {
    const { auth } = buildAuth();
    auth.createSession('agent-1', 'user-1');
    auth.createSession('agent-1', 'user-2');
    auth.createSession('agent-2', 'user-3');

    const removed = auth.revokeAllSessions('agent-1');
    expect(removed).toBe(2);
    // agent-2 session should still exist
    expect(auth.activeSessionCount).toBe(1);
  });

  // ── Concurrent session limit ──

  it('throws when exceeding maxConcurrentSessions', () => {
    const { auth } = buildAuth({ maxConcurrent: 2 });
    auth.createSession('agent-1', 'user-1');
    auth.createSession('agent-1', 'user-2');
    expect(() => auth.createSession('agent-1', 'user-3')).toThrow(
      /maximum of 2 concurrent sessions/,
    );
  });

  // ── cleanupExpiredSessions ──

  it('cleanupExpiredSessions removes expired sessions', () => {
    const { auth, clock } = buildAuth({ ttlMs: 5_000 });
    auth.createSession('agent-1', 'user-1');
    auth.createSession('agent-1', 'user-2');
    expect(auth.activeSessionCount).toBe(2);

    clock.advance(5_001);
    const removed = auth.cleanupExpiredSessions();
    expect(removed).toBe(2);
    expect(auth.activeSessionCount).toBe(0);
  });

  // ── activeSessionCount ──

  it('activeSessionCount tracks non-expired sessions', () => {
    const { auth } = buildAuth();
    expect(auth.activeSessionCount).toBe(0);
    auth.createSession('agent-1', 'user-1');
    expect(auth.activeSessionCount).toBe(1);
    auth.createSession('agent-2', 'user-2');
    expect(auth.activeSessionCount).toBe(2);
  });

  // --- Input-validation guards ---

  it('throws on empty agentId in createSession', () => {
    const { auth } = buildAuth();
    expect(() => auth.createSession('', 'user-1')).toThrow('agentId must not be empty');
  });

  it('throws on empty userId in createSession', () => {
    const { auth } = buildAuth();
    expect(() => auth.createSession('agent-1', '')).toThrow('userId must not be empty');
  });

  it('returns null for empty agentId in validateSession', () => {
    const { auth } = buildAuth();
    expect(auth.validateSession('', 'tok')).toBeNull();
  });

  it('returns null for empty token in validateSession', () => {
    const { auth } = buildAuth();
    expect(auth.validateSession('agent-1', '')).toBeNull();
  });

  it('returns false for empty token in revokeSession', () => {
    const { auth } = buildAuth();
    expect(auth.revokeSession('')).toBe(false);
  });

  it('returns 0 for empty agentId in revokeAllSessions', () => {
    const { auth } = buildAuth();
    expect(auth.revokeAllSessions('')).toBe(0);
  });
});
