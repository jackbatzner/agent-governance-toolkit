// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { createHmac, randomBytes } from 'node:crypto';
import type { McpSessionStore, McpSessionRecord } from './stores';
import { InMemorySessionStore } from './memory-stores';
import type { Clock } from './clock';
import { SystemClock } from './clock';

// ── Types ──

/** An authenticated MCP session. */
export interface McpSession {
  token: string;
  agent_id: string;
  user_id: string;
  created_at: number;
  expires_at: number;
  is_expired: boolean;
}

// ── McpSessionAuthenticator ──

/**
 * HMAC-based session authentication with TTL and concurrent session limits.
 * Matches Python MCPSessionAuthenticator and Rust McpSessionAuthenticator.
 */
export class McpSessionAuthenticator {
  private readonly store: McpSessionStore;
  private readonly clock: Clock;
  private readonly sessionTtlMs: number;
  private readonly maxConcurrentSessions: number;
  private readonly signingKey: Buffer;

  constructor(options?: {
    store?: McpSessionStore;
    clock?: Clock;
    sessionTtlMs?: number;
    maxConcurrentSessions?: number;
    signingKey?: Buffer;
  }) {
    this.store = options?.store ?? new InMemorySessionStore();
    this.clock = options?.clock ?? new SystemClock();
    this.sessionTtlMs = options?.sessionTtlMs ?? 3_600_000; // 1 hour
    this.maxConcurrentSessions = options?.maxConcurrentSessions ?? 10;
    this.signingKey = options?.signingKey ?? randomBytes(32);
  }

  /** Create a new session and return the token. */
  createSession(agentId: string, userId: string): string {
    if (!agentId) throw new Error('agentId must not be empty');
    if (!userId) throw new Error('userId must not be empty');

    // Enforce concurrent limit
    const existing = this.store.getAll(agentId).filter(
      (s) => s.expires_at > this.clock.now(),
    );
    if (existing.length >= this.maxConcurrentSessions) {
      throw new Error(
        `Agent "${agentId}" has reached the maximum of ${this.maxConcurrentSessions} concurrent sessions`,
      );
    }

    const now = this.clock.now();
    const payload = `${agentId}:${userId}:${now}:${randomBytes(16).toString('hex')}`;
    const token = createHmac('sha256', this.signingKey)
      .update(payload)
      .digest('hex');

    const record: McpSessionRecord = {
      token,
      agent_id: agentId,
      user_id: userId,
      created_at: now,
      expires_at: now + this.sessionTtlMs,
    };

    this.store.set(token, record);
    return token;
  }

  /** Validate a session token. Returns the session if valid, null for expired/invalid. */
  validateSession(agentId: string, token: string): McpSession | null {
    if (!agentId || !token) return null;

    const record = this.store.get(token);
    if (!record) return null;
    if (record.agent_id !== agentId) return null;

    const now = this.clock.now();
    // Fail closed: expired sessions return null (matches Python behaviour)
    if (now >= record.expires_at) {
      this.store.delete(token);
      return null;
    }

    return {
      token: record.token,
      agent_id: record.agent_id,
      user_id: record.user_id,
      created_at: record.created_at,
      expires_at: record.expires_at,
      is_expired: false,
    };
  }

  /** Revoke a specific session. Returns true if it existed. */
  revokeSession(token: string): boolean {
    if (!token) return false;
    return this.store.delete(token);
  }

  /** Revoke all sessions for an agent. Returns number revoked. */
  revokeAllSessions(agentId: string): number {
    if (!agentId) return 0;
    const sessions = this.store.getAll(agentId);
    for (const s of sessions) {
      this.store.delete(s.token);
    }
    return sessions.length;
  }

  /** Remove expired sessions. Returns count removed. */
  cleanupExpiredSessions(): number {
    const now = this.clock.now();
    const all = this.store.getAll();
    let removed = 0;
    for (const s of all) {
      if (s.expires_at <= now) {
        this.store.delete(s.token);
        removed++;
      }
    }
    return removed;
  }

  /** Number of active (non-expired) sessions. */
  get activeSessionCount(): number {
    const now = this.clock.now();
    return this.store.getAll().filter((s) => s.expires_at > now).length;
  }
}
