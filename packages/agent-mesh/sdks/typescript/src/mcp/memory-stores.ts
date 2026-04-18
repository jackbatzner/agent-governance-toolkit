// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import type {
  McpSessionStore,
  McpSessionRecord,
  McpNonceStore,
  McpRateLimitStore,
  McpRateLimitBucket,
  McpAuditSink,
  McpAuditRecord,
} from './stores';

// ── InMemorySessionStore ──

export class InMemorySessionStore implements McpSessionStore {
  private readonly sessions = new Map<string, McpSessionRecord>();

  get(token: string): McpSessionRecord | undefined {
    return this.sessions.get(token);
  }

  set(token: string, session: McpSessionRecord): void {
    this.sessions.set(token, session);
  }

  delete(token: string): boolean {
    return this.sessions.delete(token);
  }

  getAll(agentId?: string): McpSessionRecord[] {
    const all = Array.from(this.sessions.values());
    if (agentId === undefined) return all;
    return all.filter((s) => s.agent_id === agentId);
  }
}

// ── InMemoryNonceStore ──

export class InMemoryNonceStore implements McpNonceStore {
  private readonly nonces = new Map<string, number>();
  private readonly maxEntries: number;

  constructor(maxEntries = 10_000) {
    this.maxEntries = maxEntries;
  }

  has(nonce: string): boolean {
    return this.nonces.has(nonce);
  }

  add(nonce: string, timestampMs: number): void {
    // Evict oldest if at capacity
    if (this.nonces.size >= this.maxEntries) {
      let oldestKey: string | undefined;
      let oldestTime = Infinity;
      for (const [key, ts] of this.nonces) {
        if (ts < oldestTime) {
          oldestTime = ts;
          oldestKey = key;
        }
      }
      if (oldestKey !== undefined) {
        this.nonces.delete(oldestKey);
      }
    }
    this.nonces.set(nonce, timestampMs);
  }

  cleanup(cutoffMs: number): number {
    let removed = 0;
    for (const [key, ts] of this.nonces) {
      if (ts < cutoffMs) {
        this.nonces.delete(key);
        removed++;
      }
    }
    return removed;
  }

  /** Current number of stored nonces. */
  get size(): number {
    return this.nonces.size;
  }
}

// ── InMemoryRateLimitStore ──

export class InMemoryRateLimitStore implements McpRateLimitStore {
  private readonly buckets = new Map<string, McpRateLimitBucket>();

  getBucket(key: string): McpRateLimitBucket | undefined {
    return this.buckets.get(key);
  }

  setBucket(key: string, bucket: McpRateLimitBucket): void {
    this.buckets.set(key, bucket);
  }

  deleteBucket(key: string): boolean {
    return this.buckets.delete(key);
  }
}

// ── InMemoryAuditSink ──

export class InMemoryAuditSink implements McpAuditSink {
  private readonly entries: McpAuditRecord[] = [];
  private readonly maxEntries: number;

  constructor(maxEntries = 10_000) {
    this.maxEntries = maxEntries;
  }

  record(entry: McpAuditRecord): void {
    if (this.entries.length >= this.maxEntries) {
      this.entries.shift();
    }
    this.entries.push(entry);
  }

  getAll(): McpAuditRecord[] {
    return [...this.entries];
  }

  /** Current number of recorded entries. */
  get size(): number {
    return this.entries.length;
  }
}
