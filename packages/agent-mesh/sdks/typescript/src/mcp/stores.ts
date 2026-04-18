// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * Persistence interfaces for MCP governance components.
 * Matches Python Protocols and Rust Traits — allows pluggable storage backends.
 */

// ── Session Store ──

/** Stored session record. */
export interface McpSessionRecord {
  token: string;
  agent_id: string;
  user_id: string;
  created_at: number;
  expires_at: number;
}

/** Pluggable session storage backend. */
export interface McpSessionStore {
  get(token: string): McpSessionRecord | undefined;
  set(token: string, session: McpSessionRecord): void;
  delete(token: string): boolean;
  /** Return all sessions, optionally filtered by agentId. */
  getAll(agentId?: string): McpSessionRecord[];
}

// ── Nonce Store ──

/** Pluggable nonce storage for replay protection. */
export interface McpNonceStore {
  /** Check if a nonce has been seen before. */
  has(nonce: string): boolean;
  /** Record a nonce with its timestamp (ms since epoch). */
  add(nonce: string, timestampMs: number): void;
  /** Remove nonces older than the given cutoff (ms since epoch). Returns count removed. */
  cleanup(cutoffMs: number): number;
}

// ── Rate Limit Store ──

/** A bucket of timestamps for sliding-window rate limiting. */
export interface McpRateLimitBucket {
  timestamps: number[];
}

/** Pluggable rate-limit storage backend. */
export interface McpRateLimitStore {
  getBucket(key: string): McpRateLimitBucket | undefined;
  setBucket(key: string, bucket: McpRateLimitBucket): void;
  deleteBucket(key: string): boolean;
}

// ── Audit Sink ──

/** An MCP audit record. */
export interface McpAuditRecord {
  timestamp: number;
  agent_id: string;
  action: string;
  decision: string;
  details?: Record<string, unknown>;
}

/** Pluggable audit sink for MCP governance events. */
export interface McpAuditSink {
  /** Record an audit event. */
  record(entry: McpAuditRecord): void;
  /** Retrieve all recorded entries. */
  getAll(): McpAuditRecord[];
}
