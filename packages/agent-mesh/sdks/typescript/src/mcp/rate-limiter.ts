// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import type { McpRateLimitStore } from './stores';
import { InMemoryRateLimitStore } from './memory-stores';
import type { Clock } from './clock';
import { SystemClock } from './clock';

/** Result of a rate-limit check. */
export interface McpRateLimitDecision {
  allowed: boolean;
  remaining: number;
  retry_after_ms: number;
}

/**
 * Per-agent sliding-window rate limiter.
 * Matches Python MCPSlidingRateLimiter and Rust McpSlidingRateLimiter.
 */
export class McpSlidingRateLimiter {
  private readonly maxCallsPerWindow: number;
  private readonly windowSizeMs: number;
  private readonly store: McpRateLimitStore;
  private readonly clock: Clock;

  constructor(options?: {
    maxCallsPerWindow?: number;
    windowSizeMs?: number;
    store?: McpRateLimitStore;
    clock?: Clock;
  }) {
    this.maxCallsPerWindow = options?.maxCallsPerWindow ?? 60;
    this.windowSizeMs = options?.windowSizeMs ?? 60_000;
    this.store = options?.store ?? new InMemoryRateLimitStore();
    this.clock = options?.clock ?? new SystemClock();
  }

  /** Try to acquire a call slot. Returns true if allowed. */
  tryAcquire(agentId: string): boolean {
    if (!agentId) throw new Error('agentId must not be empty');

    const now = this.clock.now();
    const cutoff = now - this.windowSizeMs;

    const bucket = this.store.getBucket(agentId);
    const timestamps = bucket ? bucket.timestamps.filter((t) => t > cutoff) : [];

    if (timestamps.length >= this.maxCallsPerWindow) {
      this.store.setBucket(agentId, { timestamps });
      return false;
    }

    timestamps.push(now);
    this.store.setBucket(agentId, { timestamps });
    return true;
  }

  /** Check how many calls remain in the current window. */
  getRemainingBudget(agentId: string): number {
    const now = this.clock.now();
    const cutoff = now - this.windowSizeMs;
    const bucket = this.store.getBucket(agentId);
    const count = bucket ? bucket.timestamps.filter((t) => t > cutoff).length : 0;
    return Math.max(0, this.maxCallsPerWindow - count);
  }

  /** Get the current call count in the window. */
  getCallCount(agentId: string): number {
    const now = this.clock.now();
    const cutoff = now - this.windowSizeMs;
    const bucket = this.store.getBucket(agentId);
    return bucket ? bucket.timestamps.filter((t) => t > cutoff).length : 0;
  }

  /** Reset rate limit for a specific agent. */
  reset(agentId: string): void {
    this.store.deleteBucket(agentId);
  }

  /** Reset all rate limits. Use per-agent reset(agentId) for targeted clearing. */
  resetAll(): void {
    throw new Error('resetAll() is not supported by the current store interface; use reset(agentId) instead');
  }
}
