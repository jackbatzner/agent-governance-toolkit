// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import {
  MCPMaybePromise,
  MCPClock,
  MCPSlidingRateLimitConfig,
  MCPSlidingRateLimitResult,
} from './types';
import { DEFAULT_MCP_CLOCK, toTimestamp } from './mcp-utils';

export class InMemoryMCPRateLimitStore {
  private readonly buckets = new Map<string, number[]>();

  get(agentId: string): number[] {
    return [...(this.buckets.get(agentId) ?? [])];
  }

  set(agentId: string, hits: number[]): void {
    this.buckets.set(agentId, [...hits]);
  }

  reset(agentId?: string): void {
    if (agentId) {
      this.buckets.delete(agentId);
      return;
    }
    this.buckets.clear();
  }
}

export class MCPSlidingRateLimiter {
  private readonly maxRequests: number;
  private readonly windowMs: number;
  private readonly clock: MCPClock;
  private readonly store: {
    get(agentId: string): MCPMaybePromise<number[]>;
    set(agentId: string, hits: number[]): MCPMaybePromise<void>;
    reset?(agentId?: string): MCPMaybePromise<void>;
  };

  constructor(config: MCPSlidingRateLimitConfig) {
    this.maxRequests = config.maxRequests;
    this.windowMs = config.windowMs;
    this.clock = config.clock ?? DEFAULT_MCP_CLOCK;
    this.store = new InMemoryMCPRateLimitStore();
  }

  async consume(agentId: string): Promise<MCPSlidingRateLimitResult> {
    const now = toTimestamp(this.clock.now());
    const bucket = await this.prune(agentId, now);
    bucket.push(now);
    await this.store.set(agentId, bucket);

    const resetAt = bucket[0] + this.windowMs;
    const allowed = bucket.length <= this.maxRequests;
    const remaining = Math.max(this.maxRequests - bucket.length, 0);

    return {
      allowed,
      count: bucket.length,
      limit: this.maxRequests,
      remaining,
      resetAt,
      retryAfterMs: allowed ? 0 : Math.max(resetAt - now, 0),
    };
  }

  async reset(agentId?: string): Promise<void> {
    await this.store.reset?.(agentId);
  }

  private async prune(agentId: string, now: number): Promise<number[]> {
    const current = await this.store.get(agentId);
    const next = current.filter((timestamp) => now - timestamp < this.windowMs);
    await this.store.set(agentId, next);
    return next;
  }
}
