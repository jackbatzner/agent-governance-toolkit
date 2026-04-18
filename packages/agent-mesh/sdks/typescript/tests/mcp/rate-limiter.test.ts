// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { McpSlidingRateLimiter } from '../../src/mcp/rate-limiter';
import { FixedClock } from '../../src/mcp/clock';

describe('McpSlidingRateLimiter', () => {
  const BASE_TIME = 1_000_000;

  function createLimiter(maxCalls: number, windowMs: number) {
    const clock = new FixedClock(BASE_TIME);
    const limiter = new McpSlidingRateLimiter({
      maxCallsPerWindow: maxCalls,
      windowSizeMs: windowMs,
      clock,
    });
    return { limiter, clock };
  }

  it('allows up to maxCallsPerWindow', () => {
    const { limiter } = createLimiter(3, 60_000);
    expect(limiter.tryAcquire('agent-1')).toBe(true);
    expect(limiter.tryAcquire('agent-1')).toBe(true);
    expect(limiter.tryAcquire('agent-1')).toBe(true);
  });

  it('rejects after limit is reached', () => {
    const { limiter } = createLimiter(2, 60_000);
    expect(limiter.tryAcquire('agent-1')).toBe(true);
    expect(limiter.tryAcquire('agent-1')).toBe(true);
    expect(limiter.tryAcquire('agent-1')).toBe(false);
  });

  it('allows calls again after sliding window expires', () => {
    const { limiter, clock } = createLimiter(2, 10_000);
    expect(limiter.tryAcquire('agent-1')).toBe(true);
    expect(limiter.tryAcquire('agent-1')).toBe(true);
    expect(limiter.tryAcquire('agent-1')).toBe(false);

    // Advance past the window
    clock.advance(10_001);
    expect(limiter.tryAcquire('agent-1')).toBe(true);
  });

  it('getRemainingBudget returns correct count', () => {
    const { limiter } = createLimiter(5, 60_000);
    expect(limiter.getRemainingBudget('agent-1')).toBe(5);
    limiter.tryAcquire('agent-1');
    limiter.tryAcquire('agent-1');
    expect(limiter.getRemainingBudget('agent-1')).toBe(3);
  });

  it('getCallCount returns the number of calls in the window', () => {
    const { limiter } = createLimiter(10, 60_000);
    expect(limiter.getCallCount('agent-1')).toBe(0);
    limiter.tryAcquire('agent-1');
    limiter.tryAcquire('agent-1');
    expect(limiter.getCallCount('agent-1')).toBe(2);
  });

  it('reset clears rate limit for an agent', () => {
    const { limiter } = createLimiter(1, 60_000);
    limiter.tryAcquire('agent-1');
    expect(limiter.tryAcquire('agent-1')).toBe(false);
    limiter.reset('agent-1');
    expect(limiter.tryAcquire('agent-1')).toBe(true);
  });

  it('different agents have independent limits', () => {
    const { limiter } = createLimiter(1, 60_000);
    expect(limiter.tryAcquire('agent-a')).toBe(true);
    expect(limiter.tryAcquire('agent-a')).toBe(false);
    // A different agent should still be allowed
    expect(limiter.tryAcquire('agent-b')).toBe(true);
  });

  // --- Input-validation guard ---

  it('throws on empty agentId in tryAcquire', () => {
    const { limiter } = createLimiter(10, 60_000);
    expect(() => limiter.tryAcquire('')).toThrow('agentId must not be empty');
  });
});
