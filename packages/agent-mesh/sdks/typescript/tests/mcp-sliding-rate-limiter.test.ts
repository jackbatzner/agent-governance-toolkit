// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { MCPSlidingRateLimiter } from '../src';

describe('MCPSlidingRateLimiter', () => {
  it('allows requests up to the configured limit', async () => {
    let now = 0;
    const limiter = new MCPSlidingRateLimiter({
      maxRequests: 2,
      windowMs: 1_000,
      clock: {
        now: () => new Date(now),
        monotonic: () => now,
      },
    });

    expect((await limiter.consume('agent-1')).allowed).toBe(true);
    expect((await limiter.consume('agent-1')).allowed).toBe(true);
    expect((await limiter.consume('agent-1')).allowed).toBe(false);
  });

  it('resets counts after the sliding window elapses', async () => {
    let now = 0;
    const limiter = new MCPSlidingRateLimiter({
      maxRequests: 1,
      windowMs: 1_000,
      clock: {
        now: () => new Date(now),
        monotonic: () => now,
      },
    });

    expect((await limiter.consume('agent-1')).allowed).toBe(true);
    expect((await limiter.consume('agent-1')).allowed).toBe(false);

    now = 2_000;
    expect((await limiter.consume('agent-1')).allowed).toBe(true);
  });
});
