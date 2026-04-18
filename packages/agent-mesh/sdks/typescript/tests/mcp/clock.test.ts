// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { SystemClock, FixedClock } from '../../src/mcp/clock';

describe('SystemClock', () => {
  it('returns a number close to Date.now()', () => {
    const clock = new SystemClock();
    const before = Date.now();
    const result = clock.now();
    const after = Date.now();
    expect(result).toBeGreaterThanOrEqual(before);
    expect(result).toBeLessThanOrEqual(after);
  });
});

describe('FixedClock', () => {
  it('always returns the fixed time', () => {
    const clock = new FixedClock(1000);
    expect(clock.now()).toBe(1000);
    expect(clock.now()).toBe(1000);
  });

  it('advances by the given milliseconds', () => {
    const clock = new FixedClock(1000);
    clock.advance(500);
    expect(clock.now()).toBe(1500);
    clock.advance(200);
    expect(clock.now()).toBe(1700);
  });

  it('can be set to a specific time', () => {
    const clock = new FixedClock(1000);
    clock.set(5000);
    expect(clock.now()).toBe(5000);
  });

  it('handles zero and negative advances', () => {
    const clock = new FixedClock(1000);
    clock.advance(0);
    expect(clock.now()).toBe(1000);
    clock.advance(-200);
    expect(clock.now()).toBe(800);
  });
});
