// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * Clock abstraction for testable time.
 * Matches the Rust `Clock` trait and Python implicit clock DI pattern.
 */
export interface Clock {
  /** Returns the current time in milliseconds since epoch. */
  now(): number;
}

/** Real system clock using Date.now(). */
export class SystemClock implements Clock {
  now(): number {
    return Date.now();
  }
}

/** Fixed clock that always returns the same time. Useful for deterministic tests. */
export class FixedClock implements Clock {
  private time: number;

  constructor(fixedTimeMs: number) {
    this.time = fixedTimeMs;
  }

  now(): number {
    return this.time;
  }

  /** Advance the clock by the given number of milliseconds. */
  advance(ms: number): void {
    this.time += ms;
  }

  /** Set the clock to a specific time. */
  set(timeMs: number): void {
    this.time = timeMs;
  }
}
