// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { randomUUID } from 'node:crypto';

/**
 * Nonce generator abstraction for testable randomness.
 * Matches the Rust `NonceGenerator` trait.
 */
export interface NonceGenerator {
  /** Generate a unique nonce string. */
  generate(): string;
}

/** System nonce generator using crypto.randomUUID(). */
export class SystemNonceGenerator implements NonceGenerator {
  generate(): string {
    return randomUUID();
  }
}

/**
 * Deterministic nonce generator for testing.
 * Produces sequential nonces: "nonce-0", "nonce-1", etc.
 */
export class DeterministicNonceGenerator implements NonceGenerator {
  private counter = 0;
  private readonly prefix: string;

  constructor(prefix = 'nonce') {
    this.prefix = prefix;
  }

  generate(): string {
    return `${this.prefix}-${this.counter++}`;
  }

  /** Reset the counter to zero. */
  reset(): void {
    this.counter = 0;
  }
}
