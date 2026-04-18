// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { SystemNonceGenerator, DeterministicNonceGenerator } from '../../src/mcp/nonce';

describe('SystemNonceGenerator', () => {
  it('generates UUID-format nonces', () => {
    const gen = new SystemNonceGenerator();
    const nonce = gen.generate();
    expect(nonce).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
  });

  it('generates unique nonces', () => {
    const gen = new SystemNonceGenerator();
    const nonces = new Set(Array.from({ length: 100 }, () => gen.generate()));
    expect(nonces.size).toBe(100);
  });
});

describe('DeterministicNonceGenerator', () => {
  it('produces sequential nonces', () => {
    const gen = new DeterministicNonceGenerator();
    expect(gen.generate()).toBe('nonce-0');
    expect(gen.generate()).toBe('nonce-1');
    expect(gen.generate()).toBe('nonce-2');
  });

  it('supports custom prefix', () => {
    const gen = new DeterministicNonceGenerator('test');
    expect(gen.generate()).toBe('test-0');
    expect(gen.generate()).toBe('test-1');
  });

  it('resets counter', () => {
    const gen = new DeterministicNonceGenerator();
    gen.generate();
    gen.generate();
    gen.reset();
    expect(gen.generate()).toBe('nonce-0');
  });
});
