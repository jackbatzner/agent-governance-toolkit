// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { McpMessageSigner } from '../../src/mcp/signing';
import { FixedClock } from '../../src/mcp/clock';
import { DeterministicNonceGenerator } from '../../src/mcp/nonce';
import { InMemoryNonceStore } from '../../src/mcp/memory-stores';

const BASE_TIME = 1_000_000;

function buildSignerAndVerifier() {
  const key = McpMessageSigner.generateKey();
  const clock = new FixedClock(BASE_TIME);
  const signerNonceStore = new InMemoryNonceStore();
  const verifierNonceStore = new InMemoryNonceStore();

  const signer = new McpMessageSigner(key, {
    nonceStore: signerNonceStore,
    clock,
    nonceGenerator: new DeterministicNonceGenerator('sign'),
    replayWindowMs: 300_000,
  });

  const verifier = new McpMessageSigner(key, {
    nonceStore: verifierNonceStore,
    clock,
    nonceGenerator: new DeterministicNonceGenerator('verify'),
    replayWindowMs: 300_000,
  });

  return { signer, verifier, clock, signerNonceStore, verifierNonceStore, key };
}

describe('McpMessageSigner', () => {
  // ── signMessage shape ──

  it('signMessage produces McpSignedMessage with correct shape', () => {
    const { signer } = buildSignerAndVerifier();
    const msg = signer.signMessage('hello', 'sender-1');
    expect(msg).toHaveProperty('payload', 'hello');
    expect(msg).toHaveProperty('nonce');
    expect(msg).toHaveProperty('timestamp', BASE_TIME);
    expect(msg).toHaveProperty('signature');
    expect(msg).toHaveProperty('sender_id', 'sender-1');
    expect(typeof msg.signature).toBe('string');
    expect(msg.signature.length).toBeGreaterThan(0);
  });

  // ── Verify valid message ──

  it('verifyMessage succeeds for a fresh valid message', () => {
    const { signer, verifier } = buildSignerAndVerifier();
    const signed = signer.signMessage('test payload', 'agent-a');
    const result = verifier.verifyMessage(signed);
    expect(result.is_valid).toBe(true);
    expect(result.payload).toBe('test payload');
    expect(result.sender_id).toBe('agent-a');
    expect(result.failure_reason).toBeNull();
  });

  // ── Replay rejection ──

  it('rejects replay of the same message', () => {
    const { signer, verifier } = buildSignerAndVerifier();
    const signed = signer.signMessage('data', 'agent-1');

    // First verification succeeds
    const first = verifier.verifyMessage(signed);
    expect(first.is_valid).toBe(true);

    // Second verification with same nonce should fail
    const second = verifier.verifyMessage(signed);
    expect(second.is_valid).toBe(false);
    expect(second.failure_reason).toContain('Replay');
  });

  // ── Expired message ──

  it('rejects expired message outside replay window', () => {
    const { signer, verifier, clock } = buildSignerAndVerifier();
    const signed = signer.signMessage('old data', 'agent-1');

    // Advance clock past the 5-minute replay window
    clock.advance(300_001);
    const result = verifier.verifyMessage(signed);
    expect(result.is_valid).toBe(false);
    expect(result.failure_reason).toContain('expired');
  });

  // ── Tampered message ──

  it('rejects a tampered message', () => {
    const { signer, verifier } = buildSignerAndVerifier();
    const signed = signer.signMessage('original', 'agent-1');

    const tampered = { ...signed, payload: 'tampered' };
    const result = verifier.verifyMessage(tampered);
    expect(result.is_valid).toBe(false);
    expect(result.failure_reason).toContain('signature');
  });

  // ── Future-dated message ──

  it('rejects a message with a far-future timestamp', () => {
    const clock = new FixedClock(1_000_000);
    const key = McpMessageSigner.generateKey();
    const signer = new McpMessageSigner(key, { clock });
    const signed = signer.signMessage('payload', 'agent-1');

    // Reset clock to present — message is now far in the future
    clock.set(0);
    const verifier = new McpMessageSigner(key, { clock });
    const result = verifier.verifyMessage(signed);
    expect(result.is_valid).toBe(false);
    expect(result.failure_reason).toContain('future');
  });

  // ── generateKey ──

  it('generateKey returns a 32-byte buffer', () => {
    const key = McpMessageSigner.generateKey();
    expect(Buffer.isBuffer(key)).toBe(true);
    expect(key.length).toBe(32);
  });

  // ── fromBase64Key ──

  it('fromBase64Key creates a working signer', () => {
    const key = McpMessageSigner.generateKey();
    const b64 = key.toString('base64');

    const clock = new FixedClock(BASE_TIME);
    const nonceStore1 = new InMemoryNonceStore();
    const nonceStore2 = new InMemoryNonceStore();

    const signer = McpMessageSigner.fromBase64Key(b64, {
      clock,
      nonceStore: nonceStore1,
      nonceGenerator: new DeterministicNonceGenerator('b64s'),
    });
    const verifier = McpMessageSigner.fromBase64Key(b64, {
      clock,
      nonceStore: nonceStore2,
      nonceGenerator: new DeterministicNonceGenerator('b64v'),
    });

    const signed = signer.signMessage('b64 test', 'agent-b');
    const result = verifier.verifyMessage(signed);
    expect(result.is_valid).toBe(true);
    expect(result.payload).toBe('b64 test');
  });

  // ── cleanupNonceCache ──

  it('cleanupNonceCache removes old entries', () => {
    const { signer, clock, signerNonceStore } = buildSignerAndVerifier();

    // Sign a message to add a nonce
    signer.signMessage('msg1', 'agent-1');
    expect(signerNonceStore.size).toBe(1);

    // Advance clock past the replay window and sign another
    clock.advance(300_001);
    signer.signMessage('msg2', 'agent-1');
    expect(signerNonceStore.size).toBe(2);

    // Cleanup should remove the old nonce
    const removed = signer.cleanupNonceCache();
    expect(removed).toBe(1);
    expect(signerNonceStore.size).toBe(1);
  });

  // --- Input-validation guards ---

  it('throws on empty payload in signMessage', () => {
    const { signer } = buildSignerAndVerifier();
    expect(() => signer.signMessage('', 'sender-1')).toThrow('payload must not be empty');
  });

  it('throws on empty senderId in signMessage', () => {
    const { signer } = buildSignerAndVerifier();
    expect(() => signer.signMessage('hello', '')).toThrow('senderId must not be empty');
  });
});
