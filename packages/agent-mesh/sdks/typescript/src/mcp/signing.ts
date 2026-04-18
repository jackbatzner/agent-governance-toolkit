// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type { McpNonceStore } from './stores';
import { InMemoryNonceStore } from './memory-stores';
import type { Clock } from './clock';
import { SystemClock } from './clock';
import type { NonceGenerator } from './nonce';
import { SystemNonceGenerator } from './nonce';

// ── Types ──

/** A signed MCP message envelope. */
export interface McpSignedMessage {
  payload: string;
  nonce: string;
  timestamp: number;
  signature: string;
  sender_id: string;
}

/** Result of verifying a signed message. */
export interface McpVerificationResult {
  is_valid: boolean;
  payload: string | null;
  sender_id: string | null;
  failure_reason: string | null;
}

// ── Factory helpers ──

function verificationSuccess(payload: string, senderId: string): McpVerificationResult {
  return { is_valid: true, payload, sender_id: senderId, failure_reason: null };
}

function verificationFailed(reason: string): McpVerificationResult {
  return { is_valid: false, payload: null, sender_id: null, failure_reason: reason };
}

// ── McpMessageSigner ──

/**
 * HMAC-SHA256 message signing with nonce-based replay protection.
 * Matches Python MCPMessageSigner and Rust McpMessageSigner.
 *
 * **Important:** If providing a custom `nonceStore`, use separate instances for
 * the signer and verifier. Sharing one store causes the signer's nonces to be
 * treated as replays by the verifier.
 */
export class McpMessageSigner {
  private readonly signingKey: Buffer;
  private readonly nonceStore: McpNonceStore;
  private readonly clock: Clock;
  private readonly nonceGen: NonceGenerator;
  private readonly replayWindowMs: number;

  constructor(
    signingKey: Buffer,
    options?: {
      nonceStore?: McpNonceStore;
      clock?: Clock;
      nonceGenerator?: NonceGenerator;
      replayWindowMs?: number;
    },
  ) {
    this.signingKey = signingKey;
    this.nonceStore = options?.nonceStore ?? new InMemoryNonceStore();
    this.clock = options?.clock ?? new SystemClock();
    this.nonceGen = options?.nonceGenerator ?? new SystemNonceGenerator();
    this.replayWindowMs = options?.replayWindowMs ?? 300_000; // 5 minutes
  }

  /** Create a signer from a base64-encoded key. */
  static fromBase64Key(
    base64Key: string,
    options?: {
      nonceStore?: McpNonceStore;
      clock?: Clock;
      nonceGenerator?: NonceGenerator;
      replayWindowMs?: number;
    },
  ): McpMessageSigner {
    return new McpMessageSigner(Buffer.from(base64Key, 'base64'), options);
  }

  /** Generate a new random signing key. */
  static generateKey(): Buffer {
    return randomBytes(32);
  }

  /** Sign a message payload. */
  signMessage(payload: string, senderId: string): McpSignedMessage {
    if (!payload) throw new Error('payload must not be empty');
    if (!senderId) throw new Error('senderId must not be empty');

    const nonce = this.nonceGen.generate();
    const timestamp = this.clock.now();
    const data = `${payload}|${nonce}|${timestamp}|${senderId}`;
    const signature = createHmac('sha256', this.signingKey)
      .update(data)
      .digest('hex');

    this.nonceStore.add(nonce, timestamp);

    return { payload, nonce, timestamp, signature, sender_id: senderId };
  }

  /** Verify a signed message. Rejects replays and expired messages. */
  verifyMessage(envelope: McpSignedMessage): McpVerificationResult {
    const now = this.clock.now();

    // Check expiration
    if (now - envelope.timestamp > this.replayWindowMs) {
      return verificationFailed('Message expired — outside replay window');
    }

    // Reject future-dated messages to prevent replay window bypass
    if (envelope.timestamp > now + this.replayWindowMs) {
      return verificationFailed('Message timestamp is in the future');
    }

    // Check replay
    if (this.nonceStore.has(envelope.nonce)) {
      return verificationFailed('Replay detected — nonce already seen');
    }

    // Verify signature
    const data = `${envelope.payload}|${envelope.nonce}|${envelope.timestamp}|${envelope.sender_id}`;
    const expected = createHmac('sha256', this.signingKey)
      .update(data)
      .digest('hex');

    // Use timing-safe comparison to prevent timing attacks on HMAC verification
    const expectedBuf = Buffer.from(expected, 'utf-8');
    const actualBuf = Buffer.from(envelope.signature, 'utf-8');
    if (expectedBuf.length !== actualBuf.length || !timingSafeEqual(expectedBuf, actualBuf)) {
      return verificationFailed('Invalid signature');
    }

    // Record nonce to prevent replay
    this.nonceStore.add(envelope.nonce, envelope.timestamp);

    return verificationSuccess(envelope.payload, envelope.sender_id);
  }

  /** Remove nonces older than the replay window. Returns count removed. */
  cleanupNonceCache(): number {
    const cutoff = this.clock.now() - this.replayWindowMs;
    return this.nonceStore.cleanup(cutoff);
  }
}
