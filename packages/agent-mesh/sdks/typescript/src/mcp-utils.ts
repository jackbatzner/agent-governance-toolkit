// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import {
  createHmac,
  randomBytes,
  timingSafeEqual,
} from 'crypto';
import { performance } from 'perf_hooks';
import { MCPClock } from './types';

const DEFAULT_REGEX_SCAN_TIMEOUT_MS = 100;

export const DEFAULT_MCP_CLOCK: MCPClock = {
  now: () => Date.now(),
  monotonic: () => performance.now(),
};

export function toTimestamp(value: number | Date): number {
  return value instanceof Date ? value.getTime() : value;
}

export function normalizeSecret(secret: string | Uint8Array): Buffer {
  return typeof secret === 'string'
    ? Buffer.from(secret, 'utf-8')
    : Buffer.from(secret);
}

export class RegexScanBudget {
  private readonly startedAt: number;

  constructor(
    private readonly clock: MCPClock = DEFAULT_MCP_CLOCK,
    private readonly timeoutMs: number = DEFAULT_REGEX_SCAN_TIMEOUT_MS,
  ) {
    this.startedAt = this.monotonicNow();
  }

  checkpoint(
    publicMessage: string = 'Regex scan exceeded time budget - access denied',
  ): void {
    if (this.monotonicNow() - this.startedAt >= this.timeoutMs) {
      throw new Error(publicMessage);
    }
  }

  private monotonicNow(): number {
    return this.clock.monotonic?.() ?? performance.now();
  }
}

export function createRegexScanBudget(
  clock?: MCPClock,
  timeoutMs?: number,
): RegexScanBudget {
  return new RegexScanBudget(clock ?? DEFAULT_MCP_CLOCK, timeoutMs ?? DEFAULT_REGEX_SCAN_TIMEOUT_MS);
}

export function randomNonce(size: number = 18): string {
  return randomBytes(size).toString('base64url');
}

export function stableStringify(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

export function createHmacHex(
  secret: string | Uint8Array,
  ...parts: Array<string | number>
): string {
  const hmac = createHmac('sha256', normalizeSecret(secret));
  for (const part of parts) {
    hmac.update(String(part));
    hmac.update('\n');
  }
  return hmac.digest('hex');
}

export function timingSafeEqualHex(
  left: string,
  right: string,
): boolean {
  if (left.length !== right.length) {
    return false;
  }

  try {
    return timingSafeEqual(
      Buffer.from(left, 'hex'),
      Buffer.from(right, 'hex'),
    );
  } catch {
    return false;
  }
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function truncatePreview(value: string, max: number = 120): string {
  return value.length <= max ? value : `${value.slice(0, max)}...`;
}

function canonicalize(
  value: unknown,
  seen: WeakSet<object> = new WeakSet(),
): unknown {
  if (
    value === null
    || typeof value === 'string'
    || typeof value === 'number'
    || typeof value === 'boolean'
  ) {
    return value;
  }

  if (typeof value === 'bigint') {
    return value.toString();
  }

  if (value instanceof Date) {
    return value.toISOString();
  }

  if (value instanceof Uint8Array) {
    return Buffer.from(value).toString('base64');
  }

  if (Array.isArray(value)) {
    return value.map((item) => canonicalize(item, seen));
  }

  if (typeof value === 'object' && value !== null) {
    if (seen.has(value)) {
      throw new Error('Cannot canonicalize circular structures');
    }
    seen.add(value);

    const record = value as Record<string, unknown>;
    const result: Record<string, unknown> = {};
    for (const key of Object.keys(record).sort()) {
      result[key] = canonicalize(record[key], seen);
    }
    return result;
  }

  return String(value);
}
