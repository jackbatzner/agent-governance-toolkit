// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import {
  InMemorySessionStore,
  InMemoryNonceStore,
  InMemoryRateLimitStore,
  InMemoryAuditSink,
} from '../../src/mcp/memory-stores';
import type { McpSessionRecord } from '../../src/mcp/stores';

// ── InMemorySessionStore ──

describe('InMemorySessionStore', () => {
  const session: McpSessionRecord = {
    token: 'tok-1',
    agent_id: 'agent-a',
    user_id: 'user-1',
    created_at: 1000,
    expires_at: 2000,
  };

  it('stores and retrieves sessions', () => {
    const store = new InMemorySessionStore();
    store.set('tok-1', session);
    expect(store.get('tok-1')).toEqual(session);
  });

  it('returns undefined for missing tokens', () => {
    const store = new InMemorySessionStore();
    expect(store.get('missing')).toBeUndefined();
  });

  it('deletes sessions', () => {
    const store = new InMemorySessionStore();
    store.set('tok-1', session);
    expect(store.delete('tok-1')).toBe(true);
    expect(store.get('tok-1')).toBeUndefined();
    expect(store.delete('tok-1')).toBe(false);
  });

  it('filters getAll by agentId', () => {
    const store = new InMemorySessionStore();
    store.set('tok-1', session);
    store.set('tok-2', { ...session, token: 'tok-2', agent_id: 'agent-b' });
    expect(store.getAll('agent-a')).toHaveLength(1);
    expect(store.getAll('agent-b')).toHaveLength(1);
    expect(store.getAll()).toHaveLength(2);
  });
});

// ── InMemoryNonceStore ──

describe('InMemoryNonceStore', () => {
  it('tracks nonces', () => {
    const store = new InMemoryNonceStore();
    expect(store.has('n1')).toBe(false);
    store.add('n1', 1000);
    expect(store.has('n1')).toBe(true);
  });

  it('cleans up old nonces', () => {
    const store = new InMemoryNonceStore();
    store.add('old', 100);
    store.add('new', 2000);
    const removed = store.cleanup(1000);
    expect(removed).toBe(1);
    expect(store.has('old')).toBe(false);
    expect(store.has('new')).toBe(true);
  });

  it('evicts oldest when at capacity', () => {
    const store = new InMemoryNonceStore(3);
    store.add('a', 100);
    store.add('b', 200);
    store.add('c', 300);
    expect(store.size).toBe(3);
    store.add('d', 400); // should evict 'a'
    expect(store.size).toBe(3);
    expect(store.has('a')).toBe(false);
    expect(store.has('d')).toBe(true);
  });

  it('reports size', () => {
    const store = new InMemoryNonceStore();
    expect(store.size).toBe(0);
    store.add('x', 1);
    expect(store.size).toBe(1);
  });
});

// ── InMemoryRateLimitStore ──

describe('InMemoryRateLimitStore', () => {
  it('stores and retrieves buckets', () => {
    const store = new InMemoryRateLimitStore();
    const bucket = { timestamps: [100, 200, 300] };
    store.setBucket('agent-a', bucket);
    expect(store.getBucket('agent-a')).toEqual(bucket);
  });

  it('returns undefined for missing buckets', () => {
    const store = new InMemoryRateLimitStore();
    expect(store.getBucket('missing')).toBeUndefined();
  });

  it('deletes buckets', () => {
    const store = new InMemoryRateLimitStore();
    store.setBucket('agent-a', { timestamps: [100] });
    expect(store.deleteBucket('agent-a')).toBe(true);
    expect(store.getBucket('agent-a')).toBeUndefined();
    expect(store.deleteBucket('agent-a')).toBe(false);
  });
});

// ── InMemoryAuditSink ──

describe('InMemoryAuditSink', () => {
  it('records and retrieves entries', () => {
    const sink = new InMemoryAuditSink();
    const entry = {
      timestamp: 1000,
      agent_id: 'agent-a',
      action: 'tool_call',
      decision: 'allowed',
    };
    sink.record(entry);
    expect(sink.getAll()).toHaveLength(1);
    expect(sink.getAll()[0]).toEqual(entry);
  });

  it('returns a copy of entries', () => {
    const sink = new InMemoryAuditSink();
    sink.record({
      timestamp: 1000,
      agent_id: 'a',
      action: 'x',
      decision: 'y',
    });
    const first = sink.getAll();
    const second = sink.getAll();
    expect(first).not.toBe(second);
    expect(first).toEqual(second);
  });

  it('supports details field', () => {
    const sink = new InMemoryAuditSink();
    sink.record({
      timestamp: 1000,
      agent_id: 'a',
      action: 'x',
      decision: 'y',
      details: { toolName: 'read_file' },
    });
    expect(sink.getAll()[0].details).toEqual({ toolName: 'read_file' });
  });

  it('reports size', () => {
    const sink = new InMemoryAuditSink();
    expect(sink.size).toBe(0);
    sink.record({ timestamp: 1, agent_id: 'a', action: 'x', decision: 'y' });
    expect(sink.size).toBe(1);
  });
});
