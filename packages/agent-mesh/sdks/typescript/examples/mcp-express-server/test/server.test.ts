// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert/strict';
import test from 'node:test';
import { AddressInfo } from 'node:net';
import { createExampleServer } from '../src/server.ts';

process.env.NODE_ENV = 'test';

test('health endpoint returns a demo session token', async () => {
  const { app } = createExampleServer();
  const server = app.listen(0);

  try {
    const { port } = server.address() as AddressInfo;
    const response = await fetch(`http://127.0.0.1:${port}/health`);
    const payload = await response.json() as { status: string; demoSessionToken: string };

    assert.equal(response.status, 200);
    assert.equal(payload.status, 'ok');
    assert.ok(payload.demoSessionToken.length > 20);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

test('call-tool runs the governance pipeline', async () => {
  const { app, issueDemoSession } = createExampleServer();
  const server = app.listen(0);

  try {
    const { port } = server.address() as AddressInfo;
    const token = await issueDemoSession('demo-agent');
    const response = await fetch(`http://127.0.0.1:${port}/call-tool`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-session-token': token,
      },
      body: JSON.stringify({
        agentId: 'demo-agent',
        toolName: 'search_docs',
        args: { query: 'OWASP MCP' },
      }),
    });
    const payload = await response.json() as {
      allowed: boolean;
      messageVerification: { valid: boolean };
      response: { safe: boolean };
    };

    assert.equal(response.status, 200);
    assert.equal(payload.allowed, true);
    assert.equal(payload.messageVerification.valid, true);
    assert.equal(payload.response.safe, true);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
