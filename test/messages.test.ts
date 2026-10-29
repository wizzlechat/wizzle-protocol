import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decodePacket, encodePacket } from '../src/messages.ts';
import type { BridgeMessage, Packet, WizzleMessage } from '../src/messages.ts';
import { fromHex } from '../src/bytes.ts';

test('packet with a binary body round trips', () => {
  const upload: Packet<WizzleMessage> = { id: 'u1', t: 'upload', uploadId: 'u1', file: { name: 'a.png', mime: 'image/png', size: 3 } };
  const bytes = encodePacket(upload, fromHex('010203'));
  const decoded = decodePacket(bytes);
  assert.equal(decoded.header.t, 'upload');
  assert.equal(decoded.header.id, 'u1');
  assert.deepEqual(decoded.header['file'], { name: 'a.png', mime: 'image/png', size: 3 });
  assert.deepEqual(decoded.body, fromHex('010203'));
});

test('packet without a body has an empty body', () => {
  const decoded = decodePacket(encodePacket({ id: 's1', t: 'sync' }));
  assert.equal(decoded.body.length, 0);
});

test('packet rejects malformed input', () => {
  assert.throws(() => decodePacket(new Uint8Array(3)), /short/);
  assert.throws(() => decodePacket(fromHex('000000ff7b7d')), /overruns/);
  assert.throws(() => decodePacket(encodePacket({ id: 'x' } as unknown as Packet<WizzleMessage>)), /missing/);
});

test('topic packets round trip', () => {
  const wizzle: Array<Packet<WizzleMessage>> = [
    { id: 'c1', t: 'create_conversation', agentId: 'g1', title: 'Roadmap' },
    { id: 'c2', t: 'rename_conversation', conv: 'wizzle:agent:g1:roadmap', title: 'Plans' },
    { id: 'c3', t: 'delete_conversation', conv: 'wizzle:agent:g1:roadmap' },
  ];
  for (const packet of wizzle) {
    const decoded = decodePacket(encodePacket(packet));
    assert.deepEqual({ ...decoded.header }, { ...packet });
  }

  const bridge: Array<Packet<BridgeMessage>> = [
    {
      id: 'b1',
      t: 'conversation',
      conversation: { id: 'wizzle:agent:g1:roadmap', agentId: 'g1', title: 'Roadmap', topic: true, createdAt: 1700000000000 },
    },
    { id: 'b2', t: 'conversation_deleted', conv: 'wizzle:agent:g1:roadmap' },
  ];
  for (const packet of bridge) {
    const decoded = decodePacket(encodePacket(packet));
    assert.deepEqual({ ...decoded.header }, { ...packet });
  }
});

test('agent lifecycle packets and the paused status round trip', () => {
  const wizzle: Array<Packet<WizzleMessage>> = [
    { id: 'l1', t: 'pause_agent', agentId: 'g1' },
    { id: 'l2', t: 'resume_agent', agentId: 'g1' },
    { id: 'l3', t: 'restart_agent', agentId: 'g1' },
    { id: 'l4', t: 'restart_agent', agentId: 'g1', message: 'Check the new tool works' },
    { id: 'l5', t: 'delete_agent', agentId: 'g1', removeWorkspace: true },
    { id: 'l6', t: 'delete_agent', agentId: 'g1', removeWorkspace: false },
  ];
  for (const packet of wizzle) {
    const decoded = decodePacket(encodePacket(packet));
    assert.deepEqual({ ...decoded.header }, { ...packet });
  }

  const bridge: Array<Packet<BridgeMessage>> = [
    { id: 'l7', t: 'agent_deleted', agentId: 'g1' },
    { id: 'l8', t: 'agent', agent: { id: 'g1', name: 'Scout', status: 'paused' } },
  ];
  for (const packet of bridge) {
    const decoded = decodePacket(encodePacket(packet));
    assert.deepEqual({ ...decoded.header }, { ...packet });
  }
});

test('create_agent and templates packets round trip', () => {
  const create: Packet<WizzleMessage> = {
    id: 'a1',
    t: 'create_agent',
    name: 'Scout',
    description: 'legacy field',
    purpose: 'Watch the build and tell me when it breaks.',
    template: 'sales/sdr',
    copyFrom: 'ag-1',
    timezone: 'Europe/Lisbon',
  };
  assert.deepEqual({ ...decodePacket(encodePacket(create)).header }, { ...create });

  const ask: Packet<WizzleMessage> = { id: 'a2', t: 'templates' };
  assert.deepEqual({ ...decodePacket(encodePacket(ask)).header }, { ...ask });

  const list: Packet<BridgeMessage> = {
    id: 'b1',
    t: 'templates',
    templates: [
      { ref: 'sales/sdr', name: 'sdr', agentName: 'SDR', description: 'Outbound', version: '1.2.0', tasks: 2, mcpServers: 1, skills: 3 },
      { ref: 'notes', name: 'notes', tasks: 0, mcpServers: 0, skills: 0 },
    ],
  };
  assert.deepEqual({ ...decodePacket(encodePacket(list)).header }, { ...list });
});

test('key packets and library templates round trip', () => {
  const packets: Array<Packet<WizzleMessage> | Packet<BridgeMessage>> = [
    { id: 'k1', t: 'secrets' },
    {
      id: 'k2',
      t: 'create_secret',
      secret: { name: 'GitHub', type: 'generic', host: 'api.github.com', injection: { headerName: 'Authorization', valueFormat: 'Bearer {value}' }, value: 'ghp_x' },
    },
    { id: 'k3', t: 'update_secret', secretId: 's1', changes: { path: null, injection: { pathTemplate: '/bot{value}' } } },
    { id: 'k4', t: 'delete_secret', secretId: 's1' },
    { id: 'k5', t: 'agent_secrets', agentId: 'ag-1' },
    { id: 'k6', t: 'attach_secret', agentId: 'ag-1', secretId: 's1' },
    { id: 'k7', t: 'detach_secret', agentId: 'ag-1', secretId: 's1' },
    { id: 'k8', t: 'create_agent', name: 'Scout', template: 'data/analyst', secrets: ['s1', 's2'] },
    {
      id: 'b1',
      t: 'secrets',
      secrets: [
        { id: 's1', name: 'Search', type: 'generic', host: 'www.googleapis.com', path: '/customsearch/*', injection: { paramName: 'key' }, createdAt: 1 },
        { id: 's2', name: 'Rewrite', type: 'generic', host: 'api.example.com', injection: { pathRegex: '^/v1/(.*)$', pathReplacement: '/v1/{value}/$1' } },
        { id: 's3', name: 'Anthropic', type: 'anthropic', host: 'api.anthropic.com' },
      ],
    },
    { id: 'b2', t: 'secret', ref: 'k2', secret: { id: 's4', name: 'GitHub', type: 'generic', host: 'api.github.com' } },
    { id: 'b3', t: 'secret_deleted', secretId: 's1' },
    { id: 'b4', t: 'agent_secrets', agentId: 'ag-1', secretIds: ['s2'] },
    { id: 'b5', t: 'templates', templates: [{ ref: 'data/analyst', name: 'analyst', description: 'Answers data questions', category: 'data', downloaded: false }] },
  ];
  for (const packet of packets) assert.deepEqual({ ...decodePacket(encodePacket(packet)).header }, { ...packet });
});
