import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decodePacket, encodePacket } from '../src/messages.ts';
import type { BridgeMessage, Packet, PhoneMessage } from '../src/messages.ts';
import { fromHex } from '../src/bytes.ts';

test('packet with a binary body round trips', () => {
  const upload: Packet<PhoneMessage> = { id: 'u1', t: 'upload', uploadId: 'u1', file: { name: 'a.png', mime: 'image/png', size: 3 } };
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
  assert.throws(() => decodePacket(encodePacket({ id: 'x' } as unknown as Packet<PhoneMessage>)), /missing/);
});

test('topic packets round trip', () => {
  const phone: Array<Packet<PhoneMessage>> = [
    { id: 'c1', t: 'create_conversation', agentId: 'g1', title: 'Roadmap' },
    { id: 'c2', t: 'rename_conversation', conv: 'wizzle:agent:g1:roadmap', title: 'Plans' },
    { id: 'c3', t: 'delete_conversation', conv: 'wizzle:agent:g1:roadmap' },
  ];
  for (const packet of phone) {
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
  const phone: Array<Packet<PhoneMessage>> = [
    { id: 'l1', t: 'pause_agent', agentId: 'g1' },
    { id: 'l2', t: 'resume_agent', agentId: 'g1' },
    { id: 'l3', t: 'restart_agent', agentId: 'g1' },
    { id: 'l4', t: 'restart_agent', agentId: 'g1', message: 'Check the new tool works' },
    { id: 'l5', t: 'delete_agent', agentId: 'g1', removeWorkspace: true },
    { id: 'l6', t: 'delete_agent', agentId: 'g1', removeWorkspace: false },
  ];
  for (const packet of phone) {
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
  const create: Packet<PhoneMessage> = {
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

  const ask: Packet<PhoneMessage> = { id: 'a2', t: 'templates' };
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
