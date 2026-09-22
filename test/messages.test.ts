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
