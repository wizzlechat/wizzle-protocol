import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ROOM_LIMITS, mentionHandle, mentionSpans, mentioned } from '../src/room.ts';
import { decodePacket, encodePacket } from '../src/messages.ts';
import type { BridgeMessage, Packet, WizzleMessage } from '../src/messages.ts';

const members = [
  { id: 'g1', name: 'Scout' },
  { id: 'g2', name: 'Daily Brief' },
  { id: 'g3', name: 'Ada' },
  { id: 'g4', name: 'AdaBot' },
];

test('a handle is the name without whitespace', () => {
  assert.equal(mentionHandle('Daily Brief'), 'DailyBrief');
  assert.equal(mentionHandle(' Scout '), 'Scout');
});

test('mentions match without case, in member order', () => {
  assert.deepEqual(mentioned('@ada and @scout, look', members), ['g1', 'g3']);
  assert.deepEqual(mentioned('thanks @DailyBrief.', members), ['g2']);
  assert.deepEqual(mentioned('nobody here', members), []);
});

test('the longest handle wins and a handle needs a boundary on both sides', () => {
  assert.deepEqual(mentioned('@AdaBot run it', members), ['g4']);
  assert.deepEqual(mentioned('@Adam is not a member', members), []);
  assert.deepEqual(mentioned('mail scout@example.com', members), []);
  assert.deepEqual(mentioned('@Scout_ is another word', members), []);
});

test('@all names every member and wins over a member called All', () => {
  assert.deepEqual(mentioned('@all stand up', members), ['g1', 'g2', 'g3', 'g4']);
  assert.deepEqual(mentioned('@ALL', [...members, { id: 'g5', name: 'All' }]), ['g1', 'g2', 'g3', 'g4', 'g5']);
});

test('spans cover the @ and the handle', () => {
  assert.deepEqual(mentionSpans('hi @Scout and @all', members), [
    { start: 3, end: 9, id: 'g1' },
    { start: 14, end: 18, id: null },
  ]);
});

test('the handoff cap is six', () => {
  assert.equal(ROOM_LIMITS.handoffs, 6);
  assert.ok(ROOM_LIMITS.minMembers <= ROOM_LIMITS.maxMembers);
});

test('room packets round trip', () => {
  const wizzle: Array<Packet<WizzleMessage>> = [
    { id: 'r1', t: 'create_room', title: 'Launch plan', members: ['g1', 'g3'] },
    { id: 'r2', t: 'update_room', conv: 'wizzle:room:abc', title: 'Launch' },
    { id: 'r3', t: 'update_room', conv: 'wizzle:room:abc', members: ['g1', 'g2', 'g3'] },
    { id: 'r4', t: 'delete_room', conv: 'wizzle:room:abc' },
    { id: 'r5', t: 'continue_room', conv: 'wizzle:room:abc' },
    { id: 'r6', t: 'clear', conv: 'wizzle:room:abc' },
  ];
  for (const packet of wizzle) assert.deepEqual({ ...decodePacket(encodePacket(packet)).header }, { ...packet });

  const room = { id: 'wizzle:room:abc', title: 'Launch plan', members: ['g1', 'g3'], createdAt: 1700000000000, lastAgentAt: 1700000005000 };
  const bridge: Array<Packet<BridgeMessage>> = [
    { id: 'b1', t: 'rooms', rooms: [room] },
    { id: 'b2', t: 'room', ref: 'r1', room },
    { id: 'b3', t: 'room_deleted', conv: room.id },
    { id: 'b4', t: 'room_hold', conv: room.id, held: ['g3'] },
    { id: 'b5', t: 'room_hold', conv: room.id, held: [] },
  ];
  for (const packet of bridge) assert.deepEqual({ ...decodePacket(encodePacket(packet)).header }, { ...packet });
});

test('a room message, file, card, edit, question and activity carry their speaker', () => {
  const conv = 'wizzle:room:abc';
  const bridge: Array<Packet<BridgeMessage>> = [
    { id: 's1', t: 'message', message: { conv, msgId: 'm1', role: 'agent', text: '@Ada over to you', format: 'markdown', at: 1, speaker: 'g1' } },
    { id: 's2', t: 'file', conv, msgId: 'm1:f0', file: { name: 'a.pdf', mime: 'application/pdf', size: 3 }, at: 1, speaker: 'g1' },
    { id: 's3', t: 'card', conv, msgId: 'm2', card: { type: 'card' }, fallbackText: 'card', at: 2, speaker: 'g3' },
    { id: 's4', t: 'edit', conv, msgId: 'm2', text: 'fixed', speaker: 'g3' },
    { id: 's5', t: 'question', question: { conv, questionId: 'q1', question: 'Which?', options: [{ label: 'A', value: 'a' }], speaker: 'g3' } },
    { id: 's6', t: 'activity', activity: { conv, state: 'tool', tool: 'Bash', speaker: 'g3' } },
  ];
  for (const packet of bridge) assert.deepEqual({ ...decodePacket(encodePacket(packet)).header }, { ...packet });
});
