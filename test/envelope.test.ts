import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  FRAME_ACK,
  FRAME_DATA,
  FRAME_HEADER_BYTES,
  MAX_FRAME_BYTES,
  decodeControl,
  decodeFrame,
  encodeControl,
  encodeFrame,
} from '../src/envelope.ts';
import { fromHex } from '../src/bytes.ts';

test('frame round trip', () => {
  const epoch = fromHex('0102030405060708');
  const bytes = encodeFrame({ type: FRAME_DATA, epoch, seq: 42n, payload: fromHex('aabb') });
  assert.equal(bytes.length, FRAME_HEADER_BYTES + 2);
  const frame = decodeFrame(bytes);
  assert.equal(frame.type, FRAME_DATA);
  assert.deepEqual(frame.epoch, epoch);
  assert.equal(frame.seq, 42n);
  assert.deepEqual(frame.payload, fromHex('aabb'));
});

test('frame rejects bad input', () => {
  assert.throws(() => decodeFrame(new Uint8Array(FRAME_HEADER_BYTES - 1)), /short/);
  const unknown = new Uint8Array(FRAME_HEADER_BYTES);
  unknown[0] = 9;
  assert.throws(() => decodeFrame(unknown), /unknown/);
  assert.throws(() => encodeFrame({ type: FRAME_ACK, epoch: new Uint8Array(7), seq: 0n, payload: new Uint8Array(0) }), /epoch/);
  assert.throws(() => encodeFrame({ type: FRAME_DATA, epoch: new Uint8Array(8), seq: 0n, payload: new Uint8Array(MAX_FRAME_BYTES) }), /large/);
});

test('control messages round trip', () => {
  const text = encodeControl({ t: 'peer', online: true });
  assert.deepEqual(decodeControl(text), { t: 'peer', online: true });
  assert.throws(() => decodeControl('[]'));
  assert.throws(() => decodeControl('{"x":1}'));
});
