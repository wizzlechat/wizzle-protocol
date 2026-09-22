import { test } from 'node:test';
import assert from 'node:assert/strict';
import { nodeCrypto } from '../src/crypto-node.ts';
import { Session } from '../src/session.ts';
import { FRAME_ACK, FRAME_DATA, FRAME_HS, decodeFrame } from '../src/envelope.ts';
import { equal, utf8 } from '../src/bytes.ts';

const pairingId = nodeCrypto.randomBytes(16);
const psk = nodeCrypto.randomBytes(32);

function pair(phonePsk = psk, bridgePsk = psk) {
  return { phone: new Session(nodeCrypto, 'phone', pairingId, phonePsk), bridge: new Session(nodeCrypto, 'bridge', pairingId, bridgePsk) };
}

// Runs the full handshake and returns whether the bridge confirmed the phone.
function handshake(phone: Session, bridge: Session): boolean {
  const hs1 = decodeFrame(phone.beginHandshake());
  assert.equal(hs1.type, FRAME_HS);
  const hs2 = decodeFrame(bridge.handleHandshake(hs1) as Uint8Array);
  assert.equal(hs2.type, FRAME_HS);
  const confirm = phone.handleHandshake(hs2);
  assert.ok(confirm);
  const bridgeResult = bridge.open(decodeFrame(confirm));
  if (bridgeResult.kind !== 'confirm') return false;
  if (!bridgeResult.reply) return false;
  const phoneResult = phone.open(decodeFrame(bridgeResult.reply));
  return phoneResult.kind === 'confirm';
}

test('handshake then data both ways', () => {
  const { phone, bridge } = pair();
  assert.ok(!phone.ready);
  assert.ok(handshake(phone, bridge));
  assert.ok(phone.ready && bridge.ready);
  assert.ok(equal(phone.currentEpochId as Uint8Array, bridge.currentEpochId as Uint8Array));

  const toBridge = bridge.open(decodeFrame(phone.seal(utf8('hi agent'))));
  assert.equal(toBridge.kind, 'data');
  assert.equal(new TextDecoder().decode((toBridge as { plaintext: Uint8Array }).plaintext), 'hi agent');

  const toPhone = phone.open(decodeFrame(bridge.seal(utf8('hi human'))));
  assert.equal(toPhone.kind, 'data');
  const ack = decodeFrame(phone.ack() as Uint8Array);
  assert.equal(ack.type, FRAME_ACK);
  assert.equal(ack.seq, 2n);
});

test('duplicates, tampering, and foreign epochs are rejected', () => {
  const { phone, bridge } = pair();
  handshake(phone, bridge);
  const frame = phone.seal(utf8('once'));
  assert.equal(bridge.open(decodeFrame(frame)).kind, 'data');
  assert.equal(bridge.open(decodeFrame(frame)).kind, 'duplicate');

  const tampered = phone.seal(utf8('twice'));
  tampered[tampered.length - 1] = (tampered[tampered.length - 1] as number) ^ 1;
  assert.equal(bridge.open(decodeFrame(tampered)).kind, 'badTag');

  const foreign = decodeFrame(phone.seal(utf8('x')));
  foreign.epoch = new Uint8Array(8);
  assert.equal(bridge.open(foreign).kind, 'unknownEpoch');
});

test('wrong psk fails at confirm, never at data', () => {
  const { phone, bridge } = pair(psk, nodeCrypto.randomBytes(32));
  const hs1 = decodeFrame(phone.beginHandshake());
  const hs2 = decodeFrame(bridge.handleHandshake(hs1) as Uint8Array);
  const confirm = phone.handleHandshake(hs2) as Uint8Array;
  assert.equal(bridge.open(decodeFrame(confirm)).kind, 'badTag');
});

test('state survives export and import with counters intact', () => {
  const { phone, bridge } = pair();
  handshake(phone, bridge);
  bridge.open(decodeFrame(phone.seal(utf8('one'))));
  const restored = new Session(nodeCrypto, 'phone', pairingId, psk, JSON.parse(JSON.stringify(phone.exportState())));
  assert.ok(restored.ready);
  const result = bridge.open(decodeFrame(restored.seal(utf8('two'))));
  assert.equal(result.kind, 'data');
  assert.equal(decodeFrame(restored.seal(utf8('three'))).seq, 4n);
});

test('rehandshake keeps the previous epoch readable and drops the one before', () => {
  const { phone, bridge } = pair();
  handshake(phone, bridge);
  const first = phone.currentEpochId as Uint8Array;
  const buffered = phone.seal(utf8('sent while offline'));

  handshake(phone, bridge);
  const second = phone.currentEpochId as Uint8Array;
  assert.ok(!equal(first, second));
  assert.equal(bridge.open(decodeFrame(buffered)).kind, 'data');
  assert.equal(bridge.open(decodeFrame(phone.seal(utf8('new epoch')))).kind, 'data');
  assert.ok(equal(decodeFrame(phone.seal(utf8('x'))).epoch, second));

  const stale = phone.seal(utf8('will be unreadable'));
  handshake(phone, bridge);
  handshake(phone, bridge);
  assert.equal(bridge.open(decodeFrame(stale)).kind, 'unknownEpoch');
});

test('replayed handshake frames are ignored by the phone', () => {
  const { phone, bridge } = pair();
  const hs1 = decodeFrame(phone.beginHandshake());
  const hs2 = decodeFrame(bridge.handleHandshake(hs1) as Uint8Array);
  assert.ok(phone.handleHandshake(hs2));
  assert.equal(phone.handleHandshake(hs2), null);
  assert.throws(() => bridge.beginHandshake(), /phone/);
  const data = decodeFrame(phone.seal(utf8('x')));
  assert.equal(data.type, FRAME_DATA);
});
