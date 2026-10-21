import { test } from 'node:test';
import assert from 'node:assert/strict';
import { nodeCrypto } from '../src/crypto-node.ts';
import { Session } from '../src/session.ts';
import { FRAME_ACK, FRAME_DATA, FRAME_HS, decodeFrame } from '../src/envelope.ts';
import { equal, utf8 } from '../src/bytes.ts';
import type { KeyPair } from '../src/crypto.ts';
import type { SessionState } from '../src/session.ts';

const pairingId = nodeCrypto.randomBytes(16);
const psk = nodeCrypto.randomBytes(32);
const bridgeKeys = nodeCrypto.x25519KeyPair();
const phoneKeys = nodeCrypto.x25519KeyPair();

function phoneSession(own: KeyPair = phoneKeys, bridgeKey = bridgeKeys.publicKey, phonePsk = psk, state?: SessionState): Session {
  return new Session(nodeCrypto, 'phone', pairingId, { psk: phonePsk, own, peer: bridgeKey }, state);
}

function bridgeSession(pinned: Uint8Array | null = null, own: KeyPair = bridgeKeys, bridgePsk = psk, state?: SessionState): Session {
  return new Session(nodeCrypto, 'bridge', pairingId, { psk: bridgePsk, own, peer: pinned }, state);
}

function pair(phonePsk = psk, bridgePsk = psk) {
  return { phone: phoneSession(phoneKeys, bridgeKeys.publicKey, phonePsk), bridge: bridgeSession(null, bridgeKeys, bridgePsk) };
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
  const restored = phoneSession(phoneKeys, bridgeKeys.publicKey, psk, JSON.parse(JSON.stringify(phone.exportState())) as SessionState);
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

test('the first confirmed phone is pinned and a second phone with the same invite is refused', () => {
  const { phone, bridge } = pair();
  assert.ok(!bridge.peerKey);
  assert.ok(handshake(phone, bridge));
  const pinned = bridge.peerKey;
  assert.ok(pinned && equal(pinned, phoneKeys.publicKey));
  const second = phoneSession(nodeCrypto.x25519KeyPair());
  assert.throws(() => bridge.handleHandshake(decodeFrame(second.beginHandshake())), /unknown phone key/);
  assert.ok(handshake(phone, bridge));
});

test('a bridge without the invited static key cannot complete the handshake', () => {
  const phone = phoneSession();
  const impostor = bridgeSession(null, nodeCrypto.x25519KeyPair());
  const hs2 = decodeFrame(impostor.handleHandshake(decodeFrame(phone.beginHandshake())) as Uint8Array);
  const confirm = phone.handleHandshake(hs2) as Uint8Array;
  assert.ok(!['confirm', 'data'].includes(impostor.open(decodeFrame(confirm)).kind));
  assert.equal(impostor.peerKey, null);
});

test('a phone holding the psk but not the pinned static key cannot reach the bridge', () => {
  const bridge = bridgeSession(phoneKeys.publicKey);
  const thief = new Session(nodeCrypto, 'phone', pairingId, { psk, own: nodeCrypto.x25519KeyPair(), peer: bridgeKeys.publicKey });
  assert.throws(() => bridge.handleHandshake(decodeFrame(thief.beginHandshake())), /unknown phone key/);
  const forged = new Uint8Array(decodeFrame(thief.beginHandshake()).payload);
  forged.set(phoneKeys.publicKey, 32);
  const hs2 = decodeFrame(bridge.handleHandshake({ type: FRAME_HS, epoch: new Uint8Array(8), seq: 0n, payload: forged }) as Uint8Array);
  const confirm = thief.handleHandshake(hs2) as Uint8Array;
  assert.ok(!['confirm', 'data'].includes(bridge.open(decodeFrame(confirm)).kind));
  assert.ok(equal(bridge.peerKey as Uint8Array, phoneKeys.publicKey));
});

test('epochs another phone derived before the pin are dropped', () => {
  const bridge = bridgeSession();
  const early = phoneSession(nodeCrypto.x25519KeyPair());
  const earlyHs = decodeFrame(bridge.handleHandshake(decodeFrame(early.beginHandshake())) as Uint8Array);
  const earlyConfirm = early.handleHandshake(earlyHs) as Uint8Array;
  const phone = phoneSession();
  assert.ok(handshake(phone, bridge));
  assert.equal(bridge.open(decodeFrame(earlyConfirm)).kind, 'unknownEpoch');
  assert.equal(bridge.exportState().epochs.length, 1);
  assert.equal(bridge.open(decodeFrame(phone.seal(utf8('still here')))).kind, 'data');
});

test('the pinned key and epoch owners survive a bridge restart', () => {
  const { phone, bridge } = pair();
  handshake(phone, bridge);
  const state = JSON.parse(JSON.stringify(bridge.exportState())) as SessionState;
  assert.equal(state.epochs[0]?.peer !== undefined, true);
  const restored = bridgeSession(bridge.peerKey, bridgeKeys, psk, state);
  assert.equal(restored.open(decodeFrame(phone.seal(utf8('after restart')))).kind, 'data');
  assert.throws(() => restored.handleHandshake(decodeFrame(phoneSession(nodeCrypto.x25519KeyPair()).beginHandshake())), /unknown phone key/);
});

test('a phone session needs the bridge key and handshake frames must have the right size', () => {
  assert.throws(() => new Session(nodeCrypto, 'phone', pairingId, { psk, own: phoneKeys, peer: null }), /bridge key/);
  const bridge = bridgeSession();
  assert.throws(() => bridge.handleHandshake({ type: FRAME_HS, epoch: new Uint8Array(8), seq: 0n, payload: new Uint8Array(32).fill(9) }), /bad handshake/);
  const phone = phoneSession();
  phone.beginHandshake();
  assert.throws(() => phone.handleHandshake({ type: FRAME_HS, epoch: new Uint8Array(8), seq: 0n, payload: new Uint8Array(64).fill(9) }), /bad handshake/);
});
