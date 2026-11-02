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
const wizzleKeys = nodeCrypto.x25519KeyPair();

function wizzleSession(own: KeyPair = wizzleKeys, bridgeKey = bridgeKeys.publicKey, wizzlePsk = psk, state?: SessionState): Session {
  return new Session(nodeCrypto, 'wizzle', pairingId, { psk: wizzlePsk, own, peer: bridgeKey }, state);
}

function bridgeSession(pinned: Uint8Array | null = null, own: KeyPair = bridgeKeys, bridgePsk = psk, state?: SessionState): Session {
  return new Session(nodeCrypto, 'bridge', pairingId, { psk: bridgePsk, own, peer: pinned }, state);
}

function pair(wizzlePsk = psk, bridgePsk = psk) {
  return { wizzle: wizzleSession(wizzleKeys, bridgeKeys.publicKey, wizzlePsk), bridge: bridgeSession(null, bridgeKeys, bridgePsk) };
}

// Runs the full handshake and returns whether the bridge confirmed wizzle.
function handshake(wizzle: Session, bridge: Session): boolean {
  const hs1 = decodeFrame(wizzle.beginHandshake());
  assert.equal(hs1.type, FRAME_HS);
  const hs2 = decodeFrame(bridge.handleHandshake(hs1) as Uint8Array);
  assert.equal(hs2.type, FRAME_HS);
  const confirm = wizzle.handleHandshake(hs2);
  assert.ok(confirm);
  const bridgeResult = bridge.open(decodeFrame(confirm));
  if (bridgeResult.kind !== 'confirm') return false;
  if (!bridgeResult.reply) return false;
  const wizzleResult = wizzle.open(decodeFrame(bridgeResult.reply));
  return wizzleResult.kind === 'confirm';
}

test('handshake then data both ways', () => {
  const { wizzle, bridge } = pair();
  assert.ok(!wizzle.ready);
  assert.ok(handshake(wizzle, bridge));
  assert.ok(wizzle.ready && bridge.ready);
  assert.ok(equal(wizzle.currentEpochId as Uint8Array, bridge.currentEpochId as Uint8Array));

  const toBridge = bridge.open(decodeFrame(wizzle.seal(utf8('hi agent'))));
  assert.equal(toBridge.kind, 'data');
  assert.equal(new TextDecoder().decode((toBridge as { plaintext: Uint8Array }).plaintext), 'hi agent');

  const toWizzle = wizzle.open(decodeFrame(bridge.seal(utf8('hi human'))));
  assert.equal(toWizzle.kind, 'data');
  const ack = decodeFrame(wizzle.ack() as Uint8Array);
  assert.equal(ack.type, FRAME_ACK);
  assert.equal(ack.seq, 2n);
});

test('duplicates, tampering, and foreign epochs are rejected', () => {
  const { wizzle, bridge } = pair();
  handshake(wizzle, bridge);
  const frame = wizzle.seal(utf8('once'));
  assert.equal(bridge.open(decodeFrame(frame)).kind, 'data');
  assert.equal(bridge.open(decodeFrame(frame)).kind, 'duplicate');

  const tampered = wizzle.seal(utf8('twice'));
  tampered[tampered.length - 1] = (tampered[tampered.length - 1] as number) ^ 1;
  assert.equal(bridge.open(decodeFrame(tampered)).kind, 'badTag');

  const foreign = decodeFrame(wizzle.seal(utf8('x')));
  foreign.epoch = new Uint8Array(8);
  assert.equal(bridge.open(foreign).kind, 'unknownEpoch');
});

test('wrong psk fails at confirm, never at data', () => {
  const { wizzle, bridge } = pair(psk, nodeCrypto.randomBytes(32));
  const hs1 = decodeFrame(wizzle.beginHandshake());
  const hs2 = decodeFrame(bridge.handleHandshake(hs1) as Uint8Array);
  const confirm = wizzle.handleHandshake(hs2) as Uint8Array;
  assert.equal(bridge.open(decodeFrame(confirm)).kind, 'badTag');
});

test('state survives export and import, with the send counter moved ahead', () => {
  const { wizzle, bridge } = pair();
  handshake(wizzle, bridge);
  bridge.open(decodeFrame(wizzle.seal(utf8('one'))));
  const restored = wizzleSession(wizzleKeys, bridgeKeys.publicKey, psk, JSON.parse(JSON.stringify(wizzle.exportState())) as SessionState);
  assert.ok(restored.ready);
  const result = bridge.open(decodeFrame(restored.seal(utf8('two'))));
  assert.equal(result.kind, 'data');
  assert.equal(decodeFrame(restored.seal(utf8('three'))).seq, (1n << 32n) + 4n);
});

test('state restored from an older copy never repeats a nonce and still gets through', () => {
  const { wizzle, bridge } = pair();
  handshake(wizzle, bridge);
  const old = JSON.parse(JSON.stringify(wizzle.exportState())) as SessionState;
  const sent = decodeFrame(wizzle.seal(utf8('sent before the rollback')));
  assert.equal(bridge.open(sent).kind, 'data');
  const rolledBack = wizzleSession(wizzleKeys, bridgeKeys.publicKey, psk, old);
  const again = decodeFrame(rolledBack.seal(utf8('sent after the rollback')));
  assert.ok(again.seq > sent.seq);
  assert.ok(!equal(again.payload.subarray(0, 12), sent.payload.subarray(0, 12)));
  const opened = bridge.open(again);
  assert.equal(opened.kind, 'data');
  assert.equal(new TextDecoder().decode((opened as { plaintext: Uint8Array }).plaintext), 'sent after the rollback');
});

test('a payload too short to hold a nonce and a tag is refused', () => {
  const { wizzle, bridge } = pair();
  handshake(wizzle, bridge);
  const frame = decodeFrame(wizzle.seal(utf8('x')));
  assert.equal(bridge.open({ ...frame, payload: frame.payload.subarray(0, 27) }).kind, 'badTag');
});

test('rehandshake keeps the previous epoch readable and drops the one before', () => {
  const { wizzle, bridge } = pair();
  handshake(wizzle, bridge);
  const first = wizzle.currentEpochId as Uint8Array;
  const buffered = wizzle.seal(utf8('sent while offline'));

  handshake(wizzle, bridge);
  const second = wizzle.currentEpochId as Uint8Array;
  assert.ok(!equal(first, second));
  assert.equal(bridge.open(decodeFrame(buffered)).kind, 'data');
  assert.equal(bridge.open(decodeFrame(wizzle.seal(utf8('new epoch')))).kind, 'data');
  assert.ok(equal(decodeFrame(wizzle.seal(utf8('x'))).epoch, second));

  const stale = wizzle.seal(utf8('will be unreadable'));
  handshake(wizzle, bridge);
  handshake(wizzle, bridge);
  assert.equal(bridge.open(decodeFrame(stale)).kind, 'unknownEpoch');
});

test('replayed handshake frames are ignored by wizzle', () => {
  const { wizzle, bridge } = pair();
  const hs1 = decodeFrame(wizzle.beginHandshake());
  const hs2 = decodeFrame(bridge.handleHandshake(hs1) as Uint8Array);
  assert.ok(wizzle.handleHandshake(hs2));
  assert.equal(wizzle.handleHandshake(hs2), null);
  assert.throws(() => bridge.beginHandshake(), /wizzle/);
  const data = decodeFrame(wizzle.seal(utf8('x')));
  assert.equal(data.type, FRAME_DATA);
});

test('the first confirmed wizzle is pinned and a second wizzle with the same invite is refused', () => {
  const { wizzle, bridge } = pair();
  assert.ok(!bridge.peerKey);
  assert.ok(handshake(wizzle, bridge));
  const pinned = bridge.peerKey;
  assert.ok(pinned && equal(pinned, wizzleKeys.publicKey));
  const second = wizzleSession(nodeCrypto.x25519KeyPair());
  assert.throws(() => bridge.handleHandshake(decodeFrame(second.beginHandshake())), /unknown wizzle key/);
  assert.ok(handshake(wizzle, bridge));
});

test('a bridge without the invited static key cannot complete the handshake', () => {
  const wizzle = wizzleSession();
  const impostor = bridgeSession(null, nodeCrypto.x25519KeyPair());
  const hs2 = decodeFrame(impostor.handleHandshake(decodeFrame(wizzle.beginHandshake())) as Uint8Array);
  const confirm = wizzle.handleHandshake(hs2) as Uint8Array;
  assert.ok(!['confirm', 'data'].includes(impostor.open(decodeFrame(confirm)).kind));
  assert.equal(impostor.peerKey, null);
});

test('wizzle holding the psk but not the pinned static key cannot reach the bridge', () => {
  const bridge = bridgeSession(wizzleKeys.publicKey);
  const thief = new Session(nodeCrypto, 'wizzle', pairingId, { psk, own: nodeCrypto.x25519KeyPair(), peer: bridgeKeys.publicKey });
  assert.throws(() => bridge.handleHandshake(decodeFrame(thief.beginHandshake())), /unknown wizzle key/);
  const forged = new Uint8Array(decodeFrame(thief.beginHandshake()).payload);
  forged.set(wizzleKeys.publicKey, 32);
  const hs2 = decodeFrame(bridge.handleHandshake({ type: FRAME_HS, epoch: new Uint8Array(8), seq: 0n, payload: forged }) as Uint8Array);
  const confirm = thief.handleHandshake(hs2) as Uint8Array;
  assert.ok(!['confirm', 'data'].includes(bridge.open(decodeFrame(confirm)).kind));
  assert.ok(equal(bridge.peerKey as Uint8Array, wizzleKeys.publicKey));
});

test('epochs another wizzle derived before the pin are dropped', () => {
  const bridge = bridgeSession();
  const early = wizzleSession(nodeCrypto.x25519KeyPair());
  const earlyHs = decodeFrame(bridge.handleHandshake(decodeFrame(early.beginHandshake())) as Uint8Array);
  const earlyConfirm = early.handleHandshake(earlyHs) as Uint8Array;
  const wizzle = wizzleSession();
  assert.ok(handshake(wizzle, bridge));
  assert.equal(bridge.open(decodeFrame(earlyConfirm)).kind, 'unknownEpoch');
  assert.equal(bridge.exportState().epochs.length, 1);
  assert.equal(bridge.open(decodeFrame(wizzle.seal(utf8('still here')))).kind, 'data');
});

test('the pinned key and epoch owners survive a bridge restart', () => {
  const { wizzle, bridge } = pair();
  handshake(wizzle, bridge);
  const state = JSON.parse(JSON.stringify(bridge.exportState())) as SessionState;
  assert.equal(state.epochs[0]?.peer !== undefined, true);
  const restored = bridgeSession(bridge.peerKey, bridgeKeys, psk, state);
  assert.equal(restored.open(decodeFrame(wizzle.seal(utf8('after restart')))).kind, 'data');
  assert.throws(() => restored.handleHandshake(decodeFrame(wizzleSession(nodeCrypto.x25519KeyPair()).beginHandshake())), /unknown wizzle key/);
});

test('wizzle session needs the bridge key and handshake frames must have the right size', () => {
  assert.throws(() => new Session(nodeCrypto, 'wizzle', pairingId, { psk, own: wizzleKeys, peer: null }), /bridge key/);
  const bridge = bridgeSession();
  assert.throws(() => bridge.handleHandshake({ type: FRAME_HS, epoch: new Uint8Array(8), seq: 0n, payload: new Uint8Array(32).fill(9) }), /bad handshake/);
  const wizzle = wizzleSession();
  wizzle.beginHandshake();
  assert.throws(() => wizzle.handleHandshake({ type: FRAME_HS, epoch: new Uint8Array(8), seq: 0n, payload: new Uint8Array(64).fill(9) }), /bad handshake/);
});
