import { test } from 'node:test';
import assert from 'node:assert/strict';
import { nodeCrypto } from '../src/crypto-node.ts';
import { derivePairedRelaySecret, derivePsk, deriveRelaySecret, encodeInvite, newInvite, parseInvite } from '../src/pairing.ts';
import { equal } from '../src/bytes.ts';

const bridgeKey = nodeCrypto.x25519KeyPair().publicKey;

test('invite round trips through a wizzle url', () => {
  const invite = newInvite(nodeCrypto, { relay: 'wss://relay.example.com/v1', bridgeKey, expiresAt: 1_900_000_000, name: 'pi', runtime: 'nanoclaw' });
  const text = encodeInvite(invite);
  assert.ok(text.startsWith('wizzle://pair?'));
  const parsed = parseInvite(text);
  assert.equal(parsed.relay, invite.relay);
  assert.deepEqual(parsed.pairingId, invite.pairingId);
  assert.deepEqual(parsed.secret, invite.secret);
  assert.deepEqual(parsed.bridgeKey, bridgeKey);
  assert.equal(parsed.expiresAt, 1_900_000_000);
  assert.equal(parsed.name, 'pi');
  assert.equal(parsed.runtime, 'nanoclaw');
});

test('invite rejects wrong shapes', () => {
  const invite = newInvite(nodeCrypto, { relay: 'wss://relay.example.com', bridgeKey, expiresAt: 1 });
  const without = (key: string) => {
    const url = new URL(encodeInvite(invite));
    url.searchParams.delete(key);
    return url.toString();
  };
  assert.throws(() => parseInvite('https://example.com/pair?x=1'), /not a wizzle invite/);
  assert.throws(() => parseInvite('wizzle://pair?r=wss://x'), /missing/);
  assert.throws(() => parseInvite(without('k')), /missing/);
  assert.throws(() => parseInvite(without('e')), /missing/);
  assert.throws(() => parseInvite(encodeInvite({ ...invite, relay: 'https://relay.example.com' })), /websocket/);
  assert.throws(() => parseInvite(encodeInvite({ ...invite, secret: invite.secret.subarray(0, 31) })), /secret/);
  assert.throws(() => parseInvite(encodeInvite({ ...invite, bridgeKey: bridgeKey.subarray(0, 31) })), /bridge key/);
  assert.throws(() => parseInvite(encodeInvite({ ...invite, expiresAt: -5 })), /expiry/);
});

test('relay secret and psk differ and are stable', () => {
  const invite = newInvite(nodeCrypto, { relay: 'wss://relay.example.com', bridgeKey, expiresAt: 1 });
  const relay = deriveRelaySecret(nodeCrypto, invite.secret);
  const psk = derivePsk(nodeCrypto, invite.secret);
  assert.equal(relay.length, 32);
  assert.equal(psk.length, 32);
  assert.ok(!equal(relay, psk));
  assert.ok(equal(relay, deriveRelaySecret(nodeCrypto, invite.secret)));
});

test('the paired relay secret matches on both sides and needs a static private key', () => {
  const pairingId = nodeCrypto.randomBytes(16);
  const wizzle = nodeCrypto.x25519KeyPair();
  const bridge = nodeCrypto.x25519KeyPair();
  const fromWizzle = derivePairedRelaySecret(nodeCrypto, pairingId, wizzle.privateKey, bridge.publicKey);
  const fromBridge = derivePairedRelaySecret(nodeCrypto, pairingId, bridge.privateKey, wizzle.publicKey);
  assert.ok(equal(fromWizzle, fromBridge));
  const other = nodeCrypto.x25519KeyPair();
  assert.ok(!equal(fromWizzle, derivePairedRelaySecret(nodeCrypto, pairingId, other.privateKey, bridge.publicKey)));
  assert.ok(!equal(fromWizzle, derivePairedRelaySecret(nodeCrypto, nodeCrypto.randomBytes(16), wizzle.privateKey, bridge.publicKey)));
  assert.throws(() => derivePairedRelaySecret(nodeCrypto, pairingId, wizzle.privateKey, new Uint8Array(32)), /low order|derivation/);
});
