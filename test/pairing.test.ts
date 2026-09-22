import { test } from 'node:test';
import assert from 'node:assert/strict';
import { nodeCrypto } from '../src/crypto-node.ts';
import { derivePsk, deriveRelaySecret, encodeInvite, newInvite, parseInvite } from '../src/pairing.ts';
import { equal } from '../src/bytes.ts';

test('invite round trips through a wizzle url', () => {
  const invite = newInvite(nodeCrypto, 'wss://relay.example.com/v1', { name: 'pi', runtime: 'nanoclaw' });
  const text = encodeInvite(invite);
  assert.ok(text.startsWith('wizzle://pair?'));
  const parsed = parseInvite(text);
  assert.equal(parsed.relay, invite.relay);
  assert.deepEqual(parsed.pairingId, invite.pairingId);
  assert.deepEqual(parsed.secret, invite.secret);
  assert.equal(parsed.name, 'pi');
  assert.equal(parsed.runtime, 'nanoclaw');
});

test('invite rejects wrong shapes', () => {
  const invite = newInvite(nodeCrypto, 'wss://relay.example.com');
  assert.throws(() => parseInvite('https://example.com/pair?x=1'), /not a wizzle invite/);
  assert.throws(() => parseInvite('wizzle://pair?r=wss://x'), /missing/);
  assert.throws(() => parseInvite(encodeInvite({ ...invite, relay: 'https://relay.example.com' })), /websocket/);
  assert.throws(() => parseInvite(encodeInvite({ ...invite, secret: invite.secret.subarray(0, 31) })), /secret/);
});

test('relay secret and psk differ and are stable', () => {
  const invite = newInvite(nodeCrypto, 'wss://relay.example.com');
  const relay = deriveRelaySecret(nodeCrypto, invite.secret);
  const psk = derivePsk(nodeCrypto, invite.secret);
  assert.equal(relay.length, 32);
  assert.equal(psk.length, 32);
  assert.ok(!equal(relay, psk));
  assert.ok(equal(relay, deriveRelaySecret(nodeCrypto, invite.secret)));
});
