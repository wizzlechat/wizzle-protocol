import type { CryptoProvider } from './crypto.ts';
import { X25519_BYTES, dh } from './crypto.ts';
import { fromB64Url, toB64Url, utf8 } from './bytes.ts';

export const PAIRING_ID_BYTES = 16;
export const PAIRING_SECRET_BYTES = 32;
export const INVITE_SCHEME = 'wizzle:';

// What the QR code carries. The secret never reaches the relay in this form; expiresAt is unix seconds.
export type PairingInvite = {
  relay: string;
  pairingId: Uint8Array;
  secret: Uint8Array;
  bridgeKey: Uint8Array;
  expiresAt: number;
  name?: string;
  runtime?: string;
};

export type InviteOptions = {
  relay: string;
  bridgeKey: Uint8Array;
  expiresAt: number;
  name?: string;
  runtime?: string;
};

export function newInvite(crypto: CryptoProvider, opts: InviteOptions): PairingInvite {
  const invite: PairingInvite = {
    relay: opts.relay,
    pairingId: crypto.randomBytes(PAIRING_ID_BYTES),
    secret: crypto.randomBytes(PAIRING_SECRET_BYTES),
    bridgeKey: opts.bridgeKey,
    expiresAt: opts.expiresAt,
  };
  if (opts.name !== undefined) invite.name = opts.name;
  if (opts.runtime !== undefined) invite.runtime = opts.runtime;
  return invite;
}

export function encodeInvite(invite: PairingInvite): string {
  const params = new URLSearchParams();
  params.set('r', invite.relay);
  params.set('p', toB64Url(invite.pairingId));
  params.set('s', toB64Url(invite.secret));
  params.set('k', toB64Url(invite.bridgeKey));
  params.set('e', String(invite.expiresAt));
  if (invite.name !== undefined) params.set('n', invite.name);
  if (invite.runtime !== undefined) params.set('rt', invite.runtime);
  return `${INVITE_SCHEME}//pair?${params.toString()}`;
}

export function parseInvite(text: string): PairingInvite {
  const url = new URL(text);
  if (url.protocol !== INVITE_SCHEME || url.host !== 'pair') throw new Error('not a wizzle invite');
  const relay = url.searchParams.get('r');
  const p = url.searchParams.get('p');
  const s = url.searchParams.get('s');
  const k = url.searchParams.get('k');
  const e = url.searchParams.get('e');
  if (!relay || !p || !s || !k || !e) throw new Error('invite missing fields');
  const relayUrl = new URL(relay);
  if (relayUrl.protocol !== 'wss:' && relayUrl.protocol !== 'ws:') throw new Error('relay must be a websocket url');
  const pairingId = fromB64Url(p);
  const secret = fromB64Url(s);
  const bridgeKey = fromB64Url(k);
  if (pairingId.length !== PAIRING_ID_BYTES) throw new Error('bad pairing id');
  if (secret.length !== PAIRING_SECRET_BYTES) throw new Error('bad pairing secret');
  if (bridgeKey.length !== X25519_BYTES) throw new Error('bad bridge key');
  if (!/^\d{1,12}$/.test(e)) throw new Error('bad expiry');
  const invite: PairingInvite = { relay, pairingId, secret, bridgeKey, expiresAt: Number(e) };
  const name = url.searchParams.get('n');
  const runtime = url.searchParams.get('rt');
  if (name) invite.name = name;
  if (runtime) invite.runtime = runtime;
  return invite;
}

// Both sides send this in hello until the pairing completes; the relay learns only this value.
export function deriveRelaySecret(crypto: CryptoProvider, secret: Uint8Array): Uint8Array {
  return crypto.hkdfSha256(secret, new Uint8Array(0), utf8('wizzle-v2 relay'), 32);
}

export function derivePsk(crypto: CryptoProvider, secret: Uint8Array): Uint8Array {
  return crypto.hkdfSha256(secret, new Uint8Array(0), utf8('wizzle-v2 psk'), 32);
}

// Replaces the invite's relay secret once paired. It needs a static private key, so a leaked invite cannot produce it.
export function derivePairedRelaySecret(crypto: CryptoProvider, pairingId: Uint8Array, ownPrivate: Uint8Array, peerPublic: Uint8Array): Uint8Array {
  return crypto.hkdfSha256(dh(crypto, ownPrivate, peerPublic), pairingId, utf8('wizzle-v2 relay paired'), 32);
}
