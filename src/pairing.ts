import type { CryptoProvider } from './crypto.ts';
import { fromB64Url, toB64Url, utf8 } from './bytes.ts';

export const PAIRING_ID_BYTES = 16;
export const PAIRING_SECRET_BYTES = 32;
export const INVITE_SCHEME = 'wizzle:';

// What the QR code carries. The secret never reaches the relay in this form.
export type PairingInvite = {
  relay: string;
  pairingId: Uint8Array;
  secret: Uint8Array;
  name?: string;
  runtime?: string;
};

export function newInvite(crypto: CryptoProvider, relay: string, extra: { name?: string; runtime?: string } = {}): PairingInvite {
  const invite: PairingInvite = {
    relay,
    pairingId: crypto.randomBytes(PAIRING_ID_BYTES),
    secret: crypto.randomBytes(PAIRING_SECRET_BYTES),
  };
  if (extra.name !== undefined) invite.name = extra.name;
  if (extra.runtime !== undefined) invite.runtime = extra.runtime;
  return invite;
}

export function encodeInvite(invite: PairingInvite): string {
  const params = new URLSearchParams();
  params.set('r', invite.relay);
  params.set('p', toB64Url(invite.pairingId));
  params.set('s', toB64Url(invite.secret));
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
  if (!relay || !p || !s) throw new Error('invite missing fields');
  const relayUrl = new URL(relay);
  if (relayUrl.protocol !== 'wss:' && relayUrl.protocol !== 'ws:') throw new Error('relay must be a websocket url');
  const pairingId = fromB64Url(p);
  const secret = fromB64Url(s);
  if (pairingId.length !== PAIRING_ID_BYTES) throw new Error('bad pairing id');
  if (secret.length !== PAIRING_SECRET_BYTES) throw new Error('bad pairing secret');
  const invite: PairingInvite = { relay, pairingId, secret };
  const name = url.searchParams.get('n');
  const runtime = url.searchParams.get('rt');
  if (name) invite.name = name;
  if (runtime) invite.runtime = runtime;
  return invite;
}

// The relay learns only this value, and cannot recover the invite secret from it.
export function deriveRelaySecret(crypto: CryptoProvider, secret: Uint8Array): Uint8Array {
  return crypto.hkdfSha256(secret, new Uint8Array(0), utf8('wizzle-v1 relay'), 32);
}

export function derivePsk(crypto: CryptoProvider, secret: Uint8Array): Uint8Array {
  return crypto.hkdfSha256(secret, new Uint8Array(0), utf8('wizzle-v1 psk'), 32);
}
