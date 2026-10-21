export type KeyPair = { publicKey: Uint8Array; privateKey: Uint8Array };

// Every primitive the protocol needs. Node and the phone each supply one.
export interface CryptoProvider {
  randomBytes(length: number): Uint8Array;
  sha256(data: Uint8Array): Uint8Array;
  hkdfSha256(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Uint8Array;
  x25519KeyPair(): KeyPair;
  x25519(privateKey: Uint8Array, peerPublicKey: Uint8Array): Uint8Array;
  aeadSeal(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, plaintext: Uint8Array): Uint8Array;
  aeadOpen(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array): Uint8Array | null;
}

export const KEY_BYTES = 32;
export const NONCE_BYTES = 12;
export const TAG_BYTES = 16;
export const X25519_BYTES = 32;

// X25519 that refuses an all zero result, which only a low order peer key produces.
export function dh(crypto: CryptoProvider, privateKey: Uint8Array, peerPublicKey: Uint8Array): Uint8Array {
  if (peerPublicKey.length !== X25519_BYTES) throw new Error('bad peer key');
  const shared = crypto.x25519(privateKey, peerPublicKey);
  let acc = 0;
  for (const x of shared) acc |= x;
  if (acc === 0) throw new Error('low order peer key');
  return shared;
}
