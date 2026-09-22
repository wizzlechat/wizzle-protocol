import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
} from 'node:crypto';
import type { CryptoProvider, KeyPair } from './crypto.ts';
import { TAG_BYTES } from './crypto.ts';
import { concat, fromHex } from './bytes.ts';

// DER prefixes that wrap a raw X25519 key as SPKI and PKCS8.
const SPKI_PREFIX = fromHex('302a300506032b656e032100');
const PKCS8_PREFIX = fromHex('302e020100300506032b656e04220420');

function plain(b: Uint8Array): Uint8Array {
  return new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
}

function buf(b: Uint8Array): Buffer {
  return Buffer.from(b.buffer, b.byteOffset, b.byteLength);
}

export const nodeCrypto: CryptoProvider = {
  randomBytes(length) {
    return plain(randomBytes(length));
  },
  sha256(data) {
    return plain(createHash('sha256').update(buf(data)).digest());
  },
  hkdfSha256(ikm, salt, info, length) {
    return new Uint8Array(hkdfSync('sha256', buf(ikm), buf(salt), buf(info), length));
  },
  x25519KeyPair(): KeyPair {
    const pair = generateKeyPairSync('x25519');
    const spki = pair.publicKey.export({ type: 'spki', format: 'der' });
    const pkcs8 = pair.privateKey.export({ type: 'pkcs8', format: 'der' });
    return {
      publicKey: plain(spki.subarray(SPKI_PREFIX.length)),
      privateKey: plain(pkcs8.subarray(PKCS8_PREFIX.length)),
    };
  },
  x25519(privateKey, peerPublicKey) {
    const priv = createPrivateKey({ key: buf(concat(PKCS8_PREFIX, privateKey)), format: 'der', type: 'pkcs8' });
    const pub = createPublicKey({ key: buf(concat(SPKI_PREFIX, peerPublicKey)), format: 'der', type: 'spki' });
    return plain(diffieHellman({ privateKey: priv, publicKey: pub }));
  },
  aeadSeal(key, nonce, aad, plaintext) {
    const cipher = createCipheriv('chacha20-poly1305', buf(key), buf(nonce), { authTagLength: TAG_BYTES });
    cipher.setAAD(buf(aad), { plaintextLength: plaintext.length });
    return plain(Buffer.concat([cipher.update(buf(plaintext)), cipher.final(), cipher.getAuthTag()]));
  },
  aeadOpen(key, nonce, aad, ciphertext) {
    if (ciphertext.length < TAG_BYTES) return null;
    const body = ciphertext.subarray(0, ciphertext.length - TAG_BYTES);
    const tag = ciphertext.subarray(ciphertext.length - TAG_BYTES);
    const decipher = createDecipheriv('chacha20-poly1305', buf(key), buf(nonce), { authTagLength: TAG_BYTES });
    decipher.setAAD(buf(aad), { plaintextLength: body.length });
    decipher.setAuthTag(buf(tag));
    try {
      return plain(Buffer.concat([decipher.update(buf(body)), decipher.final()]));
    } catch {
      return null;
    }
  },
};
