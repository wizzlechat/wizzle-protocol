const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const B64URL_INDEX = new Map<string, number>(Array.from(B64URL, (c, i) => [c, i]));
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

export function utf8(s: string): Uint8Array {
  return encoder.encode(s);
}

export function fromUtf8(b: Uint8Array): string {
  return decoder.decode(b);
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}

export function writeU32(n: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n);
  return out;
}

export function readU32(b: Uint8Array, offset = 0): number {
  return new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(offset);
}

export function writeU64(n: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, n);
  return out;
}

export function readU64(b: Uint8Array, offset = 0): bigint {
  return new DataView(b.buffer, b.byteOffset, b.byteLength).getBigUint64(offset);
}

export function toB64Url(b: Uint8Array): string {
  let out = '';
  for (let i = 0; i < b.length; i += 3) {
    const x = b[i] as number;
    const y = i + 1 < b.length ? (b[i + 1] as number) : 0;
    const z = i + 2 < b.length ? (b[i + 2] as number) : 0;
    const triple = (x << 16) | (y << 8) | z;
    out += B64URL[(triple >> 18) & 63];
    out += B64URL[(triple >> 12) & 63];
    if (i + 1 < b.length) out += B64URL[(triple >> 6) & 63];
    if (i + 2 < b.length) out += B64URL[triple & 63];
  }
  return out;
}

export function fromB64Url(s: string): Uint8Array {
  if (s.length % 4 === 1) throw new Error('bad base64url length');
  const out = new Uint8Array(Math.floor((s.length * 3) / 4));
  let buffer = 0;
  let bits = 0;
  let offset = 0;
  for (const c of s) {
    const v = B64URL_INDEX.get(c);
    if (v === undefined) throw new Error('bad base64url character');
    buffer = (buffer << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[offset++] = (buffer >> bits) & 255;
    }
  }
  return out;
}

export function fromHex(s: string): Uint8Array {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}
