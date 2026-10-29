import { concat, readU64, writeU64 } from './bytes.ts';

// Frame layout: type(1) epoch(8) seq(8) payload. The relay reads only this header.
export const FRAME_HS = 1;
export const FRAME_DATA = 2;
export const FRAME_ACK = 3;
export type FrameType = typeof FRAME_HS | typeof FRAME_DATA | typeof FRAME_ACK;

export const EPOCH_BYTES = 8;
export const FRAME_HEADER_BYTES = 1 + EPOCH_BYTES + 8;
export const MAX_FILE_BYTES = 16 * 1024 * 1024;
export const MAX_FRAME_BYTES = MAX_FILE_BYTES + 4096;
export const ZERO_EPOCH: Uint8Array = new Uint8Array(EPOCH_BYTES);

export type Frame = {
  type: FrameType;
  epoch: Uint8Array;
  seq: bigint;
  payload: Uint8Array;
};

export function encodeFrame(frame: Frame): Uint8Array {
  if (frame.epoch.length !== EPOCH_BYTES) throw new Error('bad epoch length');
  const header = new Uint8Array(FRAME_HEADER_BYTES);
  header[0] = frame.type;
  header.set(frame.epoch, 1);
  header.set(writeU64(frame.seq), 1 + EPOCH_BYTES);
  const out = concat(header, frame.payload);
  if (out.length > MAX_FRAME_BYTES) throw new Error('frame too large');
  return out;
}

export function decodeFrame(bytes: Uint8Array): Frame {
  if (bytes.length < FRAME_HEADER_BYTES) throw new Error('frame too short');
  if (bytes.length > MAX_FRAME_BYTES) throw new Error('frame too large');
  const type = bytes[0];
  if (type !== FRAME_HS && type !== FRAME_DATA && type !== FRAME_ACK) throw new Error('unknown frame type');
  return {
    type,
    epoch: bytes.slice(1, 1 + EPOCH_BYTES),
    seq: readU64(bytes, 1 + EPOCH_BYTES),
    payload: bytes.subarray(FRAME_HEADER_BYTES),
  };
}

export function frameHeader(bytes: Uint8Array): Uint8Array {
  return bytes.subarray(0, FRAME_HEADER_BYTES);
}

// Text messages between a client and the relay. Never forwarded to the peer.
export type Role = 'wizzle' | 'bridge';
export type PushPlatform = 'ios' | 'android';

export type ClientControl =
  | { t: 'hello'; v: 2; pairing: string; role: Role; secret: string }
  | { t: 'push'; platform: PushPlatform; token: string }
  | { t: 'rekey'; secret: string }
  | { t: 'revoke' }
  | { t: 'wake' };

export type RelayControl =
  | { t: 'welcome'; peer: boolean; buffered: number; maxFrameBytes: number }
  | { t: 'peer'; online: boolean }
  | { t: 'error'; code: 'auth' | 'limit' | 'frame' | 'proto' | 'revoked'; message: string };

export const RELAY_PROTOCOL_VERSION = 2;

export function encodeControl(msg: ClientControl | RelayControl): string {
  return JSON.stringify(msg);
}

export function decodeControl(text: string): ClientControl | RelayControl {
  const parsed: unknown = JSON.parse(text);
  if (typeof parsed !== 'object' || parsed === null || typeof (parsed as { t?: unknown }).t !== 'string') {
    throw new Error('bad control message');
  }
  return parsed as ClientControl | RelayControl;
}
