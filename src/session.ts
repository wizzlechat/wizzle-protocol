import type { CryptoProvider, KeyPair } from './crypto.ts';
import { NONCE_BYTES, X25519_BYTES } from './crypto.ts';
import { concat, equal, fromB64Url, toB64Url, utf8, writeU64 } from './bytes.ts';
import type { Frame, Role } from './envelope.ts';
import { EPOCH_BYTES, FRAME_ACK, FRAME_DATA, FRAME_HS, ZERO_EPOCH, encodeFrame, frameHeader } from './envelope.ts';

const LABEL = utf8('wizzle-v1');
const INFO_P2B = utf8('wizzle-v1 p2b');
const INFO_B2P = utf8('wizzle-v1 b2p');
const MAX_EPOCHS = 2;
const MAX_SEQ = 1n << 62n;

type Epoch = {
  id: Uint8Array;
  sendKey: Uint8Array;
  recvKey: Uint8Array;
  sendSeq: bigint;
  recvSeq: bigint;
};

export type EpochState = { id: string; sendKey: string; recvKey: string; sendSeq: string; recvSeq: string };
export type SessionState = { epochs: EpochState[]; send: string | null };

export type OpenResult =
  | { kind: 'data'; plaintext: Uint8Array }
  | { kind: 'confirm'; reply: Uint8Array | null }
  | { kind: 'duplicate' }
  | { kind: 'unknownEpoch' }
  | { kind: 'badTag' };

function nonceFor(seq: bigint): Uint8Array {
  const nonce = new Uint8Array(NONCE_BYTES);
  nonce.set(writeU64(seq), NONCE_BYTES - 8);
  return nonce;
}

function isZero(b: Uint8Array): boolean {
  let acc = 0;
  for (const x of b) acc |= x;
  return acc === 0;
}

// One pairing's end to end state: handshakes, epochs, and frame sealing.
export class Session {
  readonly role: Role;
  private readonly crypto: CryptoProvider;
  private readonly pairingId: Uint8Array;
  private readonly psk: Uint8Array;
  private epochs: Epoch[] = [];
  private sendEpoch: Epoch | null = null;
  private pending: KeyPair | null = null;
  private lastRecv: { id: Uint8Array; seq: bigint } | null = null;

  constructor(crypto: CryptoProvider, role: Role, pairingId: Uint8Array, psk: Uint8Array, state?: SessionState) {
    this.crypto = crypto;
    this.role = role;
    this.pairingId = pairingId;
    this.psk = psk;
    if (state) this.importState(state);
  }

  get ready(): boolean {
    return this.sendEpoch !== null;
  }

  get currentEpochId(): Uint8Array | null {
    return this.sendEpoch ? this.sendEpoch.id : null;
  }

  // Phone side. Returns the HS frame to send through the relay.
  beginHandshake(): Uint8Array {
    if (this.role !== 'phone') throw new Error('only the phone starts a handshake');
    this.pending = this.crypto.x25519KeyPair();
    return encodeFrame({ type: FRAME_HS, epoch: ZERO_EPOCH, seq: 0n, payload: this.pending.publicKey });
  }

  // Both sides. Returns the frame to send back, or null if nothing should be sent.
  handleHandshake(frame: Frame): Uint8Array | null {
    if (frame.type !== FRAME_HS || frame.payload.length !== X25519_BYTES) throw new Error('bad handshake frame');
    const theirPub = frame.payload;
    if (this.role === 'bridge') {
      const mine = this.crypto.x25519KeyPair();
      this.derive(theirPub, mine.publicKey, mine.privateKey, theirPub);
      return encodeFrame({ type: FRAME_HS, epoch: ZERO_EPOCH, seq: 0n, payload: mine.publicKey });
    }
    if (!this.pending) return null;
    const mine = this.pending;
    this.pending = null;
    const epoch = this.derive(mine.publicKey, theirPub, mine.privateKey, theirPub);
    if (!epoch) return null;
    return this.sealWith(epoch, new Uint8Array(0));
  }

  seal(plaintext: Uint8Array): Uint8Array {
    if (!this.sendEpoch) throw new Error('no epoch yet');
    return this.sealWith(this.sendEpoch, plaintext);
  }

  open(frame: Frame): OpenResult {
    if (frame.type !== FRAME_DATA) throw new Error('not a data frame');
    const epoch = this.epochs.find((e) => equal(e.id, frame.epoch));
    if (!epoch) return { kind: 'unknownEpoch' };
    if (frame.seq <= epoch.recvSeq) return { kind: 'duplicate' };
    const aad = frameHeader(encodeFrame({ ...frame, payload: new Uint8Array(0) }));
    const plaintext = this.crypto.aeadOpen(epoch.recvKey, nonceFor(frame.seq), aad, frame.payload);
    if (plaintext === null) return { kind: 'badTag' };
    epoch.recvSeq = frame.seq;
    this.lastRecv = { id: epoch.id, seq: frame.seq };
    this.promote(epoch);
    if (plaintext.length === 0) {
      const reply = this.role === 'bridge' ? this.sealWith(epoch, new Uint8Array(0)) : null;
      return { kind: 'confirm', reply };
    }
    return { kind: 'data', plaintext };
  }

  // Acknowledges the newest frame received, so the relay can drop its copy.
  ack(): Uint8Array | null {
    if (!this.lastRecv) return null;
    return encodeFrame({ type: FRAME_ACK, epoch: this.lastRecv.id, seq: this.lastRecv.seq, payload: new Uint8Array(0) });
  }

  exportState(): SessionState {
    return {
      epochs: this.epochs.map((e) => ({
        id: toB64Url(e.id),
        sendKey: toB64Url(e.sendKey),
        recvKey: toB64Url(e.recvKey),
        sendSeq: e.sendSeq.toString(),
        recvSeq: e.recvSeq.toString(),
      })),
      send: this.sendEpoch ? toB64Url(this.sendEpoch.id) : null,
    };
  }

  private importState(state: SessionState): void {
    this.epochs = state.epochs.map((e) => ({
      id: fromB64Url(e.id),
      sendKey: fromB64Url(e.sendKey),
      recvKey: fromB64Url(e.recvKey),
      sendSeq: BigInt(e.sendSeq),
      recvSeq: BigInt(e.recvSeq),
    }));
    for (const e of this.epochs) {
      if (e.id.length !== EPOCH_BYTES || e.sendKey.length !== 32 || e.recvKey.length !== 32) throw new Error('bad session state');
    }
    this.sendEpoch = state.send ? (this.epochs.find((e) => toB64Url(e.id) === state.send) ?? null) : null;
  }

  private derive(phonePub: Uint8Array, bridgePub: Uint8Array, myPriv: Uint8Array, theirPub: Uint8Array): Epoch | null {
    const shared = this.crypto.x25519(myPriv, theirPub);
    if (isZero(shared)) throw new Error('low order peer key');
    const transcript = concat(LABEL, this.pairingId, phonePub, bridgePub);
    const id = this.crypto.sha256(transcript).subarray(0, EPOCH_BYTES);
    if (this.epochs.some((e) => equal(e.id, id))) return null;
    const p2b = this.crypto.hkdfSha256(shared, this.psk, concat(INFO_P2B, transcript), 32);
    const b2p = this.crypto.hkdfSha256(shared, this.psk, concat(INFO_B2P, transcript), 32);
    const epoch: Epoch = {
      id,
      sendKey: this.role === 'phone' ? p2b : b2p,
      recvKey: this.role === 'phone' ? b2p : p2b,
      sendSeq: 0n,
      recvSeq: 0n,
    };
    this.epochs.push(epoch);
    while (this.epochs.length > MAX_EPOCHS) {
      const dropped = this.epochs.shift();
      if (dropped && this.sendEpoch === dropped) this.sendEpoch = null;
    }
    if (!this.sendEpoch) this.sendEpoch = epoch;
    return epoch;
  }

  // The newest epoch becomes the send epoch once the peer proves it holds it.
  private promote(epoch: Epoch): void {
    const current = this.sendEpoch ? this.epochs.indexOf(this.sendEpoch) : -1;
    if (this.epochs.indexOf(epoch) > current) this.sendEpoch = epoch;
  }

  private sealWith(epoch: Epoch, plaintext: Uint8Array): Uint8Array {
    if (epoch.sendSeq >= MAX_SEQ) throw new Error('epoch exhausted');
    epoch.sendSeq += 1n;
    const seq = epoch.sendSeq;
    const aad = frameHeader(encodeFrame({ type: FRAME_DATA, epoch: epoch.id, seq, payload: new Uint8Array(0) }));
    const payload = this.crypto.aeadSeal(epoch.sendKey, nonceFor(seq), aad, plaintext);
    return encodeFrame({ type: FRAME_DATA, epoch: epoch.id, seq, payload });
  }
}
