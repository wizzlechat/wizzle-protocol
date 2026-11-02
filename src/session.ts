import type { CryptoProvider, KeyPair } from './crypto.ts';
import { NONCE_BYTES, TAG_BYTES, X25519_BYTES, dh } from './crypto.ts';
import { concat, equal, fromB64Url, toB64Url, utf8 } from './bytes.ts';
import type { Frame, Role } from './envelope.ts';
import { EPOCH_BYTES, FRAME_ACK, FRAME_DATA, FRAME_HS, ZERO_EPOCH, encodeFrame, frameHeader } from './envelope.ts';

const LABEL = utf8('wizzle-v2');
const INFO_P2B = utf8('wizzle-v2 p2b');
const INFO_B2P = utf8('wizzle-v2 b2p');
const MAX_EPOCHS = 2;
const MAX_SEQ = 1n << 62n;
// Added to each send counter that saved state brings back, so a rolled back counter still passes the peer's.
const SEQ_JUMP = 1n << 32n;

// psk from the invite, this side's static key, and the peer's static key (null on a bridge until wizzle pairs).
export type SessionKeys = { psk: Uint8Array; own: KeyPair; peer: Uint8Array | null };

type Epoch = {
  id: Uint8Array;
  sendKey: Uint8Array;
  recvKey: Uint8Array;
  sendSeq: bigint;
  recvSeq: bigint;
  peer: Uint8Array | null;
};

export type EpochState = { id: string; sendKey: string; recvKey: string; sendSeq: string; recvSeq: string; peer?: string };
export type SessionState = { epochs: EpochState[]; send: string | null };

export type OpenResult =
  | { kind: 'data'; plaintext: Uint8Array }
  | { kind: 'confirm'; reply: Uint8Array | null }
  | { kind: 'duplicate' }
  | { kind: 'unknownEpoch' }
  | { kind: 'badTag' };

// One pairing's end to end state: handshakes, epochs, and frame sealing.
export class Session {
  readonly role: Role;
  private readonly crypto: CryptoProvider;
  private readonly pairingId: Uint8Array;
  private readonly psk: Uint8Array;
  private readonly own: KeyPair;
  private peer: Uint8Array | null;
  private epochs: Epoch[] = [];
  private sendEpoch: Epoch | null = null;
  private pending: KeyPair | null = null;
  private lastRecv: { id: Uint8Array; seq: bigint } | null = null;

  constructor(crypto: CryptoProvider, role: Role, pairingId: Uint8Array, keys: SessionKeys, state?: SessionState) {
    if (role === 'wizzle' && !keys.peer) throw new Error('wizzle needs the bridge key');
    this.crypto = crypto;
    this.role = role;
    this.pairingId = pairingId;
    this.psk = keys.psk;
    this.own = keys.own;
    this.peer = keys.peer;
    if (state) this.importState(state);
  }

  get ready(): boolean {
    return this.sendEpoch !== null;
  }

  get currentEpochId(): Uint8Array | null {
    return this.sendEpoch ? this.sendEpoch.id : null;
  }

  // The bridge key in wizzle; on a bridge, the wizzle key pinned by the first confirmed handshake.
  get peerKey(): Uint8Array | null {
    return this.peer;
  }

  // Wizzle side. Returns the HS frame to send through the relay: ephemeral key then static key.
  beginHandshake(): Uint8Array {
    if (this.role !== 'wizzle') throw new Error('only wizzle starts a handshake');
    this.pending = this.crypto.x25519KeyPair();
    return encodeFrame({ type: FRAME_HS, epoch: ZERO_EPOCH, seq: 0n, payload: concat(this.pending.publicKey, this.own.publicKey) });
  }

  // Both sides. Returns the frame to send back, or null if nothing should be sent.
  handleHandshake(frame: Frame): Uint8Array | null {
    if (frame.type !== FRAME_HS) throw new Error('bad handshake frame');
    if (this.role === 'bridge') {
      if (frame.payload.length !== 2 * X25519_BYTES) throw new Error('bad handshake frame');
      const wizzleEph = frame.payload.slice(0, X25519_BYTES);
      const wizzleStatic = frame.payload.slice(X25519_BYTES);
      if (this.peer && !equal(this.peer, wizzleStatic)) throw new Error('unknown wizzle key');
      const mine = this.crypto.x25519KeyPair();
      const ikm = concat(dh(this.crypto, mine.privateKey, wizzleEph), dh(this.crypto, mine.privateKey, wizzleStatic), dh(this.crypto, this.own.privateKey, wizzleEph));
      this.derive(ikm, this.own.publicKey, wizzleStatic, wizzleEph, mine.publicKey);
      return encodeFrame({ type: FRAME_HS, epoch: ZERO_EPOCH, seq: 0n, payload: mine.publicKey });
    }
    if (frame.payload.length !== X25519_BYTES) throw new Error('bad handshake frame');
    if (!this.pending) return null;
    const mine = this.pending;
    this.pending = null;
    const bridgeEph = frame.payload.slice();
    const bridgeStatic = this.peer as Uint8Array;
    const ikm = concat(dh(this.crypto, mine.privateKey, bridgeEph), dh(this.crypto, this.own.privateKey, bridgeEph), dh(this.crypto, mine.privateKey, bridgeStatic));
    const epoch = this.derive(ikm, bridgeStatic, this.own.publicKey, mine.publicKey, bridgeEph);
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
    if (frame.payload.length < NONCE_BYTES + TAG_BYTES) return { kind: 'badTag' };
    const aad = frameHeader(encodeFrame({ ...frame, payload: new Uint8Array(0) }));
    const nonce = frame.payload.subarray(0, NONCE_BYTES);
    const plaintext = this.crypto.aeadOpen(epoch.recvKey, nonce, aad, frame.payload.subarray(NONCE_BYTES));
    if (plaintext === null) return { kind: 'badTag' };
    epoch.recvSeq = frame.seq;
    this.lastRecv = { id: epoch.id, seq: frame.seq };
    this.promote(epoch);
    if (this.role === 'bridge' && !this.peer && epoch.peer) this.pin(epoch);
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
      epochs: this.epochs.map((e) => {
        const out: EpochState = {
          id: toB64Url(e.id),
          sendKey: toB64Url(e.sendKey),
          recvKey: toB64Url(e.recvKey),
          sendSeq: e.sendSeq.toString(),
          recvSeq: e.recvSeq.toString(),
        };
        if (e.peer) out.peer = toB64Url(e.peer);
        return out;
      }),
      send: this.sendEpoch ? toB64Url(this.sendEpoch.id) : null,
    };
  }

  private importState(state: SessionState): void {
    this.epochs = state.epochs.map((e) => ({
      id: fromB64Url(e.id),
      sendKey: fromB64Url(e.sendKey),
      recvKey: fromB64Url(e.recvKey),
      sendSeq: BigInt(e.sendSeq) + SEQ_JUMP,
      recvSeq: BigInt(e.recvSeq),
      peer: e.peer ? fromB64Url(e.peer) : null,
    }));
    for (const e of this.epochs) {
      if (e.id.length !== EPOCH_BYTES || e.sendKey.length !== 32 || e.recvKey.length !== 32) throw new Error('bad session state');
      if (e.peer && e.peer.length !== X25519_BYTES) throw new Error('bad session state');
    }
    if (this.role === 'bridge' && this.peer) this.dropForeign(null);
    this.sendEpoch = state.send ? (this.epochs.find((e) => toB64Url(e.id) === state.send) ?? null) : null;
  }

  private derive(ikm: Uint8Array, bridgeStatic: Uint8Array, wizzleStatic: Uint8Array, wizzleEph: Uint8Array, bridgeEph: Uint8Array): Epoch | null {
    const transcript = concat(LABEL, this.pairingId, bridgeStatic, wizzleStatic, wizzleEph, bridgeEph);
    const id = this.crypto.sha256(transcript).subarray(0, EPOCH_BYTES);
    if (this.epochs.some((e) => equal(e.id, id))) return null;
    const p2b = this.crypto.hkdfSha256(ikm, this.psk, concat(INFO_P2B, transcript), 32);
    const b2p = this.crypto.hkdfSha256(ikm, this.psk, concat(INFO_B2P, transcript), 32);
    const epoch: Epoch = {
      id,
      sendKey: this.role === 'wizzle' ? p2b : b2p,
      recvKey: this.role === 'wizzle' ? b2p : p2b,
      sendSeq: 0n,
      recvSeq: 0n,
      peer: this.role === 'bridge' ? wizzleStatic : null,
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

  // The first wizzle app to confirm owns the pairing; epochs other wizzle apps derived before that are dropped.
  private pin(epoch: Epoch): void {
    this.peer = epoch.peer;
    this.dropForeign(epoch);
  }

  private dropForeign(keep: Epoch | null): void {
    const peer = this.peer as Uint8Array;
    this.epochs = this.epochs.filter((e) => !e.peer || equal(e.peer, peer));
    if (this.sendEpoch && !this.epochs.includes(this.sendEpoch)) this.sendEpoch = keep;
  }

  private sealWith(epoch: Epoch, plaintext: Uint8Array): Uint8Array {
    if (epoch.sendSeq >= MAX_SEQ) throw new Error('epoch exhausted');
    epoch.sendSeq += 1n;
    const seq = epoch.sendSeq;
    const aad = frameHeader(encodeFrame({ type: FRAME_DATA, epoch: epoch.id, seq, payload: new Uint8Array(0) }));
    // Random, so state restored from an older copy never repeats a nonce under this key.
    const nonce = this.crypto.randomBytes(NONCE_BYTES);
    const payload = concat(nonce, this.crypto.aeadSeal(epoch.sendKey, nonce, aad, plaintext));
    return encodeFrame({ type: FRAME_DATA, epoch: epoch.id, seq, payload });
  }
}
