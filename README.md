# wizzle-protocol

Wire protocol shared by the wizzle phone app, the relay, and every bridge.
TypeScript, zero dependencies. The relay carries its own copy of the frame
header rules in Rust; it never sees anything below the frame layer.

## Layers

1. Relay control: text WebSocket messages between one client and the relay.
   `hello`, `push`, `revoke` from the client; `welcome`, `peer`, `error` from
   the relay. Never forwarded to the peer. See `src/envelope.ts`.
2. Frames: binary WebSocket messages the relay forwards untouched. Header is
   type (1 byte), epoch (8 bytes), seq (8 bytes). Types: HS (handshake), DATA,
   ACK. The relay reads the header to buffer and trim; the payload is opaque.
3. Session: end to end keys per pairing, in epochs. See `src/session.ts`.
4. Packets: the decrypted content of a DATA frame. A 4 byte length, a JSON
   header with `id` and `t`, then an optional binary body used by `file` and
   `upload`. See `src/messages.ts` for the full catalog in both directions.

## Pairing

The bridge creates an invite (`newInvite`) and shows it as a QR code:
`wizzle://pair?r=<relay url>&p=<pairing id>&s=<secret>&n=<name>&rt=<runtime>`.
Two values derive from the secret with HKDF and different labels:

- relay secret: sent to the relay by both sides in `hello` to prove they may
  attach to the pairing. The relay stores a hash.
- psk: never leaves the two devices. It authenticates every handshake, so the
  relay cannot sit in the middle.

## Handshake and epochs

The phone always initiates. It sends an HS frame with a fresh X25519 public
key, the bridge answers with its own, and both derive an epoch:

- transcript = "wizzle-v1" || pairing id || phone key || bridge key
- epoch id = first 8 bytes of SHA-256(transcript)
- send and receive keys = HKDF-SHA256(ikm = X25519 shared secret, salt = psk,
  info = direction label || transcript)

The phone then sends an empty DATA frame (confirm) under the new epoch. The
bridge replies with its own confirm. Each side switches to sending under the
newest epoch once it has opened one valid frame from the peer under it.

Frames are ChaCha20-Poly1305 with nonce = 4 zero bytes || seq, and the 17 byte
frame header as associated data. Seq starts at 1 per epoch per direction and
must strictly increase; the receiver drops anything at or below the last seq
it accepted.

Each side keeps the current and the previous epoch. Frames the relay buffered
while one side was offline were sealed under the epoch both sides held at the
time, so they still open after a reconnect. A new handshake runs whenever both
sides are online, which is the forward secrecy boundary. Session state
(`exportState`) must be persisted by both sides, keys in secure storage.

## Limits

- `MAX_FILE_BYTES` is 16 MiB. `MAX_FRAME_BYTES` adds 4096 bytes of header
  slack. The relay rejects larger frames.
- Every packet is one frame. Files are not chunked in v1.

## Crypto providers

`Session` takes a `CryptoProvider`. `src/crypto-node.ts` implements it on
`node:crypto` for bridges. The phone supplies one on `react-native-quick-crypto`
(same API surface) or on `@noble/curves` plus `@noble/ciphers`.

## Checks

```
node --test test/*.test.ts
tsc -p tsconfig.json
```

Type checking needs `typescript` and `@types/node` available to `tsc`; nothing
is installed in this folder.
