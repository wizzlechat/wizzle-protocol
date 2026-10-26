# wizzle-protocol

Wire protocol shared by the wizzle phone app, the relay, and every bridge.
TypeScript, zero dependencies. The relay carries its own copy of the frame
header rules in Rust; it never sees anything below the frame layer.

## Layers

1. Relay control: text WebSocket messages between one client and the relay,
   version 2. `hello`, `push`, `rekey`, `revoke`, `wake` from the client;
   `welcome`, `peer`, `error` from the relay. Never forwarded to the peer.
   `push` comes only from the phone, `wake` only from the bridge. See
   `src/envelope.ts`.
2. Frames: binary WebSocket messages the relay forwards untouched. Header is
   type (1 byte), epoch (8 bytes), seq (8 bytes). Types: HS (handshake), DATA,
   ACK. The relay reads the header to buffer and trim; the payload is opaque.
3. Session: end to end keys per pairing, in epochs. See `src/session.ts`.
4. Packets: the decrypted content of a DATA frame. A 4 byte length, a JSON
   header with `id` and `t`, then an optional binary body used by `file` and
   `upload`. See `src/messages.ts` for the full catalog in both directions.

## Pairing

The bridge makes a static X25519 key pair for the pairing, creates an invite
(`newInvite`) and shows it as a QR code:
`wizzle://pair?r=<relay url>&p=<pairing id>&s=<secret>&k=<bridge static key>&e=<expiry, unix seconds>&n=<name>&rt=<runtime>`.
The phone refuses an invite past its expiry and makes a static key pair of its
own for the pairing. Three values matter to the relay and the handshake:

- invite relay secret (`deriveRelaySecret`): HKDF of the secret. Both sides send
  it in `hello` until the pairing completes. The relay stores a hash.
- psk (`derivePsk`): HKDF of the secret with another label. It never leaves the
  two devices and salts every handshake.
- paired relay secret (`derivePairedRelaySecret`): HKDF of the static to static
  X25519 secret, salted with the pairing id. Once the bridge has pinned a phone
  it sends this to the relay in `rekey`, and from then on only this secret
  attaches. A leaked invite holds neither static private key, so it cannot
  produce it.

The first phone whose handshake the bridge confirms is pinned by its static key
(`Session.peerKey`). The bridge refuses handshakes from any other phone key and
drops epochs another phone derived before the pin. So an invite works once.

## Handshake and epochs

The phone always initiates. It sends an HS frame with a fresh ephemeral X25519
key followed by its static key (64 bytes), the bridge answers with an ephemeral
key of its own (32 bytes), and both derive an epoch:

- transcript = "wizzle-v2" || pairing id || bridge static || phone static ||
  phone ephemeral || bridge ephemeral
- ikm = DH(phone ephemeral, bridge ephemeral) || DH(phone static, bridge
  ephemeral) || DH(phone ephemeral, bridge static)
- epoch id = first 8 bytes of SHA-256(transcript)
- send and receive keys = HKDF-SHA256(ikm, salt = psk, info = direction label
  || transcript)

The ephemeral to ephemeral term gives forward secrecy. The two static terms mean
only the holder of the phone's static key can be the phone and only the holder
of the bridge's static key from the invite can be the bridge, so neither the
relay nor anyone with a copy of the invite can sit in the middle. Any DH result
of all zeros (a low order key) is refused.

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

## Elements

An agent makes a UI element appear in the app by sending a file whose name ends
in `.wizzle.json` (`src/element.ts`). It travels as an ordinary `file` packet;
the app recognizes it by the name and draws it with its own components.

- Envelope: `{ "wizzle": 1, "id", "kind", "title", "content" }`. `id` is unique
  per agent, and the same id again replaces the element; `kind` is free text
  that groups elements in the app.
- Nodes: `text` (`role` title, body or caption), `image` (https), `stack`,
  `list`, `reveal` (front and back, flipped on the phone) and `pager` (pages
  swiped on the phone).
- `validateElement` never throws. It drops invalid and unknown nodes, cuts what
  is over the limits (`ELEMENT_LIMITS`), and reports each change. Without an
  id, a title and content there is no element.

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
