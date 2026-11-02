# wizzle-protocol

Wire protocol shared by the wizzle app, the relay, and every bridge.
TypeScript, zero dependencies. The relay carries its own copy of the frame
header rules in Rust; it never sees anything below the frame layer.

## Layers

1. Relay control: text WebSocket messages between one client and the relay,
   version 2. `hello`, `push`, `rekey`, `revoke`, `wake` from the client;
   `welcome`, `peer`, `error` from the relay. Never forwarded to the peer.
   `push` comes only from wizzle, `wake` only from the bridge. See
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
wizzle refuses an invite past its expiry and makes a static key pair of its
own for the pairing. Three values matter to the relay and the handshake:

- invite relay secret (`deriveRelaySecret`): HKDF of the secret. Both sides send
  it in `hello` until the pairing completes. The relay stores a hash.
- psk (`derivePsk`): HKDF of the secret with another label. It never leaves the
  two devices and salts every handshake.
- paired relay secret (`derivePairedRelaySecret`): HKDF of the static to static
  X25519 secret, salted with the pairing id. Once the bridge has pinned wizzle
  it sends this to the relay in `rekey`, and from then on only this secret
  attaches. A leaked invite holds neither static private key, so it cannot
  produce it.

The first wizzle app whose handshake the bridge confirms is pinned by its static key
(`Session.peerKey`). The bridge refuses handshakes from any other wizzle key and
drops epochs another wizzle app derived before the pin. So an invite works once.

## Handshake and epochs

wizzle always initiates. It sends an HS frame with a fresh ephemeral X25519
key followed by its static key (64 bytes), the bridge answers with an ephemeral
key of its own (32 bytes), and both derive an epoch:

- transcript = "wizzle-v2" || pairing id || bridge static || wizzle static ||
  wizzle ephemeral || bridge ephemeral
- ikm = DH(wizzle ephemeral, bridge ephemeral) || DH(wizzle static, bridge
  ephemeral) || DH(wizzle ephemeral, bridge static)
- epoch id = first 8 bytes of SHA-256(transcript)
- send and receive keys = HKDF-SHA256(ikm, salt = psk, info = direction label
  || transcript)

The ephemeral to ephemeral term gives forward secrecy. The two static terms mean
only the holder of wizzle's static key can be wizzle and only the holder
of the bridge's static key from the invite can be the bridge, so neither the
relay nor anyone with a copy of the invite can sit in the middle. Any DH result
of all zeros (a low order key) is refused.

wizzle then sends an empty DATA frame (confirm) under the new epoch. The
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
- Nodes: `text` (`role` title, heading, body or caption), `image` (https), `stack`,
  `list`, `reveal` (front and back, flipped in wizzle), `pager` (pages
  swiped in wizzle) and `article` (a long read: optional `title`, `subtitle`,
  `byline` and image `cover`, then `body`, the one field the app renders as
  markdown, up to 40000 characters).
- `validateElement` never throws. It drops invalid and unknown nodes, cuts what
  is over the limits (`ELEMENT_LIMITS`), and reports each change. Without an
  id, a title and content there is no element.

## Rooms

A room is one conversation where several agents and the owner talk
(`src/room.ts`). Bridges report it with the `rooms` capability.

- Catalog: `rooms` lists every room, `room` answers a `create_room` or
  `update_room` (its `ref`), and `room_deleted` drops one. A `Room` has the
  conversation `id`, a `title` and its `members` (agent ids).
- Messages, files, cards, edits, questions and activity in a room carry
  `speaker`, the agent id that produced them. Messages without it are the
  owner's or a system line.
- Mentions: an agent's handle is its name without whitespace, matched without
  case (`mentionHandle`). `mentioned` returns the members a text names, and
  `@all` names every member. Bridges and apps share this one parser, so what
  the app shows as a handoff is what woke the agent.
- A message from the owner wakes only the members it names. An agent's
  message is passed to every other member and wakes the ones it names.
- Handoff cap: after `ROOM_LIMITS.handoffs` agent to agent wakes without an
  owner message, the next named agents are not woken and `room_hold` lists
  them. `continue_room` wakes them and starts the count again; an owner
  message also starts it again. `room_hold` with an empty list clears the hold.
- `clear` with a room's id clears every member's session for that room.

## Limits

- `MAX_FILE_BYTES` is 16 MiB. `MAX_FRAME_BYTES` adds 4096 bytes of header
  slack. The relay rejects larger frames.
- Every packet is one frame. Files are not chunked in v1.

## Crypto providers

`Session` takes a `CryptoProvider`. `src/crypto-node.ts` implements it on
`node:crypto` for bridges. wizzle supplies one on `react-native-quick-crypto`
(same API surface) or on `@noble/curves` plus `@noble/ciphers`.

## Checks

```
node --test test/*.test.ts
tsc -p tsconfig.json
```

Type checking needs `typescript` and `@types/node` available to `tsc`; nothing
is installed in this folder.
