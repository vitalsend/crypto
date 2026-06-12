# vitalsend-crypto

The end-to-end encryption core of [vitalsend.eu](https://vitalsend.eu),
published as a standalone package. This is not a demo and not a cleanroom
rewrite: it is the exact code the live service ships to browsers, extracted
so it can be reviewed, tested, and reused on its own.

- **Proven primitives, nothing homemade.** XChaCha20-Poly1305, Argon2id and
  keyed BLAKE2b via libsodium, the only dependency.
- **Built for real files.** Parallel encryption in a Web Worker pool,
  resumable uploads, and streaming decrypt; transfers tested up to 1 TB on
  ordinary consumer hardware run in the browser without ever holding the
  whole file in memory.
- **Claims you can run.** Every integrity guarantee (tampering, reordering,
  truncation, extension, duplication, cross-file substitution) is verified
  by the test suite, and frozen fixtures pin backward compatibility.
- **Honest about limits.** SECURITY.md documents what this does not protect
  against, not only what it does.

## How it works

Files are encrypted on the sender's device, in the browser, before anything
is uploaded. The key is generated locally and placed in the share link's
`#fragment`, the part of a URL that browsers never send to servers. Whoever
holds the link (and the optional password) can decrypt; the server that
stores the ciphertext cannot.

The file is split into chunks, each sealed with authenticated encryption and
bound to its position in the stream, so a download fails loudly if anything
was modified, reordered, removed, or added in transit or at rest.

[vitalsend.eu](https://vitalsend.eu) builds a one-shot handover service on
top of this package: each transfer allows exactly one successful download,
and after that download, or on expiry, the file is destroyed. That policy is
enforced server-side; this package provides the cryptography that keeps the
server blind to the content. VitalSend is designed for secure handover, not
long-term storage or collaboration.

## At a glance

- **AEAD:** XChaCha20-Poly1305 (libsodium) for metadata and every chunk
- **Keys:** 32-byte random link key, shared only in the URL `#fragment`
  (never sent to any server)
- **Optional password second factor:** Argon2id (MODERATE), mixed into the
  root key; parameters stored in the authenticated header
- **Subkeys:** per-purpose BLAKE2b derivations (`chunk`, `meta`, `header`)
- **Framing:** per-chunk nonce = fileNonce ‖ u64be(index), AAD = index;
  reordering, truncation, duplication, extension, and cross-file substitution
  are all detected
- **Transport-agnostic:** you supply `uploadPart`/`fetchPartStream` callbacks;
  this package never performs I/O and never reads environment variables

## Install

Vendor this directory, or `npm install` it from the repo. Peer dependency:
`libsodium-wrappers-sumo`.

## Usage

```js
import {
  encryptAndUpload, decryptAndDownload,
  encodeLinkKey, decodeLinkKey, buildShareLink, parseShareLinkHash,
} from './index.js';

// Encrypt + upload (transport is yours)
const shareKey = await encryptAndUpload({
  file,                                  // a File/Blob-like with .stream()
  password: null,                        // optional second factor (min 10 chars)
  uploadHeader: async (bytes) => { /* PUT header */ },
  uploadPart: async (index, bytes, offset) => { /* PUT chunk */ },
});
const link = buildShareLink('https://example.com/d/?file=ID', encodeLinkKey(shareKey), false);

// Download + decrypt
const { linkKey } = parseShareLinkHash(location.hash);
await decryptAndDownload({
  fetchHeader: async () => headerBytes,
  fetchPartStream: async function* () { yield* chunks; },
  linkKey,
  password: null,
  onMetadata: async (meta) => { /* { name, size, type }, authenticated */ },
  onPlainChunk: async (chunk) => { /* stream to disk */ },
});
```

### Worker pipeline (optional)

`encryptAndUploadWithWorker(options)` encrypts chunks in a Web Worker pool to
keep key material and CPU load off the main thread. It takes the same options
as `encryptAndUpload` plus a `worker` object:

```js
await encryptAndUploadWithWorker({
  ...sameOptionsAsAbove,
  worker: {
    enabled: true,                  // default true; falls back to encryptAndUpload when false or no Worker support
    url: '/js/encrypt-worker.js',   // where your bundler serves worker/encrypt-worker.js
    queueMax: null,                 // optional cap on in-flight chunks
    debug: false,                   // console timing logs
  },
});
```

You must bundle `worker/encrypt-worker.js` separately (it is a Worker entry
point, `type: "module"`) and serve it at the `url` you pass. Without a worker
build, use `encryptAndUpload`: identical output, main thread only.

## Wire format (v3)

```
header := "E2EEFILE" | version(1=0x03) | chunkSize(u32be) | flags(1)
        | totalChunks(u64be) | fileNonce(16)
        | pwhashLen(u32be) | [salt(16) | ops(u64be) | mem(u64be)]
        | metaNonce(24) | metaLen(u32be) | metaCipher
        | headerMac(32)            BLAKE2b keyed with headerMacKey
chunk[i] := XChaCha20-Poly1305(plain[i], aad=u64be(i), nonce=fileNonce|u64be(i), key=chunkKey)
rootKey  := linkKey                              (no password)
          | BLAKE2b(linkKey, key=Argon2id(pw))   (password)
subkey_X := BLAKE2b-32("vitalsend:X:v3", key=rootKey)   X ∈ {chunk, meta, header}
```

## Why not libsodium `secretstream`?

The obvious alternative to this chunk framing is libsodium's
`crypto_secretstream_xchacha20poly1305`, which provides chunked AEAD with
built-in ordering and truncation detection. We deliberately don't use it:
`secretstream` ratchets its state strictly sequentially, so every chunk must
be encrypted (and decrypted) in order on one thread. This format instead
binds the chunk index into both the nonce (`fileNonce ‖ u64be(i)`) and the
AAD, which gives the same integrity guarantees (reordering, truncation,
extension, and duplication are all detected) while allowing parallel
encryption in a worker pool and resume from an arbitrary chunk offset.
The guarantees come from the AEAD construction itself;
`security-properties.test.js` verifies each one against this implementation,
so a regression fails the test suite.

## Security

Read [SECURITY.md](./SECURITY.md), including the known-limitations section,
before relying on this. Run the security property tests with `npm test`
(see `security-properties.test.js` and the frozen backward-compatibility
fixtures in `fixtures/`).

## License

Dual-licensed: [AGPL-3.0-or-later](./LICENSE) or [commercial](./COMMERCIAL.md).

AGPL-3.0 is a strong copyleft license: if you build this code into a product
or service, including software offered over a network, you must publish that
product's complete corresponding source under the same terms. If that does
not fit your product, a commercial license is available: contact
jorgenk@vitalsend.eu.

Author: Jörgen Karlsson (jorgen@karlsson.com, jorgenk@vitalsend.eu)
