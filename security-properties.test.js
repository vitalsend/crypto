// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Jörgen Karlsson <jorgen@karlsson.com, jorgenk@vitalsend.eu>
// frontend/src/js/crypto/security-properties.test.js
// @vitest-environment node
// Executable security claims: each test encodes one property the v3 format
// guarantees. If one of these fails, the format is broken; do not "fix" the
// test; fix the code or bump the format version.
import { describe, it, expect, beforeAll } from 'vitest';
import sodium from 'libsodium-wrappers-sumo';
import { encryptAndUpload, decryptAndDownload } from './index.js';
import { HEADER_MAC_BYTES } from './format.js';

beforeAll(async () => { await sodium.ready; });

function makeFile(bytes) {
  return {
    name: 'x.bin', size: bytes.length, type: 'application/octet-stream', lastModified: 0,
    stream() { return new ReadableStream({ start(c) { c.enqueue(bytes); c.close(); } }); },
  };
}

async function encrypt({ password = null, linkKey = new Uint8Array(32).fill(4) } = {}) {
  const plaintext = Uint8Array.from({ length: 70 }, (_, i) => (i * 7) % 256);
  let header = null; const parts = [];
  await encryptAndUpload({
    file: makeFile(plaintext), linkKey, password, chunkSize: 32,
    uploadHeader: async (h) => { header = h; },
    uploadPart: async (i, p) => { parts[i] = p; },
  });
  return { plaintext, linkKey, password, header, parts };
}

async function decrypt({ header, parts, linkKey, password = null }) {
  const got = [];
  await decryptAndDownload({
    fetchHeader: async () => header,
    fetchPartStream: async function* () { for (const p of parts) yield p; },
    linkKey, password,
    onPlainChunk: async (c) => got.push(...c),
  });
  return new Uint8Array(got);
}

describe('tamper detection', () => {
  it('flipped header byte -> Header authentication failed', async () => {
    const s = await encrypt();
    const header = new Uint8Array(s.header);
    header[header.length - HEADER_MAC_BYTES - 1] ^= 1; // inside metaCipher, parse-clean
    await expect(decrypt({ ...s, header })).rejects.toThrow('Header authentication failed');
  });
  it('flipped ciphertext byte -> chunk AEAD failure', async () => {
    const s = await encrypt();
    const parts = s.parts.map((p) => new Uint8Array(p));
    parts[1][5] ^= 1;
    await expect(decrypt({ ...s, parts })).rejects.toThrow();
  });
});

describe('stream integrity', () => {
  it('dropped final chunk -> Missing chunks', async () => {
    const s = await encrypt();
    await expect(decrypt({ ...s, parts: s.parts.slice(0, -1) })).rejects.toThrow('Missing chunks');
  });
  it('reordered chunks -> AEAD failure (index is bound into nonce+AAD)', async () => {
    const s = await encrypt();
    const parts = [s.parts[1], s.parts[0], ...s.parts.slice(2)];
    await expect(decrypt({ ...s, parts })).rejects.toThrow();
  });
  it('injected extra chunk -> Unexpected extra chunk', async () => {
    const s = await encrypt();
    await expect(decrypt({ ...s, parts: [...s.parts, s.parts[s.parts.length - 1]] }))
      .rejects.toThrow('Unexpected extra chunk');
  });
  it('duplicated chunk in place -> AEAD failure', async () => {
    const s = await encrypt();
    const parts = [s.parts[0], s.parts[0], ...s.parts.slice(2)];
    await expect(decrypt({ ...s, parts })).rejects.toThrow();
  });
});

describe('key separation', () => {
  it('wrong link key -> Header authentication failed', async () => {
    const s = await encrypt();
    await expect(decrypt({ ...s, linkKey: new Uint8Array(32).fill(9) }))
      .rejects.toThrow('Header authentication failed');
  });
  it("cross-file substitution: file B's bytes under file A's key fails", async () => {
    const a = await encrypt({ linkKey: new Uint8Array(32).fill(1) });
    const b = await encrypt({ linkKey: new Uint8Array(32).fill(2) });
    await expect(decrypt({ header: b.header, parts: b.parts, linkKey: a.linkKey }))
      .rejects.toThrow('Header authentication failed');
    // even A's authenticated header cannot unlock B's chunks
    await expect(decrypt({ header: a.header, parts: b.parts, linkKey: a.linkKey })).rejects.toThrow();
  });
});

describe('password second factor (Argon2, slow tests)', () => {
  it('wrong password -> Header authentication failed; missing -> Password required', async () => {
    const s = await encrypt({ password: 'CORRECTPASS23' });
    await expect(decrypt({ ...s, password: 'WRONGPASSWORD9' })).rejects.toThrow('Header authentication failed');
    await expect(decrypt({ ...s, password: null })).rejects.toThrow('Password required to decrypt');
  });
  it('oversized Argon2 params in header are rejected BEFORE hashing (DoS guard)', async () => {
    const s = await encrypt({ password: 'CORRECTPASS23' });
    const header = new Uint8Array(s.header);
    // pwhash ops u64 offset: magic(8)+ver(1)+chunkSize(4)+flags(1)+totalChunks(8)+fileNonce(16)+len(4)+salt
    const opsOff = 8 + 1 + 4 + 1 + 8 + 16 + 4 + sodium.crypto_pwhash_SALTBYTES;
    new DataView(header.buffer).setBigUint64(opsOff, 2n ** 40n, false);
    await expect(decrypt({ ...s, header, password: 'CORRECTPASS23' }))
      .rejects.toThrow('Invalid password parameters');
  });
});
