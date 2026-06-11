// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Jörgen Karlsson <jorgen@karlsson.com, jorgenk@vitalsend.eu>
// frontend/src/js/crypto/format.test.js
// @vitest-environment node
import { describe, it, expect, beforeAll } from 'vitest';
import sodium from 'libsodium-wrappers-sumo';
import {
  HEADER_MAGIC, HEADER_VERSION, HEADER_MAC_BYTES, FILE_NONCE_BYTES,
  KDF_CONTEXT_CHUNK, KDF_CONTEXT_META, KDF_CONTEXT_HEADER,
  u8concat, u32be, u64be, readU32be, readU64be,
  deriveSubkey, chunkNonce, sealChunk, openChunk,
  buildHeader, parseHeaderV3, extractHeaderFromPayload, verifyHeaderMac,
} from './format.js';

beforeAll(async () => { await sodium.ready; });

describe('constants (wire-format invariants, NEVER change)', () => {
  it('pins v3 identity', () => {
    expect(HEADER_MAGIC).toBe('E2EEFILE');
    expect(HEADER_VERSION).toBe(3);
    expect(HEADER_MAC_BYTES).toBe(32);
    expect(FILE_NONCE_BYTES).toBe(16);
    expect(KDF_CONTEXT_CHUNK).toBe('vitalsend:chunk:v3');
    expect(KDF_CONTEXT_META).toBe('vitalsend:meta:v3');
    expect(KDF_CONTEXT_HEADER).toBe('vitalsend:header:v3');
  });
  it('chunk overhead is 16 bytes (download.js depends on this)', async () => {
    const { getChunkOverheadBytes } = await import('./format.js');
    expect(await getChunkOverheadBytes()).toBe(16);
  });
});

describe('byte helpers', () => {
  it('u32/u64 round-trip big-endian', () => {
    expect(readU32be(u32be(0xdeadbeef), 0)).toBe(0xdeadbeef);
    expect(readU64be(u64be(1234567890123), 0)).toBe(1234567890123);
  });
  it('u8concat concatenates', () => {
    expect(Array.from(u8concat(new Uint8Array([1]), new Uint8Array([2, 3])))).toEqual([1, 2, 3]);
  });
});

describe('chunk framing', () => {
  it('nonce = fileNonce || u64be(index)', () => {
    const fn = new Uint8Array(16).fill(7);
    const n = chunkNonce(fn, 5);
    expect(n.length).toBe(24);
    expect(Array.from(n.slice(0, 16))).toEqual(Array.from(fn));
    expect(readU64be(n, 16)).toBe(5);
  });
  it('seal/open round-trips and binds the index', () => {
    const key = new Uint8Array(32).fill(1);
    const fn = new Uint8Array(16).fill(2);
    const plain = new TextEncoder().encode('hello');
    const ct = sealChunk(key, fn, 0, plain);
    expect(Array.from(openChunk(key, fn, 0, ct))).toEqual(Array.from(plain));
    expect(() => openChunk(key, fn, 1, ct)).toThrow(); // wrong index -> wrong nonce+AAD
  });
});

describe('header build/parse', () => {
  function sampleHeader() {
    const macKey = new Uint8Array(32).fill(9);
    const metaNonce = new Uint8Array(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES).fill(3);
    const metaCipher = new Uint8Array(40).fill(4); // >= ABYTES(16)
    return {
      header: buildHeader({
        chunkSize: 1024, hasPassword: false, totalChunks: 7,
        fileNonce: new Uint8Array(16).fill(5),
        pwhashBlock: new Uint8Array(0), metaNonce, metaCipher, headerMacKey: macKey,
      }),
      macKey,
    };
  }
  it('round-trips through parseHeaderV3', () => {
    const { header, macKey } = sampleHeader();
    const parsed = parseHeaderV3(header);
    expect(parsed.chunkSize).toBe(1024);
    expect(parsed.totalChunks).toBe(7);
    expect(parsed.hasPwhash).toBe(false);
    expect(verifyHeaderMac(parsed, macKey)).toBe(true);
  });
  it('rejects tamper via MAC, bad magic, truncation', () => {
    const { header, macKey } = sampleHeader();
    const tampered = new Uint8Array(header);
    tampered[tampered.length - HEADER_MAC_BYTES - 1] ^= 1;
    expect(verifyHeaderMac(parseHeaderV3(tampered), macKey)).toBe(false);
    const badMagic = new Uint8Array(header); badMagic[0] ^= 1;
    expect(() => parseHeaderV3(badMagic)).toThrow('Bad magic');
    expect(() => parseHeaderV3(header.slice(0, 20))).toThrow(/Truncated/);
  });
  it('extractHeaderFromPayload returns exactly the header prefix', () => {
    const { header } = sampleHeader();
    const payload = u8concat(header, new Uint8Array(50).fill(8));
    expect(extractHeaderFromPayload(payload).length).toBe(header.length);
  });
});
