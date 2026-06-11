// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Jörgen Karlsson <jorgen@karlsson.com, jorgenk@vitalsend.eu>
//
// VitalSend E2EE wire format (v3): constants, byte helpers, header
// serialization/parsing, keyed header MAC, and per-chunk AEAD framing.
// The constants and layout in this file define the wire format; changing
// any of them breaks every existing share link. Do not modify without a
// version bump.
import sodium from "libsodium-wrappers-sumo";

const enc = new TextEncoder();
const dec = new TextDecoder();

export const HEADER_MAGIC = "E2EEFILE";
export const HEADER_VERSION = 3;
export const HEADER_MAC_BYTES = 32;
export const FILE_NONCE_BYTES = 16;
export const PASSWORD_MIN_LENGTH = 10;
export const MAX_HEADER_BYTES = 128 * 1024;
export const MAX_METADATA_BYTES = 32 * 1024;
export const MAX_CHUNK_SIZE = 64 * 1024 * 1024;
export const DEFAULT_CHUNK_SIZE = 32 * 1024 * 1024;
export const KDF_CONTEXT_CHUNK = "vitalsend:chunk:v3";
export const KDF_CONTEXT_META = "vitalsend:meta:v3";
export const KDF_CONTEXT_HEADER = "vitalsend:header:v3";

export function u8concat(...chunks) {
  const len = chunks.reduce((a, c) => a + c.length, 0);
  const out = new Uint8Array(len);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

export function u32be(n) {
  const b = new Uint8Array(4);
  b[0] = (n >>> 24) & 255;
  b[1] = (n >>> 16) & 255;
  b[2] = (n >>> 8) & 255;
  b[3] = n & 255;
  return b;
}

export function u64be(n) {
  const out = new Uint8Array(8);
  const dv = new DataView(out.buffer);
  dv.setBigUint64(0, BigInt(n), false);
  return out;
}

export function readU32be(u8, off) {
  return ((u8[off] << 24) | (u8[off + 1] << 16) | (u8[off + 2] << 8) | u8[off + 3]) >>> 0;
}

export function readU64be(u8, off) {
  const dv = new DataView(u8.buffer, u8.byteOffset + off, 8);
  return Number(dv.getBigUint64(0, false));
}

export function ensureAvailable(u8, off, needed, label) {
  if (off + needed > u8.length) {
    throw new Error(`Truncated header while reading ${label}.`);
  }
}

export function deriveSubkey(rootKey, context) {
  return sodium.crypto_generichash(32, context, rootKey);
}

export function parseHeaderV3(headerBytes) {
  if (headerBytes.length > MAX_HEADER_BYTES) throw new Error("Header too large.");
  let off = 0;

  ensureAvailable(headerBytes, off, 8, "magic");
  const magic = dec.decode(headerBytes.slice(off, off + 8));
  off += 8;
  if (magic !== HEADER_MAGIC) throw new Error("Bad magic");

  ensureAvailable(headerBytes, off, 1, "version");
  const ver = headerBytes[off++];
  if (ver !== HEADER_VERSION) throw new Error("Unsupported version");

  ensureAvailable(headerBytes, off, 4, "chunk size");
  const chunkSize = readU32be(headerBytes, off);
  off += 4;
  if (chunkSize < 1 || chunkSize > MAX_CHUNK_SIZE) throw new Error("Invalid chunk size");

  ensureAvailable(headerBytes, off, 1, "flags");
  const flags = headerBytes[off++];
  const hasPwhash = (flags & 1) !== 0;

  ensureAvailable(headerBytes, off, 8, "total chunks");
  const totalChunks = readU64be(headerBytes, off);
  off += 8;
  if (totalChunks < 1) throw new Error("Invalid total chunks");

  ensureAvailable(headerBytes, off, 16, "file nonce");
  const fileNonce = headerBytes.slice(off, off + 16);
  off += 16;

  ensureAvailable(headerBytes, off, 4, "pwhash length");
  const pwhashLen = readU32be(headerBytes, off);
  off += 4;
  ensureAvailable(headerBytes, off, pwhashLen, "pwhash block");
  const pwhashBlock = headerBytes.slice(off, off + pwhashLen);
  off += pwhashLen;

  ensureAvailable(headerBytes, off, sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, "metadata nonce");
  const metaNonce = headerBytes.slice(off, off + sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  off += sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

  ensureAvailable(headerBytes, off, 4, "metadata length");
  const metaLen = readU32be(headerBytes, off);
  off += 4;
  if (metaLen < sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES || metaLen > MAX_METADATA_BYTES) {
    throw new Error("Invalid metadata length");
  }
  ensureAvailable(headerBytes, off, metaLen, "metadata cipher");
  const metaCipher = headerBytes.slice(off, off + metaLen);
  off += metaLen;

  ensureAvailable(headerBytes, off, HEADER_MAC_BYTES, "header MAC");
  const headerMac = headerBytes.slice(off, off + HEADER_MAC_BYTES);
  off += HEADER_MAC_BYTES;
  if (off !== headerBytes.length) throw new Error("Unexpected header size");

  return {
    chunkSize,
    totalChunks,
    hasPwhash,
    fileNonce,
    pwhashLen,
    pwhashBlock,
    metaNonce,
    metaCipher,
    headerMac,
    headerBody: headerBytes.slice(0, headerBytes.length - HEADER_MAC_BYTES),
  };
}

export function extractHeaderFromPayload(bytes) {
  let off = 0;
  ensureAvailable(bytes, off, 8, "magic");
  off += 8;
  ensureAvailable(bytes, off, 1, "version");
  off += 1;
  ensureAvailable(bytes, off, 4, "chunk size");
  off += 4;
  ensureAvailable(bytes, off, 1, "flags");
  off += 1;
  ensureAvailable(bytes, off, 8, "total chunks");
  off += 8;
  ensureAvailable(bytes, off, 16, "file nonce");
  off += 16;
  ensureAvailable(bytes, off, 4, "pwhash length");
  const pwhashLen = readU32be(bytes, off);
  off += 4;
  ensureAvailable(bytes, off, pwhashLen, "pwhash block");
  off += pwhashLen;
  ensureAvailable(bytes, off, sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, "metadata nonce");
  off += sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
  ensureAvailable(bytes, off, 4, "metadata length");
  const metaLen = readU32be(bytes, off);
  off += 4;
  ensureAvailable(bytes, off, metaLen, "metadata cipher");
  off += metaLen;
  ensureAvailable(bytes, off, HEADER_MAC_BYTES, "header MAC");
  off += HEADER_MAC_BYTES;
  return bytes.slice(0, off);
}

export async function getChunkOverheadBytes() {
  await sodium.ready;
  return sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES;
}

export function chunkNonce(fileNonce, index) {
  return u8concat(fileNonce, u64be(index));
}

// Per-chunk AEAD framing: nonce = fileNonce || u64be(index), AAD = u64be(index).
// Used by the main-thread encrypt path, the worker, and decrypt: one implementation.
export function sealChunk(chunkKey, fileNonce, index, plain) {
  return sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plain, u64be(index), null, chunkNonce(fileNonce, index), chunkKey
  );
}

export function openChunk(chunkKey, fileNonce, index, cipher) {
  return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null, cipher, u64be(index), chunkNonce(fileNonce, index), chunkKey
  );
}

export function buildHeader({ chunkSize, hasPassword, totalChunks, fileNonce, pwhashBlock, metaNonce, metaCipher, headerMacKey }) {
  const headerBody = u8concat(
    enc.encode(HEADER_MAGIC),
    new Uint8Array([HEADER_VERSION]),
    u32be(chunkSize),
    new Uint8Array([hasPassword ? 1 : 0]),
    u64be(totalChunks),
    fileNonce,
    u32be(pwhashBlock.length),
    pwhashBlock,
    metaNonce,
    u32be(metaCipher.length),
    metaCipher
  );
  const headerMac = sodium.crypto_generichash(HEADER_MAC_BYTES, headerBody, headerMacKey);
  return u8concat(headerBody, headerMac);
}

export function verifyHeaderMac(parsed, headerMacKey) {
  const expected = sodium.crypto_generichash(HEADER_MAC_BYTES, parsed.headerBody, headerMacKey);
  return sodium.memcmp(parsed.headerMac, expected);
}
