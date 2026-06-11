// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Jörgen Karlsson <jorgen@karlsson.com, jorgenk@vitalsend.eu>
//
// Streaming decrypt pipeline. Transport is caller-supplied
// (fetchHeader/fetchPartStream); this module never performs I/O.
import sodium from "libsodium-wrappers-sumo";
import {
  KDF_CONTEXT_CHUNK, KDF_CONTEXT_META, KDF_CONTEXT_HEADER,
  deriveSubkey, openChunk, parseHeaderV3, extractHeaderFromPayload, verifyHeaderMac,
} from "./format.js";
import { deriveRootKey } from "./kdf.js";

const dec = new TextDecoder();

export async function decryptAndDownload({
  fetchHeader,          // async () => Uint8Array  (the exact bytes you uploaded as header)
  fetchPartStream,      // async function* () yields Uint8Array ciphertext parts in order
  linkKey = null,       // Uint8Array(32) from URL fragment
  fileKey = null,       // legacy alias for linkKey
  password = null,      // optional string (second factor)
  onMetadata = null,    // (metaObj) => void
  onPlainChunk,         // async (u8PlainChunk) => void  (write to stream / file sink)
}) {
  await sodium.ready;

  const header = await fetchHeader();
  const headerBytes = header instanceof Uint8Array ? header : new Uint8Array(header);
  const parsed = parseHeaderV3(headerBytes);

  const providedKey = linkKey ?? fileKey;
  if (!providedKey) throw new Error("Missing link key");
  const linkKeyBytes = new Uint8Array(providedKey);

  // Resolve root key (link key only, or link key + password). deriveRootKey
  // normalizes the password and clamps the header's Argon2 params.
  if (parsed.hasPwhash && password == null) throw new Error("Password required to decrypt");
  if (!parsed.hasPwhash && parsed.pwhashLen !== 0) throw new Error("Unexpected pwhash data");
  const rootKey = deriveRootKey(linkKeyBytes, parsed.hasPwhash ? password : null, parsed.pwhashBlock);

  const chunkKey = deriveSubkey(rootKey, KDF_CONTEXT_CHUNK);
  const metaKey = deriveSubkey(rootKey, KDF_CONTEXT_META);
  const headerMacKey = deriveSubkey(rootKey, KDF_CONTEXT_HEADER);

  if (!verifyHeaderMac(parsed, headerMacKey)) throw new Error("Header authentication failed");

  const metaPlain = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    parsed.metaCipher,
    parsed.fileNonce,
    parsed.metaNonce,
    metaKey
  );
  const metaObj = JSON.parse(dec.decode(metaPlain));
  if (onMetadata) await onMetadata(metaObj);

  let totalOut = 0;
  let expectedSize = typeof metaObj.size === "number" ? metaObj.size : null;
  let index = 0;

  for await (const ctPart of fetchPartStream()) {
    if (index >= parsed.totalChunks) {
      throw new Error("Unexpected extra chunk");
    }

    const message = openChunk(chunkKey, parsed.fileNonce, index, ctPart);

    if (expectedSize != null && totalOut+message.length > expectedSize) {
      const remaining = expectedSize - totalOut;
      if (remaining < 0) throw new Error("Size mismatch / tampered metadata");
      const trimmed = message.slice(0, remaining);
      await onPlainChunk(trimmed);
      totalOut += trimmed.length;
    } else {
      await onPlainChunk(message);
      totalOut += message.length;
    }
    index += 1;
  }

  if (index !== parsed.totalChunks) {
    throw new Error("Missing chunks");
  }
  if (expectedSize != null && totalOut !== expectedSize) {
    throw new Error("Size mismatch / tampered metadata");
  }

  sodium.memzero(chunkKey);
  sodium.memzero(metaKey);
  sodium.memzero(headerMacKey);
  sodium.memzero(rootKey);
  sodium.memzero(linkKeyBytes);
}

export async function parseEncryptedHeader(headerBytes) {
  await sodium.ready;
  const bytes = headerBytes instanceof Uint8Array ? headerBytes : new Uint8Array(headerBytes);
  const parsed = parseHeaderV3(bytes);
  return {
    headerBytes: bytes,
    chunkSize: parsed.chunkSize,
    totalChunks: parsed.totalChunks,
  };
}

export async function splitEncryptedPayload(payload) {
  await sodium.ready;
  const bytes = payload instanceof Uint8Array ? payload : new Uint8Array(payload);
  const headerBytes = extractHeaderFromPayload(bytes);
  const parsed = parseHeaderV3(headerBytes);
  const headerLen = headerBytes.length;
  const cipherBytes = bytes.slice(headerLen);
  if (cipherBytes.length === 0) throw new Error("Missing ciphertext");

  const partSize = parsed.chunkSize + sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES;
  const parts = [];
  for (let i = 0; i < parsed.totalChunks; i += 1) {
    const start = i * partSize;
    const end = i === parsed.totalChunks - 1 ? cipherBytes.length : start + partSize;
    if (end > cipherBytes.length) throw new Error("Truncated ciphertext");
    const part = cipherBytes.slice(start, end);
    if (part.length < sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES) {
      throw new Error("Invalid ciphertext chunk");
    }
    parts.push(part);
  }
  return { headerBytes, parts };
}
