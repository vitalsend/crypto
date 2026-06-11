// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Jörgen Karlsson <jorgen@karlsson.com, jorgenk@vitalsend.eu>
//
// vitalsend-crypto: browser E2EE chunked file encryption (XChaCha20-Poly1305).
// Public surface; everything not exported here is internal.
export {
  encryptAndUpload,
  encryptAndUploadWithWorker,
  getChunkOverheadBytes,
  DEFAULT_CHUNK_SIZE,
  MAX_CHUNK_SIZE,
} from "./encrypt.js";
export {
  decryptAndDownload,
  parseEncryptedHeader,
  splitEncryptedPayload,
} from "./decrypt.js";
export { normalizePassword } from "./kdf.js";
export { PASSWORD_MIN_LENGTH, HEADER_VERSION, HEADER_MAGIC } from "./format.js";
export {
  encodeLinkKey,
  decodeLinkKey,
  buildShareLink,
  parseShareLinkHash,
} from "./link-key.js";
