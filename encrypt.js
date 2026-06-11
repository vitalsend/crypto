// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Jörgen Karlsson <jorgen@karlsson.com, jorgenk@vitalsend.eu>
//
// Browser-only E2EE chunked encryption pipeline using libsodium (WASM).
// Transport is caller-supplied (uploadHeader/uploadPart callbacks); this
// module never performs I/O and never reads environment variables.
import sodium from "libsodium-wrappers-sumo";
import {
  MAX_METADATA_BYTES, MAX_CHUNK_SIZE, DEFAULT_CHUNK_SIZE,
  KDF_CONTEXT_CHUNK, KDF_CONTEXT_META, KDF_CONTEXT_HEADER,
  u8concat, deriveSubkey, sealChunk, buildHeader, parseHeaderV3,
  verifyHeaderMac, getChunkOverheadBytes,
} from "./format.js";
import { buildPasswordHashBlock, deriveRootKey } from "./kdf.js";

export { DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE, getChunkOverheadBytes };

const enc = new TextEncoder();
const dec = new TextDecoder();
const MAX_WORKER_POOL_SIZE = 6;
const MIN_WORKER_POOL_SIZE = 2;
const DEFAULT_WORKER_URL = "/js/encrypt-worker.js";
const nowMs = () => (typeof performance !== "undefined" && performance.now ? performance.now() : Date.now());

function normalizeResumeOffset(resumeFromBytes, headerLength, chunkStride) {
  const offset = Number(resumeFromBytes || 0);
  if (!Number.isFinite(offset) || offset <= 0) {
    return { resumeChunkIndex: 0, shouldUploadHeader: true };
  }
  if (offset < headerLength) {
    return { resumeChunkIndex: 0, shouldUploadHeader: true };
  }
  const remaining = offset - headerLength;
  const alignedRemaining = Math.floor(remaining / chunkStride) * chunkStride;
  const resumeChunkIndex = Math.floor(alignedRemaining / chunkStride);
  return {
    resumeChunkIndex,
    shouldUploadHeader: resumeChunkIndex === 0,
  };
}

function verifyResumeMetadata(parsed, metaKey, file) {
  const metaPlain = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    parsed.metaCipher,
    parsed.fileNonce,
    parsed.metaNonce,
    metaKey
  );
  const meta = JSON.parse(dec.decode(metaPlain));
  if (Number(meta?.size || 0) !== Number(file.size || 0)) {
    throw new Error("Resume data mismatch.");
  }
  if (meta?.name && file.name && meta.name !== file.name) {
    throw new Error("Resume data mismatch.");
  }
}

function buildEncryptionState({ file, linkKeyBytes, password, chunkSize, totalChunks, resumeHeaderBytes }) {
  if (resumeHeaderBytes) {
    const headerBytes = resumeHeaderBytes instanceof Uint8Array
      ? resumeHeaderBytes
      : new Uint8Array(resumeHeaderBytes || []);
    let parsed;
    try {
      parsed = parseHeaderV3(headerBytes);
    } catch {
      throw new Error("Resume data mismatch.");
    }
    if (parsed.chunkSize !== chunkSize || parsed.totalChunks !== totalChunks) {
      throw new Error("Resume data mismatch.");
    }
    const hasPassword = parsed.hasPwhash;
    if (hasPassword !== (password != null)) {
      throw new Error("Resume data mismatch.");
    }
    let rootKey;
    try {
      rootKey = deriveRootKey(linkKeyBytes, password, parsed.pwhashBlock);
    } catch {
      throw new Error("Resume data mismatch.");
    }
    const chunkKey = deriveSubkey(rootKey, KDF_CONTEXT_CHUNK);
    const metaKey = deriveSubkey(rootKey, KDF_CONTEXT_META);
    const headerMacKey = deriveSubkey(rootKey, KDF_CONTEXT_HEADER);
    if (!verifyHeaderMac(parsed, headerMacKey)) {
      throw new Error("Resume data mismatch.");
    }
    verifyResumeMetadata(parsed, metaKey, file);
    return { headerBytes, fileNonce: parsed.fileNonce, rootKey, chunkKey, metaKey, headerMacKey };
  }

  const { pwhashBlock, rootKey } = buildPasswordHashBlock(password, linkKeyBytes);
  const chunkKey = deriveSubkey(rootKey, KDF_CONTEXT_CHUNK);
  const metaKey = deriveSubkey(rootKey, KDF_CONTEXT_META);
  const headerMacKey = deriveSubkey(rootKey, KDF_CONTEXT_HEADER);

  const meta = {
    name: file.name,
    size: file.size,
    type: file.type || "application/octet-stream",
    lastModified: file.lastModified ?? null,
  };
  const metaBytes = enc.encode(JSON.stringify(meta));
  if (metaBytes.length + sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES > MAX_METADATA_BYTES) {
    throw new Error("Metadata too large.");
  }

  const metaNonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const fileNonce = sodium.randombytes_buf(16);
  const metaCipher = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    metaBytes,
    fileNonce,
    null,
    metaNonce,
    metaKey
  );

  const headerBytes = buildHeader({
    chunkSize, hasPassword: password != null, totalChunks,
    fileNonce, pwhashBlock, metaNonce, metaCipher, headerMacKey,
  });
  return { headerBytes, fileNonce, rootKey, chunkKey, metaKey, headerMacKey };
}

export async function encryptAndUpload({
  file,                        // File
  uploadPart,                  // async (partIndex:number, bytes:Uint8Array) => void
  uploadHeader,                // async (bytes:Uint8Array) => void
  linkKey = null,              // Uint8Array(32) or null to generate (shared in URL fragment)
  outOfBandFileKey = null,     // legacy alias for linkKey
  password = null,             // optional string (second factor)
  chunkSize = DEFAULT_CHUNK_SIZE,
  padToChunkBoundary = false,  // optional tail padding (disabled by default)
  onProgress = null,           // optional (percent:number) => void
  resumeFromBytes = 0,         // optional ciphertext offset to resume from
  resumeHeaderBytes = null,    // encrypted header from original upload when resuming
  onHeader = null,             // optional (bytes:Uint8Array) => void
  debug = false,
}) {
  await sodium.ready;

  if (!Number.isInteger(chunkSize) || chunkSize < 1 || chunkSize > MAX_CHUNK_SIZE) {
    throw new Error("Invalid chunk size.");
  }
  const totalBytes = Number(file.size || 0);
  const totalChunks = totalBytes === 0 ? 1 : Math.ceil(totalBytes / chunkSize);

  // 1) Link key (32 bytes). Share via URL fragment.
  const providedKey = linkKey ?? outOfBandFileKey;
  const linkKeyBytes = providedKey ? new Uint8Array(providedKey) : sodium.randombytes_buf(
    sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES
  );
  const shareKey = new Uint8Array(linkKeyBytes);

  const {
    headerBytes,
    fileNonce,
    rootKey,
    chunkKey,
    metaKey,
    headerMacKey,
  } = buildEncryptionState({ file, linkKeyBytes, password, chunkSize, totalChunks, resumeHeaderBytes });
  if (typeof onHeader === "function") {
    onHeader(headerBytes);
  }
  const cipherOverhead = sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES;
  const chunkStride = chunkSize + cipherOverhead;
  const { resumeChunkIndex, shouldUploadHeader } = normalizeResumeOffset(
    resumeFromBytes,
    headerBytes.length,
    chunkStride
  );
  if (shouldUploadHeader) {
    await uploadHeader(headerBytes, 0);
  }

  // 5) Chunk encrypt + upload parts
  const reader = file.stream().getReader();
  let buf = new Uint8Array(0);
  let part = 0;
  let processedBytes = Math.min(totalBytes, resumeChunkIndex * chunkSize);
  const reportProgress = () => {
    if (typeof onProgress !== "function") return;
    if (!totalBytes) {
      onProgress(100);
      return;
    }
    const percent = Math.min(100, Math.floor((processedBytes / totalBytes) * 100));
    onProgress(percent);
  };

  const encryptChunk = async (plain, index) => sealChunk(chunkKey, fileNonce, index, plain);
  const partOffset = (index) => headerBytes.length + (index * chunkStride);

  const pipelineStats = debug
    ? { chunks: 0, encryptMs: 0, uploadMs: 0 }
    : null;

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;

    const chunk = new Uint8Array(value);
    buf = buf.length ? u8concat(buf, chunk) : chunk;

    while (buf.length >= chunkSize) {
      const plain = buf.slice(0, chunkSize);
      buf = buf.slice(chunkSize);

      const encryptStart = debug ? nowMs() : 0;
      const ct = await encryptChunk(plain, part);
      const encryptMs = debug ? nowMs() - encryptStart : 0;
      if (part >= resumeChunkIndex) {
        const uploadStart = debug ? nowMs() : 0;
        await uploadPart(part, ct, partOffset(part));
        const uploadMs = debug ? nowMs() - uploadStart : 0;
        if (pipelineStats) {
          pipelineStats.chunks += 1;
          pipelineStats.encryptMs += encryptMs;
          pipelineStats.uploadMs += uploadMs;
          console.info('[vitalsend] upload chunk', part, 'encryptMs', Math.round(encryptMs), 'uploadMs', Math.round(uploadMs));
        }
      }
      part += 1;
      processedBytes += plain.length;
      reportProgress();
    }
  }

  if (totalBytes === 0) {
    const encryptStart = debug ? nowMs() : 0;
    const ct = await encryptChunk(new Uint8Array(0), part);
    const encryptMs = debug ? nowMs() - encryptStart : 0;
    if (part >= resumeChunkIndex) {
      const uploadStart = debug ? nowMs() : 0;
      await uploadPart(part, ct, partOffset(part));
      const uploadMs = debug ? nowMs() - uploadStart : 0;
      if (pipelineStats) {
        pipelineStats.chunks += 1;
        pipelineStats.encryptMs += encryptMs;
        pipelineStats.uploadMs += uploadMs;
        console.info('[vitalsend] upload chunk', part, 'encryptMs', Math.round(encryptMs), 'uploadMs', Math.round(uploadMs));
      }
    }
    part += 1;
    reportProgress();
  } else if (buf.length > 0) {
    let finalPlain = buf;
    if (padToChunkBoundary && finalPlain.length < chunkSize) {
      const padLen = chunkSize - finalPlain.length;
      const pad = new Uint8Array(padLen);
      pad.fill(padLen);
      finalPlain = u8concat(finalPlain, pad);
    }
    const encryptStart = debug ? nowMs() : 0;
    const ct = await encryptChunk(finalPlain, part);
    const encryptMs = debug ? nowMs() - encryptStart : 0;
    if (part >= resumeChunkIndex) {
      const uploadStart = debug ? nowMs() : 0;
      await uploadPart(part, ct, partOffset(part));
      const uploadMs = debug ? nowMs() - uploadStart : 0;
      if (pipelineStats) {
        pipelineStats.chunks += 1;
        pipelineStats.encryptMs += encryptMs;
        pipelineStats.uploadMs += uploadMs;
        console.info('[vitalsend] upload chunk', part, 'encryptMs', Math.round(encryptMs), 'uploadMs', Math.round(uploadMs));
      }
    }
    part += 1;
    processedBytes += buf.length;
    reportProgress();
  }

  if (pipelineStats && pipelineStats.chunks > 0) {
    console.info(
      '[vitalsend] upload pipeline totals',
      'chunks',
      pipelineStats.chunks,
      'encryptMs',
      Math.round(pipelineStats.encryptMs),
      'uploadMs',
      Math.round(pipelineStats.uploadMs)
    );
  }
  sodium.memzero(chunkKey);
  sodium.memzero(metaKey);
  sodium.memzero(headerMacKey);
  sodium.memzero(rootKey);
  sodium.memzero(linkKeyBytes);
  return shareKey;
}

function resolveWorkerOptions(worker) {
  const w = worker || {};
  const rawQueueMax = Number(w.queueMax);
  return {
    enabled: w.enabled !== false,
    url: w.url || DEFAULT_WORKER_URL,
    queueMax: Number.isFinite(rawQueueMax) && rawQueueMax >= 1 ? Math.floor(rawQueueMax) : null,
    debug: w.debug === true,
  };
}

function shouldUseUploadWorker(enabled) {
  if (!enabled) return false;
  if (typeof window === "undefined") return false;
  return typeof window.Worker !== "undefined";
}

function createEncryptWorker(url) {
  return new Worker(url, { type: "module" });
}

function getWorkerPoolSize() {
  if (typeof navigator === "undefined" || !navigator.hardwareConcurrency) {
    return 4;
  }
  return Math.min(
    MAX_WORKER_POOL_SIZE,
    Math.max(MIN_WORKER_POOL_SIZE, Math.floor(navigator.hardwareConcurrency - 1))
  );
}

function getWorkerQueueMax(totalBytes, poolSize, override) {
  if (override) return override;
  const base = poolSize * 4;
  if (!totalBytes) return base;
  const mb = totalBytes / (1024 * 1024);
  if (mb < 256) return base;
  if (mb < 1024) return base * 2;
  return base * 4;
}

function getUploadParallelism(poolSize) {
  return Math.max(1, Math.min(poolSize, 4));
}

export async function encryptAndUploadWithWorker(options) {
  const workerOpts = resolveWorkerOptions(options.worker);
  if (!shouldUseUploadWorker(workerOpts.enabled)) {
    if (workerOpts.debug) {
      console.info('[vitalsend] worker pipeline disabled');
    }
    return encryptAndUpload({ ...options, debug: options.debug ?? workerOpts.debug });
  }
  if (workerOpts.debug) {
    console.info('[vitalsend] worker pipeline enabled');
  }
  const {
    file,
    uploadPart,
    uploadHeader,
    linkKey = null,
    outOfBandFileKey = null,
    password = null,
    chunkSize = DEFAULT_CHUNK_SIZE,
    padToChunkBoundary = false,
    onProgress = null,
    resumeFromBytes = 0,
    resumeHeaderBytes = null,
    onHeader = null,
  } = options;

  await sodium.ready;

  if (!Number.isInteger(chunkSize) || chunkSize < 1 || chunkSize > MAX_CHUNK_SIZE) {
    throw new Error("Invalid chunk size.");
  }

  const totalBytes = Number(file.size || 0);
  const totalChunks = totalBytes === 0 ? 1 : Math.ceil(totalBytes / chunkSize);
  const poolSize = getWorkerPoolSize();
  const uploadParallelism = getUploadParallelism(poolSize);
  const queueMax = getWorkerQueueMax(totalBytes, poolSize, workerOpts.queueMax);
  if (workerOpts.debug) {
    console.info(
      '[vitalsend] worker pipeline config',
      'pool',
      poolSize,
      'uploadParallelism',
      uploadParallelism,
      'queueMax',
      queueMax
    );
  }

  const providedKey = linkKey ?? outOfBandFileKey;
  const linkKeyBytes = providedKey ? new Uint8Array(providedKey) : sodium.randombytes_buf(
    sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES
  );
  const shareKey = new Uint8Array(linkKeyBytes);

  const {
    headerBytes,
    fileNonce,
    rootKey,
    chunkKey,
    metaKey,
    headerMacKey,
  } = buildEncryptionState({ file, linkKeyBytes, password, chunkSize, totalChunks, resumeHeaderBytes });
  if (typeof onHeader === "function") {
    onHeader(headerBytes);
  }

  const cipherOverhead = sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES;
  const chunkStride = chunkSize + cipherOverhead;
  const { resumeChunkIndex, shouldUploadHeader } = normalizeResumeOffset(
    resumeFromBytes,
    headerBytes.length,
    chunkStride
  );
  if (shouldUploadHeader) {
    await uploadHeader(headerBytes, 0);
  }

  const workers = Array.from({ length: poolSize }, (_, idx) => ({
    id: idx + 1,
    worker: createEncryptWorker(workerOpts.url),
    busy: false,
  }));
  const pendingQueue = [];
  const results = new Map();
  const workerStats = workerOpts.debug
    ? { chunks: 0, encryptMs: 0, uploadMs: 0 }
    : null;
  let workerError = null;

  let pendingEncrypt = 0;
  let readInFlight = 0;
  let uploadInFlight = 0;
  let failed = false;
  let encryptedBytes = Math.min(totalBytes, resumeChunkIndex * chunkSize);
  let nextReadIndex = resumeChunkIndex;

  const cleanup = () => {
    for (const entry of workers) {
      entry.worker.terminate();
    }
  };

  const pendingTotal = () => pendingEncrypt + pendingQueue.length + readInFlight + results.size;

  const fail = (err) => {
    failed = true;
    workerError = err instanceof Error ? err : new Error(String(err));
    cleanup();
  };

  const notifyCapacity = () => {
    if (pendingTotal() < queueMax && nextReadIndex < totalChunks) {
      scheduleReads();
    }
  };

  const partOffset = (index) => headerBytes.length + (index * chunkStride);

  const startUpload = async (index, part) => {
    uploadInFlight += 1;
    try {
      const uploadStart = workerOpts.debug ? nowMs() : 0;
      await uploadPart(index, part.bytes, partOffset(index));
      const uploadMs = workerOpts.debug ? nowMs() - uploadStart : 0;
      if (workerStats) {
        workerStats.chunks += 1;
        workerStats.encryptMs += part.encryptMs || 0;
        workerStats.uploadMs += uploadMs;
        console.info('[vitalsend] upload chunk', index, 'encryptMs', Math.round(part.encryptMs || 0), 'uploadMs', Math.round(uploadMs));
      }
    } catch (err) {
      fail(err);
    } finally {
      uploadInFlight = Math.max(0, uploadInFlight - 1);
      notifyCapacity();
      scheduleUploads();
    }
  };

  const scheduleUploads = () => {
    if (failed) return;
    while (uploadInFlight < uploadParallelism && results.size > 0) {
      const index = Math.min(...results.keys());
      const part = results.get(index);
      results.delete(index);
      startUpload(index, part);
    }
  };

  const dispatchWork = () => {
    for (const entry of workers) {
      if (entry.busy) continue;
      const job = pendingQueue.shift();
      if (!job) break;
      entry.busy = true;
      pendingEncrypt += 1;
      if (workerOpts.debug) {
        console.info('[vitalsend] dispatch chunk', job.index, 'worker', entry.id, 'queued', pendingQueue.length);
      }
      entry.worker.postMessage(
        {
          type: "chunk",
          index: job.index,
          bytes: job.bytes,
          plainBytes: job.plainBytes,
        },
        [job.bytes.buffer]
      );
    }
  };

  for (const entry of workers) {
    entry.worker.onmessage = (event) => {
      const message = event.data || {};
      if (message.type !== "part") {
        if (message.type === "error") {
          fail(new Error(message.message || "Worker error."));
        }
        return;
      }
      entry.busy = false;
      pendingEncrypt = Math.max(0, pendingEncrypt - 1);
      notifyCapacity();
      if (workerOpts.debug) {
        console.info('[vitalsend] encrypted chunk', message.index, 'worker', entry.id, 'encryptMs', Math.round(message.encryptMs || 0));
      }
      const bytes = message.bytes instanceof Uint8Array
        ? message.bytes
        : new Uint8Array(message.bytes || []);
      encryptedBytes += Number(message.plainBytes || 0);
      if (typeof onProgress === "function") {
        if (!totalBytes) {
          onProgress(100);
        } else {
          const percent = Math.min(100, Math.floor((encryptedBytes / totalBytes) * 100));
          onProgress(percent);
        }
      }
      results.set(message.index, { bytes, encryptMs: message.encryptMs || 0 });
      dispatchWork();
      scheduleUploads();
    };
    entry.worker.onerror = () => {
      fail(new Error("Worker error."));
    };
    entry.worker.postMessage({
      type: "init",
      payload: {
        chunkKey: chunkKey.slice(),
        fileNonce: fileNonce.slice(),
      },
    });
  }

  if (typeof onProgress === "function") {
    if (!totalBytes) {
      onProgress(100);
    } else {
      const percent = Math.min(100, Math.floor((encryptedBytes / totalBytes) * 100));
      onProgress(percent);
    }
  }

  const enqueueRead = async (index) => {
    const start = index * chunkSize;
    const end = Math.min(totalBytes, start + chunkSize);
    const buffer = await file.slice(start, end).arrayBuffer();
    let plain = new Uint8Array(buffer);
    const plainBytes = plain.length;
    if (padToChunkBoundary && plain.length < chunkSize) {
      const padLen = chunkSize - plain.length;
      const pad = new Uint8Array(padLen);
      pad.fill(padLen);
      plain = u8concat(plain, pad);
    }
    pendingQueue.push({ index, bytes: plain, plainBytes });
    dispatchWork();
    notifyCapacity();
  };

  const scheduleReads = () => {
    while (nextReadIndex < totalChunks && pendingTotal() < queueMax && !failed) {
      const index = nextReadIndex;
      nextReadIndex += 1;
      readInFlight += 1;
      enqueueRead(index)
        .catch((err) => fail(err))
        .finally(() => {
          readInFlight = Math.max(0, readInFlight - 1);
          notifyCapacity();
          scheduleReads();
        });
    }
  };

  try {
    scheduleReads();
  } catch (err) {
    failed = true;
    cleanup();
    throw err;
  }

  while (!failed && (pendingEncrypt > 0 || results.size > 0 || pendingQueue.length > 0 || readInFlight > 0 || nextReadIndex < totalChunks || uploadInFlight > 0)) {
    scheduleUploads();
    await new Promise((resolve) => setTimeout(resolve, 0));
  }

  if (failed) {
    throw workerError || new Error("Worker pipeline failed.");
  }

  cleanup();
  if (workerStats && workerStats.chunks > 0) {
    console.info(
      '[vitalsend] upload pipeline totals',
      'chunks',
      workerStats.chunks,
      'encryptMs',
      Math.round(workerStats.encryptMs),
      'uploadMs',
      Math.round(workerStats.uploadMs)
    );
  }

  sodium.memzero(chunkKey);
  sodium.memzero(metaKey);
  sodium.memzero(headerMacKey);
  sodium.memzero(rootKey);
  sodium.memzero(linkKeyBytes);

  return shareKey;
}
