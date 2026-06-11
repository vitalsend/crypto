// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Jörgen Karlsson <jorgen@karlsson.com, jorgenk@vitalsend.eu>
//
// Encrypt worker: encrypts chunks in parallel for the upload pipeline.
// Uses the exact same sealChunk as the main thread; parity by construction.
import sodium from "libsodium-wrappers-sumo";
import { sealChunk } from "../format.js";

let chunkKey = null;
let fileNonce = null;
let initPromise = null;

const nowMs = () => (typeof performance !== "undefined" && performance.now ? performance.now() : Date.now());

function postError(err) {
  const message = err instanceof Error ? err.message : String(err || "Worker error");
  self.postMessage({ type: "error", message });
}

async function initWorker(payload) {
  await sodium.ready;
  if (!payload?.chunkKey || !payload?.fileNonce) {
    throw new Error("Missing worker init payload.");
  }
  chunkKey = new Uint8Array(payload.chunkKey);
  fileNonce = new Uint8Array(payload.fileNonce);
  self.postMessage({ type: "ready" });
}

self.onmessage = (event) => {
  const message = event.data || {};
  if (message.type === "init") {
    initPromise = initWorker(message.payload).catch(postError);
    return;
  }
  if (message.type !== "chunk") return;

  void (async () => {
    if (!initPromise) throw new Error("Worker not initialized.");
    await initPromise;
    if (!chunkKey || !fileNonce) throw new Error("Worker not initialized.");
    const bytes = message.bytes instanceof Uint8Array ? message.bytes : new Uint8Array(message.bytes || []);
    const encryptStart = nowMs();
    const ct = sealChunk(chunkKey, fileNonce, message.index, bytes);
    const encryptMs = nowMs() - encryptStart;
    self.postMessage(
      { type: "part", index: message.index, bytes: ct, encryptMs, plainBytes: Number(message.plainBytes || 0) },
      [ct.buffer]
    );
  })().catch(postError);
};
