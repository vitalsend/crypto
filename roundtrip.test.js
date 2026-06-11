// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Jörgen Karlsson <jorgen@karlsson.com, jorgenk@vitalsend.eu>
// @vitest-environment node
import { describe, it, expect } from 'vitest';
import { encryptAndUpload, encryptAndUploadWithWorker, getChunkOverheadBytes, decryptAndDownload } from './index.js';

function u8concat(...chunks) {
  const len = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(len);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

function makeFile(bytes, name = 'payload.bin', type = 'application/octet-stream') {
  return {
    name,
    size: bytes.length,
    type,
    lastModified: 0,
    stream() {
      return new ReadableStream({
        start(controller) {
          controller.enqueue(bytes);
          controller.close();
        },
      });
    },
  };
}

async function roundTrip({
  bytes,
  linkKey,
  password,
  chunkSize = 8,
  padToChunkBoundary = false,
  encryptFn = encryptAndUpload,
}) {
  let headerBytes = null;
  const parts = [];
  const file = makeFile(bytes);

  await encryptFn({
    file,
    uploadHeader: async (header) => {
      headerBytes = header;
    },
    uploadPart: async (_index, part) => {
      parts.push(part);
    },
    linkKey,
    password,
    chunkSize,
    padToChunkBoundary,
  });

  const outputChunks = [];
  let metadata = null;
  await decryptAndDownload({
    fetchHeader: async () => headerBytes,
    fetchPartStream: async function* () {
      for (const part of parts) yield part;
    },
    linkKey,
    password,
    onMetadata: (meta) => {
      metadata = meta;
    },
    onPlainChunk: async (chunk) => {
      outputChunks.push(chunk);
    },
  });

  return { headerBytes, output: u8concat(...outputChunks), metadata, parts };
}

describe('encryption flow', () => {
  it('round-trips data with link key only', async () => {
    const bytes = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    const linkKey = new Uint8Array(32).fill(7);
    const { output, metadata } = await roundTrip({ bytes, linkKey, padToChunkBoundary: false });

    expect(Array.from(output)).toEqual(Array.from(bytes));
    expect(metadata.name).toBe('payload.bin');
    expect(metadata.size).toBe(bytes.length);
  });

  it('round-trips across chunk boundaries', async () => {
    const linkKey = new Uint8Array(32).fill(5);
    const chunkSize = 4;
    const sizes = [0, 1, 3, 4, 5, 7, 8, 9, 12, 17];
    for (const size of sizes) {
      const bytes = new Uint8Array(size);
      for (let i = 0; i < size; i += 1) {
        bytes[i] = (i * 31) % 256;
      }
      const { output } = await roundTrip({ bytes, linkKey, chunkSize, padToChunkBoundary: false });
      expect(Array.from(output)).toEqual(Array.from(bytes));
    }
  });

  it('requires the password when extra protection is enabled', async () => {
    const bytes = new Uint8Array([10, 20, 30, 40, 50, 60, 70]);
    const linkKey = new Uint8Array(32).fill(9);
    const password = 'LongerPwd1';
    const { headerBytes, parts } = await roundTrip({ bytes, linkKey, password, padToChunkBoundary: false });

    await expect(
      decryptAndDownload({
        fetchHeader: async () => headerBytes,
        fetchPartStream: async function* () {
          for (const part of parts) yield part;
        },
        linkKey,
        password: 'WrongPassword1',
        onPlainChunk: async () => {},
      })
    ).rejects.toThrow(/password|auth|header/i);
  });

  it('rejects short passwords during encryption', async () => {
    const bytes = new Uint8Array([1, 2, 3]);
    const linkKey = new Uint8Array(32).fill(4);
    await expect(
      encryptAndUpload({
        file: makeFile(bytes),
        uploadHeader: async () => {},
        uploadPart: async () => {},
        linkKey,
        password: 'short',
      })
    ).rejects.toThrow(/password/i);
  });

  it('detects header tampering', async () => {
    const bytes = new Uint8Array([9, 8, 7, 6, 5, 4, 3, 2, 1]);
    const linkKey = new Uint8Array(32).fill(3);
    const { headerBytes, parts } = await roundTrip({ bytes, linkKey });
    const tamperedHeader = new Uint8Array(headerBytes);
    tamperedHeader[5] ^= 1;

    await expect(
      decryptAndDownload({
        fetchHeader: async () => tamperedHeader,
        fetchPartStream: async function* () {
          for (const part of parts) yield part;
        },
        linkKey,
        onPlainChunk: async () => {},
      })
    ).rejects.toThrow(/magic|header|auth|mac/i);
  });

  it('falls back to the main-thread pipeline when workers are unavailable', async () => {
    const bytes = new Uint8Array([3, 6, 9, 12, 15, 18]);
    const linkKey = new Uint8Array(32).fill(4);
    const { output } = await roundTrip({
      bytes,
      linkKey,
      encryptFn: encryptAndUploadWithWorker,
      padToChunkBoundary: false,
    });

    expect(Array.from(output)).toEqual(Array.from(bytes));
  });

  it('rounds a misaligned resume offset down to the last full encrypted chunk', async () => {
    const bytes = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9]);
    const linkKey = new Uint8Array(32).fill(6);
    const chunkSize = 4;
    const overhead = await getChunkOverheadBytes();
    let headerLength = 0;
    const uploaded = [];
    let headerUploads = 0;

    await encryptAndUpload({
      file: makeFile(bytes),
      linkKey,
      chunkSize,
      resumeFromBytes: 0,
      onHeader: (header) => {
        headerLength = header.length;
      },
      uploadHeader: async () => {
        headerUploads += 1;
      },
      uploadPart: async (index, _part, offset) => {
        uploaded.push({ index, offset });
      },
    }).catch(() => {
      throw new Error('unexpected failure');
    });

    uploaded.length = 0;
    headerUploads = 0;
    const misalignedOffset = headerLength + (chunkSize + overhead) + 3;

    await encryptAndUpload({
      file: makeFile(bytes),
      linkKey,
      chunkSize,
      resumeFromBytes: misalignedOffset,
      onHeader: (header) => {
        headerLength = header.length;
      },
      uploadHeader: async () => {
        headerUploads += 1;
      },
      uploadPart: async (index, _part, offset) => {
        uploaded.push({ index, offset });
      },
    });

    expect(headerUploads).toBe(0);
    expect(uploaded.map((item) => item.index)).toEqual([1, 2]);
    expect(uploaded[0].offset).toBe(headerLength + chunkSize + overhead);
  });

  it('resumes with the original encrypted header parameters', async () => {
    const bytes = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9]);
    const linkKey = new Uint8Array(32).fill(8);
    const chunkSize = 4;
    const overhead = await getChunkOverheadBytes();
    let headerBytes = null;
    const parts = [];

    await encryptAndUpload({
      file: makeFile(bytes),
      linkKey,
      chunkSize,
      onHeader: (header) => {
        headerBytes = header;
      },
      uploadHeader: async () => {},
      uploadPart: async (index, part) => {
        if (index === 0) {
          parts[index] = part;
        }
      },
    });

    const resumeFromBytes = headerBytes.length + chunkSize + overhead;
    await encryptAndUpload({
      file: makeFile(bytes),
      linkKey,
      chunkSize,
      resumeFromBytes,
      resumeHeaderBytes: headerBytes,
      uploadHeader: async () => {
        throw new Error('header should not be uploaded on resume');
      },
      uploadPart: async (index, part) => {
        parts[index] = part;
      },
    });

    const outputChunks = [];
    await decryptAndDownload({
      fetchHeader: async () => headerBytes,
      fetchPartStream: async function* () {
        for (const part of parts) yield part;
      },
      linkKey,
      onPlainChunk: async (chunk) => {
        outputChunks.push(chunk);
      },
    });

    expect(Array.from(u8concat(...outputChunks))).toEqual(Array.from(bytes));
  });
});
