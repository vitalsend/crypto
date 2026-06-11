// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Jörgen Karlsson <jorgen@karlsson.com, jorgenk@vitalsend.eu>
// @vitest-environment node
import { describe, it, expect } from 'vitest';
import { encryptAndUpload, parseEncryptedHeader } from './index.js';

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

async function buildHeader({ bytes, chunkSize = 4, linkKey }) {
  let headerBytes = null;
  await encryptAndUpload({
    file: makeFile(bytes),
    uploadHeader: async (header) => {
      headerBytes = header;
    },
    uploadPart: async () => {},
    linkKey,
    chunkSize,
    padToChunkBoundary: false,
  });
  return headerBytes;
}

describe('header parsing', () => {
  it('parses a valid header', async () => {
    const bytes = new Uint8Array([1, 2, 3, 4, 5]);
    const linkKey = new Uint8Array(32).fill(9);
    const chunkSize = 4;
    const header = await buildHeader({ bytes, chunkSize, linkKey });
    const parsed = await parseEncryptedHeader(header);

    expect(parsed.chunkSize).toBe(chunkSize);
    expect(parsed.totalChunks).toBe(2);
    expect(parsed.headerBytes).toBeInstanceOf(Uint8Array);
  });

  it('rejects bad magic', async () => {
    const header = await buildHeader({
      bytes: new Uint8Array([1, 2, 3]),
      linkKey: new Uint8Array(32).fill(1),
    });
    const tampered = new Uint8Array(header);
    tampered[0] = 0x00;
    await expect(parseEncryptedHeader(tampered)).rejects.toThrow(/magic/i);
  });

  it('rejects unsupported version', async () => {
    const header = await buildHeader({
      bytes: new Uint8Array([1, 2, 3]),
      linkKey: new Uint8Array(32).fill(2),
    });
    const tampered = new Uint8Array(header);
    tampered[8] = 9;
    await expect(parseEncryptedHeader(tampered)).rejects.toThrow(/version/i);
  });

  it('rejects truncated headers', async () => {
    const header = await buildHeader({
      bytes: new Uint8Array([1, 2, 3, 4]),
      linkKey: new Uint8Array(32).fill(3),
    });
    const truncated = header.slice(0, header.length - 5);
    await expect(parseEncryptedHeader(truncated)).rejects.toThrow(/truncated|header/i);
  });

  it('rejects invalid chunk sizes', async () => {
    const header = await buildHeader({
      bytes: new Uint8Array([1, 2, 3, 4]),
      linkKey: new Uint8Array(32).fill(4),
    });
    const tampered = new Uint8Array(header);
    tampered[9] = 0;
    tampered[10] = 0;
    tampered[11] = 0;
    tampered[12] = 0;
    await expect(parseEncryptedHeader(tampered)).rejects.toThrow(/chunk size/i);
  });

  it('rejects zero total chunks', async () => {
    const header = await buildHeader({
      bytes: new Uint8Array([1, 2, 3, 4]),
      linkKey: new Uint8Array(32).fill(5),
    });
    const tampered = new Uint8Array(header);
    for (let i = 14; i < 22; i += 1) {
      tampered[i] = 0;
    }
    await expect(parseEncryptedHeader(tampered)).rejects.toThrow(/total chunks/i);
  });
});
