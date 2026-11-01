// @vitest-environment node
import { describe, it, expect, beforeAll } from 'vitest';
import sodium from 'libsodium-wrappers-sumo';
import { encryptAndUpload, getChunkOverheadBytes } from './encrypt.js';

beforeAll(async () => { await sodium.ready; });

function makeFile(bytes, { name = 'payload.bin', type = 'application/octet-stream', lastModified = 0 } = {}) {
  return {
    name,
    size: bytes.length,
    type,
    lastModified,
    stream() {
      return new ReadableStream({
        start(controller) { controller.enqueue(bytes); controller.close(); },
      });
    },
  };
}

describe('resume metadata guard', () => {
  it('rejects a resume when the file lastModified changed (nonce-reuse guard)', async () => {
    const bytes = new Uint8Array(16).fill(7);
    const linkKey = new Uint8Array(32).fill(8);
    const chunkSize = 4;
    const overhead = await getChunkOverheadBytes();
    let headerBytes = null;

    await encryptAndUpload({
      file: makeFile(bytes, { lastModified: 111 }),
      linkKey,
      chunkSize,
      onHeader: (header) => { headerBytes = header; },
      uploadHeader: async () => {},
      uploadPart: async () => {},
    });

    const resumeFromBytes = headerBytes.length + chunkSize + overhead;
    await expect(encryptAndUpload({
      file: makeFile(bytes, { lastModified: 222 }), // same name+size, different mtime
      linkKey,
      chunkSize,
      resumeFromBytes,
      resumeHeaderBytes: headerBytes,
      uploadHeader: async () => {},
      uploadPart: async () => {},
    })).rejects.toThrow('Resume data mismatch.');
  });

  it('allows a resume when lastModified is unchanged', async () => {
    const bytes = new Uint8Array(16).fill(7);
    const linkKey = new Uint8Array(32).fill(8);
    const chunkSize = 4;
    const overhead = await getChunkOverheadBytes();
    let headerBytes = null;

    await encryptAndUpload({
      file: makeFile(bytes, { lastModified: 111 }),
      linkKey,
      chunkSize,
      onHeader: (header) => { headerBytes = header; },
      uploadHeader: async () => {},
      uploadPart: async () => {},
    });

    const resumeFromBytes = headerBytes.length + chunkSize + overhead;
    await expect(encryptAndUpload({
      file: makeFile(bytes, { lastModified: 111 }),
      linkKey,
      chunkSize,
      resumeFromBytes,
      resumeHeaderBytes: headerBytes,
      uploadHeader: async () => {},
      uploadPart: async () => {},
    })).resolves.toBeDefined();
  });
});
