// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Jörgen Karlsson <jorgen@karlsson.com, jorgenk@vitalsend.eu>
// frontend/src/js/crypto/compat.test.js
// @vitest-environment node
// Backward-compat proof: fixtures were produced by the PRE-extraction code
// and are frozen. The new decrypt path MUST accept them forever (v3 links
// in the wild depend on it). Never regenerate the fixtures.
import { describe, it, expect } from 'vitest';
import { decryptAndDownload } from './decrypt.js';
import noPw from './fixtures/v3-no-password.json';
import withPw from './fixtures/v3-password.json';

const fromB64 = (s) => new Uint8Array(Buffer.from(s, 'base64'));

async function decryptFixture(f, { password = f.password } = {}) {
  const got = [];
  let meta = null;
  await decryptAndDownload({
    fetchHeader: async () => fromB64(f.header),
    fetchPartStream: async function* () { for (const p of f.parts) yield fromB64(p); },
    linkKey: fromB64(f.linkKey),
    password,
    onMetadata: async (m) => { meta = m; },
    onPlainChunk: async (c) => got.push(...c),
  });
  return { plain: new Uint8Array(got), meta };
}

describe('golden v3 fixtures (frozen pre-extraction bytes)', () => {
  it('decrypts the no-password fixture', async () => {
    const { plain, meta } = await decryptFixture(noPw);
    expect(Array.from(plain)).toEqual(Array.from(fromB64(noPw.plaintext)));
    expect(meta.name).toBe('fixture.bin');
  });
  it('decrypts the password fixture', async () => {
    const { plain } = await decryptFixture(withPw);
    expect(Array.from(plain)).toEqual(Array.from(fromB64(withPw.plaintext)));
  });
  it('decrypts the password fixture with lower-cased input (normalization)', async () => {
    const { plain } = await decryptFixture(withPw, { password: withPw.password.toLowerCase() });
    expect(Array.from(plain)).toEqual(Array.from(fromB64(withPw.plaintext)));
  });
});
