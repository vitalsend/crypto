// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Jörgen Karlsson <jorgen@karlsson.com, jorgenk@vitalsend.eu>
// frontend/src/js/crypto/kdf.test.js
// @vitest-environment node
import { describe, it, expect, beforeAll } from 'vitest';
import sodium from 'libsodium-wrappers-sumo';
import { normalizePassword, assertPassword, buildPasswordHashBlock, deriveRootKey } from './kdf.js';

beforeAll(async () => { await sodium.ready; });

describe('normalizePassword', () => {
  it('trims and upper-cases', () => {
    expect(normalizePassword('  abcDEF2345 ')).toBe('ABCDEF2345');
  });
  it('passes null through (no password)', () => {
    expect(normalizePassword(null)).toBe(null);
    expect(normalizePassword(undefined)).toBe(null);
  });
});

describe('assertPassword', () => {
  it('rejects short/non-string', () => {
    expect(() => assertPassword('SHORT')).toThrow(/at least 10/);
    expect(() => assertPassword(12345678901)).toThrow(/at least 10/);
  });
  it('accepts 10+ chars', () => { expect(() => assertPassword('ABCDEFGH23')).not.toThrow(); });
});

describe('root key derivation', () => {
  const linkKey = new Uint8Array(32).fill(7);

  it('no password: rootKey === linkKey, empty block', () => {
    const { pwhashBlock, rootKey } = buildPasswordHashBlock(null, linkKey);
    expect(pwhashBlock.length).toBe(0);
    expect(rootKey).toBe(linkKey);
    expect(deriveRootKey(linkKey, null, new Uint8Array(0))).toBe(linkKey);
  });

  it('password: encrypt-side block reproduces the same rootKey on decrypt-side', () => {
    const { pwhashBlock, rootKey } = buildPasswordHashBlock('TESTPASSWORD23', linkKey);
    expect(pwhashBlock.length).toBe(sodium.crypto_pwhash_SALTBYTES + 16);
    const rederived = deriveRootKey(linkKey, 'TESTPASSWORD23', pwhashBlock);
    expect(Array.from(rederived)).toEqual(Array.from(rootKey));
  });

  it('case-insensitive: lower/spaced input derives the same rootKey', () => {
    const { pwhashBlock, rootKey } = buildPasswordHashBlock('TESTPASSWORD23', linkKey);
    const rederived = deriveRootKey(linkKey, '  testpassword23 ', pwhashBlock);
    expect(Array.from(rederived)).toEqual(Array.from(rootKey));
  });

  it('clamps attacker-controlled Argon2 params (DoS guard)', () => {
    const { pwhashBlock } = buildPasswordHashBlock('TESTPASSWORD23', linkKey);
    const evil = new Uint8Array(pwhashBlock);
    // ops u64 starts right after the salt; set to a huge value
    new DataView(evil.buffer).setBigUint64(sodium.crypto_pwhash_SALTBYTES, 2n ** 40n, false);
    expect(() => deriveRootKey(linkKey, 'TESTPASSWORD23', evil)).toThrow('Invalid password parameters');
  });

  it('rejects wrong-size block and missing password', () => {
    const { pwhashBlock } = buildPasswordHashBlock('TESTPASSWORD23', linkKey);
    expect(() => deriveRootKey(linkKey, 'TESTPASSWORD23', pwhashBlock.slice(0, 10))).toThrow('Invalid pwhash block');
    expect(() => deriveRootKey(linkKey, null, pwhashBlock)).toThrow('Password required to decrypt');
  });
});
