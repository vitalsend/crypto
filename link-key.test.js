// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Jörgen Karlsson <jorgen@karlsson.com, jorgenk@vitalsend.eu>
import { describe, it, expect } from 'vitest';
import { encodeLinkKey, decodeLinkKey, buildShareLink, parseShareLinkHash } from './link-key.js';

describe('link key helpers', () => {
  it('round-trips a 32-byte key', () => {
    const key = new Uint8Array(32).fill(9);
    const encoded = encodeLinkKey(key);
    const decoded = decodeLinkKey(encoded);
    expect(decoded).toBeInstanceOf(Uint8Array);
    expect(Array.from(decoded)).toEqual(Array.from(key));
  });

  it('parses share link hash flags', () => {
    const key = new Uint8Array(32).fill(1);
    const encoded = encodeLinkKey(key);
    const parsed = parseShareLinkHash(`#k=${encoded}&p=1`);
    expect(parsed.requiresPassword).toBe(true);
    expect(Array.from(parsed.linkKey)).toEqual(Array.from(key));
  });

  it('rejects keys that are not exactly 32 bytes', () => {
    expect(() => encodeLinkKey(new Uint8Array(31))).toThrow('32 bytes');
    expect(() => decodeLinkKey('aGVsbG8')).toThrow('Invalid link key');
  });

  it('buildShareLink puts the key in the fragment with optional p=1', () => {
    const key = encodeLinkKey(new Uint8Array(32).fill(1));
    expect(buildShareLink('https://x.test/d/?file=ID', key, false)).toBe(`https://x.test/d/?file=ID#k=${key}`);
    expect(buildShareLink('https://x.test/d/?file=ID', key, true)).toBe(`https://x.test/d/?file=ID#k=${key}&p=1`);
  });
});
