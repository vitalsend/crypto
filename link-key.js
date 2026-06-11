// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Jörgen Karlsson <jorgen@karlsson.com, jorgenk@vitalsend.eu>
//
// URL-fragment link-key codec: the 32-byte key travels in the #fragment,
// which browsers never send to the server.
function toBase64(bytes) {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64');
  }
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function fromBase64(value) {
  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(value, 'base64'));
  }
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function toBase64Url(value) {
  return value.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64Url(value) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padLength = (4 - (normalized.length % 4)) % 4;
  return normalized + '='.repeat(padLength);
}

export function encodeLinkKey(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
    throw new Error('Link key must be 32 bytes.');
  }
  return toBase64Url(toBase64(bytes));
}

export function decodeLinkKey(value) {
  if (!value) return null;
  const raw = fromBase64Url(String(value));
  const bytes = fromBase64(raw);
  if (bytes.length !== 32) {
    throw new Error('Invalid link key.');
  }
  return bytes;
}

export function buildShareLink(baseLink, encodedKey, requiresPassword) {
  if (!baseLink) return '';
  if (!encodedKey) return baseLink;
  const base = String(baseLink).split('#')[0];
  const params = new URLSearchParams();
  params.set('k', encodedKey);
  if (requiresPassword) params.set('p', '1');
  return `${base}#${params.toString()}`;
}

export function parseShareLinkHash(hash) {
  const cleaned = String(hash || '').replace(/^#/, '');
  const params = new URLSearchParams(cleaned);
  let linkKey = null;
  const keyValue = params.get('k');
  if (keyValue) {
    linkKey = decodeLinkKey(keyValue);
  }
  return {
    linkKey,
    requiresPassword: params.get('p') === '1',
  };
}
