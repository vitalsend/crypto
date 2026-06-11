// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Jörgen Karlsson <jorgen@karlsson.com, jorgenk@vitalsend.eu>
//
// Password handling and root-key derivation. The optional password is a
// second factor mixed into the root key; the 32-byte link key remains the
// primary secret. normalizePassword is the single normalization point:
// every KDF entry point applies it, so encrypt and decrypt cannot diverge.
import sodium from "libsodium-wrappers-sumo";
import { PASSWORD_MIN_LENGTH, u8concat, u64be, readU64be } from "./format.js";

export function normalizePassword(password) {
  if (password == null) return null;
  return String(password).trim().toUpperCase();
}

export function assertPassword(password) {
  if (typeof password !== "string" || password.length < PASSWORD_MIN_LENGTH) {
    throw new Error(`Password must be at least ${PASSWORD_MIN_LENGTH} characters.`);
  }
}

// Encrypt side: fresh salt + Argon2id(MODERATE) -> rootKey, plus the
// parameter block stored (authenticated) in the header.
export function buildPasswordHashBlock(password, linkKeyBytes) {
  if (password == null) {
    return { pwhashBlock: new Uint8Array(0), rootKey: linkKeyBytes };
  }
  const normalized = normalizePassword(password);
  assertPassword(normalized);
  const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
  const ops = sodium.crypto_pwhash_OPSLIMIT_MODERATE;
  const mem = sodium.crypto_pwhash_MEMLIMIT_MODERATE;
  const passwordKey = sodium.crypto_pwhash(32, normalized, salt, ops, mem, sodium.crypto_pwhash_ALG_DEFAULT);
  const rootKey = sodium.crypto_generichash(32, linkKeyBytes, passwordKey);
  sodium.memzero(passwordKey);
  return { pwhashBlock: u8concat(salt, u64be(ops), u64be(mem)), rootKey };
}

// Decrypt/resume side: re-derive the root key from the stored parameter
// block. ops/mem come from an untrusted header, so they are clamped to
// MODERATE before any hashing; a hostile header cannot pin the CPU/RAM.
export function deriveRootKey(linkKeyBytes, password, pwhashBlock) {
  if (!pwhashBlock || pwhashBlock.length === 0) {
    return linkKeyBytes;
  }
  if (password == null) throw new Error("Password required to decrypt");
  const normalized = normalizePassword(password);
  assertPassword(normalized);
  if (pwhashBlock.length !== sodium.crypto_pwhash_SALTBYTES + 16) {
    throw new Error("Invalid pwhash block");
  }
  const salt = pwhashBlock.slice(0, sodium.crypto_pwhash_SALTBYTES);
  const ops = readU64be(pwhashBlock, sodium.crypto_pwhash_SALTBYTES);
  const mem = readU64be(pwhashBlock, sodium.crypto_pwhash_SALTBYTES + 8);
  if (ops < 1 || ops > sodium.crypto_pwhash_OPSLIMIT_MODERATE
    || mem < 1 || mem > sodium.crypto_pwhash_MEMLIMIT_MODERATE) {
    throw new Error("Invalid password parameters");
  }
  const passwordKey = sodium.crypto_pwhash(32, normalized, salt, ops, mem, sodium.crypto_pwhash_ALG_DEFAULT);
  const rootKey = sodium.crypto_generichash(32, linkKeyBytes, passwordKey);
  sodium.memzero(passwordKey);
  return rootKey;
}
