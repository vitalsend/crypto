# Changelog

All notable changes to vitalsend-crypto. The wire format (v3) is frozen;
see CONTRIBUTING.md. Each release is published as a single squashed commit
tagged `vX.Y.Z`.

## 1.0.1 (2026-06-12)

Documentation only; no code changes.

- SECURITY.md, limitation 6: corrected to claim only the mitigation that
  exists today (this published source). Per-release bundle hashes,
  Subresource Integrity, and reproducible builds are planned, not yet
  implemented. TLS-terminating CDNs named explicitly as part of the
  delivery-trust problem.
- README: the License section now explains the AGPL-3.0 strong-copyleft
  obligations and the commercial alternative.
- README: noted that transfers have been tested up to 1 TB on ordinary
  consumer hardware.

## 1.0.0 (2026-06-11)

Initial public release.

- Extracted from the VitalSend frontend as a standalone package: the exact
  code vitalsend.eu ships to browsers.
- Browser E2EE chunked file encryption: XChaCha20-Poly1305 AEAD via
  libsodium, 32-byte link key shared only in the URL fragment, optional
  Argon2id password factor, per-purpose BLAKE2b subkeys, keyed header MAC.
- Worker-pool parallel encryption, resumable uploads, streaming decrypt.
- Security property test suite (tampering, reordering, truncation,
  extension, duplication, cross-file substitution) and frozen v3 golden
  fixtures pinning backward compatibility.
