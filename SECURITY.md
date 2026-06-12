# Security

## Threat model

Protects file **content and metadata confidentiality and integrity** against:
the storage/transfer server (honest-but-curious or compromised at rest),
network attackers (on top of TLS), and anyone who obtains ciphertext without
the link. The server is trusted only for *availability*: it cannot read,
substitute, reorder, truncate, extend, or duplicate content undetected
(see `security-properties.test.js` for the executable claims). The full
service-level threat model is published at
https://vitalsend.eu/security/threat-model/.

## Construction

XChaCha20-Poly1305 AEAD per chunk and for metadata; 32-byte random link key;
optional Argon2id-derived password factor; per-purpose BLAKE2b subkeys; keyed
BLAKE2b header MAC verified in constant time before any metadata or content
is used. Chunk index is bound into both nonce and AAD; total chunk count and
plaintext size are authenticated. Argon2 parameters read from the (untrusted
until verified) header are clamped to MODERATE limits before hashing.

## Known limitations

1. **The key travels in the URL fragment.** The `#fragment` is never sent to
   the server by browsers, but the full link (key included) lives in the
   sender's clipboard, chat logs, email, and the recipient's browser history.
   Anyone holding the link can decrypt (subject to the optional password).
   This is the fundamental usability/security trade of link-based E2EE.
   If the sender asks the VitalSend service to email the link to the
   recipient, the server briefly handles the full link (key included) for
   that delivery. Senders who must keep the key fully server-blind should
   share the link through their own channel.
2. **The optional password is not zero-knowledge.** In the VitalSend service
   it is sent (over TLS) to the server, which stores a bcrypt hash and
   counts attempts; exceeding the limit permanently destroys the file.
   The password also feeds the client-side KDF, but the server, never
   holding the link key, cannot decrypt regardless. Treat the password as a
   brute-force gate and second factor, not a server-blind secret.
3. **Generated passwords are ~50 bits** (10 chars from a 32-symbol alphabet).
   Adequate as a second factor behind a server-side lockout; not
   standalone-strength against offline attack if the link also leaks.
4. **Sizes leak.** Ciphertext length reveals plaintext length (±chunk
   padding, which is off by default), and metadata length is visible.
   The server also sees upload/download timing and IP addresses.
5. **No forward secrecy.** One static symmetric key per file. Revocation is
   operational (delete-on-read, expiry), not cryptographic.
6. **You trust the JavaScript the server delivers.** As with all in-browser
   E2EE, a malicious or compromised server, or any party between it and the
   browser such as a TLS-terminating CDN, could ship backdoored crypto JS.
   The mitigation in place today is this published source. Published
   per-release bundle hashes, Subresource Integrity, and reproducible builds
   are planned but not yet implemented; even combined, none of these fully
   eliminates the trust requirement.
7. **Worker key copies are not explicitly zeroed.** Main-thread key material
   is `memzero`'d on successful completion (not on thrown errors); Web Worker copies are freed by termination
   rather than explicit zeroing.
8. **Format is frozen at v3.** Backward compatibility with live links is
   pinned by never-regenerated golden fixtures (`fixtures/`).

## Reporting

Follow the coordinated disclosure policy at
**https://vitalsend.eu/security/disclosure/** (90-day window, safe harbour
for good-faith research): email **security@vitalsend.eu**. Please do not
open public issues for unpatched vulnerabilities; this repository is
explicitly in scope of that policy.
