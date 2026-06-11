# Contributing

Thank you for reviewing or improving vitalsend-crypto. Two ground rules:

## 1. Contributor License Agreement (required)

This project is dual-licensed (AGPL-3.0 + commercial). To keep that model
possible, every contribution must grant Jörgen Karlsson the right to
relicense it under the commercial license. By submitting a pull request you
agree to license your contribution under **both** the AGPL-3.0-or-later and
the project's commercial license, and you confirm you have the right to do so
(sign-off per the Developer Certificate of Origin: `git commit -s`).
Contributions without this grant cannot be merged.

## 2. The wire format is frozen

`format.js` defines the v3 format. The constants, KDF context strings, header
layout, and chunk framing must not change since live share links depend on them.
Format changes require a new version (v4) negotiated via the header version
byte, with v3 decrypt support retained. The golden fixtures under `fixtures/`
are never regenerated.

Run the suite with `npm test`. Security findings: follow
https://vitalsend.eu/security/disclosure/ (email security@vitalsend.eu)
rather than opening a public issue.
