## Unreleased

- `tool/check_grapheneos_keys.dart` and a weekly `keys-drift` workflow
  compare the bundled GrapheneOS keys with upstream `attestation.json` and
  open an issue on drift. No change to the package API.

## 0.1.1

- Example app uses `package:material_ui` (Flutter 3.47+ deprecates
  `package:flutter/material.dart`). No change to the package itself.
- Published from GitHub Actions (pub.dev automated publishing).

## 0.1.0

- First release.
- `AndroidAttestation.attest()`: hardware key attestation with a fresh
  challenge; reports chain validity, Google root pinning, security level,
  verified boot state and key, bootloader lock, OS version and patch level,
  certificate serials and the DER chain.
- `AndroidAttestation.isGrapheneOS()`: offline check against the official
  GrapheneOS verified boot keys (attestation.json, timestamp 1776709772).
- `AndroidAttestation.fetchRevokedSerials()`: Google's attestation
  revocation list.
