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
