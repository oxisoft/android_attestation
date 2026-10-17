# android_attestation

Android hardware key attestation for Flutter, with an offline check for
[GrapheneOS](https://grapheneos.org).

The phone's secure hardware (TEE or StrongBox) signs a certificate describing
the OS it booted: verified boot state, the key that signed the OS, whether the
bootloader is locked, and the security patch level. A rooted or modified OS
cannot forge that signature. This package generates a throwaway key, asks for
that certificate chain, verifies it on the device and gives you the result.

No dependencies, no Google Play services, no network (unless you ask for the
revocation list). Android only; on other platforms every call returns
"unavailable" instead of throwing.

## Use

```dart
import 'package:android_attestation/android_attestation.dart';

// Is this an official GrapheneOS build on a locked device?
final bool graphene = await AndroidAttestation.isGrapheneOS();

// Or read the facts yourself.
final AttestationResult r = await AndroidAttestation.attest();
if (r.isTrustworthy) {
  print(r.verifiedBootState); // verified, selfSigned, unverified, failed
  print(r.deviceLocked);
  print(r.osPatchLevel);      // e.g. 202610
}
```

`attest()` takes about 50 ms to a few seconds depending on the hardware. Run it
once and cache the answer rather than calling it on every screen.

## What is checked

`AttestationResult.isTrustworthy` requires all of:

- every certificate in the chain is signed by the next, the root by itself;
- the root key is one of Google's hardware attestation roots (pinned by
  public key);
- the certificate carries the random challenge of this call (no replay);
- the key lives in the TEE or StrongBox, not in software.

`isGrapheneOS()` adds: verified boot state is *self-signed*, the bootloader is
locked, and the verified boot key is one of the official GrapheneOS keys
bundled in `grapheneOSVerifiedBootKeys`, taken from GrapheneOS's signed
[attestation.json](https://grapheneos.org/attestation.json) (see their
[attestation compatibility guide](https://grapheneos.org/articles/attestation-compatibility-guide)).
GrapheneOS with an unlocked bootloader is deliberately *not* accepted: the
hardware can no longer vouch for what is running.

New devices: pass keys this version does not know yet with
`isGrapheneOS(extraVerifiedBootKeys: {...})`.

## Revocation

Attestation can be faked with leaked device keys. Google publishes the
revoked ones; fetch the list (one HTTPS request) and pass it in:

```dart
final Set<String> revoked = await AndroidAttestation.fetchRevokedSerials();
final bool graphene =
    await AndroidAttestation.isGrapheneOS(revokedSerials: revoked);
```

## Threat model

The check runs inside your app. Someone able to patch your APK can skip it,
the same way they could skip a paywall. That makes it a good fit for things
like unlocking features for GrapheneOS users, and not a server-side security
boundary. For that, send `AttestationResult.certificateChain` to your server
and verify it there.

## Example

`example/` is a small app that attests the device and shows (and copies) a
full report, including the certificate chain.

## License

MIT, by [OxiSoft](https://oxisoft.io). Not affiliated with the GrapheneOS
project.
