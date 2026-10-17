/// Android hardware key attestation for Flutter, with a GrapheneOS check.
///
/// The device's secure hardware (TEE or StrongBox) signs a certificate that
/// describes the OS it booted: its verified boot state, the key that signed
/// it, whether the bootloader is locked, and its patch level. A rooted OS
/// cannot forge that signature. See [AndroidAttestation].
library;

import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'src/grapheneos_keys.dart';

export 'src/grapheneos_keys.dart';

/// Where the attested key lives.
enum SecurityLevel {
  /// Software keystore: the attestation proves nothing.
  software,

  /// Trusted Execution Environment.
  trustedEnvironment,

  /// Dedicated secure element (StrongBox).
  strongBox,

  /// A value this package does not know.
  unknown,
}

/// The device's verified boot state, as reported by the secure hardware.
enum VerifiedBootState {
  /// Locked bootloader, OS signed by the device maker's key (stock OS).
  verified,

  /// Locked bootloader, OS signed by a user-installed key (e.g. GrapheneOS).
  selfSigned,

  /// Unlocked bootloader: any OS, no verification.
  unverified,

  /// Verification failed.
  failed,

  /// Not reported, or a value this package does not know.
  unknown,
}

/// Facts read from one attestation. Nothing here is a verdict on its own;
/// check [isTrustworthy] before relying on any OS field.
@immutable
class AttestationResult {
  /// Creates a result; normally built by [AndroidAttestation.attest].
  const AttestationResult({
    required this.chainValid,
    required this.rootTrusted,
    required this.challengeMatches,
    required this.attestationSecurityLevel,
    required this.verifiedBootState,
    this.verifiedBootKey,
    this.deviceLocked = false,
    this.osVersion,
    this.osPatchLevel,
    this.attestationVersion,
    this.strongBox = false,
    this.certificateSerials = const <String>[],
    this.certificateChain = const <Uint8List>[],
    this.error,
  });

  /// Builds a result from the platform channel map.
  factory AttestationResult.fromMap(Map<Object?, Object?> m) {
    int? asInt(Object? v) => v is int ? v : null;
    return AttestationResult(
      chainValid: m['chainValid'] == true,
      rootTrusted: m['rootTrusted'] == true,
      challengeMatches: m['challengeMatches'] == true,
      attestationSecurityLevel:
          _securityLevel(asInt(m['attestationSecurityLevel'])),
      verifiedBootState: _bootState(asInt(m['verifiedBootState'])),
      verifiedBootKey: (m['verifiedBootKey'] as String?)?.toLowerCase(),
      deviceLocked: m['deviceLocked'] == true,
      osVersion: asInt(m['osVersion']),
      osPatchLevel: asInt(m['osPatchLevel']),
      attestationVersion: asInt(m['attestationVersion']),
      strongBox: m['strongBox'] == true,
      certificateSerials:
          (m['certificateSerials'] as List<Object?>? ?? const <Object?>[])
              .whereType<String>()
              .map((String s) => s.toLowerCase())
              .toList(growable: false),
      certificateChain:
          (m['certificateChain'] as List<Object?>? ?? const <Object?>[])
              .whereType<Uint8List>()
              .toList(growable: false),
      error: m['error'] as String?,
    );
  }

  /// A result for platforms or failures where nothing could be attested.
  const AttestationResult.unavailable(String this.error)
      : chainValid = false,
        rootTrusted = false,
        challengeMatches = false,
        attestationSecurityLevel = SecurityLevel.unknown,
        verifiedBootState = VerifiedBootState.unknown,
        verifiedBootKey = null,
        deviceLocked = false,
        osVersion = null,
        osPatchLevel = null,
        attestationVersion = null,
        strongBox = false,
        certificateSerials = const <String>[],
        certificateChain = const <Uint8List>[];

  /// Every certificate is signed by the next one, the root by itself.
  final bool chainValid;

  /// The chain ends in one of Google's hardware attestation root keys.
  final bool rootTrusted;

  /// The certificate carries the fresh random challenge of this call, so it
  /// was not replayed from another device or an earlier run.
  final bool challengeMatches;

  /// Where the attestation was produced.
  final SecurityLevel attestationSecurityLevel;

  /// Boot state from the hardware-enforced root of trust.
  final VerifiedBootState verifiedBootState;

  /// Lower-case hex fingerprint of the key that signed the booted OS.
  final String? verifiedBootKey;

  /// Whether the bootloader is locked.
  final bool deviceLocked;

  /// OS version, e.g. 160000 for Android 16.
  final int? osVersion;

  /// OS security patch level as YYYYMM, e.g. 202610.
  final int? osPatchLevel;

  /// Attestation format version (KeyMint 100+ / Keymaster 1-4).
  final int? attestationVersion;

  /// The key was generated in StrongBox rather than the TEE.
  final bool strongBox;

  /// Lower-case hex serial numbers of the chain, leaf first, for checking
  /// against Google's revocation list
  /// ([AndroidAttestation.fetchRevokedSerials]).
  final List<String> certificateSerials;

  /// The DER-encoded certificate chain, leaf first. Send it to a server to
  /// verify the attestation where the app cannot interfere.
  final List<Uint8List> certificateChain;

  /// Why attestation failed or was incomplete, if it did.
  final String? error;

  /// Hardware-backed, fresh, and signed up to a Google attestation root.
  bool get isTrustworthy =>
      error == null &&
      chainValid &&
      rootTrusted &&
      challengeMatches &&
      (attestationSecurityLevel == SecurityLevel.trustedEnvironment ||
          attestationSecurityLevel == SecurityLevel.strongBox);

  /// Whether this result proves an official GrapheneOS build on a locked
  /// device. [extraKeys] adds verified boot keys not yet in
  /// [grapheneOSVerifiedBootKeys]; [revokedSerials] rejects chains that
  /// contain a revoked certificate.
  bool isGrapheneOS({
    Iterable<String> extraKeys = const <String>[],
    Set<String> revokedSerials = const <String>{},
  }) {
    if (!isTrustworthy) return false;
    if (verifiedBootState != VerifiedBootState.selfSigned) return false;
    if (!deviceLocked) return false;
    final String? key = verifiedBootKey;
    if (key == null) return false;
    if (certificateSerials.any(revokedSerials.contains)) return false;
    return grapheneOSVerifiedBootKeys.containsKey(key) ||
        extraKeys.map((String k) => k.toLowerCase()).contains(key);
  }

  @override
  String toString() => 'AttestationResult(trustworthy: $isTrustworthy, '
      'chainValid: $chainValid, rootTrusted: $rootTrusted, '
      'challengeMatches: $challengeMatches, '
      'level: ${attestationSecurityLevel.name}, '
      'boot: ${verifiedBootState.name}, locked: $deviceLocked, '
      'bootKey: $verifiedBootKey, patch: $osPatchLevel, error: $error)';

  static SecurityLevel _securityLevel(int? v) => switch (v) {
        0 => SecurityLevel.software,
        1 => SecurityLevel.trustedEnvironment,
        2 => SecurityLevel.strongBox,
        _ => SecurityLevel.unknown,
      };

  static VerifiedBootState _bootState(int? v) => switch (v) {
        0 => VerifiedBootState.verified,
        1 => VerifiedBootState.selfSigned,
        2 => VerifiedBootState.unverified,
        3 => VerifiedBootState.failed,
        _ => VerifiedBootState.unknown,
      };
}

/// Entry point. All methods are safe to call on any platform: off Android
/// they report "unavailable" instead of throwing.
abstract final class AndroidAttestation {
  static const MethodChannel _channel = MethodChannel('android_attestation');

  /// Overrides platform detection in tests.
  @visibleForTesting
  static bool? debugIsAndroid;

  static bool get _isAndroid =>
      debugIsAndroid ??
      (!kIsWeb && defaultTargetPlatform == TargetPlatform.android);

  /// Generates a throwaway hardware key with a fresh challenge and returns
  /// what its attestation certificate says. Takes 50 ms to a few seconds
  /// (StrongBox is slower than the TEE); the key is deleted afterwards.
  static Future<AttestationResult> attest(
      {bool preferStrongBox = false}) async {
    if (!_isAndroid) {
      return const AttestationResult.unavailable('not Android');
    }
    try {
      final Map<Object?, Object?>? m = await _channel
          .invokeMapMethod<Object?, Object?>(
              'attest', <String, Object?>{'preferStrongBox': preferStrongBox});
      if (m == null) {
        return const AttestationResult.unavailable('no result');
      }
      return AttestationResult.fromMap(m);
    } on PlatformException catch (e) {
      return AttestationResult.unavailable(e.message ?? e.code);
    } on MissingPluginException {
      return const AttestationResult.unavailable('plugin not registered');
    }
  }

  /// True only when the secure hardware attests an official GrapheneOS
  /// build on a locked bootloader. Never throws; any failure is `false`.
  ///
  /// The check runs on the device. Anyone able to patch the app could skip
  /// it, so it suits convenience features (e.g. a free upgrade), not a
  /// server-side security boundary; for that, verify the chain on a server.
  static Future<bool> isGrapheneOS({
    Iterable<String> extraVerifiedBootKeys = const <String>[],
    Set<String> revokedSerials = const <String>{},
  }) async {
    final AttestationResult r = await attest();
    return r.isGrapheneOS(
        extraKeys: extraVerifiedBootKeys, revokedSerials: revokedSerials);
  }

  /// Google's attestation revocation list: lower-case hex serials of
  /// revoked or suspended attestation certificates. Leaked device keys are
  /// how attestation gets faked, so long-lived decisions should check it.
  ///
  /// Makes one HTTPS request to android.googleapis.com. Throws on network
  /// errors; callers decide whether to fail open or closed.
  static Future<Set<String>> fetchRevokedSerials({
    Uri? url,
    Duration timeout = const Duration(seconds: 15),
  }) async {
    final HttpClient client = HttpClient()..connectionTimeout = timeout;
    try {
      final HttpClientRequest req = await client
          .getUrl(url ??
              Uri.parse('https://android.googleapis.com/attestation/status'))
          .timeout(timeout);
      final HttpClientResponse res = await req.close().timeout(timeout);
      if (res.statusCode != 200) {
        throw HttpException('status ${res.statusCode}');
      }
      final String body =
          await res.transform(utf8.decoder).join().timeout(timeout);
      return parseRevocationList(body);
    } finally {
      client.close(force: true);
    }
  }

  /// Parses the JSON served by Google's revocation endpoint.
  static Set<String> parseRevocationList(String json) {
    final Object? decoded = jsonDecode(json);
    if (decoded is! Map<String, Object?>) return <String>{};
    final Object? entries = decoded['entries'];
    if (entries is! Map<String, Object?>) return <String>{};
    return entries.keys.map((String k) => k.toLowerCase()).toSet();
  }
}
