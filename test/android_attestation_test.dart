import 'package:android_attestation/android_attestation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

const MethodChannel _channel = MethodChannel('android_attestation');

// Pixel 8 on GrapheneOS, as the hardware would report it.
const String _pixel8 =
    'cd7479653aa88208f9f03034810ef9b7b0af8a9d41e2000e458ac403a2acb233';

Map<String, Object?> _report({
  bool chainValid = true,
  bool rootTrusted = true,
  bool challengeMatches = true,
  int level = 1,
  int bootState = 1,
  bool locked = true,
  String? bootKey = _pixel8,
  List<String> serials = const <String>['1', 'abc', 'f00d'],
  String? error,
}) =>
    <String, Object?>{
      'chainValid': chainValid,
      'rootTrusted': rootTrusted,
      'challengeMatches': challengeMatches,
      'attestationSecurityLevel': level,
      'verifiedBootState': bootState,
      'deviceLocked': locked,
      'verifiedBootKey': bootKey,
      'osVersion': 160000,
      'osPatchLevel': 202610,
      'attestationVersion': 300,
      'strongBox': false,
      'certificateSerials': serials,
      'certificateChain': <Uint8List>[
        Uint8List.fromList(<int>[1, 2, 3])
      ],
      if (error != null) 'error': error,
    };

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() => AndroidAttestation.debugIsAndroid = true);
  tearDown(() {
    AndroidAttestation.debugIsAndroid = null;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(_channel, null);
  });

  void answer(Object? Function(MethodCall) f) =>
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(_channel, (MethodCall c) async => f(c));

  group('AttestationResult.isGrapheneOS', () {
    AttestationResult r(Map<String, Object?> m) => AttestationResult.fromMap(m);

    test('accepts a trustworthy GrapheneOS attestation', () {
      expect(r(_report()).isGrapheneOS(), isTrue);
      expect(r(_report(level: 2)).isGrapheneOS(), isTrue);
    });

    test('accepts upper-case boot keys from the platform', () {
      expect(r(_report(bootKey: _pixel8.toUpperCase())).isGrapheneOS(), isTrue);
    });

    test('rejects anything not hardware-backed and fresh', () {
      expect(r(_report(chainValid: false)).isGrapheneOS(), isFalse);
      expect(r(_report(rootTrusted: false)).isGrapheneOS(), isFalse);
      expect(r(_report(challengeMatches: false)).isGrapheneOS(), isFalse);
      expect(r(_report(level: 0)).isGrapheneOS(), isFalse);
      expect(r(_report(error: 'x')).isGrapheneOS(), isFalse);
    });

    test('rejects stock OS, unlocked and failed boot states', () {
      expect(r(_report(bootState: 0)).isGrapheneOS(), isFalse);
      expect(r(_report(bootState: 2)).isGrapheneOS(), isFalse);
      expect(r(_report(bootState: 3)).isGrapheneOS(), isFalse);
      expect(r(_report(locked: false)).isGrapheneOS(), isFalse);
    });

    test('rejects unknown boot keys unless passed as extra', () {
      const String other =
          '0000000000000000000000000000000000000000000000000000000000000001';
      expect(r(_report(bootKey: other)).isGrapheneOS(), isFalse);
      expect(r(_report(bootKey: null)).isGrapheneOS(), isFalse);
      expect(
          r(_report(bootKey: other))
              .isGrapheneOS(extraKeys: <String>[other.toUpperCase()]),
          isTrue);
    });

    test('rejects a chain containing a revoked certificate', () {
      expect(
          r(_report()).isGrapheneOS(revokedSerials: <String>{'abc'}), isFalse);
      expect(
          r(_report()).isGrapheneOS(revokedSerials: <String>{'abd'}), isTrue);
    });
  });

  group('AndroidAttestation', () {
    test('passes preferStrongBox and parses the answer', () async {
      Object? args;
      answer((MethodCall c) {
        args = c.arguments;
        return _report();
      });
      final AttestationResult res =
          await AndroidAttestation.attest(preferStrongBox: true);
      expect(args, <String, Object?>{'preferStrongBox': true});
      expect(res.verifiedBootState, VerifiedBootState.selfSigned);
      expect(res.attestationSecurityLevel, SecurityLevel.trustedEnvironment);
      expect(res.osPatchLevel, 202610);
      expect(res.certificateChain.single, <int>[1, 2, 3]);
      expect(await AndroidAttestation.isGrapheneOS(), isTrue);
    });

    test('platform errors become false, never exceptions', () async {
      answer((MethodCall c) =>
          throw PlatformException(code: 'attestation_failed', message: 'x'));
      final AttestationResult res = await AndroidAttestation.attest();
      expect(res.error, 'x');
      expect(await AndroidAttestation.isGrapheneOS(), isFalse);
    });

    test('off Android nothing is called', () async {
      AndroidAttestation.debugIsAndroid = false;
      bool called = false;
      answer((MethodCall c) {
        called = true;
        return _report();
      });
      expect(await AndroidAttestation.isGrapheneOS(), isFalse);
      expect(called, isFalse);
    });
  });

  test('parseRevocationList reads Google\'s format', () {
    const String json = '{"entries":{"C35747A0":{"status":"REVOKED"},'
        '"6681152659205225093":{"status":"SUSPENDED"}}}';
    expect(AndroidAttestation.parseRevocationList(json),
        <String>{'c35747a0', '6681152659205225093'});
    expect(AndroidAttestation.parseRevocationList('[]'), isEmpty);
  });

  test('bundled GrapheneOS keys are well-formed', () {
    expect(grapheneOSVerifiedBootKeys, isNotEmpty);
    for (final String k in grapheneOSVerifiedBootKeys.keys) {
      expect(k, matches(RegExp(r'^[0-9a-f]{64}$')));
    }
  });
}
