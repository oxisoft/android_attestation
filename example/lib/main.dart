import 'dart:convert';

import 'package:android_attestation/android_attestation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

void main() => runApp(const ExampleApp());

class ExampleApp extends StatelessWidget {
  const ExampleApp({super.key});

  @override
  Widget build(BuildContext context) => MaterialApp(
    title: 'Attestation',
    theme: ThemeData(colorSchemeSeed: Colors.teal, useMaterial3: true),
    home: const AttestationPage(),
  );
}

class AttestationPage extends StatefulWidget {
  const AttestationPage({super.key});

  @override
  State<AttestationPage> createState() => _AttestationPageState();
}

class _AttestationPageState extends State<AttestationPage> {
  AttestationResult? _result;
  bool _busy = false;
  bool _strongBox = false;
  Duration? _took;

  Future<void> _run() async {
    setState(() => _busy = true);
    final Stopwatch sw = Stopwatch()..start();
    final AttestationResult r = await AndroidAttestation.attest(
      preferStrongBox: _strongBox,
    );
    sw.stop();
    debugPrint('attestation: $r');
    debugPrint('attestation chain: ${_chainBase64(r).join(',')}');
    setState(() {
      _result = r;
      _took = sw.elapsed;
      _busy = false;
    });
  }

  List<String> _chainBase64(AttestationResult r) =>
      r.certificateChain.map(base64Encode).toList();

  String _report(AttestationResult r) =>
      const JsonEncoder.withIndent('  ').convert(<String, Object?>{
        'isGrapheneOS': r.isGrapheneOS(),
        'isTrustworthy': r.isTrustworthy,
        'chainValid': r.chainValid,
        'rootTrusted': r.rootTrusted,
        'challengeMatches': r.challengeMatches,
        'securityLevel': r.attestationSecurityLevel.name,
        'strongBox': r.strongBox,
        'verifiedBootState': r.verifiedBootState.name,
        'deviceLocked': r.deviceLocked,
        'verifiedBootKey': r.verifiedBootKey,
        'device': grapheneOSVerifiedBootKeys[r.verifiedBootKey],
        'osVersion': r.osVersion,
        'osPatchLevel': r.osPatchLevel,
        'attestationVersion': r.attestationVersion,
        'error': r.error,
        'chain': _chainBase64(r),
      });

  @override
  Widget build(BuildContext context) {
    final AttestationResult? r = _result;
    return Scaffold(
      appBar: AppBar(title: const Text('Android attestation')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: <Widget>[
          SwitchListTile(
            title: const Text('Prefer StrongBox'),
            value: _strongBox,
            onChanged: (bool v) => setState(() => _strongBox = v),
          ),
          FilledButton(
            onPressed: _busy ? null : _run,
            child: Text(_busy ? 'Attesting...' : 'Attest this device'),
          ),
          if (r != null) ...<Widget>[
            const SizedBox(height: 24),
            Text(
              r.isGrapheneOS() ? 'GrapheneOS: YES' : 'GrapheneOS: no',
              key: const Key('verdict'),
              style: Theme.of(context).textTheme.headlineMedium,
            ),
            Text('Took ${_took?.inMilliseconds} ms'),
            const SizedBox(height: 12),
            SelectableText(
              _report(r),
              style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
            ),
            const SizedBox(height: 12),
            OutlinedButton(
              onPressed: () =>
                  Clipboard.setData(ClipboardData(text: _report(r))),
              child: const Text('Copy report'),
            ),
          ],
        ],
      ),
    );
  }
}
