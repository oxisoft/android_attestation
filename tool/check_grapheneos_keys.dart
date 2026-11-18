// Compares the GrapheneOS verified boot keys bundled in
// lib/src/grapheneos_keys.dart with the list GrapheneOS publishes.
//
// Usage:
//   dart run tool/check_grapheneos_keys.dart [--keys-file <path>]
//       [--upstream <url or file>] [--report <markdown file>]
//
// Exit codes: 0 = in sync, 1 = drift (diff printed and written to --report),
// 2 = error (download or parse failure).
//
// Only plain dart:io, so it runs with the Dart SDK alone (no Flutter).
import 'dart:convert';
import 'dart:io';

const String _defaultUpstream = 'https://grapheneos.org/attestation.json';
const String _defaultKeysFile = 'lib/src/grapheneos_keys.dart';

Future<void> main(List<String> args) async {
  String keysFile = _defaultKeysFile;
  String upstream = _defaultUpstream;
  String? report;
  for (int i = 0; i < args.length; i++) {
    final String arg = args[i];
    if (i + 1 >= args.length) {
      _fail('missing value for $arg');
    }
    switch (arg) {
      case '--keys-file':
        keysFile = args[++i];
      case '--upstream':
        upstream = args[++i];
      case '--report':
        report = args[++i];
      default:
        _fail('unknown argument $arg');
    }
  }

  final String source = await File(keysFile).readAsString();
  final Map<String, String> bundled = <String, String>{
    for (final RegExpMatch m in RegExp(
      r"'([0-9a-f]{64})':\s*'([^']*)'",
    ).allMatches(source))
      m.group(1)!: m.group(2)!,
  };
  final RegExpMatch? tsMatch = RegExp(
    r'grapheneOSVerifiedBootKeysTimestamp\s*=\s*(\d+)',
  ).firstMatch(source);
  if (bundled.isEmpty || tsMatch == null) {
    _fail('could not parse keys or timestamp from $keysFile');
  }
  final int bundledTs = int.parse(tsMatch.group(1)!);

  final Map<String, dynamic> json;
  try {
    json = jsonDecode(await _read(upstream)) as Map<String, dynamic>;
  } on Object catch (e) {
    _fail('could not read $upstream: $e');
  }
  final Set<String> upstreamKeys = <String>{
    for (final dynamic k in json['verifiedBootKeys'] as List<dynamic>)
      (k as String).toLowerCase(),
  };
  final int upstreamTs = json['timestamp'] as int;

  final List<String> added = upstreamKeys
      .where((String k) => !bundled.containsKey(k))
      .toList()
    ..sort();
  final List<String> removed = bundled.keys
      .where((String k) => !upstreamKeys.contains(k))
      .toList()
    ..sort();

  if (added.isEmpty && removed.isEmpty && upstreamTs == bundledTs) {
    stdout.writeln(
      'In sync: ${bundled.length} keys, timestamp $bundledTs ($upstream).',
    );
    return;
  }

  final StringBuffer out = StringBuffer()
    ..writeln('GrapheneOS verified boot keys differ from the bundled list.')
    ..writeln()
    ..writeln('- Upstream: $upstream')
    ..writeln(
      '- Timestamp: bundled `$bundledTs` '
      '(${_date(bundledTs)}), upstream `$upstreamTs` (${_date(upstreamTs)})',
    )
    ..writeln(
        '- Keys: bundled ${bundled.length}, upstream ${upstreamKeys.length}')
    ..writeln();
  if (added.isNotEmpty) {
    out.writeln('New upstream keys (missing from the package):');
    for (final String k in added) {
      out.writeln('- `$k`');
    }
    out.writeln();
  }
  if (removed.isNotEmpty) {
    out.writeln('Bundled keys no longer listed upstream:');
    for (final String k in removed) {
      out.writeln('- `$k` (${bundled[k]})');
    }
    out.writeln();
  }
  out.writeln(
    'Refresh: verify the signature of attestation.json '
    '(see the README section "GrapheneOS keys"), update '
    '`lib/src/grapheneos_keys.dart` (keys, device names, timestamp), add a '
    'CHANGELOG entry and release a patch version.',
  );
  stdout.write(out);
  if (report != null) {
    await File(report).writeAsString(out.toString());
  }
  exit(1);
}

Future<String> _read(String location) async {
  if (!location.startsWith('http://') && !location.startsWith('https://')) {
    return File(location).readAsString();
  }
  final HttpClient client = HttpClient()
    ..connectionTimeout = const Duration(seconds: 30);
  try {
    final HttpClientRequest request = await client.getUrl(Uri.parse(location));
    final HttpClientResponse response = await request.close();
    if (response.statusCode != 200) {
      throw HttpException('HTTP ${response.statusCode}');
    }
    return await response.transform(utf8.decoder).join();
  } finally {
    client.close();
  }
}

String _date(int ts) => DateTime.fromMillisecondsSinceEpoch(
      ts * 1000,
      isUtc: true,
    ).toIso8601String().substring(0, 10);

Never _fail(String message) {
  stderr.writeln('error: $message');
  exit(2);
}
