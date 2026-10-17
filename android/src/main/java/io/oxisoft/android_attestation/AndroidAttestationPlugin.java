package io.oxisoft.android_attestation;

import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import io.flutter.embedding.engine.plugins.FlutterPlugin;
import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;

/** Flutter entry point: generates an attested key and reports what the hardware says. */
public class AndroidAttestationPlugin implements FlutterPlugin, MethodChannel.MethodCallHandler {
    private static final String ALIAS = "io.oxisoft.android_attestation.probe";

    private MethodChannel channel;
    private ExecutorService executor;
    private final Handler main = new Handler(Looper.getMainLooper());

    @Override
    public void onAttachedToEngine(FlutterPluginBinding binding) {
        channel = new MethodChannel(binding.getBinaryMessenger(), "android_attestation");
        channel.setMethodCallHandler(this);
        executor = Executors.newSingleThreadExecutor();
    }

    @Override
    public void onDetachedFromEngine(FlutterPluginBinding binding) {
        channel.setMethodCallHandler(null);
        executor.shutdown();
    }

    @Override
    public void onMethodCall(MethodCall call, MethodChannel.Result result) {
        if (!"attest".equals(call.method)) {
            result.notImplemented();
            return;
        }
        Boolean sb = call.argument("preferStrongBox");
        final boolean preferStrongBox = sb == null || sb;
        // Key generation takes from ~50 ms (TEE) to over a second (StrongBox):
        // never on the platform thread.
        executor.execute(() -> {
            try {
                Map<String, Object> r = attest(preferStrongBox);
                main.post(() -> result.success(r));
            } catch (Throwable t) {
                main.post(() -> result.error("attestation_failed", t.toString(), null));
            }
        });
    }

    private static Map<String, Object> attest(boolean preferStrongBox) throws Exception {
        Map<String, Object> out = new HashMap<>();
        out.put("sdkInt", Build.VERSION.SDK_INT);
        byte[] challenge = new byte[32];
        new SecureRandom().nextBytes(challenge);

        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        boolean strongBox = false;
        try {
            if (preferStrongBox && Build.VERSION.SDK_INT >= 28) {
                try {
                    generate(challenge, true);
                    strongBox = true;
                } catch (ProviderException e) {
                    // StrongBoxUnavailableException extends ProviderException.
                    generate(challenge, false);
                }
            } else {
                generate(challenge, false);
            }
            Certificate[] raw = ks.getCertificateChain(ALIAS);
            if (raw == null || raw.length == 0) {
                out.put("error", "keystore returned no certificate chain");
                return out;
            }
            List<X509Certificate> chain = new ArrayList<>();
            List<byte[]> encoded = new ArrayList<>();
            for (Certificate c : raw) {
                chain.add((X509Certificate) c);
                encoded.add(c.getEncoded());
            }
            out.put("certificateChain", encoded);
            out.putAll(AttestationVerifier.evaluate(chain, challenge));
            out.put("strongBox", strongBox);
            return out;
        } finally {
            try {
                ks.deleteEntry(ALIAS);
            } catch (Exception ignored) {
                // Nothing to clean up.
            }
        }
    }

    private static void generate(byte[] challenge, boolean strongBox) throws Exception {
        KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge);
        if (strongBox && Build.VERSION.SDK_INT >= 28) {
            b.setIsStrongBoxBacked(true);
        }
        KeyPairGenerator g = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        g.initialize(b.build());
        g.generateKeyPair();
    }
}
