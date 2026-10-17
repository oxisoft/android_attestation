package io.oxisoft.android_attestation;

import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Verifies an Android key attestation certificate chain and extracts the
 * fields that matter for an OS check. Pure Java (no Android APIs), so it can
 * be unit-tested on the JVM with a recorded chain.
 *
 * Policy (what counts as "GrapheneOS") is decided on the Dart side; this class
 * only reports facts.
 */
final class AttestationVerifier {
    static final String KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17";

    /**
     * SHA-256 of the SubjectPublicKeyInfo of Google's hardware attestation
     * roots, from https://android.googleapis.com/attestation/root.
     * Pinning the key, not the certificate, keeps re-issued root
     * certificates for the same key valid.
     */
    static final Set<String> GOOGLE_ROOT_SPKI_SHA256 = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            // RSA-4096 root, in use since 2016 (re-issued 2019/2022 with the same key)
            "feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae",
            // ECDSA P-384 "Key Attestation CA1" root (2025+ rotation)
            "3ee44512a1af2beb39c889490c60ea3f82e43f5d5a5532f5ab9419f676cd07ec"
    )));

    private static final int TAG_ROOT_OF_TRUST = 704;
    private static final int TAG_OS_VERSION = 705;
    private static final int TAG_OS_PATCH_LEVEL = 706;
    private static final int TAG_VENDOR_PATCH_LEVEL = 718;
    private static final int TAG_BOOT_PATCH_LEVEL = 719;

    private AttestationVerifier() {}

    static Map<String, Object> evaluate(List<X509Certificate> chain, byte[] expectedChallenge) {
        Map<String, Object> out = new HashMap<>();
        out.put("chainLength", chain.size());

        List<String> serials = new ArrayList<>();
        for (X509Certificate c : chain) serials.add(c.getSerialNumber().toString(16));
        out.put("certificateSerials", serials);

        out.put("chainValid", chainSignaturesValid(chain));
        if (!chain.isEmpty()) {
            String rootSpki = hex(sha256(chain.get(chain.size() - 1).getPublicKey().getEncoded()));
            out.put("rootSpkiSha256", rootSpki);
            out.put("rootTrusted", GOOGLE_ROOT_SPKI_SHA256.contains(rootSpki));
        } else {
            out.put("rootTrusted", false);
        }

        byte[] ext = null;
        for (X509Certificate c : chain) {
            ext = c.getExtensionValue(KEY_DESCRIPTION_OID);
            if (ext != null) break;
        }
        if (ext == null) {
            out.put("error", "no key attestation extension in chain");
            return out;
        }
        // getExtensionValue() returns the DER OCTET STRING that wraps the value.
        Der wrapped = Der.parse(ext);
        parseKeyDescription(Der.parse(wrapped.value), expectedChallenge, out);
        return out;
    }

    static void parseKeyDescription(Der keyDescription, byte[] expectedChallenge, Map<String, Object> out) {
        List<Der> f = keyDescription.children();
        if (f.size() < 8) throw new IllegalArgumentException("KeyDescription too short");
        out.put("attestationVersion", f.get(0).asLong());
        out.put("attestationSecurityLevel", f.get(1).asLong());
        out.put("keymasterVersion", f.get(2).asLong());
        out.put("keymasterSecurityLevel", f.get(3).asLong());
        byte[] challenge = f.get(4).value;
        out.put("challengeMatches", expectedChallenge != null
                && MessageDigest.isEqual(challenge, expectedChallenge));

        // Only the hardware-enforced list is trusted; software-enforced values
        // can be written by the OS itself.
        Der hardware = f.get(7);
        for (Der item : hardware.children()) {
            if (item.tagClass != Der.CLASS_CONTEXT) continue;
            switch (item.tag) {
                case TAG_ROOT_OF_TRUST: {
                    List<Der> rot = item.explicitInner().children();
                    out.put("verifiedBootKey", hex(rot.get(0).value));
                    out.put("deviceLocked", rot.get(1).asBoolean());
                    out.put("verifiedBootState", rot.get(2).asLong());
                    if (rot.size() > 3) out.put("verifiedBootHash", hex(rot.get(3).value));
                    break;
                }
                case TAG_OS_VERSION:
                    out.put("osVersion", item.explicitInner().asLong());
                    break;
                case TAG_OS_PATCH_LEVEL:
                    out.put("osPatchLevel", item.explicitInner().asLong());
                    break;
                case TAG_VENDOR_PATCH_LEVEL:
                    out.put("vendorPatchLevel", item.explicitInner().asLong());
                    break;
                case TAG_BOOT_PATCH_LEVEL:
                    out.put("bootPatchLevel", item.explicitInner().asLong());
                    break;
                default:
                    break;
            }
        }
    }

    /** Each certificate must be signed by the next; the last one by itself. */
    static boolean chainSignaturesValid(List<X509Certificate> chain) {
        if (chain.size() < 2) return false;
        try {
            for (int i = 0; i < chain.size(); i++) {
                PublicKey issuer = (i + 1 < chain.size() ? chain.get(i + 1) : chain.get(i)).getPublicKey();
                chain.get(i).verify(issuer);
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }
}
