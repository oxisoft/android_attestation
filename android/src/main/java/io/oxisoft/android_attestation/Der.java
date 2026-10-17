package io.oxisoft.android_attestation;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Minimal DER reader: just enough ASN.1 to walk Android's KeyDescription.
 *
 * Kept dependency-free so the plugin adds nothing to the host app's classpath.
 */
final class Der {
    static final int CLASS_UNIVERSAL = 0;
    static final int CLASS_CONTEXT = 2;

    static final int TAG_BOOLEAN = 1;
    static final int TAG_INTEGER = 2;
    static final int TAG_OCTET_STRING = 4;
    static final int TAG_ENUMERATED = 10;
    static final int TAG_SEQUENCE = 16;
    static final int TAG_SET = 17;

    final int tagClass;
    final boolean constructed;
    final int tag;
    final byte[] value;

    private Der(int tagClass, boolean constructed, int tag, byte[] value) {
        this.tagClass = tagClass;
        this.constructed = constructed;
        this.tag = tag;
        this.value = value;
    }

    /** Parses exactly one element that must fill the whole buffer. */
    static Der parse(byte[] data) {
        int[] pos = {0};
        Der d = read(data, pos, data.length);
        if (pos[0] != data.length) {
            throw new IllegalArgumentException("trailing bytes after DER element");
        }
        return d;
    }

    /** Parses a concatenation of elements (the content of a constructed element). */
    static List<Der> parseAll(byte[] data) {
        List<Der> out = new ArrayList<>();
        int[] pos = {0};
        while (pos[0] < data.length) {
            out.add(read(data, pos, data.length));
        }
        return out;
    }

    private static Der read(byte[] b, int[] pos, int end) {
        int p = pos[0];
        int first = u8(b, p++, end);
        int cls = first >>> 6;
        boolean cons = (first & 0x20) != 0;
        int tag = first & 0x1f;
        if (tag == 0x1f) {
            tag = 0;
            int x;
            int guard = 0;
            do {
                x = u8(b, p++, end);
                tag = (tag << 7) | (x & 0x7f);
                if (++guard > 4) throw new IllegalArgumentException("tag too long");
            } while ((x & 0x80) != 0);
        }
        int len = u8(b, p++, end);
        if ((len & 0x80) != 0) {
            int n = len & 0x7f;
            if (n == 0 || n > 4) throw new IllegalArgumentException("unsupported length");
            len = 0;
            for (int i = 0; i < n; i++) {
                len = (len << 8) | u8(b, p++, end);
            }
            if (len < 0) throw new IllegalArgumentException("negative length");
        }
        if (p + len > end || p + len < p) {
            throw new IllegalArgumentException("length beyond buffer");
        }
        byte[] v = new byte[len];
        System.arraycopy(b, p, v, 0, len);
        pos[0] = p + len;
        return new Der(cls, cons, tag, v);
    }

    private static int u8(byte[] b, int i, int end) {
        if (i >= end) throw new IllegalArgumentException("truncated DER");
        return b[i] & 0xff;
    }

    List<Der> children() {
        if (!constructed) return Collections.emptyList();
        return parseAll(value);
    }

    boolean is(int cls, int t) {
        return tagClass == cls && tag == t;
    }

    BigInteger asBigInteger() {
        if (value.length == 0) throw new IllegalArgumentException("empty integer");
        return new BigInteger(value);
    }

    long asLong() {
        return asBigInteger().longValue();
    }

    boolean asBoolean() {
        if (value.length != 1) throw new IllegalArgumentException("bad boolean");
        return value[0] != 0;
    }

    /** For an explicitly tagged [n] element: the single wrapped element. */
    Der explicitInner() {
        List<Der> c = children();
        if (c.size() != 1) throw new IllegalArgumentException("explicit tag without single child");
        return c.get(0);
    }
}
