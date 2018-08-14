package com.raugfer.crypto;

public class blake2b {

    private static long ROR(long x, int n) { return (x << (64 - n)) ^ (x >>> n); }

    private static long b2n(byte[] b, int i) {
        return ((long) (b[i + 0] & 0xff) << 0)
            | ((long) (b[i + 1] & 0xff) << 8)
            | ((long) (b[i + 2] & 0xff) << 16)
            | ((long) (b[i + 3] & 0xff) << 24)
            | ((long) (b[i + 4] & 0xff) << 32)
            | ((long) (b[i + 5] & 0xff) << 40)
            | ((long) (b[i + 6] & 0xff) << 48)
            | ((long) (b[i + 7] & 0xff) << 56);
    }

    private static void n2b(long n, byte[] b, int i) {
        b[i + 0] = (byte)((n >>  0) & 0xff);
        b[i + 1] = (byte)((n >>  8) & 0xff);
        b[i + 2] = (byte)((n >> 16) & 0xff);
        b[i + 3] = (byte)((n >> 24) & 0xff);
        b[i + 4] = (byte)((n >> 32) & 0xff);
        b[i + 5] = (byte)((n >> 40) & 0xff);
        b[i + 6] = (byte)((n >> 48) & 0xff);
        b[i + 7] = (byte)((n >> 56) & 0xff);
    }

    private static long[] mix(long a, long b, long c, long d, long x, long y) {
        a += b + x;
        d = ROR(d ^ a, 32);
        c += d;
        b = ROR(b ^ c, 24);
        a += b + y;
        d = ROR(d ^ a, 16);
        c += d;
        b = ROR(b ^ c, 63);
        return new long[]{ a, b, c, d };
    }

    public static byte[] hash(byte[] message) {
        return hash(message, new byte[]{ }, new byte[]{ }, new byte[]{ }, 64);
    }

    public static byte[] hash(byte[] message, byte[] key, byte[] salt, byte[] person, int size) {
        assert key.length <= 64;
        assert salt.length <= 16;
        assert person.length <= 16;
        assert size <= 64;
        if (key.length > 0) {
            byte[] b = new byte[128];
            System.arraycopy(key, 0, b, 0, key.length);
            key = b;
            message = bytes.concat(key, message);
        }
        if (salt.length < 16) {
            byte[] b = new byte[16];
            System.arraycopy(salt, 0, b, 0, salt.length);
            salt = b;
        }
        if (person.length < 16) {
            byte[] b = new byte[16];
            System.arraycopy(person, 0, b, 0, person.length);
            person = b;
        }
        int bytesize = message.length;
        int modulo = bytesize % 128;
        int padding = modulo > 0 ? 128 - modulo : 0;
        if (bytesize == 0) padding = 128;
        byte[] b = new byte[bytesize + padding];
        System.arraycopy(message, 0, b, 0, message.length);
        message = b;
        assert message.length % 128 == 0;
        long[] ws = new long[message.length / 8];
        for (int i = 0; i < message.length; i += 8) {
            ws[i / 8] = b2n(message, i);
        }
        long[] IV = {
                0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL,
                0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L,
                0x510e527fade682d1L, 0x9b05688c2b3e6c1fL,
                0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L,
        };
        byte[][] sigma = {
                { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
                { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
                { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
                { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
                { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
                { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
                { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
                { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
                { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
                { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
        };
        long h0 = IV[0], h1 = IV[1], h2 = IV[2], h3 = IV[3], h4 = IV[4], h5 = IV[5], h6 = IV[6], h7 = IV[7];
        h0 ^= 0x01010000 | key.length << 8 | size;
        h4 ^= b2n(salt, 0);
        h5 ^= b2n(salt, 8);
        h6 ^= b2n(person, 0);
        h7 ^= b2n(person, 8);
        int t = 0;
        for (int j = 0; j < ws.length; j += 16) {
            long[] w = new long[16];
            System.arraycopy(ws, j, w, 0, 16);
            boolean last_chunk = bytesize - t <= 128;
            t += last_chunk ? 128 - padding : 128;
            long v0 = h0, v1 = h1, v2 = h2, v3 = h3, v4 = h4, v5 = h5, v6 = h6, v7 = h7;
            long v8 = IV[0], v9 = IV[1], v10 = IV[2], v11 = IV[3], v12 = IV[4], v13 = IV[5], v14 = IV[6], v15 = IV[7];
            v12 ^= t;
            if (last_chunk) v14 ^= 0xffffffffffffffffL;
            for (int r = 0; r < 12; r++) {
                long[] m = new long[16];
                for (int i = 0; i < 16; i++) m[i] = w[sigma[r % 10][i]];
                long[] l;
                l = mix(v0, v4, v8, v12, m[0], m[1]); v0 = l[0]; v4 = l[1]; v8 = l[2]; v12 = l[3];
                l = mix(v1, v5, v9, v13, m[2], m[3]); v1 = l[0]; v5 = l[1]; v9 = l[2]; v13 = l[3];
                l = mix(v2, v6, v10, v14, m[4], m[5]); v2 = l[0]; v6 = l[1]; v10 = l[2]; v14 = l[3];
                l = mix(v3, v7, v11, v15, m[6], m[7]); v3 = l[0]; v7 = l[1]; v11 = l[2]; v15 = l[3];
                l = mix(v0, v5, v10, v15, m[8], m[9]); v0 = l[0]; v5 = l[1]; v10 = l[2]; v15 = l[3];
                l = mix(v1, v6, v11, v12, m[10], m[11]); v1 = l[0]; v6 = l[1]; v11 = l[2]; v12 = l[3];
                l = mix(v2, v7, v8, v13, m[12], m[13]); v2 = l[0]; v7 = l[1]; v8 = l[2]; v13 = l[3];
                l = mix(v3, v4, v9, v14, m[14], m[15]); v3 = l[0]; v4 = l[1]; v9 = l[2]; v14 = l[3];
            }
            h0 ^= v0 ^ v8;
            h1 ^= v1 ^ v9;
            h2 ^= v2 ^ v10;
            h3 ^= v3 ^ v11;
            h4 ^= v4 ^ v12;
            h5 ^= v5 ^ v13;
            h6 ^= v6 ^ v14;
            h7 ^= v7 ^ v15;
        }
        b = new byte[64];
        n2b(h0, b, 0);
        n2b(h1, b, 8);
        n2b(h2, b, 16);
        n2b(h3, b, 24);
        n2b(h4, b, 32);
        n2b(h5, b, 40);
        n2b(h6, b, 48);
        n2b(h7, b, 56);
        return bytes.sub(b, 0, size);
    }

}
