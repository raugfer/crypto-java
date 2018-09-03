package com.raugfer.crypto;

public class blake1s {

    private static int ROR(int x, int n) { return (x << (32 - n)) ^ (x >>> n); }

    private static int b2n(byte[] b, int i) {
        return (((int) b[i + 0] & 0xff) << 24)
             | (((int) b[i + 1] & 0xff) << 16)
             | (((int) b[i + 2] & 0xff) <<  8)
             | (((int) b[i + 3] & 0xff) <<  0);
    }

    private static void n2b(int n, byte[] b, int i) {
        b[i + 0] = (byte)((n >> 24) & 0xff);
        b[i + 1] = (byte)((n >> 16) & 0xff);
        b[i + 2] = (byte)((n >>  8) & 0xff);
        b[i + 3] = (byte)((n >>  0) & 0xff);
    }

    private static int[] mix(int a, int b, int c, int d, int x, int y) {
        a += b + x;
        d = ROR(d ^ a, 16);
        c += d;
        b = ROR(b ^ c, 12);
        a += b + y;
        d = ROR(d ^ a, 8);
        c += d;
        b = ROR(b ^ c, 7);
        return new int[]{ a, b, c, d };
    }

    public static byte[] hash(byte[] message) {
        return hash(message, new byte[]{ }, 32);
    }

    public static byte[] hash(byte[] message, byte[] key, int size) {
        assert size == 28 || size == 32;
        if (key.length >= 16) {
            byte[] b = new byte[16];
            System.arraycopy(key, key.length - b.length, b, 0, b.length);
            key = b;
        } else {
            byte[] b = new byte[16];
            System.arraycopy(key, 0, b, b.length - key.length, key.length);
            key = b;
        }
        int salt0 = b2n(key, 0);
        int salt1 = b2n(key, 4);
        int salt2 = b2n(key, 8);
        int salt3 = b2n(key, 12);
        int bytesize = message.length;
        long bitsize = 8 * bytesize;
        int modulo = (bytesize + 1 + 8) % 64;
        int padding = modulo > 0 ? 64 - modulo : 0;
        byte[] b = new byte[message.length + padding + 1 + 8];
        System.arraycopy(message, 0, b, 0, message.length);
        b[message.length] = (byte) 0x80;
        if (size == 32) b[message.length + padding] |= (byte) 0x01;
        n2b((int) (bitsize >> 32), b, message.length + padding + 1);
        n2b((int) (bitsize >> 0), b, message.length + padding + 5);
        message = b;
        assert message.length % 64 == 0;
        int[] ws = new int[message.length / 4];
        for (int i = 0; i < message.length; i += 4) {
            ws[i / 4] = b2n(message, i);
        }
        int[] IV = {
                0xc1059ed8, 0x367cd507,
                0x3070dd17, 0xf70e5939,
                0xffc00b31, 0x68581511,
                0x64f98fa7, 0xbefa4fa4,
        };
        if (size == 32) {
            IV = new int[]{
                    0x6a09e667, 0xbb67ae85,
                    0x3c6ef372, 0xa54ff53a,
                    0x510e527f, 0x9b05688c,
                    0x1f83d9ab, 0x5be0cd19,
            };
        }
        int[] C = {
                0x243f6a88, 0x85a308d3,
                0x13198a2e, 0x03707344,
                0xa4093822, 0x299f31d0,
                0x082efa98, 0xec4e6c89,
                0x452821e6, 0x38d01377,
                0xbe5466cf, 0x34e90c6c,
                0xc0ac29b7, 0xc97c50dd,
                0x3f84d5b5, 0xb5470917,
        };
        byte[][] sigma = {
                {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
                {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
                {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
                {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
                {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
                {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
                {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
                {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
                {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
                {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
        };
        int h0 = IV[0], h1 = IV[1], h2 = IV[2], h3 = IV[3], h4 = IV[4], h5 = IV[5], h6 = IV[6], h7 = IV[7];
        long t = 0;
        for (int j = 0; j < ws.length; j += 16) {
            int[] w = new int[16];
            System.arraycopy(ws, j, w, 0, 16);
            long last_t = t;
            t += 512;
            if (t > bitsize) t = bitsize;
            int v0 = h0, v1 = h1, v2 = h2, v3 = h3, v4 = h4, v5 = h5, v6 = h6, v7 = h7;
            int v8 = C[0], v9 = C[1], v10 = C[2], v11 = C[3], v12 = C[4], v13 = C[5], v14 = C[6], v15 = C[7];
            v8 ^= salt0;
            v9 ^= salt1;
            v10 ^= salt2;
            v11 ^= salt3;
            if (last_t < t) {
                v12 ^= (int) t;
                v13 ^= (int) t;
                v14 ^= (int) (t >> 32);
                v15 ^= (int) (t >> 32);
            }
            for (int r = 0; r < 14; r++) {
                int[] m = new int[16];
                for (int i = 0; i < 16; i++) m[i] = w[sigma[r % 10][i]];
                int[] k = new int[16];
                for (int i = 0; i < 16; i++) k[i] = C[sigma[r % 10][i]];
                int[] l;
                l = mix(v0, v4, v8, v12, m[0] ^ k[1], m[1] ^ k[0]); v0 = l[0]; v4 = l[1]; v8 = l[2]; v12 = l[3];
                l = mix(v1, v5, v9, v13, m[2] ^ k[3], m[3] ^ k[2]); v1 = l[0]; v5 = l[1]; v9 = l[2]; v13 = l[3];
                l = mix(v2, v6, v10, v14, m[4] ^ k[5], m[5] ^ k[4]); v2 = l[0]; v6 = l[1]; v10 = l[2]; v14 = l[3];
                l = mix(v3, v7, v11, v15, m[6] ^ k[7], m[7] ^ k[6]); v3 = l[0]; v7 = l[1]; v11 = l[2]; v15 = l[3];
                l = mix(v0, v5, v10, v15, m[8] ^ k[9], m[9] ^ k[8]); v0 = l[0]; v5 = l[1]; v10 = l[2]; v15 = l[3];
                l = mix(v1, v6, v11, v12, m[10] ^ k[11], m[11] ^ k[10]); v1 = l[0]; v6 = l[1]; v11 = l[2]; v12 = l[3];
                l = mix(v2, v7, v8, v13, m[12] ^ k[13], m[13] ^ k[12]); v2 = l[0]; v7 = l[1]; v8 = l[2]; v13 = l[3];
                l = mix(v3, v4, v9, v14, m[14] ^ k[15], m[15] ^ k[14]); v3 = l[0]; v4 = l[1]; v9 = l[2]; v14 = l[3];
            }
            h0 ^= v0 ^ v8 ^ salt0;
            h1 ^= v1 ^ v9 ^ salt1;
            h2 ^= v2 ^ v10 ^ salt2;
            h3 ^= v3 ^ v11 ^ salt3;
            h4 ^= v4 ^ v12 ^ salt0;
            h5 ^= v5 ^ v13 ^ salt1;
            h6 ^= v6 ^ v14 ^ salt2;
            h7 ^= v7 ^ v15 ^ salt3;
        }
        byte[] digest = new byte[32];
        n2b(h0, digest, 0);
        n2b(h1, digest, 4);
        n2b(h2, digest, 8);
        n2b(h3, digest, 12);
        n2b(h4, digest, 16);
        n2b(h5, digest, 20);
        n2b(h6, digest, 24);
        n2b(h7, digest, 28);
        return bytes.sub(digest, 0, size);
    }

}
