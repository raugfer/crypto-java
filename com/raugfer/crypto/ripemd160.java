package com.raugfer.crypto;

public class ripemd160 {

    private static int ROL(int x, int n) { return (x << n) ^ (x >>> (32 - n)); }
    private static int F(int x, int y, int z) { return x ^ y ^ z; }
    private static int G(int x, int y, int z) { return (x & y) ^ (~x & z); }
    private static int H(int x, int y, int z) { return (x | ~y) ^ z; }
    private static int I(int x, int y, int z) { return (x & z) ^ (y & ~z); }
    private static int J(int x, int y, int z) { return x ^ (y | ~z); }

    private interface mixfun {
        int mix(int x, int y, int z);
    }

    private static int[] halfround(Object[] p, int[] w, int a, int b, int c, int d, int e) {
        for (int i = 0; i < 5; i++) {
            mixfun f = ((mixfun[]) p[0])[i];
            int k = ((int[]) p[1])[i];
            byte[] o = ((byte[][]) p[2])[i];
            byte[] s = ((byte[][]) p[3])[i];
            for (int j = 0; j < 16; j++) {
                a = ROL(a + f.mix(b, c, d) + w[o[j]] + k, s[j]) + e;
                c = ROL(c, 10);
                int t = e; e = d; d = c; c = b; b = a; a = t;
            }
        }
        return new int[]{ a, b, c, d, e };
    }

    public static byte[] hash(byte[] message) {
        return hash(message, false);
    }

    public static byte[] hash(byte[] message, boolean compressed) {
        if (!compressed) {
            int bytesize = message.length;
            int bitsize = 8 * bytesize;
            int modulo = (bytesize + 1 + 8) % 64;
            int padding = modulo > 0 ? 64 - modulo : 0;
            byte[] b = new byte[bytesize + 1 + padding + 8];
            System.arraycopy(message, 0, b, 0, message.length);
            b[bytesize] = (byte)0x80;
            b[b.length-8] = (byte)((bitsize >> 0) & 0xff);
            b[b.length-7] = (byte)((bitsize >> 8) & 0xff);
            b[b.length-6] = (byte)((bitsize >> 16) & 0xff);
            b[b.length-5] = (byte)((bitsize >> 24) & 0xff);
            message = b;
        }
        assert message.length % 64 == 0;
        int[] ws = new int[message.length/4];
        for (int i = 0; i < message.length; i += 4) {
            ws[i/4] = ((message[i+0] & 0xff) <<  0)
                    | ((message[i+1] & 0xff) <<  8)
                    | ((message[i+2] & 0xff) << 16)
                    | ((message[i+3] & 0xff) << 24);
        }
        int[] s = {
                0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
        };
        Object[] u = {
            new mixfun[]{ ripemd160::F, ripemd160::G, ripemd160::H, ripemd160::I, ripemd160::J },
            new int[]{ 0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e },
            new byte[][]{
                {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
                {7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8},
                {3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12},
                {1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2},
                {4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13},
            },
            new byte[][]{
                {11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8},
                {7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12},
                {11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5},
                {11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12},
                {9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6},
            },
        };
        Object[] v = {
            new mixfun[]{ ripemd160::J, ripemd160::I, ripemd160::H, ripemd160::G, ripemd160::F },
            new int[]{ 0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000 },
            new byte[][]{
                {5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12},
                {6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2},
                {15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13},
                {8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14},
                {12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11},
            },
            new byte[][]{
                {8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6},
                {9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11},
                {9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5},
                {15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8},
                {8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11},
            },
        };
        int s0 = s[0], s1 = s[1], s2 = s[2], s3 = s[3], s4 = s[4];
        for (int j = 0; j < ws.length; j += 16) {
            int[] w = new int[16];
            System.arraycopy(ws, j, w, 0, 16);
            int[] u_a = halfround(u, w, s0, s1, s2, s3, s4);
            int[] v_a = halfround(v, w, s0, s1, s2, s3, s4);
            s0 += u_a[1] + v_a[2];
            s1 += u_a[2] + v_a[3];
            s2 += u_a[3] + v_a[4];
            s3 += u_a[4] + v_a[0];
            s4 += u_a[0] + v_a[1];
            int t0 = s0; s0 = s1; s1 = s2; s2 = s3; s3 = s4; s4 = t0;
        }
        s[0] = s0; s[1] = s1; s[2] = s2; s[3] = s3; s[4] = s4;
        byte[] b = new byte[20];
        for (int i = 0; i < s.length; i++) {
            b[4*i+0] = (byte)((s[i] >>  0) & 0xff);
            b[4*i+1] = (byte)((s[i] >>  8) & 0xff);
            b[4*i+2] = (byte)((s[i] >> 16) & 0xff);
            b[4*i+3] = (byte)((s[i] >> 24) & 0xff);
        }
        return b;
    }

}
