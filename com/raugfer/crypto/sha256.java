package com.raugfer.crypto;

public class sha256 {

    private static int CH(int x, int y, int z) { return (x & (y ^ z)) ^ z; }
    private static int MAJ(int x, int y, int z) { return (x & y) ^ ((x ^ y) & z); }
    private static int RTR(int x, int y) { return (x >>> y) ^ (x << (32 - y)); }
    private static int EP0(int x) { return RTR(x, 2) ^ RTR(x, 13) ^ RTR(x, 22); }
    private static int EP1(int x) { return RTR(x, 6) ^ RTR(x, 11) ^ RTR(x, 25); }
    private static int SIG0(int x) { return RTR(x, 7) ^ RTR(x, 18) ^ (x >>> 3); }
    private static int SIG1(int x) { return RTR(x, 17) ^ RTR(x, 19) ^ (x >>> 10); }

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
            b[b.length-4] = (byte)((bitsize >> 24) & 0xff);
            b[b.length-3] = (byte)((bitsize >> 16) & 0xff);
            b[b.length-2] = (byte)((bitsize >>  8) & 0xff);
            b[b.length-1] = (byte)((bitsize >>  0) & 0xff);
            message = b;
        }
        assert message.length % 64 == 0;
        int[] ws = new int[message.length/4];
        for (int i = 0; i < message.length; i += 4) {
            ws[i/4] = ((message[i+0] & 0xff) << 24)
                    | ((message[i+1] & 0xff) << 16)
                    | ((message[i+2] & 0xff) <<  8)
                    | ((message[i+3] & 0xff) <<  0);
        }
        int[] s = {
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        };
        int[] k = {
                0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
                0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
                0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
                0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
                0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
                0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
                0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
                0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
                0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
        };
        int s0 = s[0], s1 = s[1], s2 = s[2], s3 = s[3], s4 = s[4], s5 = s[5], s6 = s[6], s7 = s[7];
        for (int j = 0; j < ws.length; j += 16) {
            int[] w = new int[64];
            System.arraycopy(ws, j, w, 0, 16);
            for (int i = 16; i < 64; i++) {
                w[i] = w[i-16] + SIG0(w[i-15]) + w[i-7] + SIG1(w[i-2]);
            }
            int a = s0;
            int b = s1;
            int c = s2;
            int d = s3;
            int e = s4;
            int f = s5;
            int g = s6;
            int h = s7;
            for (int i = 0; i < 64; i++) {
                int t1 = h + EP1(e) + CH(e, f, g) + k[i] + w[i];
                int t2 = EP0(a) + MAJ(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + t1;
                d = c;
                c = b;
                b = a;
                a = t1 + t2;
            }
            s0 += a;
            s1 += b;
            s2 += c;
            s3 += d;
            s4 += e;
            s5 += f;
            s6 += g;
            s7 += h;
        }
        s[0] = s0; s[1] = s1; s[2] = s2; s[3] = s3; s[4] = s4; s[5] = s5; s[6] = s6; s[7] = s7;
        byte[] b = new byte[32];
        for (int i = 0; i < s.length; i++) {
            b[4*i+0] = (byte)((s[i] >> 24) & 0xff);
            b[4*i+1] = (byte)((s[i] >> 16) & 0xff);
            b[4*i+2] = (byte)((s[i] >>  8) & 0xff);
            b[4*i+3] = (byte)((s[i] >>  0) & 0xff);
        }
        return b;
    }

}
