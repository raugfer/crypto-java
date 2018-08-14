package com.raugfer.crypto;

public class sha512 {

    private static long CH(long x, long y, long z) { return (x & (y ^ z)) ^ z; }
    private static long MAJ(long x, long y, long z) { return (x & y) ^ ((x ^ y) & z); }
    private static long RTR(long x, int y) { return (x >>> y) ^ (x << (64 - y)); }
    private static long EP0(long x) { return RTR(x, 28) ^ RTR(x, 34) ^ RTR(x, 39); }
    private static long EP1(long x) { return RTR(x, 14) ^ RTR(x, 18) ^ RTR(x, 41); }
    private static long SIG0(long x) { return RTR(x, 1) ^ RTR(x, 8) ^ (x >>> 7); }
    private static long SIG1(long x) { return RTR(x, 19) ^ RTR(x, 61) ^ (x >>> 6); }

    public static byte[] hash(byte[] message) {
        return hash(message, false);
    }

    public static byte[] hash(byte[] message, boolean compressed) {
        if (!compressed) {
            int bytesize = message.length;
            long bitsize = 8 * bytesize;
            int modulo = (bytesize + 1 + 16) % 128;
            int padding = modulo > 0 ? 128 - modulo : 0;
            byte[] b = new byte[bytesize + 1 + padding + 16];
            System.arraycopy(message, 0, b, 0, message.length);
            b[bytesize] = (byte)0x80;
            b[b.length-8] = (byte)((bitsize >> 56) & 0xff);
            b[b.length-7] = (byte)((bitsize >> 48) & 0xff);
            b[b.length-6] = (byte)((bitsize >> 40) & 0xff);
            b[b.length-5] = (byte)((bitsize >> 32) & 0xff);
            b[b.length-4] = (byte)((bitsize >> 24) & 0xff);
            b[b.length-3] = (byte)((bitsize >> 16) & 0xff);
            b[b.length-2] = (byte)((bitsize >>  8) & 0xff);
            b[b.length-1] = (byte)((bitsize >>  0) & 0xff);
            message = b;
        }
        assert message.length % 128 == 0;
        long[] ws = new long[message.length/8];
        for (int i = 0; i < message.length; i += 8) {
            ws[i/8] = ((long)(message[i+0] & 0xff) << 56)
                    | ((long)(message[i+1] & 0xff) << 48)
                    | ((long)(message[i+2] & 0xff) << 40)
                    | ((long)(message[i+3] & 0xff) << 32)
                    | ((long)(message[i+4] & 0xff) << 24)
                    | ((long)(message[i+5] & 0xff) << 16)
                    | ((long)(message[i+6] & 0xff) <<  8)
                    | ((long)(message[i+7] & 0xff) <<  0);
        }
        long[] s = {
                0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL, 0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L,
                0x510e527fade682d1L, 0x9b05688c2b3e6c1fL, 0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L,
        };
        long[] k = {
                0x428a2f98d728ae22L, 0x7137449123ef65cdL, 0xb5c0fbcfec4d3b2fL, 0xe9b5dba58189dbbcL,
                0x3956c25bf348b538L, 0x59f111f1b605d019L, 0x923f82a4af194f9bL, 0xab1c5ed5da6d8118L,
                0xd807aa98a3030242L, 0x12835b0145706fbeL, 0x243185be4ee4b28cL, 0x550c7dc3d5ffb4e2L,
                0x72be5d74f27b896fL, 0x80deb1fe3b1696b1L, 0x9bdc06a725c71235L, 0xc19bf174cf692694L,
                0xe49b69c19ef14ad2L, 0xefbe4786384f25e3L, 0x0fc19dc68b8cd5b5L, 0x240ca1cc77ac9c65L,
                0x2de92c6f592b0275L, 0x4a7484aa6ea6e483L, 0x5cb0a9dcbd41fbd4L, 0x76f988da831153b5L,
                0x983e5152ee66dfabL, 0xa831c66d2db43210L, 0xb00327c898fb213fL, 0xbf597fc7beef0ee4L,
                0xc6e00bf33da88fc2L, 0xd5a79147930aa725L, 0x06ca6351e003826fL, 0x142929670a0e6e70L,
                0x27b70a8546d22ffcL, 0x2e1b21385c26c926L, 0x4d2c6dfc5ac42aedL, 0x53380d139d95b3dfL,
                0x650a73548baf63deL, 0x766a0abb3c77b2a8L, 0x81c2c92e47edaee6L, 0x92722c851482353bL,
                0xa2bfe8a14cf10364L, 0xa81a664bbc423001L, 0xc24b8b70d0f89791L, 0xc76c51a30654be30L,
                0xd192e819d6ef5218L, 0xd69906245565a910L, 0xf40e35855771202aL, 0x106aa07032bbd1b8L,
                0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L, 0x2748774cdf8eeb99L, 0x34b0bcb5e19b48a8L,
                0x391c0cb3c5c95a63L, 0x4ed8aa4ae3418acbL, 0x5b9cca4f7763e373L, 0x682e6ff3d6b2b8a3L,
                0x748f82ee5defb2fcL, 0x78a5636f43172f60L, 0x84c87814a1f0ab72L, 0x8cc702081a6439ecL,
                0x90befffa23631e28L, 0xa4506cebde82bde9L, 0xbef9a3f7b2c67915L, 0xc67178f2e372532bL,
                0xca273eceea26619cL, 0xd186b8c721c0c207L, 0xeada7dd6cde0eb1eL, 0xf57d4f7fee6ed178L,
                0x06f067aa72176fbaL, 0x0a637dc5a2c898a6L, 0x113f9804bef90daeL, 0x1b710b35131c471bL,
                0x28db77f523047d84L, 0x32caab7b40c72493L, 0x3c9ebe0a15c9bebcL, 0x431d67c49c100d4cL,
                0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL, 0x5fcb6fab3ad6faecL, 0x6c44198c4a475817L,
        };
        long s0 = s[0], s1 = s[1], s2 = s[2], s3 = s[3], s4 = s[4], s5 = s[5], s6 = s[6], s7 = s[7];
        for (int j = 0; j < ws.length; j += 16) {
            long[] w = new long[80];
            System.arraycopy(ws, j, w, 0, 16);
            for (int i = 16; i < 80; i++) {
                w[i] = w[i-16] + SIG0(w[i-15]) + w[i-7] + SIG1(w[i-2]);
            }
            long a = s0;
            long b = s1;
            long c = s2;
            long d = s3;
            long e = s4;
            long f = s5;
            long g = s6;
            long h = s7;
            for (int i = 0; i < 80; i++) {
                long t1 = h + EP1(e) + CH(e, f, g) + k[i] + w[i];
                long t2 = EP0(a) + MAJ(a, b, c);
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
        byte[] b = new byte[64];
        for (int i = 0; i < s.length; i++) {
            b[8*i+0] = (byte)((s[i] >> 56) & 0xff);
            b[8*i+1] = (byte)((s[i] >> 48) & 0xff);
            b[8*i+2] = (byte)((s[i] >> 40) & 0xff);
            b[8*i+3] = (byte)((s[i] >> 32) & 0xff);
            b[8*i+4] = (byte)((s[i] >> 24) & 0xff);
            b[8*i+5] = (byte)((s[i] >> 16) & 0xff);
            b[8*i+6] = (byte)((s[i] >>  8) & 0xff);
            b[8*i+7] = (byte)((s[i] >>  0) & 0xff);
        }
        return b;
    }

}
