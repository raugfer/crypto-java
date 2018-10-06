package com.raugfer.crypto;

public class sha3_256 {

    private static long ROT(long x, int y) { return (x >>> (64 - y)) | (x << y); }

    public static byte[] hash(byte[] message) {
        return hash(message, false);
    }

    public static byte[] hash(byte[] message, boolean compressed) {
        if (!compressed) {
            int bytesize = message.length;
            int bitsize = 8 * bytesize;
            int padding = (1088 - bitsize % 1088) / 8;
            byte[] b = new byte[bytesize + 1 + (padding - 2) + 1];
            System.arraycopy(message, 0, b, 0, message.length);
            b[bytesize] |= (byte)0x06;
            b[b.length-1] |= (byte)0x80;
            message = b;
        }
        assert message.length % 136 == 0;
        long[] ws = new long[message.length/8];
        for (int i = 0; i < message.length; i += 8) {
            ws[i/8] = ((long)(message[i+0] & 0xff) <<  0)
                    | ((long)(message[i+1] & 0xff) <<  8)
                    | ((long)(message[i+2] & 0xff) << 16)
                    | ((long)(message[i+3] & 0xff) << 24)
                    | ((long)(message[i+4] & 0xff) << 32)
                    | ((long)(message[i+5] & 0xff) << 40)
                    | ((long)(message[i+6] & 0xff) << 48)
                    | ((long)(message[i+7] & 0xff) << 56);
        }
        long[][] s = new long[5][5];
        long[] RC = {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
            0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
            0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
            0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
            0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
            0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
            0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L,
        };
        byte[][] R = {
            { 0, 36,  3, 41, 18},
            { 1, 44, 10, 45,  2},
            {62,  6, 43, 15, 61},
            {28, 55, 25, 21, 56},
            {27, 20, 39,  8, 14},
        };
        for (int j = 0; j < ws.length; j += 17) {
            long[] w = new long[25];
            System.arraycopy(ws, j, w, 0, 17);
            for (int y = 0; y < 5; y++)
                for (int x = 0; x < 5; x++)
                    s[x][y] ^= w[5 * y + x];
            for (int i = 0; i < 24; i++) {
                long[] C = new long[5];
                for (int x = 0; x < 5; x++)
                    C[x] = s[x][0] ^ s[x][1] ^ s[x][2] ^ s[x][3] ^ s[x][4];
                long[] D = new long[5];
                for (int x = 0; x < 5; x++)
                    D[x] = C[(x+4) % 5] ^ ROT(C[(x+1) % 5], 1);
                for (int x = 0; x < 5; x++)
                    for (int y = 0; y < 5; y++)
                        s[x][y] ^= D[x];
                long[][] B = new long[5][5];
                for (int x = 0; x < 5; x++)
                    for (int y = 0; y < 5; y++) {
                        B[y][(2 * x + 3 * y) % 5] = ROT(s[x][y], R[x][y]);
                    }
                for (int x = 0; x < 5; x++)
                    for (int y = 0; y < 5; y++)
                        s[x][y] = B[x][y] ^ ((~B[(x+1) % 5][y]) & B[(x+2) % 5][y]);
                s[0][0] ^= RC[i];
            }
        }
        byte[] b = new byte[32];
        for (int x = 0; x < 4; x++) {
            b[8*x+0] = (byte)((s[x][0] >>  0) & 0xff);
            b[8*x+1] = (byte)((s[x][0] >>  8) & 0xff);
            b[8*x+2] = (byte)((s[x][0] >> 16) & 0xff);
            b[8*x+3] = (byte)((s[x][0] >> 24) & 0xff);
            b[8*x+4] = (byte)((s[x][0] >> 32) & 0xff);
            b[8*x+5] = (byte)((s[x][0] >> 40) & 0xff);
            b[8*x+6] = (byte)((s[x][0] >> 48) & 0xff);
            b[8*x+7] = (byte)((s[x][0] >> 56) & 0xff);
        }
        return b;
    }

}
