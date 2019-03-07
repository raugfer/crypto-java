package com.raugfer.crypto;

import java.math.BigInteger;

public class hashing {

    public static byte[] hash160(byte[] message) { return ripemd160(sha256(message)); }

    public static byte[] hash256(byte[] message) { return sha256(sha256(message)); }

    public static byte[] blake160(byte[] message) { return ripemd160(blake1s(message)); }

    public static byte[] blake256(byte[] message) { return blake1s(blake1s(message)); }

    public static byte[] ripemd160(byte[] message) { return ripemd160(message, false); }

    public static byte[] ripemd160(byte[] message, boolean compressed) { return ripemd160.hash(message, compressed); }

    public static byte[] sha256(byte[] message) { return sha256(message, false); }

    public static byte[] sha256(byte[] message, boolean compressed) { return sha256.hash(message, compressed); }

    public static byte[] sha512(byte[] message) { return sha512(message, false); }

    public static byte[] sha512(byte[] message, boolean compressed) { return sha512.hash(message, compressed); }

    public static byte[] sha512h(byte[] message) { return bytes.sub(sha512(message), 0, 32); }

    public static byte[] keccak256(byte[] message) { return keccak256(message, false); }

    public static byte[] keccak256(byte[] message, boolean compressed) { return keccak256.hash(message, compressed); }

    public static byte[] blake1s(byte[] message) { return blake1s.hash(message); }

    public static byte[] blake1s(byte[] message, int size) { return blake1s.hash(message, new byte[]{ }, size); }

    public static byte[] blake1s(byte[] message, byte[] key, int size) { return blake1s.hash(message, key, size); }

    public static byte[] blake2b(byte[] message) { return blake2b.hash(message); }

    public static byte[] blake2b(byte[] message, int size) { return blake2b.hash(message, new byte[]{ }, new byte[]{ }, new byte[]{ }, size); }

    public static byte[] blake2b(byte[] message, byte[] person, int size) { return blake2b.hash(message, new byte[]{ }, new byte[]{ }, person, size); }

    public static byte[] sha3_256(byte[] message) { return sha3_256(message, false); }

    public static byte[] sha3_256(byte[] message, boolean compressed) { return sha3_256.hash(message, compressed); }

    public static byte[] securehash(byte[] message) { return keccak256(blake2b(message, 32)); }

    public static byte[] addresshash(byte[] message) { return blake2b(sha3_256(message), 28); }

    public static byte[] hmac(byte[] k, byte[] b, hashfun f, int size) {
        if (k.length > size) k = f.hash(k);
        if (k.length < size) {
            byte[] t = new byte[size];
            System.arraycopy(k, 0, t, 0, k.length);
            k = t;
        }
        byte[] p = new byte[size];
        byte[] q = new byte[size];
        for (int i = 0; i < p.length; i++) {
            p[i] = (byte) (k[i] ^ 0x5c);
            q[i] = (byte) (k[i] ^ 0x36);
        }
        return f.hash(bytes.concat(p, f.hash(bytes.concat(q, b))));
    }

    public static byte[] hmac_sha256(byte[] k, byte[] b) {
        return hmac(k, b, hashing::sha256, 64);
    }

    public static byte[] hmac_sha512(byte[] k, byte[] b) {
        return hmac(k, b, hashing::sha512, 128);
    }

    public static byte[] pbkdf2(byte[] k, byte[] salt) {
        return pbkdf2(k, salt, 2048, 64, hashing::hmac_sha512);
    }

    public static byte[] pbkdf2(byte[] k, byte[] salt, int iterations, int keylen, hmacfun f) {
        byte[] b = new byte[keylen];
        int offset = 0;
        for (int index = 1; offset < keylen; index++) {
            byte[] v = binint.n2b(BigInteger.valueOf(index), 4);
            byte[] u = f.hmac(k, bytes.concat(salt, v));
            byte[] rv = u;
            for (int j = 1; j < iterations; j++) {
                u = f.hmac(k, u);
                for (int i = 0; i < rv.length; i++) rv[i] ^= u[i];
            }
            int length = b.length - offset;
            if (length > rv.length) length = rv.length;
            System.arraycopy(rv, 0, b, offset, length);
            offset += length;
        }
        return b;
    }

    private static BigInteger bits2int(byte[] data, int qlen) {
        BigInteger v = binint.b2n(data);
        int vlen = 8 * data.length;
        if (vlen > qlen) v = v.shiftRight(vlen - qlen);
        return v;
    }

    private static byte[] int2octets(BigInteger n, int qlen) {
        int rolen = (qlen+7)/8;
        byte[] b = binint.n2b(n, rolen);
        if (b.length > rolen) {
            byte[] t = new byte[rolen];
            System.arraycopy(b, b.length - rolen, t, 0, t.length);
            b = t;
        }
        return b;
    }

    private static byte[] bits2octets(byte[] data, BigInteger q, int qlen) {
        BigInteger z1 = bits2int(data, qlen);
        BigInteger z2 = z1.subtract(q);
        return int2octets(z2.compareTo(BigInteger.ZERO) < 0 ? z1 : z2, qlen);
    }

    public static BigInteger det_k(BigInteger x, byte[] h1, BigInteger q) {
        return det_k(x, h1, q, hashing::hmac_sha256);
    }

    public static BigInteger det_k(BigInteger x, byte[] h1, BigInteger q, hmacfun f) {
        int qlen = q.toString(2).length();
        byte[] octets = bytes.concat(int2octets(x, qlen), bits2octets(h1, q, qlen));
        byte[] K = new byte[h1.length];                                     // c.
        byte[] V = new byte[h1.length];                                     // b.
        for (int i = 0; i < V.length; i++) V[i] = 0x01;
        K = f.hmac(K, bytes.concat(V, new byte[]{ 0x00 }, octets));         // d.
        V = f.hmac(K, V);						                            // e.
        K = f.hmac(K, bytes.concat(V, new byte[]{ 0x01 }, octets));         // f.
        V = f.hmac(K, V);						                            // g.
        while (true) {
            byte[] T = new byte[0];                                         // h.1.
            int tlen = 8 * T.length;
            while (tlen < qlen) {                                           // h.2.
                V = f.hmac(K, V);
                T = bytes.concat(T, V);
                tlen = 8 * T.length;
            }
            BigInteger k = bits2int(T, qlen);                               // h.3.
            if (k.compareTo(BigInteger.ZERO) > 0 && k.compareTo(q) < 0) return k;
            K = f.hmac(K, bytes.concat(V, new byte[]{ 0x00 }));
            V = f.hmac(K, V);
        }
    }

    public interface hashfun {
        byte[] hash(byte[] b);
    }

    public interface hmacfun {
        byte[] hmac(byte[] k, byte[] b);
    }

}
