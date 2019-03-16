package com.raugfer.crypto;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class protobuf {

    private static pair<byte[], byte[]> getb(byte[] b, int n) {
        if (b.length < n) throw new IllegalArgumentException("End of input");
        return new pair<>(bytes.sub(b, 0, n), bytes.sub(b, n));
    }

    private static pair<Integer, byte[]> getf(byte[] b) {
        pair<byte[], byte[]> t = getb(b, 1);
        byte[] d = t.l;
        b = t.r;
        return new pair<>(binint.b2n(d).intValue(), b);
    }

    private static triple<pair<Integer, Integer>, Object, byte[]> dec(byte[] b, int f) {
        int t = f & 0x07, n = (f & 0xf8) >> 3;
        if (t == 0) {
            int v = 0x80;
            BigInteger d = BigInteger.ZERO;
            int i = 0;
            while ((v & 0x80) != 0) {
                pair<Integer, byte[]> r = getf(b);
                v = r.l;
                b = r.r;
                d = d.or(BigInteger.valueOf(v & 0x7f).shiftLeft(i * 7));
                i++;
            }
            return new triple<>(new pair<>(n, t), d, b);
        }
        if (t == 2) {
            triple<pair<Integer, Integer>, Object, byte[]> r = dec(b, 0);
            BigInteger l = (BigInteger) r.r;
            b = r.t;
            pair<byte[], byte[]> s = getb(b, l.intValue());
            byte[] d = s.l;
            b = s.r;
            return new triple<>(new pair<>(n, t), d, b);
        }
        throw new IllegalArgumentException("Illegal input");
    }

    public static Object loads(byte[] b) {
        return loads(b, new HashMap<>());
    }

    public static Object loads(byte[] b, Map<Integer, Object> meta) {
        Map<Integer, Object> o = new HashMap<>();
        while (b.length > 0) {
            pair<Integer, byte[]> r = getf(b);
            int f = r.l;
            b = r.r;
            triple<pair<Integer, Integer>, Object, byte[]> s = dec(b, f);
            int n = s.l.l;
            int t = s.l.r;
            Object d = s.r;
            b = s.t;
            if (t == 2 && meta.containsKey(n)) d = loads((byte[]) d, (Map<Integer, Object>) meta.get(n));
            o.put(n, d);
        }
        return o;
    }

    private static byte[] enc(int n, Object _v) {
        if (_v instanceof BigInteger) {
            BigInteger v = (BigInteger) _v;
            assert v.signum() >= 0;
            byte[] b = binint.n2b(BigInteger.valueOf(n << 3 | 0), 1);
            while (v.compareTo(BigInteger.valueOf(0x80)) >= 0) {
                b = bytes.concat(b, binint.n2b(v.and(BigInteger.valueOf(0x7f)).or(BigInteger.valueOf(0x80)), 1));
                v = v.shiftRight(7);
            }
            b = bytes.concat(b, binint.n2b(v.and(BigInteger.valueOf(0x7f)), 1));
            return b;
        }
        if (_v instanceof byte[]) {
            byte[] v = (byte[]) _v;
            byte[] b = binint.n2b(BigInteger.valueOf(n << 3 | 2), 1);
            b = bytes.concat(b, bytes.sub(enc(0, BigInteger.valueOf(v.length)), 1));
            b = bytes.concat(b, v);
            return b;
        }
        throw new IllegalArgumentException("Illegal input" + _v);
    }

    public static byte[] dumps(Object _o) {
        if (_o instanceof Map) {
            Map<Integer, Object> o = (Map<Integer, Object>) _o;
            byte[] b = new byte[]{ };
            Integer[] ns = o.keySet().toArray(new Integer[]{ });
            Arrays.sort(ns);
            for (int n : ns) {
                Object v = o.get(n);
                if (v instanceof Map) v = dumps(v);
                b = bytes.concat(b, enc(n, v));
            }
            return b;
        }
        throw new IllegalArgumentException("Unsupported value");
    }

}