package com.raugfer.crypto;

import java.math.BigInteger;

public class secp256k1 {

    private static BigInteger p = new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16);
    private static BigInteger a = new BigInteger("0000000000000000000000000000000000000000000000000000000000000000", 16);
    private static BigInteger b = new BigInteger("0000000000000000000000000000000000000000000000000000000000000007", 16);
    private static BigInteger[] G = new BigInteger[]{
            new BigInteger("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16),
            new BigInteger("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16),
    };
    public static final BigInteger n = new BigInteger("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16);

    public static boolean rng(BigInteger e) {
        return e.compareTo(BigInteger.ZERO) > 0 && e.compareTo(n) < 0;
    }

    public static boolean has(BigInteger[] P) {
        if (P == null) return false;
        BigInteger x = P[0], y = P[1];
        return y.pow(2).subtract(x.pow(3).add(x.multiply(a)).add(b)).mod(p).equals(BigInteger.ZERO);
    }

    private static BigInteger[] add(BigInteger[] P1, BigInteger[] P2) {
        if (P1 == null) return P2;
        if (P2 == null) return P1;
        BigInteger x1 = P1[0], y1 = P1[1];
        BigInteger x2 = P2[0], y2 = P2[1];
        BigInteger l;
        if (x1.equals(x2)) {
            if (!y1.equals(y2)) return null;
            if (y1.equals(BigInteger.ZERO)) return null;
            l = x1.pow(2).multiply(BigInteger.valueOf(3)).add(a).multiply(y1.shiftLeft(1).modPow(p.subtract(BigInteger.valueOf(2)), p));
        } else {
            l = y2.subtract(y1).multiply(x2.subtract(x1).modPow(p.subtract(BigInteger.valueOf(2)), p));
        }
        BigInteger x3 = l.pow(2).subtract(x1).subtract(x2);
        BigInteger y3 = l.multiply(x1.subtract(x3)).subtract(y1);
        BigInteger[] P3 = new BigInteger[]{ x3.mod(p), y3.mod(p) };
        return P3;
    }

    private static BigInteger[] mul(BigInteger[] P, BigInteger e) {
        if (e.equals(BigInteger.ZERO)) return null;
        BigInteger[] Q = mul(add(P, P), e.shiftRight(1));
        if (!e.and(BigInteger.ONE).equals(BigInteger.ZERO)) Q = add(Q, P);
        return Q;
    }

    public static BigInteger aex(BigInteger e1, BigInteger e2) {
        if (!rng(e1)) throw new IllegalArgumentException("Out of range");
        if (!rng(e2)) throw new IllegalArgumentException("Out of range");
        BigInteger e3 = e1.add(e2).mod(n);
        if (!rng(e3)) throw new IllegalArgumentException("Out of range");
        return e3;
    }

    public static BigInteger[] apt(BigInteger[] P1, BigInteger[] P2) {
        if (!has(P1)) throw new IllegalArgumentException("Invalid point");
        if (!has(P2)) throw new IllegalArgumentException("Invalid point");
        BigInteger[] P3 = add(P1, P2);
        assert has(P3);
        return P3;
    }

    public static BigInteger fnd(BigInteger x, boolean odd) {
        BigInteger y = x.pow(3).add(x.multiply(a)).add(b).modPow(p.add(BigInteger.ONE).shiftRight(2), p);
        if (odd == y.and(BigInteger.ONE).equals(BigInteger.ZERO)) y = p.subtract(y);
        BigInteger[] P = new BigInteger[]{ x, y };
        assert has(P) && mul(P, n) == null;
        return y;
    }

    public static BigInteger[] gen(BigInteger e) {
        assert has(G);
        if (!rng(e)) throw new IllegalArgumentException("Out of range");
        BigInteger[] P = mul(G, e);
        if (P == null) throw new IllegalArgumentException("Point at infinity");
        BigInteger x = P[0], y = P[1];
        assert has(P) && mul(P, n) == null;
        return P;
    }

    public static pair<BigInteger, Boolean> enc(BigInteger[] P) {
        BigInteger x = P[0], y = P[1];
        if (!has(P)) throw new IllegalArgumentException("Invalid point");
        boolean odd = y.and(BigInteger.ONE).equals(BigInteger.ONE);
        return new pair<>(x, odd);
    }

    public static BigInteger[] dec(BigInteger p, boolean odd) {
        BigInteger x = p;
        BigInteger y = fnd(x, odd);
        BigInteger[] P = new BigInteger[]{ x, y };
        if (!has(P)) throw new IllegalArgumentException("Invalid point");
        return P;
    }

    public static Object[] sgn(BigInteger e, BigInteger h, BigInteger k) {
        if (!rng(e)) throw new IllegalArgumentException("Out of range");
        if (!rng(h)) throw new IllegalArgumentException("Out of range");
        BigInteger[] P = gen(k);
        BigInteger r = P[0], y = P[1];
        BigInteger s = ((k.modPow(n.subtract(BigInteger.valueOf(2)), n)).multiply(h.add(r.multiply(e)))).mod(n);
        boolean odd = y.and(BigInteger.ONE).equals(BigInteger.ONE);
        if (s.compareTo(n.shiftRight(1)) > 0) {
            s = n.subtract(s);
            odd = !odd;
        }
        if (!rng(s)) throw new IllegalArgumentException("Out of range");
        return new Object[]{ r, s, odd };
    }

    public static boolean ver(BigInteger[] P, BigInteger h, Object[] S) {
        if (!(has(P) && mul(P, n) == null)) throw new IllegalArgumentException("Invalid point");
        if (!rng(h)) throw new IllegalArgumentException("Out of range");
        BigInteger r = (BigInteger) S[0];
        BigInteger s = (BigInteger) S[1];
        if (!rng(r)) throw new IllegalArgumentException("Out of range");
        if (!rng(s)) throw new IllegalArgumentException("Out of range");
        if (s.compareTo(n.shiftRight(2)) > 0) throw new IllegalArgumentException("Out of range");
        BigInteger w = s.modPow(n.subtract(BigInteger.valueOf(2)), n);
        BigInteger u = h.multiply(w).mod(n), v = r.multiply(w).mod(n);
        BigInteger[] Q = add(mul(G, u), mul(P, v));
        if (Q == null) throw new IllegalArgumentException("Point at infinity");
        BigInteger x = Q[0];
        return r.equals(x);
    }

    public static BigInteger[] rec(BigInteger h, Object[] S) {
        if (!rng(h)) throw new IllegalArgumentException("Out of range");
        BigInteger r = (BigInteger) S[0];
        BigInteger s = (BigInteger) S[1];
        boolean odd = (boolean) S[3];
        if (!rng(r)) throw new IllegalArgumentException("Out of range");
        if (!rng(s)) throw new IllegalArgumentException("Out of range");
        if (s.compareTo(n.shiftRight(2)) > 0) throw new IllegalArgumentException("Out of range");
        BigInteger[] R = { r, fnd(r, odd) };
        BigInteger z = h.negate().mod(n);
        BigInteger invr = r.modPow(n.subtract(BigInteger.valueOf(2)), n);
        BigInteger[] P = mul(add(mul(R, s), mul(G, z)), invr);
        if (!(has(P) && mul(P, n) == null)) throw new IllegalArgumentException("Invalid point");
        return P;
    }

}
