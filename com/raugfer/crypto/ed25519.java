package com.raugfer.crypto;

import java.math.BigInteger;

public class ed25519 {

    private static int b = 256;
    private static BigInteger q = new BigInteger("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16);
    private static BigInteger d = new BigInteger("52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3", 16);
    private static BigInteger[] B = new BigInteger[]{
            new BigInteger("216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a", 16),
            new BigInteger("6666666666666666666666666666666666666666666666666666666666666658", 16),
    };
    public static final BigInteger l = new BigInteger("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16);

    public static boolean rng(BigInteger e) {
        return e.compareTo(BigInteger.ZERO) > 0 && e.compareTo(l) < 0;
    }

    public static BigInteger red(BigInteger e) {
        return e.mod(l);
    }

    public static boolean has(BigInteger[] P) {
        BigInteger x = P[0], y = P[1];
        return y.pow(2).subtract(x.pow(2).add(d.multiply(x.pow(2)).multiply(y.pow(2))).add(BigInteger.ONE)).mod(q).equals(BigInteger.ZERO);
    }

    private static BigInteger[] add(BigInteger[] P1, BigInteger[] P2) {
        BigInteger x1 = P1[0], y1 = P1[1];
        BigInteger x2 = P2[0], y2 = P2[1];
        BigInteger f = d.multiply(x1).multiply(x2).multiply(y1).multiply(y2);
        BigInteger x3 = x1.multiply(y2).add(y1.multiply(x2)).multiply(BigInteger.ONE.add(f).modPow(q.subtract(BigInteger.valueOf(2)), q));
        BigInteger y3 = x1.multiply(x2).add(y1.multiply(y2)).multiply(BigInteger.ONE.subtract(f).modPow(q.subtract(BigInteger.valueOf(2)), q));
        BigInteger[] P3 = new BigInteger[]{ x3.mod(q), y3.mod(q) };
        assert has(P3);
        return P3;
    }

    private static BigInteger[] mul(BigInteger[] P, BigInteger e) {
        if (e.equals(BigInteger.ZERO)) return new BigInteger[]{ BigInteger.ZERO, BigInteger.ONE };
        if (e.equals(BigInteger.ONE)) return P;
        BigInteger[] Q = mul(add(P, P), e.shiftRight(1));
        if (!e.and(BigInteger.ONE).equals(BigInteger.ZERO)) Q = add(Q, P);
        return Q;
    }

    public static BigInteger fnd(BigInteger y, boolean odd) {
        BigInteger xx = y.pow(2).subtract(BigInteger.ONE).multiply(d.multiply(y.pow(2)).add(BigInteger.ONE).modPow(q.subtract(BigInteger.valueOf(2)), q));
        BigInteger x = xx.modPow(q.add(BigInteger.valueOf(3)).divide(BigInteger.valueOf(8)), q);
        if (!x.pow(2).subtract(xx).mod(q).equals(BigInteger.ZERO)) {
            BigInteger I = BigInteger.valueOf(2).modPow(q.subtract(BigInteger.ONE).divide(BigInteger.valueOf(4)), q);
            x = x.multiply(I).mod(q);
        }
        if (!x.and(BigInteger.ONE).equals(BigInteger.ZERO)) x = q.subtract(x);
        if (odd && x.and(BigInteger.ONE).equals(BigInteger.ZERO)) x = q.subtract(x);
        if (!odd && x.and(BigInteger.ONE).equals(BigInteger.ONE)) x = q.subtract(x);
        BigInteger[] P = new BigInteger[]{ x, y };
        assert has(P);
        return x;
    }

    public static BigInteger[] gen(BigInteger e, hashing.hashfun f) {
        byte[] h1 = f.hash(binint.n2b(e, 32));
        BigInteger a = binint.b2n(bytes.rev(bytes.sub(h1, 0, 32)));
        a = a.and(new BigInteger("3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8", 16));
        a = a.or(new BigInteger("4000000000000000000000000000000000000000000000000000000000000000", 16));
        return _gen(red(a));
    }

    private static BigInteger[] _gen(BigInteger e) {
        if (!rng(e)) throw new IllegalArgumentException("Out of range");
        assert has(B);
        BigInteger[] P = mul(B, e);
        assert has(P);
        return P;
    }

    public static BigInteger enc(BigInteger[] P) {
        if (!has(P)) throw new IllegalArgumentException("Invalid point");
        BigInteger x = P[0], y = P[1];
        BigInteger p = y.and(BigInteger.valueOf(2).pow(b-1).subtract(BigInteger.ONE)).or(x.and(BigInteger.ONE).shiftLeft(255));
        return p;
    }

    public static BigInteger[] dec(BigInteger p) {
        BigInteger y = p.and(BigInteger.valueOf(2).pow(b-1).subtract(BigInteger.ONE));
        boolean odd = p.shiftRight(255).and(BigInteger.ONE).equals(BigInteger.ONE);
        BigInteger x = fnd(y, odd);
        BigInteger[] P = new BigInteger[]{ x, y };
        if (!has(P)) throw new IllegalArgumentException("Invalid point");
        return P;
    }

    public static Object[] sgn(BigInteger e, BigInteger h, hashing.hashfun f, int h_len) {
        byte[] b = binint.n2b(h, h_len);

        byte[] h1 = f.hash(binint.n2b(e, 32));
        BigInteger a = binint.b2n(bytes.rev(bytes.sub(h1, 0, 32)));
        a = a.and(new BigInteger("3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8", 16));
        a = a.or(new BigInteger("4000000000000000000000000000000000000000000000000000000000000000", 16));
        BigInteger[] P = _gen(red(a));
        BigInteger A = enc(P);

        byte[] h2 = f.hash(bytes.concat(bytes.sub(h1, 32), b));
        BigInteger r = binint.b2n(bytes.rev(h2));
        BigInteger[] Q = _gen(red(r));
        BigInteger R = enc(Q);

        byte[] h3 = f.hash(bytes.concat(bytes.rev(binint.n2b(R, 32)), bytes.rev(binint.n2b(A, 32)), b));
        BigInteger t = binint.b2n(bytes.rev(h3));

        BigInteger S = r.add(a.multiply(t)).mod(l);

        boolean odd = A.shiftRight(255).and(BigInteger.ONE).equals(BigInteger.ONE);

        return new Object[]{ R, S, odd };
    }

    public static boolean ver(BigInteger[] P, BigInteger h, Object[] o, hashing.hashfun f, int h_len) {
        BigInteger R = (BigInteger) o[0];
        BigInteger S = (BigInteger) o[1];
        Boolean odd = (Boolean) o[2];
        if (odd != null) {
            BigInteger x = P[0], y = P[1];
            P = new BigInteger[]{ fnd(y, odd), y };
        }
        if (!has(P)) throw new IllegalArgumentException("Invalid point");
        if (S.compareTo(l) >= 0) throw new IllegalArgumentException("Out of range");
        byte[] b = binint.n2b(h, h_len);
        BigInteger A = enc(P);
        BigInteger[] Q = dec(R);
        if (!has(Q)) throw new IllegalArgumentException("Invalid point");
        byte[] h3 = f.hash(bytes.concat(bytes.rev(binint.n2b(R, 32)), bytes.rev(binint.n2b(A, 32)), b));
        BigInteger t = binint.b2n(bytes.rev(h3));
        BigInteger[] P1 = _gen(S);
        BigInteger[] P2 = add(Q, mul(P, red(t)));
        return P1[0].equals(P2[0]) && P1[1].equals(P2[1]);
    }

}
