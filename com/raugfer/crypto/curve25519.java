package com.raugfer.crypto;

import java.math.BigInteger;

public class curve25519 {

    private static final BigInteger p = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger a24 = BigInteger.valueOf(121665);
    private static final int bits = 255;
    private static final BigInteger u = BigInteger.valueOf(9);

    private static BigInteger __(BigInteger n) {
        return n.mod(p);
    }

    private static pair<BigInteger, BigInteger> cswap(BigInteger swap, BigInteger x_2, BigInteger x_3) {
        BigInteger dummy = __(swap.multiply(__(x_2.subtract(x_3))));
        x_2 = __(x_2.subtract(dummy));
        x_3 = __(x_3.subtract(dummy));
        return new pair<>(x_2, x_3);
    }

    public static BigInteger X25519(BigInteger k) {
        return X25519(k, u);
    }

    public static BigInteger X25519(BigInteger k, BigInteger u) {
        assert k.compareTo(BigInteger.ONE.shiftLeft(bits)) < 0;
        BigInteger x_1 = u;
        BigInteger x_2 = BigInteger.ONE;
        BigInteger z_2 = BigInteger.ZERO;
        BigInteger x_3 = u;
        BigInteger z_3 = BigInteger.ONE;
        BigInteger swap = BigInteger.ZERO;
        for (int i = bits-1; i >= 0; i--) {
            BigInteger k_t = k.shiftRight(i).and(BigInteger.ONE);
            swap = swap.xor(k_t);
            pair<BigInteger, BigInteger> t = cswap(swap, x_2, x_3);
            x_2 = t.l;
            x_3 = t.r;
            t = cswap(swap, z_2, z_3);
            z_2 = t.l;
            z_3 = t.r;
            swap = k_t;
            BigInteger A = __(x_2.add(z_2));
            BigInteger AA = __(A.pow(2));
            BigInteger B = __(x_2.subtract(z_2));
            BigInteger BB = __(B.pow(2));
            BigInteger E = __(AA.subtract(BB));
            BigInteger C = __(x_3.add(z_3));
            BigInteger D = __(x_3.subtract(z_3));
            BigInteger DA = __(D.multiply(A));
            BigInteger CB = __(C.multiply(B));
            x_3 = __(__(DA.add(CB)).pow(2));
            z_3 = __(x_1.multiply(__(__(DA.subtract(CB)).pow(2))));
            x_2 = __(AA.multiply(BB));
            z_2 = __(E.multiply(__(AA.add(__(a24.multiply(E))))));
        }
        pair<BigInteger, BigInteger> t = cswap(swap, x_2, x_3);
        x_2 = t.l;
        x_3 = t.r;
        t = cswap(swap, z_2, z_3);
        z_2 = t.l;
        z_3 = t.r;
        return __(x_2.multiply(z_2.modPow(p.subtract(BigInteger.valueOf(2)), p)));
    }

    public static BigInteger enc_ed25519(BigInteger x) {
        return __(x.subtract(BigInteger.ONE).multiply(x.add(BigInteger.ONE).modPow(p.subtract(BigInteger.valueOf(2)), p)));
    }

    public static BigInteger dec_ed25519(BigInteger y) {
        return __(y.add(BigInteger.ONE).multiply(BigInteger.ONE.subtract(y).modPow(p.subtract(BigInteger.valueOf(2)), p)));
    }

}
