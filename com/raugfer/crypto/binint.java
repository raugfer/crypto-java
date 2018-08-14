package com.raugfer.crypto;

import java.math.BigInteger;

public class binint {

    private final static String digits = "0123456789abcdef";

    public static byte[] h2b(String s) {
        int length = s.length();
        if (length % 2 != 0) {
            s = "0" + s;
            length++;
        }
        byte[] b = new byte[length / 2];
        for (int i = 0; i < b.length; i++) {
            int p1 = digits.indexOf(Character.toLowerCase(s.charAt(2*i+0)));
            if (p1 < 0) throw new IllegalArgumentException("Invalid input");
            int p2 = digits.indexOf(Character.toLowerCase(s.charAt(2*i+1)));
            if (p2 < 0) throw new IllegalArgumentException("Invalid input");
            b[i] = (byte)((p1 << 4) | (p2 << 0));
        }
        return b;
    }

    public static String b2h(byte[] b) {
        if (b.length == 0) return "0";
        char[] c = new char[2*b.length];
        for (int i = 0; i < b.length; i++) {
            c[2*i+0] = digits.charAt((b[i] >> 4) & 0x0f);
            c[2*i+1] = digits.charAt((b[i] >> 0) & 0x0f);
        }
        return new String(c);
    }

    public static BigInteger b2n(byte[] b) {
        if (b.length == 0 || b[0] < 0) {
            byte[] t = new byte[b.length + 1];
            System.arraycopy(b, 0, t, 1, b.length);
            b = t;
        }
        return new BigInteger(b);
    }

    public static byte[] n2b(BigInteger n) {
        return n2b(n, 0);
    }

    public static byte[] n2b(BigInteger n, int length) {
        if (n.compareTo(BigInteger.ZERO) < 0) throw new IllegalArgumentException("Negative number");
        byte[] b = n.toByteArray();
        if (b[0] == 0) {
            byte[] t = new byte[b.length - 1];
            System.arraycopy(b, 1, t, 0, t.length);
            b = t;
        }
        if (length > b.length) {
            byte[] t = new byte[length];
            System.arraycopy(b, 0, t, length - b.length, b.length);
            b = t;
        }
        return b;
    }

    public static BigInteger h2n(String s) { return b2n(h2b(s)); }

    public static String n2h(BigInteger n) {
        return n2h(n, 0);
    }

    public static String n2h(BigInteger n, int length) {
        return b2h(n2b(n, length));
    }

}
