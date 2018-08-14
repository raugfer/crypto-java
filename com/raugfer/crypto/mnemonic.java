package com.raugfer.crypto;

import java.math.BigInteger;
import java.text.Normalizer;
import java.util.Arrays;

public class mnemonic {

    public static String mnemonic(BigInteger entropy, int size, String[] wordlist) {
        if (wordlist.length != 2048) throw new IllegalArgumentException("Invalid wordlist");
        int div = size / 32;
        int mod = size % 32;
        if (div <= 0 || div > 256 || mod != 0) throw new IllegalArgumentException("Invalid size");
        if (entropy.compareTo(BigInteger.ONE.shiftLeft(size)) >= 0) throw new IllegalArgumentException("Invalid entropy");
        byte[] b = binint.n2b(entropy, size / 8);
        byte[] h = hashing.sha256(b);
        byte[] t = new byte[b.length + h.length];
        System.arraycopy(b, 0, t, 0, b.length);
        System.arraycopy(h, 0, t, b.length, h.length);
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < t.length; i++) {
            String s = Integer.toBinaryString(t[i] & 0xff);
            for (int j = s.length(); j < 8; j++) sb.append("0");
            sb.append(s);
        }
        int count = 3 * div;
        String[] words = new String[count];
        int begin = 0;
        for (int i = 0; i < words.length; i++) {
            int end = begin + 11;
            int index = Integer.parseInt(sb.substring(begin, end), 2);
            words[i] = wordlist[index];
            begin = end;
        }
        StringBuffer join = new StringBuffer();
        for (String word : words) {
            join.append(word);
            join.append(" ");
        }
        return join.substring(0, join.length() - 1);
    }

    public static pair<BigInteger, Integer> unmnemonic(String mnemonic, String[] wordlist) {
        if (wordlist.length != 2048) throw new IllegalArgumentException("Invalid wordlist");
        String[] words = mnemonic.split(" ");
        int count = words.length;
        if (count % 3 != 0) throw new IllegalArgumentException("Invalid mnemonic");
        int[] indexes = new int[count];
        for (int i = 0; i < count; i++) {
            String word = words[i];
            int index = Arrays.binarySearch(wordlist, word);
            if (index == -1) throw new IllegalArgumentException("Invalid mnemonic");
            indexes[i] = index;
        }
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < indexes.length; i++) {
            String s = Integer.toBinaryString(indexes[i]);
            for (int j = s.length(); j < 11; j++) sb.append("0");
            sb.append(s);
        }
        int div = count / 3;
        int size = 11 * count - div;
        byte[] b = new byte[size / 8];
        int begin = 0;
        for (int i = 0; i < b.length; i++) {
            int end = begin + 8;
            b[i] = (byte) Integer.parseInt(sb.substring(begin, end), 2);
            begin = end;
        }
        byte[] h = hashing.sha256(b);
        StringBuffer sb2 = new StringBuffer();
        for (int i = 0; i < h.length; i++) {
            String s = Integer.toBinaryString(h[i] & 0xff);
            for (int j = s.length(); j < 8; j++) sb2.append("0");
            sb2.append(s);
        }
        if (!sb.substring(size, size+div).equals(sb2.substring(0, div))) throw new IllegalArgumentException("Invalid mnemonic");
        return new pair<>(binint.b2n(b), size);
    }

    public static BigInteger seed(String mnemonic, String password) {
        String salt = "mnemonic" + Normalizer.normalize(password, Normalizer.Form.NFKD);
        byte[] seed = hashing.pbkdf2(mnemonic.getBytes(), salt.getBytes());
        return binint.b2n(seed);
    }

}
