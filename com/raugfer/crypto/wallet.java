package com.raugfer.crypto;

import java.math.BigInteger;

public class wallet {

    private static String base32_encode(byte[] b, String kind, String coin, boolean testnet) {
        String fun = coins.attr("base32.check", "<none>", coin, testnet);
        fun = coins.attr(kind + ".base32.check", fun, coin, testnet);
        hashing.hashfun f;
        if (fun.equals("<none>")) f = (t) -> new byte[]{};
        else
        if (fun.equals("crc16:2")) f = base32::_rev_crc16;
        else
        if (fun.equals("blake2b:5")) f = base32::_rev_blake2b_5;
        else {
            throw new IllegalStateException("Unknown hashing function");
        }
        byte[] prefix = coins.attr(kind + ".base32.prefix", new byte[]{ }, coin, testnet);
        byte[] suffix = coins.attr(kind + ".base32.suffix", new byte[]{ }, coin, testnet);
        String w = base32.check_encode(b, prefix, suffix, f);
        String digits = coins.attr("base32.digits", base32.digits, coin, testnet);
        w = base32.translate(w, null, digits);
        return w;
    }

    private static byte[] base32_decode(String w, String kind, String coin, boolean testnet) {
        String fun = coins.attr("base32.check", "<none>", coin, testnet);
        fun = coins.attr(kind + ".base32.check", fun, coin, testnet);
        int hash_len;
        hashing.hashfun f;
        if (fun.equals("<none>")) {
            hash_len = 0;
            f = (t) -> new byte[]{};
        }
        else
        if (fun.equals("crc16:2")) {
            hash_len = 2;
            f = base32::_rev_crc16;
        }
        else
        if (fun.equals("blake2b:5")) {
            hash_len = 5;
            f = base32::_rev_blake2b_5;
        }
        else {
            throw new IllegalStateException("Unknown hashing function");
        }
        String digits = coins.attr("base32.digits", base32.digits, coin, testnet);
        w = base32.translate(w, digits, null);
        byte[] prefix = coins.attr(kind + ".base32.prefix", new byte[]{ }, coin, testnet);
        byte[] suffix = coins.attr(kind + ".base32.suffix", new byte[]{ }, coin, testnet);
        triple<byte[], byte[], byte[]> t = base32.check_decode(w, prefix.length, suffix.length, hash_len, f);
        byte[] b = t.l, p = t.r, s = t.t;
        if (!bytes.equ(p, prefix)) throw new IllegalArgumentException("Invalid prefix");
        if (!bytes.equ(s, suffix)) throw new IllegalArgumentException("Invalid suffix");
        return b;
    }

    private static String base58_encode(byte[] b, String kind, String coin, boolean testnet) {
        String fun = coins.attr("base58.check", "<none>", coin, testnet);
        fun = coins.attr(kind + ".base58.check", fun, coin, testnet);
        hashing.hashfun f;
        if (fun.equals("<none>")) f = (t) -> new byte[]{ };
        else
        if (fun.equals("hash256:4")) f = base58::_sub_hash256_0_4;
        else
        if (fun.equals("ripemd160:4")) f = base58::_sub_ripemd160_0_4;
        else
        if (fun.equals("blake1s:4")) f = base58::_sub_blake1s_0_4;
        else
        if (fun.equals("blake256:4")) f = base58::_sub_blake256_0_4;
        else
        if (fun.equals("securehash:4")) f = base58::_sub_securehash_0_4;
        else
        if (fun.equals("crc32:5")) f = base58::_concat_crc32_5;
        else {
            throw new IllegalStateException("Unknown hashing function");
        }
        byte[] prefix = coins.attr(kind + ".base58.prefix", new byte[]{ }, coin, testnet);
        byte[] suffix = coins.attr(kind + ".base58.suffix", new byte[]{ }, coin, testnet);
        String w = base58.check_encode(b, prefix, suffix, f);
        String digits = coins.attr("base58.digits", base58.digits, coin, testnet);
        w = base58.translate(w, null, digits);
        return w;
    }

    private static byte[] base58_decode(String w, String kind, String coin, boolean testnet) {
        String fun = coins.attr("base58.check", "<none>", coin, testnet);
        fun = coins.attr(kind + ".base58.check", fun, coin, testnet);
        int hash_len;
        hashing.hashfun f;
        if (fun.equals("<none>")) {
            hash_len = 0;
            f = (t) -> new byte[]{ };
        }
        else
        if (fun.equals("hash256:4")) {
            hash_len = 4;
            f = base58::_sub_hash256_0_4;
        }
        else
        if (fun.equals("ripemd160:4")) {
            hash_len = 4;
            f = base58::_sub_ripemd160_0_4;
        }
        else
        if (fun.equals("blake1s:4")) {
            hash_len = 4;
            f = base58::_sub_blake1s_0_4;
        }
        else
        if (fun.equals("blake256:4")) {
            hash_len = 4;
            f = base58::_sub_blake256_0_4;
        }
        else
        if (fun.equals("securehash:4")) {
            hash_len = 4;
            f = base58::_sub_securehash_0_4;
        }
        else
        if (fun.equals("crc32:5")) {
            hash_len = 5;
            f = base58::_concat_crc32_5;
        }
        else {
            throw new IllegalStateException("Unknown hashing function");
        }
        String digits = coins.attr("base58.digits", base58.digits, coin, testnet);
        w = base58.translate(w, digits, null);
        byte[] prefix = coins.attr(kind + ".base58.prefix", new byte[]{ }, coin, testnet);
        byte[] suffix = coins.attr(kind + ".base58.suffix", new byte[]{ }, coin, testnet);
        triple<byte[], byte[], byte[]> t = base58.check_decode(w, prefix.length, suffix.length, hash_len, f);
        byte[] b = t.l, p = t.r, s = t.t;
        if (!bytes.equ(p, prefix)) throw new IllegalArgumentException("Invalid prefix");
        if (!bytes.equ(s, suffix)) throw new IllegalArgumentException("Invalid suffix");
        return b;
    }

    public static String privatekey_encode(BigInteger e, boolean compressed, String coin, boolean testnet) {
        compressed = coins.attr("privatekey.compressed", compressed, coin, testnet);
        String curve = coins.attr("ecc.curve", coin, testnet);
        byte[] b;
        if (curve.equals("secp256k1")) {
            if (!secp256k1.rng(e)) throw new IllegalArgumentException("Out of range");
            b = binint.n2b(e, 32);
            if (compressed) b = bytes.concat(b, new byte[]{ (byte)0x01 });
        }
        else
        if (curve.equals("nist256p1")) {
            if (!nist256p1.rng(e)) throw new IllegalArgumentException("Out of range");
            b = binint.n2b(e, 32);
            if (compressed) b = bytes.concat(b, new byte[]{ (byte)0x01 });
        }
        else
        if (curve.equals("ed25519")) {
            b = binint.n2b(e, 32);
        }
        else {
            throw new IllegalStateException("Unknown curve");
        }
        boolean reverse = coins.attr("privatekey.reverse", false, coin, testnet);
        if (reverse) b = bytes.rev(b);
        String fmt = coins.attr("privatekey.format", coin, testnet);
        switch (fmt) {
            case "hex": return binint.n2h(e, 32);
            case "sec2": return binint.b2h(b);
            case "base32": return base32_encode(b, "privatekey", coin, testnet);
            case "base58": return base58_encode(b, "privatekey", coin, testnet);
            default: throw new IllegalStateException("Unknown format");
        }
    }

    public static pair<BigInteger, Boolean> privatekey_decode(String w, String coin, boolean testnet) {
        String fmt = coins.attr("privatekey.format", coin, testnet);
        boolean reverse = coins.attr("privatekey.reverse", false, coin, testnet);
        BigInteger e = null;
        byte[] b;
        boolean compressed;
        if (fmt.equals("hex")) {
            b = binint.h2b(w);
            if (reverse) b = bytes.rev(b);
            if (b.length != 32) throw new IllegalArgumentException("Invalid length");
            e = binint.b2n(b);
            compressed = false;
        }
        else
        if (fmt.equals("sec2")) {
            b = binint.h2b(w);
            compressed = true;
        }
        else
        if (fmt.equals("base32")) {
            b = base32_decode(w, "privatekey", coin, testnet);
            compressed = true;
        }
        else
        if (fmt.equals("base58")) {
            boolean mini = coins.attr("privatekey.mini", true, coin, testnet);
            if (mini && w.substring(0, 1).equals("S")) return mini_privatekey_decode(w);
            b = base58_decode(w, "privatekey", coin, testnet);
            compressed = true;
        }
        else {
            throw new IllegalStateException("Unknown format");
        }
        if (reverse) b = bytes.rev(b);
        String curve = coins.attr("ecc.curve", coin, testnet);
        if (curve.equals("secp256k1")) {
            if (compressed) {
                if (b.length == 32) {
                    e = binint.b2n(b);
                    compressed = false;
                }
            }
            if (!compressed) b = bytes.concat(binint.n2b(e, 32), new byte[]{ (byte)0x01 });
            if (b.length != 33) throw new IllegalArgumentException("Invalid length");
            byte[] suffix = bytes.sub(b, 32);
            b = bytes.sub(b, 0, 32);
            if (!bytes.equ(suffix, new byte[]{ (byte)0x01 })) throw new IllegalArgumentException("Invalid suffix");
            e = binint.b2n(b);
            if (!secp256k1.rng(e)) throw new IllegalArgumentException("Out of range");
        }
        else
        if (curve.equals("nist256p1")) {
            if (compressed) {
                if (b.length == 32) {
                    e = binint.b2n(b);
                    compressed = false;
                }
            }
            if (!compressed) b = bytes.concat(binint.n2b(e, 32), new byte[]{ (byte)0x01 });
            if (b.length != 33) throw new IllegalArgumentException("Invalid length");
            byte[] suffix = bytes.sub(b, 32);
            b = bytes.sub(b, 0, 32);
            if (!bytes.equ(suffix, new byte[]{ (byte)0x01 })) throw new IllegalArgumentException("Invalid suffix");
            e = binint.b2n(b);
            if (!nist256p1.rng(e)) throw new IllegalArgumentException("Out of range");
        }
        else
        if (curve.equals("ed25519")) {
            if (!compressed) b = binint.n2b(e, 32);
            if (b.length != 32) throw new IllegalArgumentException("Invalid length");
            e = binint.b2n(b);
        }
        else {
            throw new IllegalStateException("Unknown curve");
        }
        boolean expected_compressed = coins.attr("privatekey.compressed", compressed, coin, testnet);
        if (compressed != expected_compressed) throw new IllegalArgumentException("Compression mismatch");
        return new pair<>(e, compressed);
    }

    private static String mini_privatekey_deduce(BigInteger e, int size) {
        BigInteger n;
        byte[] prefix;
        int length;
        if (size == 22) {
            // 128 bits => 8 + 120 bits
            n = BigInteger.ONE.shiftLeft(120);
            prefix = new byte[]{ (byte)0xcb };
            length = 15;
        } else if (size == 26) {
            // 152 bits => 8 + 144 bits
            n = BigInteger.ONE.shiftLeft(144);
            prefix = new byte[]{ (byte)0x89 };
            length = 18;
        } else if (size == 30) {
            // 175 bits => 7 + 168 bits
            n = BigInteger.ONE.shiftLeft(168);
            prefix = new byte[]{ (byte)0x5d };
            length = 21;
        } else {
            throw new IllegalArgumentException("Invalid size");
        }
        String w;
        while (true) {
            e = e.mod(n);
            byte[] b = bytes.concat(prefix, binint.n2b(e, length));
            w = base58.encode(b);
            b = (w + "?").getBytes();
            if (bytes.equ(bytes.sub(hashing.sha256(b), 0, 1), new byte[]{ 0x00 })) break;
            e = e.add(BigInteger.ONE);
        }
        return w;
    }

    private static pair<BigInteger, Boolean> mini_privatekey_decode(String w) {
        if (!(w.length() == 22 || w.length() == 26 || w.length() == 30)) throw new IllegalArgumentException("Invalid length");
        if (w.charAt(0) != 'S') throw new IllegalArgumentException("Invalid prefix");
        base58.decode(w); // validate base58
        byte[] b = (w + "?").getBytes();
        if (!bytes.equ(bytes.sub(hashing.sha256(b), 0, 1), new byte[]{ 0x00 })) throw new IllegalArgumentException("Invalid hash");
        b = w.getBytes();
        byte[] h = hashing.sha256(b);
        BigInteger e = binint.b2n(h);
        if (!secp256k1.rng(e)) throw new IllegalArgumentException("Out of range");
        return new pair<>(e, false);
    }

    public static BigInteger[] publickey_derive(BigInteger e, String coin, boolean testnet) {
        String curve = coins.attr("ecc.curve", coin, testnet);
        if (curve.equals("secp256k1")) {
            return secp256k1.gen(e);
        }
        else
        if (curve.equals("nist256p1")) {
            return nist256p1.gen(e);
        }
        else
        if (curve.equals("ed25519")) {
            String fun = coins.attr("ed25519.hashing", "sha512", coin, testnet);
            if (fun.equals("blake2b")) return ed25519.gen(e, hashing::blake2b);
            if (fun.equals("sha512")) return ed25519.gen(e, hashing::sha512);
            throw new IllegalStateException("Unknown hash function");
        }
        else {
            throw new IllegalStateException("Unknown curve");
        }
    }

    public static String publickey_encode(BigInteger[] P, boolean compressed, String coin, boolean testnet) {
        compressed = coins.attr("publickey.compressed", compressed, coin, testnet);
        byte[][] prefixes = coins.attr("publickey.compressed.prefixes", new byte[][]{ new byte[]{ (byte)0x02 }, new byte[]{ (byte)0x03 } }, coin, testnet);
        String curve = coins.attr("ecc.curve", coin, testnet);
        byte[] b;
        if (curve.equals("secp256k1")) {
            pair<BigInteger, Boolean> t = secp256k1.enc(P);
            BigInteger p = t.l;
            boolean odd = t.r;
            byte[] prefix = prefixes[odd ? 1 : 0];
            b = bytes.concat(prefix, binint.n2b(p, 32));
            if (!compressed) {
                BigInteger x = P[0], y = P[1];
                prefix = new byte[]{ (byte)0x04 };
                b = bytes.concat(prefix, binint.n2b(x, 32), binint.n2b(y, 32));
            }
        }
        else
        if (curve.equals("nist256p1")) {
            pair<BigInteger, Boolean> t = nist256p1.enc(P);
            BigInteger p = t.l;
            boolean odd = t.r;
            byte[] prefix = prefixes[odd ? 1 : 0];
            b = bytes.concat(prefix, binint.n2b(p, 32));
            if (!compressed) {
                BigInteger x = P[0], y = P[1];
                prefix = new byte[]{ (byte)0x04 };
                b = bytes.concat(prefix, binint.n2b(x, 32), binint.n2b(y, 32));
            }
        }
        else
        if (curve.equals("ed25519")) {
            BigInteger x = P[0], y = P[1];
            boolean use_curve = coins.attr("publickey.curve25519", false, coin, testnet);
            BigInteger p = use_curve ? curve25519.dec_ed25519(y) : ed25519.enc(P);
            b = bytes.rev(binint.n2b(p, 32));
        }
        else {
            throw new IllegalStateException("Unknown curve");
        }
        String fmt = coins.attr("publickey.format", coin, testnet);
        String w;
        switch (fmt) {
            case "hex":
                BigInteger x = P[0], y = P[1];
                b = bytes.concat(binint.n2b(x, 32), binint.n2b(y, 32));
                w = binint.b2h(b);
                break;
            case "sec2":
                w = binint.b2h(b);
                break;
            case "base32":
                w = base32_encode(b, "publickey", coin, testnet);
                break;
            case "base58":
                w = base58_encode(b, "publickey", coin, testnet);
                break;
            default:
                throw new IllegalStateException("Unknown format");
        }
        String prefix = coins.attr("publickey.prefix", "", coin, testnet);
        String suffix = coins.attr("publickey.suffix", "", coin, testnet);
        return prefix + w + suffix;
    }

    public static pair<BigInteger[], Boolean> publickey_decode(String w, String coin, boolean testnet) {
        {
            String prefix = coins.attr("publickey.prefix", "", coin, testnet);
            String suffix = coins.attr("publickey.suffix", "", coin, testnet);
            if (w.length() < prefix.length()) throw new IllegalArgumentException("Invalid length");
            String p = w.substring(0, prefix.length());
            if (!p.equals(prefix)) throw new IllegalArgumentException("Invalid prefix");
            w = w.substring(prefix.length());
            if (w.length() < suffix.length()) throw new IllegalArgumentException("Invalid length");
            String s = w.substring(w.length() - suffix.length());
            if (!s.equals(suffix)) throw new IllegalArgumentException("Invalid suffix");
            w = w.substring(0, w.length() - suffix.length());
        }
        String fmt = coins.attr("publickey.format", coin, testnet);
        BigInteger[] P = null;
        byte[] b;
        boolean compressed;
        if (fmt.equals("hex")) {
            b = binint.h2b(w);
            if (b.length != 64) throw new IllegalArgumentException("Invalid length");
            BigInteger x = binint.b2n(bytes.sub(b, 0, 32));
            BigInteger y = binint.b2n(bytes.sub(b, 32));
            P = new BigInteger[]{ x, y };
            compressed = false;
        }
        else
        if (fmt.equals("sec2")) {
            b = binint.h2b(w);
            compressed = true;
        }
        else
        if (fmt.equals("base32")) {
            b = base32_decode(w, "publickey", coin, testnet);
            compressed = true;
        }
        else
        if (fmt.equals("base58")) {
            b = base58_decode(w, "publickey", coin, testnet);
            compressed = true;
        }
        else {
            throw new IllegalStateException("Unkown curve");
        }
        byte[][] prefixes = coins.attr("publickey.compressed.prefixes", new byte[][]{ new byte[]{ (byte)0x02 }, new byte[]{ (byte)0x03 } }, coin, testnet);
        String curve = coins.attr("ecc.curve", coin, testnet);
        if (curve.equals("secp256k1")) {
            if (compressed) {
                if (b.length == 65) {
                    byte[] prefix = bytes.sub(b, 0, 1);
                    b = bytes.sub(b, 1);
                    if (!bytes.equ(prefix, new byte[]{ (byte)0x04 })) throw new IllegalArgumentException("Invalid prefix");
                    BigInteger x = binint.b2n(bytes.sub(b, 0, 32));
                    BigInteger y = binint.b2n(bytes.sub(b, 32));
                    P = new BigInteger[]{ x, y };
                    compressed = false;
                }
            }
            if (!compressed) {
                pair<BigInteger, Boolean> t = secp256k1.enc(P);
                BigInteger p = t.l;
                boolean odd = t.r;
                byte[] prefix = prefixes[odd ? 1 : 0];
                b = bytes.concat(prefix, binint.n2b(p, 32));
            }
            if (b.length != 33) throw new IllegalArgumentException("Invalid length");
            byte[] prefix = bytes.sub(b, 0, 1);
            b = bytes.sub(b, 1);
            if (!bytes.equ(prefix, prefixes[0]) && !bytes.equ(prefix, prefixes[1])) throw new IllegalArgumentException("Invalid prefix");
            boolean odd = bytes.equ(prefix, prefixes[1]);
            BigInteger p = binint.b2n(b);
            P = secp256k1.dec(p, odd);
        }
        else
        if (curve.equals("nist256p1")) {
            if (compressed) {
                if (b.length == 65) {
                    byte[] prefix = bytes.sub(b, 0, 1);
                    b = bytes.sub(b, 1);
                    if (!bytes.equ(prefix, new byte[]{ (byte)0x04 })) throw new IllegalArgumentException("Invalid prefix");
                    BigInteger x = binint.b2n(bytes.sub(b, 0, 32));
                    BigInteger y = binint.b2n(bytes.sub(b, 32));
                    P = new BigInteger[]{ x, y };
                    compressed = false;
                }
            }
            if (!compressed) {
                pair<BigInteger, Boolean> t = nist256p1.enc(P);
                BigInteger p = t.l;
                boolean odd = t.r;
                byte[] prefix = prefixes[odd ? 1 : 0];
                b = bytes.concat(prefix, binint.n2b(p, 32));
            }
            if (b.length != 33) throw new IllegalArgumentException("Invalid length");
            byte[] prefix = bytes.sub(b, 0, 1);
            b = bytes.sub(b, 1);
            if (!bytes.equ(prefix, prefixes[0]) && !bytes.equ(prefix, prefixes[1])) throw new IllegalArgumentException("Invalid prefix");
            boolean odd = bytes.equ(prefix, prefixes[1]);
            BigInteger p = binint.b2n(b);
            P = nist256p1.dec(p, odd);
        }
        else
        if (curve.equals("ed25519")) {
            if (!compressed) {
                BigInteger p = ed25519.enc(P);
                b = bytes.rev(binint.n2b(p, 32));
            }
            if (b.length != 32) throw new IllegalArgumentException("Invalid length");
            BigInteger p = binint.b2n(bytes.rev(b));
            boolean use_curve = coins.attr("publickey.curve25519", false, coin, testnet);
            P = ed25519.dec(use_curve ? curve25519.enc_ed25519(p) : p);
        }
        else {
            throw new IllegalStateException("Unknown curve");
        }
        boolean expected_compressed = coins.attr("publickey.compressed", compressed, coin, testnet);
        if (compressed != expected_compressed) throw new IllegalArgumentException("Compression mismatch");
        return new pair<>(P, compressed);
    }

    private static BigInteger address_derive(BigInteger[] P, boolean compressed, String coin, boolean testnet) {
        compressed = coins.attr("publickey.compressed", compressed, coin, testnet);
        String curve = coins.attr("ecc.curve", coin, testnet);
        byte[] b;
        if (curve.equals("secp256k1")) {
            pair<BigInteger, Boolean> t = secp256k1.enc(P);
            BigInteger p = t.l;
            boolean odd = t.r;
            byte[] prefix = odd ? new byte[]{ (byte)0x03 } : new byte[]{ (byte)0x02 };
            b = bytes.concat(prefix, binint.n2b(p, 32));
            if (!compressed) {
                BigInteger x = P[0], y = P[1];
                prefix = new byte[]{ (byte)0x04 };
                b = bytes.concat(prefix, binint.n2b(x, 32), binint.n2b(y, 32));
            }
        }
        else
        if (curve.equals("nist256p1")) {
            pair<BigInteger, Boolean> t = nist256p1.enc(P);
            BigInteger p = t.l;
            boolean odd = t.r;
            byte[] prefix = odd ? new byte[]{ (byte)0x03 } : new byte[]{ (byte)0x02 };
            b = bytes.concat(prefix, binint.n2b(p, 32));
            if (!compressed) {
                BigInteger x = P[0], y = P[1];
                prefix = new byte[]{ (byte)0x04 };
                b = bytes.concat(prefix, binint.n2b(x, 32), binint.n2b(y, 32));
            }
        }
        else
        if (curve.equals("ed25519")) {
            BigInteger x = P[0], y = P[1];
            boolean use_curve = coins.attr("publickey.curve25519", false, coin, testnet);
            BigInteger p = use_curve ? curve25519.dec_ed25519(y) : ed25519.enc(P);
            b = bytes.rev(binint.n2b(p, 32));
        }
        else {
            throw new IllegalStateException("Unknown curve");
        }
        boolean raw = coins.attr("address.hashing.raw", false, coin, testnet);
        if (raw) {
            BigInteger x = P[0], y = P[1];
            b = bytes.concat(binint.n2b(x, 32), binint.n2b(y, 32));
        }
        byte[] prefix = coins.attr("address.envelope.prefix", new byte[]{ }, coin, testnet);
        byte[] suffix = coins.attr("address.envelope.suffix", new byte[]{ }, coin, testnet);
        b = bytes.concat(prefix, b, suffix);
        String fun = coins.attr("address.hashing", coin, testnet);
        switch (fun) {
            case "identity": break;
            case "sha256": b = hashing.sha256(b); break;
            case "hash160": b = hashing.hash160(b); break;
            case "blake160": b = hashing.blake160(b); break;
            case "keccak256": b = hashing.keccak256(b); break;
            case "securehash": b = hashing.securehash(b); break;
            case "addresshash": b = hashing.addresshash(b); break;
            default: throw new IllegalStateException("Unknown hash function");
        }
        boolean reverse = coins.attr("address.hashing.reverse", false, coin, testnet);
        if (reverse) b = bytes.rev(b);
        int bits = coins.attr("address.bits", 160, coin, testnet);
        b = bytes.sub(b, b.length - bits/8);
        return binint.b2n(b);
    }

    public static String address_encode(BigInteger h, String kind, String coin, boolean testnet) {
        String[] kinds = coins.attr("address.kinds", new String[]{ "address" }, coin, testnet);
        boolean reverse = coins.attr("address.reverse", false, coin, testnet);
        int bits = coins.attr("address.bits", 160, coin, testnet);
        boolean found = false;
        for (String k: kinds) {
            if (kind.equals(k)) {
                found = true;
                break;
            }
        }
        if (!found) throw new IllegalArgumentException("Invalid kind");
        if (h.compareTo(BigInteger.ZERO) < 0 || h.compareTo(BigInteger.ONE.shiftLeft(bits)) >= 0) throw new IllegalArgumentException("Out of range");
        byte[] b = binint.n2b(h, bits / 8);
        if (reverse) b = bytes.rev(b);
        String fmt = coins.attr("address.format", coin, testnet);
        String w;
        switch (fmt) {
            case "decimal":
                w = binint.b2n(b).toString();
                break;
            case "hexmix":
                String s = binint.b2h(b);
                String hex = binint.b2h(hashing.keccak256(s.getBytes()));
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < s.length(); i++) {
                    char c = s.charAt(i);
                    char digit = hex.charAt(i);
                    int value = Integer.parseInt(Character.toString(digit), 16);
                    sb.append(value >= 8 ? Character.toUpperCase(c) : Character.toLowerCase(c));
                }
                w = sb.toString();
                break;
            case "base32":
                w = base32_encode(b, kind, coin, testnet);
                break;
            case "base58":
                w = base58_encode(b, kind, coin, testnet);
                break;
            default:
                throw new IllegalStateException("Unknown format");
        }
        String prefix = coins.attr("address.prefix", "", coin, testnet);
        String suffix = coins.attr("address.suffix", "", coin, testnet);
        return prefix + w + suffix;
    }

    public static pair<BigInteger, String> address_decode(String w, String coin, boolean testnet) {
        String[] kinds = coins.attr("address.kinds", new String[]{ "address" }, coin, testnet);
        boolean reverse = coins.attr("address.reverse", false, coin, testnet);
        int bits = coins.attr("address.bits", 160, coin, testnet);
        String prefix = coins.attr("address.prefix", "", coin, testnet);
        String suffix = coins.attr("address.suffix", "", coin, testnet);
        if (w.length() < prefix.length()) throw new IllegalArgumentException("Invalid length");
        String p = w.substring(0, prefix.length());
        if (!p.equals(prefix)) throw new IllegalArgumentException("Invalid prefix");
        w = w.substring(prefix.length());
        if (w.length() < suffix.length()) throw new IllegalArgumentException("Invalid length");
        String s = w.substring(w.length()-suffix.length());
        if (!s.equals(suffix)) throw new IllegalArgumentException("Invalid suffix");
        w = w.substring(0, w.length()-suffix.length());
        String fmt = coins.attr("address.format", coin, testnet);
        switch (fmt) {
            case "decimal":
                BigInteger h = new BigInteger(w);
                if (h.compareTo(BigInteger.ZERO) < 0 || h.compareTo(BigInteger.ONE.shiftLeft(bits)) >= 0) throw new IllegalArgumentException("Out of range");
                byte[] b = binint.n2b(h, bits / 8);
                if (reverse) b = bytes.rev(b);
                return new pair<>(binint.b2n(b), kinds[0]);
            case "hexmix":
                s = w;
                boolean checksum = !s.equals(s.toUpperCase()) && !s.equals(s.toLowerCase());
                if (checksum) {
                    b = s.toLowerCase().getBytes();
                    String hex = binint.b2h(hashing.keccak256(b));
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < s.length(); i++) {
                        char c = s.charAt(i);
                        char digit = hex.charAt(i);
                        int value = Integer.parseInt(Character.toString(digit), 16);
                        sb.append(value >= 8 ? Character.toUpperCase(c) : Character.toLowerCase(c));
                    }
                    if (!s.equals(sb.toString())) throw new IllegalArgumentException("Invalid hash");
                }
                b = binint.h2b(s);
                if (b.length != bits / 8) throw new IllegalArgumentException("Invalid length");
                if (reverse) b = bytes.rev(b);
                return new pair<>(binint.b2n(b), kinds[0]);
            case "base32":
                for (String kind : kinds) {
                    try {
                        b = base32_decode(w, kind, coin, testnet);
                    } catch (Exception e) {
                        continue;
                    }
                    if (b.length != bits/8) throw new IllegalArgumentException("Invalid length");
                    if (reverse) b = bytes.rev(b);
                    return new pair<>(binint.b2n(b), kind);
                }
                throw new IllegalArgumentException("Invalid prefix");
            case "base58":
                for (String kind : kinds) {
                    try {
                        b = base58_decode(w, kind, coin, testnet);
                    } catch (Exception e) {
                        continue;
                    }
                    if (b.length != bits/8) throw new IllegalArgumentException("Invalid length");
                    if (reverse) b = bytes.rev(b);
                    return new pair<>(binint.b2n(b), kind);
                }
                throw new IllegalArgumentException("Invalid prefix");
            default: throw new IllegalStateException("Unknown format");
        }
    }

    public static String publickey_from_privatekey(String w, String coin, boolean testnet) {
        pair<BigInteger, Boolean> t = privatekey_decode(w, coin, testnet);
        BigInteger e = t.l;
        boolean compressed = t.r;
        BigInteger[] P = publickey_derive(e, coin, testnet);
        return publickey_encode(P, compressed, coin, testnet);
    }

    public static String address_from_publickey(String w, String coin, boolean testnet) {
        pair<BigInteger[], Boolean> t = publickey_decode(w, coin, testnet);
        BigInteger[] P = t.l;
        boolean compressed = t.r;
        BigInteger h = address_derive(P, compressed, coin, testnet);
        return address_encode(h, "address", coin, testnet);
    }

    public static String address_from_script(byte[] script, String kind, String coin, boolean testnet) {
        if (!(kind.equals("script") || kind.equals("script2"))) throw new IllegalArgumentException("Invalid kind");
        byte[] b = hashing.hash160(script);
        BigInteger h = binint.b2n(b);
        return address_encode(h, kind, coin, testnet);
    }

    public static String privatekey_combine(String w1, String w2, boolean compressed, String coin, boolean testnet) {
        pair<BigInteger, Boolean> t1 = privatekey_decode(w1, coin, testnet);
        BigInteger e1 = t1.l;
        boolean compressed1 = t1.r;
        pair<BigInteger, Boolean> t2 = privatekey_decode(w2, coin, testnet);
        BigInteger e2 = t2.l;
        boolean compressed2 = t2.r;
        BigInteger e = secp256k1.aex(e1, e2);
        return privatekey_encode(e, compressed, coin, testnet);
    }

    public static String publickey_combine(String w1, String w2, boolean compressed, String coin, boolean testnet) {
        pair<BigInteger[], Boolean> t1 = publickey_decode(w1, coin, testnet);
        BigInteger[] P1 = t1.l;
        boolean compressed1 = t1.r;
        pair<BigInteger[], Boolean> t2 = publickey_decode(w2, coin, testnet);
        BigInteger[] P2 = t2.l;
        boolean compressed2 = t2.r;
        BigInteger[] P = secp256k1.apt(P1, P2);
        return publickey_encode(P, compressed, coin, testnet);
    }

}
