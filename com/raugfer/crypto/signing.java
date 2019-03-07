package com.raugfer.crypto;

import java.math.BigInteger;

public class signing {

    private static String arb(BigInteger n) {
        String s = binint.n2h(n);
        if (s.length() % 2 == 1) s = "0" + s;
        if (Integer.parseInt(s.substring(0,1), 16) >= 8) s = "00" + s;
        return s;
    }

    private static byte[] signature_encode(Object[] S, String coin, boolean testnet) {
        BigInteger r = (BigInteger) S[0];
        BigInteger s = (BigInteger) S[1];
        Boolean odd = (Boolean) S[2];
        String fmt = coins.attr("signature.format", coin, testnet);
        if (fmt.equals("der")) {
            if (!secp256k1.rng(r)) throw new IllegalArgumentException("Out of range");
            if (!secp256k1.rng(s)) throw new IllegalArgumentException("Out of range");
            if (s.compareTo(secp256k1.n.shiftRight(1)) > 0) throw new IllegalArgumentException("Out of range");
            byte[] hexr = binint.h2b(arb(r));
            byte[] hexs = binint.h2b(arb(s));
            byte[] body = bytes.concat(new byte[]{ 0x02, (byte)hexr.length }, hexr, new byte[]{ 0x02, (byte)hexs.length }, hexs);
            return bytes.concat(new byte[]{ 0x30, (byte)body.length }, body);
        }
        if (fmt.equals("rec")) {
            byte[] hexr = binint.n2b(r, 32);
            byte[] hexs = binint.n2b(s, 32);
            byte[] hexodd = binint.n2b(odd ? BigInteger.ONE : BigInteger.ZERO, 1);
            return bytes.concat(hexr, hexs, hexodd);
        }
        if (fmt.equals("bbe")) {
            byte[] hexr = binint.n2b(r, 32);
            byte[] hexs = binint.n2b(s, 32);
            return bytes.concat(hexr, hexs);
        }
        if (fmt.equals("ble")) {
            byte[] hexr = bytes.rev(binint.n2b(r, 32));
            byte[] hexs = bytes.rev(binint.n2b(s, 32));
            return bytes.concat(hexr, hexs);
        }
        if (fmt.equals("blex")) {
            if (odd) s = s.or(BigInteger.ONE.shiftLeft(255));
            byte[] hexr = bytes.rev(binint.n2b(r, 32));
            byte[] hexs = bytes.rev(binint.n2b(s, 32));
            return bytes.concat(hexr, hexs);
        }
        throw new IllegalStateException("Unknown format");
    }

    public static Object[] signature_decode(byte[] signature, String coin, boolean testnet) {
        String fmt = coins.attr("signature.format", coin, testnet);
        if (fmt.equals("der")) {
            if (signature.length < 2) throw new IllegalArgumentException("Invalid signature");
            byte prefix = signature[0];
            int size = (int)signature[1] & 0xff;
            byte[] body = bytes.sub(signature, 2);
            if (prefix != 0x30) throw new IllegalArgumentException("Invalid signature");
            if (size != body.length) throw new IllegalArgumentException("Invalid signature");
            if (size < 6 || size > 70) throw new IllegalArgumentException("Invalid signature");
            byte prefixr = body[0];
            int sizer = (int)body[1] & 0xff;
            if (prefixr != 0x02) throw new IllegalArgumentException("Invalid signature");
            if (sizer < 1 || sizer > 33) throw new IllegalArgumentException("Invalid signature");
            BigInteger r = binint.b2n(bytes.sub(body, 2, 2+sizer));
            int offset = 2+sizer;
            byte prefixs = body[offset];
            int sizes = (int)body[offset+1] & 0xff;
            if (prefixs != 0x02) throw new IllegalArgumentException("Invalid signature");
            if (sizes < 1 || sizes > 33) throw new IllegalArgumentException("Invalid signature");
            BigInteger s = binint.b2n(bytes.sub(body, offset+2, offset+2+sizes));
            if (size != 4+sizer+sizes) throw new IllegalArgumentException("Invalid signature");
            if (!secp256k1.rng(r)) throw new IllegalArgumentException("Out of range");
            if (!secp256k1.rng(s)) throw new IllegalArgumentException("Out of range");
            if (s.compareTo(secp256k1.n.shiftRight(2)) > 0) throw new IllegalArgumentException("Out of range");
            return new Object[]{ r, s, null };
        }
        if (fmt.equals("rec")) {
            if (signature.length != 65) throw new IllegalArgumentException("Invalid signature");
            BigInteger r = binint.b2n(bytes.sub(signature, 0, 32));
            BigInteger s = binint.b2n(bytes.sub(signature, 32, 64));
            boolean odd = bytes.sub(signature, 64)[0] != 0;
            return new Object[]{ r, s, odd };
        }
        if (fmt.equals("bbe")) {
            if (signature.length != 64) throw new IllegalArgumentException("Invalid signature");
            BigInteger r = binint.b2n(bytes.sub(signature, 0, 32));
            BigInteger s = binint.b2n(bytes.sub(signature, 32));
            return new Object[]{ r, s, null };
        }
        if (fmt.equals("ble")) {
            if (signature.length != 64) throw new IllegalArgumentException("Invalid signature");
            BigInteger r = binint.b2n(bytes.rev(bytes.sub(signature, 0, 32)));
            BigInteger s = binint.b2n(bytes.rev(bytes.sub(signature, 32)));
            return new Object[]{ r, s, null };
        }
        if (fmt.equals("blex")) {
            if (signature.length != 64) throw new IllegalArgumentException("Invalid signature");
            BigInteger r = binint.b2n(bytes.rev(bytes.sub(signature, 0, 32)));
            BigInteger s = binint.b2n(bytes.rev(bytes.sub(signature, 32)));
            boolean odd = s.shiftRight(255).and(BigInteger.ONE).equals(BigInteger.ONE);
            s = s.and(BigInteger.ONE.shiftLeft(255).subtract(BigInteger.ONE));
            return new Object[]{ r, s, odd };
        }
        throw new IllegalStateException("Unknown format");
    }

    public static byte[] signature_create(String privatekey, byte[] data, BigInteger k, String coin, boolean testnet) {
        pair<BigInteger, Boolean> t = wallet.privatekey_decode(privatekey, coin, testnet);
        BigInteger e = t.l;
        boolean compressed = t.r;
        String fun = coins.attr("signature.hashing", "<none>", coin, testnet);
        byte[] prefix = coins.attr("signature.hashing.prefix", new byte[]{ }, coin, testnet);
        byte[] b;
        switch (fun) {
            case "<none>": b = bytes.concat(prefix, data); break;
            case "hash256": b = hashing.hash256(bytes.concat(prefix, data)); break;
            case "keccak256": b = hashing.keccak256(bytes.concat(prefix, data)); break;
            case "sha256": b = hashing.sha256(bytes.concat(prefix, data)); break;
            case "sha512h": b = hashing.sha512h(bytes.concat(prefix, data)); break;
            case "blake1s": b = hashing.blake1s(bytes.concat(prefix, data)); break;
            case "blake2b256": b = hashing.blake2b(data, prefix, 32); break;
            default: throw new IllegalStateException("Unknown hash function");
        }
        byte[] envelop_prefix = coins.attr("signature.hashing.envelop.prefix", new byte[]{ }, coin, testnet);
        b = bytes.concat(envelop_prefix, b);
        BigInteger h = binint.b2n(b);
        int h_len = b.length;
        Object[] S;
        String curve = coins.attr("ecc.curve", coin, testnet);
        if (curve.equals("secp256k1")) {
            if (k == null) k = hashing.det_k(e, b, secp256k1.n);
            S = secp256k1.sgn(e, h, k);
        }
        else
        if (curve.equals("nist256p1")) {
            if (k == null) k = hashing.det_k(e, b, nist256p1.n);
            S = nist256p1.sgn(e, h, k);
        }
        else
        if (curve.equals("ed25519")) {
            fun = coins.attr("ed25519.hashing", "sha512", coin, testnet);
            hashing.hashfun f;
            switch (fun) {
                case "blake2b": f = hashing::blake2b; break;
                case "sha512": f = hashing::sha512; break;
                default: throw new IllegalStateException("Unknown hash function");
            }
            S = ed25519.sgn(e, h, f, h_len);
        }
        else {
            throw new IllegalStateException("Unknown curve");
        }
        return signature_encode(S, coin, testnet);
    }

    public static boolean signature_verify(String publickey, byte[] data, byte[] signature, String coin, boolean testnet) {
        pair<BigInteger[], Boolean> t = wallet.publickey_decode(publickey, coin, testnet);
        BigInteger[] P = t.l;
        boolean compressed = t.r;
        Object[] S = signature_decode(signature, coin, testnet);
        String fun = coins.attr("signature.hashing", "<none>", coin, testnet);
        byte[] prefix = coins.attr("signature.hashing.prefix", new byte[]{ }, coin, testnet);
        byte[] b;
        switch (fun) {
            case "<none>": b = bytes.concat(prefix, data); break;
            case "hash256": b = hashing.hash256(bytes.concat(prefix, data)); break;
            case "keccak256": b = hashing.keccak256(bytes.concat(prefix, data)); break;
            case "sha256": b = hashing.sha256(bytes.concat(prefix, data)); break;
            case "sha512h": b = hashing.sha512h(bytes.concat(prefix, data)); break;
            case "blake1s": b = hashing.blake1s(bytes.concat(prefix, data)); break;
            case "blake2b256": b = hashing.blake2b(data, prefix, 32); break;
            default: throw new IllegalStateException("Unknown hash function");
        }
        byte[] envelop_prefix = coins.attr("signature.hashing.envelop.prefix", new byte[]{ }, coin, testnet);
        b = bytes.concat(envelop_prefix, b);
        BigInteger h = binint.b2n(b);
        int h_len = b.length;
        String curve = coins.attr("ecc.curve", coin, testnet);
        if (curve.equals("secp256k1")) {
            return secp256k1.ver(P, h, S);
        }
        else
        if (curve.equals("nist256p1")) {
            return nist256p1.ver(P, h, S);
        }
        else
        if (curve.equals("ed25519")) {
            fun = coins.attr("ed25519.hashing", "sha512", coin, testnet);
            hashing.hashfun f;
            switch (fun) {
                case "blake2b": f = hashing::blake2b; break;
                case "sha512": f = hashing::sha512; break;
                default: throw new IllegalStateException("Unknown hash function");
            }
            return ed25519.ver(P, h, S, f, h_len);
        }
        else {
            throw new IllegalStateException("Unknown curve");
        }
    }

}
