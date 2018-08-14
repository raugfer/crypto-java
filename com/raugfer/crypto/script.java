package com.raugfer.crypto;

import java.math.BigInteger;

public class script {

    public static final byte[] OP_FALSE = { (byte)0x00 };
    public static final byte[] OP_0 = { (byte)0x00 };
    public static final byte[] OP_PUSHDATA1 = { (byte)0x4c };
    public static final byte[] OP_PUSHDATA2 = { (byte)0x4d };
    public static final byte[] OP_PUSHDATA4 = { (byte)0x4e };
    public static final byte[] OP_1NEGATE = { (byte)0x4f };
    public static final byte[] OP_RESERVED = { (byte)0x50 };
    public static final byte[] OP_TRUE = { (byte)0x51 };
    public static final byte[] OP_1 = { (byte)0x51 };
    public static final byte[] OP_2 = { (byte)0x52 };
    public static final byte[] OP_3 = { (byte)0x53 };
    public static final byte[] OP_4 = { (byte)0x54 };
    public static final byte[] OP_5 = { (byte)0x55 };
    public static final byte[] OP_6 = { (byte)0x56 };
    public static final byte[] OP_7 = { (byte)0x57 };
    public static final byte[] OP_8 = { (byte)0x58 };
    public static final byte[] OP_9 = { (byte)0x59 };
    public static final byte[] OP_10 = { (byte)0x5a };
    public static final byte[] OP_11 = { (byte)0x5b };
    public static final byte[] OP_12 = { (byte)0x5c };
    public static final byte[] OP_13 = { (byte)0x5d };
    public static final byte[] OP_14 = { (byte)0x5e };
    public static final byte[] OP_15 = { (byte)0x5f };
    public static final byte[] OP_16 = { (byte)0x60 };
    public static final byte[] OP_NOP = { (byte)0x61 };
    public static final byte[] OP_VER = { (byte)0x62 };
    public static final byte[] OP_IF = { (byte)0x63 };
    public static final byte[] OP_NOTIF = { (byte)0x64 };
    public static final byte[] OP_VERIF = { (byte)0x65 };
    public static final byte[] OP_VERNOTIF = { (byte)0x66 };
    public static final byte[] OP_ELSE = { (byte)0x67 };
    public static final byte[] OP_ENDIF = { (byte)0x68 };
    public static final byte[] OP_VERIFY = { (byte)0x69 };
    public static final byte[] OP_RETURN = { (byte)0x6a };
    public static final byte[] OP_DROP = { (byte)0x75 };
    public static final byte[] OP_DUP = { (byte)0x76 };
    public static final byte[] OP_EQUAL = { (byte)0x87 };
    public static final byte[] OP_EQUALVERIFY = { (byte)0x88 };
    public static final byte[] OP_RIPEMD160 = { (byte)0xa6 };
    public static final byte[] OP_SHA256 = { (byte)0xa8 };
    public static final byte[] OP_HASH160 = { (byte)0xa9 };
    public static final byte[] OP_CHECKSIG = { (byte)0xac };
    public static final byte[] OP_CHECKMULTISIG = { (byte)0xae };
    public static final byte[] OP_CHECKLOCKTIMEVERIFY = { (byte)0xb1 };
    public static final byte[] OP_CHECKSEQUENCEVERIFY = { (byte)0xb2 };

    public static byte[] OP(int n) {
        if (n < -1 || n > 16) throw new IllegalArgumentException("Invalid size");
        if (n == -1) return OP_1NEGATE;
        if (n == 0) return OP_0;
        return new byte[]{ (byte)(0x50 + n) };
    }

    public static byte[] OP_PUSHDATA(byte[] b) {
        int n = b.length;
        byte [] o;
        byte [] s;
        if (n >= 1<<16) {
            o = OP_PUSHDATA4;
            s = binint.n2b(BigInteger.valueOf(n), 4);
        } else if (n >= 1<<8) {
            o = OP_PUSHDATA2;
            s = binint.n2b(BigInteger.valueOf(n), 2);
        } else if (n >= 76) {
            o = OP_PUSHDATA1;
            s = binint.n2b(BigInteger.valueOf(n), 1);
        } else {
            o = new byte[]{ };
            s = binint.n2b(BigInteger.valueOf(n), 1);
        }
        return bytes.concat(o, s, b);
    }

    public static byte[] scriptsig(byte[] signature, String publickey) {
        byte[] b = binint.h2b(publickey);
        byte[] t1 = OP_PUSHDATA(signature);
        byte[] t2 = OP_PUSHDATA(b);
        return bytes.concat(t1, t2);
    }

    public static byte[] scriptpubkey(String address, String message, String coin, boolean testnet) {
        if (address == null) {
            if (message == null) {
                return OP_RETURN;
            }
            return bytes.concat(OP_RETURN, OP_PUSHDATA(message.getBytes()));
        }
        pair<BigInteger, String> t = wallet.address_decode(address, coin, testnet);
        BigInteger h = t.l;
        String kind = t.r;
        byte[] hash = binint.n2b(h, 20);
        if (kind.equals("address")) {
            // pay-to-pubkey-hash
            return bytes.concat(OP_DUP, OP_HASH160, OP_PUSHDATA(hash), OP_EQUALVERIFY, OP_CHECKSIG);
        }
        if (kind.equals("script") || kind.equals("script2")) {
            // pay-to-script-hash
            return bytes.concat(OP_HASH160, OP_PUSHDATA(hash), OP_EQUAL);
        }
        throw new IllegalArgumentException("Unknown kind");
    }

}
