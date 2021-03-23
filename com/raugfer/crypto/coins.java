package com.raugfer.crypto;

public class coins {

    public static final dict coins = new dict();

    static {
        dict attrs = new dict();
        attrs.put("overloads", "ethereum");
        attrs.put("hdwallet.coin_type", 714);
        attrs.put("chain.id", (_testnetfun) (testnet -> testnet ? 97 : 56));
        attrs.put("confirmations", 15);
        attrs.put("block.time", 3);
        attrs.put("transfer.gaslimit", 21000);
        coins.put("binancecoin", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("ecc.curve", "secp256k1");
        attrs.put("base58.check", "hash256:4");
        attrs.put("privatekey.format", "base58");
        attrs.put("publickey.format", "sec2");
        attrs.put("address.format", "base58");
        attrs.put("address.hashing", "hash160");
        attrs.put("address.kinds", new String[]{ "address", "script" });
        attrs.put("address.mode", "utxo");
        attrs.put("privatekey.base58.prefix", (_testnetfun) (testnet -> testnet ? new byte[]{ (byte)0xef } : new byte[]{ (byte)0x80 }));
        attrs.put("address.base58.prefix", (_testnetfun) (testnet -> testnet ? new byte[]{ (byte)0x6f } : new byte[]{ (byte)0x00 }));
        attrs.put("script.base58.prefix", (_testnetfun) (testnet -> testnet ? new byte[]{ (byte)0xc4 } : new byte[]{ (byte)0x05 }));
        attrs.put("xprivatekey.base58.prefix", (_testnetfun) (testnet -> testnet
                ? new byte[]{ (byte)0x04, (byte)0x35, (byte)0x83, (byte)0x94 }
                : new byte[]{ (byte)0x04, (byte)0x88, (byte)0xad, (byte)0xe4 }
        ));
        attrs.put("xpublickey.base58.prefix", (_testnetfun) (testnet -> testnet
                ? new byte[]{ (byte)0x04, (byte)0x35, (byte)0x87, (byte)0xcf }
                : new byte[]{ (byte)0x04, (byte)0x88, (byte)0xb2, (byte)0x1e }
        ));
        attrs.put("hdwallet.coin_type", 0);
        attrs.put("transaction.format", "inout");
        attrs.put("transaction.hashing", "hash256");
        attrs.put("transaction.hashing.reverse", true);
        attrs.put("signature.format", "der");
        attrs.put("signature.hashing", "hash256");
        attrs.put("sighash.method", "default");
        attrs.put("confirmations", 2);
        attrs.put("block.time", 10 * 60);
        attrs.put("decimals", 8);
        coins.put("bitcoin", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "bitcoin");
        attrs.put("hdwallet.coin_type", 145);
        attrs.put("sighash.method", "forkid");
        attrs.put("sighash.forkid", 0);
        attrs.put("confirmations", 6);
        coins.put("bitcoincash", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "bitcoin");
        attrs.put("privatekey.base58.prefix", (_testnetfun) (testnet -> testnet ? new byte[]{ (byte)0xef } : new byte[]{ (byte)0x80 }));
        attrs.put("address.base58.prefix", (_testnetfun) (testnet -> testnet ? new byte[]{ (byte)0x6f } : new byte[]{ (byte)0x26 }));
        attrs.put("script.base58.prefix", (_testnetfun) (testnet -> testnet ? new byte[]{ (byte)0xc4 } : new byte[]{ (byte)0x17 }));
        attrs.put("hdwallet.coin_type", 156);
        attrs.put("sighash.method", "forkid");
        attrs.put("sighash.forkid", 79);
        attrs.put("confirmations", 10);
        coins.put("bitcoingold", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "bitcoincash");
        attrs.put("hdwallet.coin_type", 236);
        attrs.put("confirmations", 72);
        attrs.put("default_fee", 960);
        coins.put("bitcoinsv", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("ecc.curve", "ed25519");
        attrs.put("address.base58.check", "crc32:5");
        attrs.put("privatekey.format", "hex");
        attrs.put("publickey.format", "sec2");
        attrs.put("address.envelope.prefix", new byte[]{ (byte)0x83, (byte)0x00, (byte)0x82, (byte)0x00, (byte)0x58, (byte)0x40 });
        attrs.put("address.envelope.suffix", (_testnetfun) (testnet -> bytes.concat(
                new byte[32],
                testnet
                    ? new byte[]{ (byte)0xa1, (byte)0x02, (byte)0x45, (byte)0x1a, (byte)0x41, (byte)0x70, (byte)0xcb, (byte)0x17 }
                    : new byte[]{ (byte)0xa0 }
        )));
        attrs.put("address.format", "base58");
        attrs.put("address.hashing", "addresshash");
        attrs.put("address.bits", 224);
        attrs.put("address.mode", "utxo");
        attrs.put("address.base58.prefix", (_testnetfun) (testnet -> bytes.concat(
                new byte[]{ (byte)0x82, (byte)0xd8, (byte)0x18, (byte)0x58 },
                testnet
                        ? new byte[]{ (byte)0x28 }
                        : new byte[]{ (byte)0x21 },
                new byte[]{ (byte)0x83, (byte)0x58, (byte)0x1c }
        )));
        attrs.put("address.base58.suffix", (_testnetfun) (testnet -> bytes.concat(
                testnet
                        ? new byte[]{ (byte)0xa1, (byte)0x02, (byte)0x45, (byte)0x1a, (byte)0x41, (byte)0x70, (byte)0xcb, (byte)0x17 }
                        : new byte[]{ (byte)0xa0 },
                new byte[]{ (byte)0x00 }
        )));
        attrs.put("xprivatekey.base58.prefix", (_testnetfun) (testnet -> testnet
                ? new byte[]{ (byte)0x04, (byte)0x35, (byte)0x83, (byte)0x94 }
                : new byte[]{ (byte)0x04, (byte)0x88, (byte)0xad, (byte)0xe4 }
        ));
        attrs.put("xpublickey.base58.prefix", (_testnetfun) (testnet -> testnet
                ? new byte[]{ (byte)0x04, (byte)0x35, (byte)0x87, (byte)0xcf }
                : new byte[]{ (byte)0x04, (byte)0x88, (byte)0xb2, (byte)0x1e }
        ));
        attrs.put("hdwallet.coin_type", 1815);
        attrs.put("transaction.format", "cbor");
        attrs.put("transaction.hashing", "blake2b256");
        attrs.put("signature.format", "ble");
        attrs.put("signature.hashing", "blake2b256");
        attrs.put("signature.hashing.envelop.prefix", (_testnetfun) (testnet -> bytes.concat(
                new byte[]{ (byte)0x01, (byte)0x1a },
                testnet
                    ? new byte[]{ (byte)0x41, (byte)0x70, (byte)0xcb, (byte)0x17 }
                    : new byte[]{ (byte)0x2d, (byte)0x96, (byte)0x4a, (byte)0x09 },
                new byte[]{ (byte)0x58, (byte)0x20 })
        ));
        attrs.put("confirmations", 20);
        attrs.put("block.time", 20);
        attrs.put("decimals", 6);
        coins.put("cardano", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "bitcoin");
        attrs.put("privatekey.base58.prefix", (_testnetfun) (testnet -> testnet ? new byte[]{ (byte)0xef } : new byte[]{ (byte)0xcc }));
        attrs.put("address.base58.prefix", (_testnetfun) (testnet -> testnet ? new byte[]{ (byte)0x8c } : new byte[]{ (byte)0x4c }));
        attrs.put("script.base58.prefix", (_testnetfun) (testnet -> testnet ? new byte[]{ (byte)0x13 } : new byte[]{ (byte)0x10 }));
        attrs.put("hdwallet.coin_type", 5);
        attrs.put("confirmations", 6);
        attrs.put("block.time", 5 * 30);
        attrs.put("default_fee", 6400);
        coins.put("dash", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "bitcoin");
        attrs.put("base58.check", "blake256:4");
        attrs.put("privatekey.base58.check", "blake1s:4");
        attrs.put("privatekey.compressed", false);
        attrs.put("publickey.format", "base58");
        attrs.put("publickey.compressed", true);
        attrs.put("publickey.compressed.prefixes", new byte[][]{ new byte[]{ (byte)0x00 }, new byte[]{ (byte)0x80 } });
        attrs.put("address.hashing", "blake160");
        attrs.put("privatekey.base58.prefix", (_testnetfun) (testnet -> testnet ? new byte[]{ (byte)0x23, (byte)0x0e, (byte)0x00 } : new byte[]{ (byte)0x22, (byte)0xde, (byte)0x00 }));
        attrs.put("publickey.base58.prefix", (_testnetfun) (testnet -> testnet ? new byte[]{ (byte)0x28, (byte)0xf7 } : new byte[]{ (byte)0x13, (byte)0x86 }));
        attrs.put("address.base58.prefix", (_testnetfun) (testnet -> testnet ? new byte[]{ (byte)0x0f, (byte)0x21 } : new byte[]{ (byte)0x07, (byte)0x3f }));
        attrs.put("scrip.base58.prefix", (_testnetfun) (testnet -> testnet ? new byte[]{ (byte)0x0e, (byte)0xfc } : new byte[]{ (byte)0x07, (byte)0x1a }));
        attrs.put("xprivatekey.base58.check", "blake256:4");
        attrs.put("xpublickey.base58.check", "blake256:4");
        attrs.put("xprivatekey.base58.prefix", (_testnetfun) (testnet -> testnet
                ? new byte[]{ (byte)0x04, (byte)0x35, (byte)0x83, (byte)0x97 }
                : new byte[]{ (byte)0x02, (byte)0xfd, (byte)0xa4, (byte)0xe8 }
        ));
        attrs.put("xpublickey.base58.prefix", (_testnetfun) (testnet -> testnet
                ? new byte[]{ (byte)0x04, (byte)0x35, (byte)0x87, (byte)0xd1 }
                : new byte[]{ (byte)0x02, (byte)0xfd, (byte)0xa9, (byte)0x26 }
        ));
        attrs.put("hdwallet.coin_type", 42);
        attrs.put("transaction.format", "dcrinout");
        attrs.put("transaction.hashing", "blake1s");
        attrs.put("signature.hashing", "blake1s");
        attrs.put("confirmations", 6);
        attrs.put("block.time", (_testnetfun) (testnet -> testnet ? 2 * 60 : 5 * 60));
        coins.put("decred", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "bitcoin");
        attrs.put("address.kinds", new String[]{ "address", "script", "script2" });
        attrs.put("privatekey.base58.prefix", (_testnetfun) (testnet -> testnet ? new byte[]{ (byte)0xfe } : new byte[]{ (byte)0x80 }));
        attrs.put("address.base58.prefix", (_testnetfun) (testnet -> testnet ? new byte[]{ (byte)0x7e } : new byte[]{ (byte)0x1e }));
        attrs.put("script.base58.prefix", (_testnetfun) (testnet -> testnet ? new byte[]{ (byte)0xc4 } : new byte[]{ (byte)0x05 }));
        attrs.put("script2.base58.prefix", (_testnetfun) (testnet -> testnet ? new byte[]{ (byte)0x8c } : new byte[]{ (byte)0x3f }));
        attrs.put("hdwallet.coin_type", 20);
        attrs.put("confirmations", 400);
        attrs.put("block.time", 15);
        attrs.put("default_fee", 64000);
        coins.put("digibyte", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "bitcoin");
        attrs.put("privatekey.base58.prefix", (_testnetfun) (testnet -> testnet ? new byte[]{ (byte)0xf1 } : new byte[]{ (byte)0x9e }));
        attrs.put("address.base58.prefix", (_testnetfun) (testnet -> testnet ? new byte[]{ (byte)0x71 } : new byte[]{ (byte)0x1e }));
        attrs.put("script.base58.prefix", (_testnetfun) (testnet -> testnet ? new byte[]{ (byte)0xc4 } : new byte[]{ (byte)0x16 }));
        attrs.put("xprivatekey.base58.prefix", (_testnetfun) (testnet -> testnet
                ? new byte[]{ (byte)0x04, (byte)0x35, (byte)0x83, (byte)0x94 }
                : new byte[]{ (byte)0x02, (byte)0xfa, (byte)0xc3, (byte)0x98 }
        ));
        attrs.put("xpublickey.base58.prefix", (_testnetfun) (testnet -> testnet
                ? new byte[]{ (byte)0x04, (byte)0x35, (byte)0x87, (byte)0xcf }
                : new byte[]{ (byte)0x02, (byte)0xfa, (byte)0xca, (byte)0xfd }
        ));
        attrs.put("hdwallet.coin_type", 3);
        attrs.put("confirmations", 6);
        attrs.put("block.time", 60);
        coins.put("dogecoin", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("ecc.curve", "secp256k1");
        attrs.put("privatekey.format", "hex");
        attrs.put("publickey.format", "hex");
        attrs.put("address.format", "hexmix");
        attrs.put("address.hashing", "keccak256");
        attrs.put("address.hashing.raw", true);
        attrs.put("address.prefix", "0x");
        attrs.put("address.mode", "account");
        attrs.put("xprivatekey.base58.prefix", (_testnetfun) (testnet -> testnet
                ? new byte[]{ (byte)0x04, (byte)0x35, (byte)0x83, (byte)0x94 }
                : new byte[]{ (byte)0x04, (byte)0x88, (byte)0xad, (byte)0xe4 }
        ));
        attrs.put("xpublickey.base58.prefix", (_testnetfun) (testnet -> testnet
                ? new byte[]{ (byte)0x04, (byte)0x35, (byte)0x87, (byte)0xcf }
                : new byte[]{ (byte)0x04, (byte)0x88, (byte)0xb2, (byte)0x1e }
        ));
        attrs.put("hdwallet.coin_type", 60);
        attrs.put("transaction.format", "rlp");
        attrs.put("transaction.hashing", "keccak256");
        attrs.put("signature.format", "rec");
        attrs.put("signature.hashing", "keccak256");
        attrs.put("chain.id", (_testnetfun) (testnet -> testnet ? 3 : 1));
        attrs.put("confirmations", 36);
        attrs.put("block.time", 15);
        attrs.put("decimals", 18);
        attrs.put("transfer.gaslimit", 21000);
        coins.put("ethereum", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "ethereum");
        attrs.put("hdwallet.coin_type", 61);
        attrs.put("chain.id", (_testnetfun) (testnet -> testnet ? 62 : 61));
        attrs.put("confirmations", 72);
        attrs.put("transfer.gaslimit", 21000);
        coins.put("ethereumclassic", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "ethereum");
        attrs.put("hdwallet.coin_type", 60); // may change in the future
        attrs.put("chain.id", (_testnetfun) (testnet -> testnet ? 4002 : 250));
        attrs.put("confirmations", 36);
        attrs.put("block.time", 10);
        attrs.put("transfer.gaslimit", 21000);
        coins.put("fantom", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("ecc.curve", "ed25519");
        attrs.put("privatekey.format", "sec2");
        attrs.put("publickey.format", "sec2");
        attrs.put("address.format", "decimal");
        attrs.put("address.hashing", "sha256");
        attrs.put("address.hashing.reverse", true);
        attrs.put("address.bits", 64);
        attrs.put("address.suffix", "L");
        attrs.put("address.mode", "account");
        attrs.put("xprivatekey.base58.prefix", (_testnetfun) (testnet -> testnet
                ? new byte[]{ (byte)0x04, (byte)0x35, (byte)0x83, (byte)0x94 }
                : new byte[]{ (byte)0x04, (byte)0x88, (byte)0xad, (byte)0xe4 }
        ));
        attrs.put("xpublickey.base58.prefix", (_testnetfun) (testnet -> testnet
                ? new byte[]{ (byte)0x04, (byte)0x35, (byte)0x87, (byte)0xcf }
                : new byte[]{ (byte)0x04, (byte)0x88, (byte)0xb2, (byte)0x1e }
        ));
        attrs.put("hdwallet.coin_type", 134);
        attrs.put("transaction.format", "liskdatablock");
        attrs.put("transaction.hashing", "sha256");
        attrs.put("transaction.hashing.reverse", true);
        attrs.put("transaction.id.bits", 64);
        attrs.put("transaction.id.format", "decimal");
        attrs.put("signature.format", "ble");
        attrs.put("signature.hashing", "sha256");
        attrs.put("confirmations", 304);
        attrs.put("block.time", 10);
        attrs.put("decimals", 8);
        coins.put("lisk", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "bitcoin");
        attrs.put("address.kinds", new String[]{ "address", "script", "script2" });
        attrs.put("privatekey.base58.prefix", (_testnetfun) (testnet -> testnet ? new byte[]{ (byte)0xef } : new byte[]{ (byte)0xb0 }));
        attrs.put("address.base58.prefix", (_testnetfun) (testnet -> testnet ? new byte[]{ (byte)0x6f } : new byte[]{ (byte)0x30 }));
        attrs.put("script.base58.prefix", (_testnetfun) (testnet -> testnet ? new byte[]{ (byte)0xc4 } : new byte[]{ (byte)0x05 }));
        attrs.put("script2.base58.prefix", (_testnetfun) (testnet -> testnet ? new byte[]{ (byte)0x3a } : new byte[]{ (byte)0x32 }));
/*
		'xprivatekey.base58.prefix': lambda testnet: b'\x04\x36\xef\x7d' if testnet else b'\x01\x9d\x9c\xfe',
		'xpublickey.base58.prefix': lambda testnet: b'\x04\x36\xf6\xe1' if testnet else b'\x01\x9d\xa4\x62',
*/
        attrs.put("hdwallet.coin_type", 2);
        attrs.put("confirmations", 6);
        attrs.put("block.time", 5 * 30);
        attrs.put("default_fee", 100000);
        coins.put("litecoin", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("ecc.curve", "ed25519");
        attrs.put("ed25519.hashing", "blake2b");
        attrs.put("base32.digits", "13456789abcdefghijkmnopqrstuwxyz");
        attrs.put("base32.check", "blake2b:5");
        attrs.put("privatekey.format", "hex");
        attrs.put("publickey.format", "sec2");
        attrs.put("address.format", "base32");
        attrs.put("address.hashing", "identity");
        attrs.put("address.bits", 256);
        attrs.put("address.prefix", "xrb_");
        attrs.put("address.base32.prefix", new byte[]{ });
        attrs.put("address.mode", "account");
        attrs.put("xprivatekey.base58.prefix", (_testnetfun) (testnet -> testnet
                ? new byte[]{ (byte)0x04, (byte)0x35, (byte)0x83, (byte)0x94 }
                : new byte[]{ (byte)0x04, (byte)0x88, (byte)0xad, (byte)0xe4 }
        ));
        attrs.put("xpublickey.base58.prefix", (_testnetfun) (testnet -> testnet
                ? new byte[]{ (byte)0x04, (byte)0x35, (byte)0x87, (byte)0xcf }
                : new byte[]{ (byte)0x04, (byte)0x88, (byte)0xb2, (byte)0x1e }
        ));
        attrs.put("hdwallet.coin_type", 165);
        attrs.put("transaction.format", "raiblock");
        attrs.put("transaction.hashing", "blake2b256");
        attrs.put("transaction.pow.threshold", (_testnetfun) (testnet -> testnet ? 0xff00000000000000L : 0xffffffc000000000L));
        attrs.put("signature.format", "ble");
        attrs.put("signature.hashing", "blake2b256");
        attrs.put("voting.representative", (_testnetfun) (testnet -> testnet ? "xrb_1beta1ayfkpj1tfbhi3e9ihkocjkqi6ms5e4xrbmbybqnkza1e5jrake8wai" : "xrb_1nanode8ngaakzbck8smq6ru9bethqwyehomf79sae1k7xd47dkidjqzffeg"));
        attrs.put("confirmations", 1);
        attrs.put("block.time", 10);
        attrs.put("decimals", 30);
        coins.put("nano", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("ecc.curve", "nist256p1");
        attrs.put("base58.check", "hash256:4");
        attrs.put("privatekey.format", "base58");
        attrs.put("privatekey.compressed", true);
        attrs.put("privatekey.mini", false);
        attrs.put("publickey.format", "sec2");
        attrs.put("publickey.compressed", true);
        attrs.put("address.format", "base58");
        attrs.put("address.hashing", "hash160");
        attrs.put("address.envelope.prefix", new byte[]{ (byte)0x21 });
        attrs.put("address.envelope.suffix", new byte[]{ (byte)0xac });
        attrs.put("address.mode", "utxo");
        attrs.put("privatekey.base58.prefix", (_testnetfun) (testnet -> testnet ? new byte[]{ (byte)0x80 } : new byte[]{ (byte)0x80 }));
        attrs.put("address.base58.prefix", (_testnetfun) (testnet -> testnet ? new byte[]{ (byte)0x17 } : new byte[]{ (byte)0x17 }));
        attrs.put("xprivatekey.base58.prefix", (_testnetfun) (testnet -> testnet
                ? new byte[]{ (byte)0x04, (byte)0x35, (byte)0x83, (byte)0x94 }
                : new byte[]{ (byte)0x04, (byte)0x88, (byte)0xad, (byte)0xe4 }
        ));
        attrs.put("xpublickey.base58.prefix", (_testnetfun) (testnet -> testnet
                ? new byte[]{ (byte)0x04, (byte)0x35, (byte)0x87, (byte)0xcf }
                : new byte[]{ (byte)0x04, (byte)0x88, (byte)0xb2, (byte)0x1e }
        ));
        attrs.put("hdwallet.coin_type", 888);
        attrs.put("transaction.format", "neoinout");
        attrs.put("transaction.hashing", "hash256");
        attrs.put("transaction.hashing.reverse", true);
        attrs.put("signature.format", "bbe");
        attrs.put("signature.hashing", "sha256");
        attrs.put("confirmations", 10);
        attrs.put("block.time", 15);
        attrs.put("decimals", 0);
        attrs.put("asset", "c56f33fc6ecfcd0c225c4ab356fee59390af8560be0e930faebe74a6daff7c9b");
        coins.put("neo", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "neo");
        attrs.put("decimals", 8);
        attrs.put("asset", "602c79718b16e442de58778e148d0b1084e3b2dffd5de6b7b16cee7969282de7");
        coins.put("neogas", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "bitcoin");
        attrs.put("privatekey.base58.prefix", (_testnetfun) (testnet -> testnet ? new byte[]{ (byte)0xef } : new byte[]{ (byte)0x80 }));
        attrs.put("address.base58.prefix", (_testnetfun) (testnet -> testnet ? new byte[]{ (byte)0x78 } : new byte[]{ (byte)0x3a }));
        attrs.put("script.base58.prefix", (_testnetfun) (testnet -> testnet ? new byte[]{ (byte)0x6e } : new byte[]{ (byte)0x32 }));
        attrs.put("hdwallet.coin_type", 2301);
        attrs.put("confirmations", 20);
        attrs.put("block.time", 2 * 64);
        attrs.put("default_fee", 2560000);
        coins.put("qtum", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("ecc.curve", "secp256k1");
        attrs.put("base58.digits", "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz");
        attrs.put("base58.check", "hash256:4");
        attrs.put("privatekey.format", "base58");
        attrs.put("privatekey.compressed", false);
        attrs.put("privatekey.mini", false);
        attrs.put("publickey.format", "base58");
        attrs.put("publickey.compressed", true);
        attrs.put("address.format", "base58");
        attrs.put("address.hashing", "hash160");
        attrs.put("address.mode", "account");
        attrs.put("privatekey.base58.prefix", new byte[]{ (byte)0x22 });
        attrs.put("publickey.base58.prefix", new byte[]{ (byte)0x23 });
        attrs.put("address.base58.prefix", new byte[]{ (byte)0x00 });
        attrs.put("xprivatekey.base58.prefix", (_testnetfun) (testnet -> testnet
                ? new byte[]{ (byte)0x04, (byte)0x35, (byte)0x83, (byte)0x94 }
                : new byte[]{ (byte)0x04, (byte)0x88, (byte)0xad, (byte)0xe4 }
        ));
        attrs.put("xpublickey.base58.prefix", (_testnetfun) (testnet -> testnet
                ? new byte[]{ (byte)0x04, (byte)0x35, (byte)0x87, (byte)0xcf }
                : new byte[]{ (byte)0x04, (byte)0x88, (byte)0xb2, (byte)0x1e }
        ));
        attrs.put("hdwallet.coin_type", 144);
        attrs.put("transaction.format", "serial");
        attrs.put("transaction.hashing", "sha512h");
        attrs.put("transaction.hashing.prefix", new byte[]{ (byte)0x54, (byte)0x58, (byte)0x4e, (byte)0x00 });
        attrs.put("signature.format", "der");
        attrs.put("signature.hashing", "sha512h");
        attrs.put("signature.hashing.prefix", new byte[]{ (byte)0x53, (byte)0x54, (byte)0x58, (byte)0x00 });
        attrs.put("account.reserved", 20000000);
        attrs.put("confirmations", 12);
        attrs.put("block.time", 4);
        attrs.put("decimals", 6);
        coins.put("ripple", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("ecc.curve", "ed25519");
        attrs.put("base32.digits", "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567");
        attrs.put("base32.check", "crc16:2");
        attrs.put("privatekey.format", "base32");
        attrs.put("publickey.format", "base32");
        attrs.put("address.format", "base32");
        attrs.put("address.hashing", "identity");
        attrs.put("address.bits", 256);
        attrs.put("address.mode", "account");
        attrs.put("privatekey.base32.prefix", new byte[]{ (byte)0x90 });
        attrs.put("publickey.base32.prefix", new byte[]{ (byte)0x30 });
        attrs.put("address.base32.prefix", new byte[]{ (byte)0x30 });
        attrs.put("xprivatekey.base58.prefix", (_testnetfun) (testnet -> testnet
                ? new byte[]{ (byte)0x04, (byte)0x35, (byte)0x83, (byte)0x94 }
                : new byte[]{ (byte)0x04, (byte)0x88, (byte)0xad, (byte)0xe4 }
        ));
        attrs.put("xpublickey.base58.prefix", (_testnetfun) (testnet -> testnet
                ? new byte[]{ (byte)0x04, (byte)0x35, (byte)0x87, (byte)0xcf }
                : new byte[]{ (byte)0x04, (byte)0x88, (byte)0xb2, (byte)0x1e }
        ));
        attrs.put("hdwallet.coin_type", 148);
        attrs.put("transaction.format", "xdr");
        attrs.put("transaction.hashing", "sha256");
        attrs.put("transaction.hashing.prefix", (_testnetfun)(testnet -> testnet
            ? new byte[]{
                (byte)0xce, (byte)0xe0, (byte)0x30, (byte)0x2d, (byte)0x59, (byte)0x84,
                (byte)0x4d, (byte)0x32, (byte)0xbd, (byte)0xca, (byte)0x91, (byte)0x5c,
                (byte)0x82, (byte)0x03, (byte)0xdd, (byte)0x44, (byte)0xb3, (byte)0x3f,
                (byte)0xbb, (byte)0x7e, (byte)0xdc, (byte)0x19, (byte)0x05, (byte)0x1e,
                (byte)0xa3, (byte)0x7a, (byte)0xbe, (byte)0xdf, (byte)0x28, (byte)0xec,
                (byte)0xd4, (byte)0x72, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x02,
            }
            : new byte[]{
                (byte)0x7a, (byte)0xc3, (byte)0x39, (byte)0x97, (byte)0x54, (byte)0x4e,
                (byte)0x31, (byte)0x75, (byte)0xd2, (byte)0x66, (byte)0xbd, (byte)0x02,
                (byte)0x24, (byte)0x39, (byte)0xb2, (byte)0x2c, (byte)0xdb, (byte)0x16,
                (byte)0x50, (byte)0x8c, (byte)0x01, (byte)0x16, (byte)0x3f, (byte)0x26,
                (byte)0xe5, (byte)0xcb, (byte)0x2a, (byte)0x3e, (byte)0x10, (byte)0x45,
                (byte)0xa9, (byte)0x79, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x02,
            }
        ));
        attrs.put("signature.format", "ble");
        attrs.put("signature.hashing", "sha256");
        attrs.put("signature.hashing.prefix", (_testnetfun) (testnet -> testnet
            ? new byte[]{
                (byte)0xce, (byte)0xe0, (byte)0x30, (byte)0x2d, (byte)0x59, (byte)0x84,
                (byte)0x4d, (byte)0x32, (byte)0xbd, (byte)0xca, (byte)0x91, (byte)0x5c,
                (byte)0x82, (byte)0x03, (byte)0xdd, (byte)0x44, (byte)0xb3, (byte)0x3f,
                (byte)0xbb, (byte)0x7e, (byte)0xdc, (byte)0x19, (byte)0x05, (byte)0x1e,
                (byte)0xa3, (byte)0x7a, (byte)0xbe, (byte)0xdf, (byte)0x28, (byte)0xec,
                (byte)0xd4, (byte)0x72, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x02,
            }
            : new byte[]{
                (byte)0x7a, (byte)0xc3, (byte)0x39, (byte)0x97, (byte)0x54, (byte)0x4e,
                (byte)0x31, (byte)0x75, (byte)0xd2, (byte)0x66, (byte)0xbd, (byte)0x02,
                (byte)0x24, (byte)0x39, (byte)0xb2, (byte)0x2c, (byte)0xdb, (byte)0x16,
                (byte)0x50, (byte)0x8c, (byte)0x01, (byte)0x16, (byte)0x3f, (byte)0x26,
                (byte)0xe5, (byte)0xcb, (byte)0x2a, (byte)0x3e, (byte)0x10, (byte)0x45,
                (byte)0xa9, (byte)0x79, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x02,
            }
        ));
        attrs.put("account.reserved", 10000000);
        attrs.put("confirmations", 2);
        attrs.put("block.time", 5);
        attrs.put("decimals", 7);
        coins.put("stellar", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("ecc.curve", "secp256k1");
        attrs.put("base58.check", "hash256:4");
        attrs.put("privatekey.format", "hex");
        attrs.put("publickey.format", "sec2");
        attrs.put("address.format", "base58");
        attrs.put("address.hashing", "keccak256");
        attrs.put("address.hashing.raw", true);
        attrs.put("address.mode", "account");
        attrs.put("address.base58.prefix", new byte[]{ (byte)0x41 });
        attrs.put("xprivatekey.base58.prefix", (_testnetfun) (testnet -> testnet
                ? new byte[]{ (byte)0x04, (byte)0x35, (byte)0x83, (byte)0x94 }
                : new byte[]{ (byte)0x04, (byte)0x88, (byte)0xad, (byte)0xe4 }
        ));
        attrs.put("xpublickey.base58.prefix", (_testnetfun) (testnet -> testnet
                ? new byte[]{ (byte)0x04, (byte)0x35, (byte)0x87, (byte)0xcf }
                : new byte[]{ (byte)0x04, (byte)0x88, (byte)0xb2, (byte)0x1e }
        ));
        attrs.put("hdwallet.coin_type", 195);
        attrs.put("transaction.format", "protobuf");
        attrs.put("transaction.hashing", "sha256");
        attrs.put("signature.format", "rec");
        attrs.put("signature.hashing", "sha256");
        attrs.put("account.reserved", 1000000);
        attrs.put("confirmations", 20);
        attrs.put("block.time", 15);
        attrs.put("decimals", 6);
        coins.put("tron", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("ecc.curve", "ed25519");
        attrs.put("address.base58.check", "securehash:4");
        attrs.put("privatekey.format", "base58");
        attrs.put("privatekey.reverse", true);
        attrs.put("privatekey.mini", false);
        attrs.put("publickey.format", "base58");
        attrs.put("publickey.curve25519", true);
        attrs.put("address.format", "base58");
        attrs.put("address.hashing", "securehash");
        attrs.put("address.hashing.reverse", true);
        attrs.put("address.reverse", true);
        attrs.put("address.mode", "account");
        attrs.put("address.base58.prefix", (_testnetfun) (testnet -> testnet
                ? new byte[]{ (byte)0x01, (byte)'T' }
                : new byte[]{ (byte)0x01, (byte)'W' }
        ));
        attrs.put("xprivatekey.base58.prefix", (_testnetfun) (testnet -> testnet
                ? new byte[]{ (byte)0x04, (byte)0x35, (byte)0x83, (byte)0x94 }
                : new byte[]{ (byte)0x04, (byte)0x88, (byte)0xad, (byte)0xe4 }
        ));
        attrs.put("xpublickey.base58.prefix", (_testnetfun) (testnet -> testnet
                ? new byte[]{ (byte)0x04, (byte)0x35, (byte)0x87, (byte)0xcf }
                : new byte[]{ (byte)0x04, (byte)0x88, (byte)0xb2, (byte)0x1e }
        ));
        attrs.put("hdwallet.coin_type", 5741564);
        attrs.put("transaction.format", "wavestx");
        attrs.put("transaction.hashing", "blake2b256");
        attrs.put("transaction.id.format", "base58");
        attrs.put("signature.format", "blex");
        attrs.put("confirmations", 20);
        attrs.put("block.time", 30);
        attrs.put("decimals", 8);
        coins.put("waves", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "bitcoin");
        attrs.put("privatekey.base58.prefix", (_testnetfun) (testnet -> testnet ? new byte[]{ (byte)0xef } : new byte[]{ (byte)0x80 }));
        attrs.put("address.base58.prefix", (_testnetfun) (testnet -> testnet ? new byte[]{ (byte)0x1d, (byte)0x25 } : new byte[]{ (byte)0x1c, (byte)0xb8 }));
        attrs.put("script.base58.prefix", (_testnetfun) (testnet -> testnet ? new byte[]{ (byte)0x1c, (byte)0xba } : new byte[]{ (byte)0x1c, (byte)0xbd }));
        attrs.put("hdwallet.coin_type", 133);
        attrs.put("transaction.version", 0x80000004);
        attrs.put("transaction.groupid", 0x892f2085);
        attrs.put("signature.hashing", "blake2b256");
        attrs.put("signature.hashing.prefix", bytes.concat("ZcashSigHash".getBytes(), new byte[]{ (byte)0x60, (byte)0x0e, (byte)0xb4, (byte)0x2b }));
        attrs.put("sighash.method", "sapling");
        attrs.put("confirmations", 20);
        attrs.put("block.time", 5 * 30);
        attrs.put("decimals", 8);
        coins.put("zcash", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "ethereum");
        attrs.put("transfer.gaslimit", 150000);
        attrs.put("contract.address", (_testnetfun) (testnet -> testnet ? "0xfb04393b9a8a59d7b6228fe544ae89d9064419fd" : "0xe41d2489571d322189246dafa5ebde1f4699f498"));
        coins.put("erc20-0x", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "ethereum");
        attrs.put("transfer.gaslimit", 150000);
        attrs.put("contract.address", (_testnetfun) (testnet -> testnet ? "0xfe7eebb77d7ce6096119c5374a10d05ad43e7267" : "0x5ca9a71b1d01849c0a95490cc00559717fcf0d1d"));
        coins.put("erc20-aeternity", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "ethereum");
        attrs.put("transfer.gaslimit", 150000);
        attrs.put("contract.address", (_testnetfun) (testnet -> testnet ? "0x97ab730ac4877f9db639e7de03cd8bc526a81590" : "0xe94327d07fc17907b4db788e5adf2ed424addff6"));
        coins.put("erc20-augur", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "ethereum");
        attrs.put("transfer.gaslimit", 150000);
        attrs.put("contract.address", (_testnetfun) (testnet -> testnet ? "0xf7e88715df7aceb0563b22f3f9a593d869eccdfa" : "0x0d8775f648430679a709e98d2b0cb6250d2887ef"));
        coins.put("erc20-basicattentiontoken", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "ethereum");
        attrs.put("transfer.gaslimit", 150000);
        attrs.put("contract.address", (_testnetfun) (testnet -> testnet ? "0x6369dcdb37c2f32c9ef1ae5124fa19266c8ea922" : "0xb8c77482e45f1f44de1745f52c74426c631bdd52"));
        coins.put("erc20-binancecoin", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "ethereum");
        attrs.put("transfer.gaslimit", 150000);
        attrs.put("contract.address", (_testnetfun) (testnet -> testnet ? "0x40b329333e1cea0235f6a44a92e29fd6d6ab5184" : "0x514910771af9ca656af840dff83e8264ecf986ca"));
        coins.put("erc20-chainlink", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "ethereum");
        attrs.put("transfer.gaslimit", 150000);
        attrs.put("contract.address", (_testnetfun) (testnet -> testnet ? "0x1f1cb7a560db6e7cbdff2e6ec4544834acf2cfde" : "0x6b175474e89094c44da98b954eedeac495271d0f"));
        coins.put("erc20-dai", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "ethereum");
        attrs.put("transfer.gaslimit", 150000);
        attrs.put("contract.address", (_testnetfun) (testnet -> testnet ? "0xa61ad21f601358586ad00aac9f2303512cc46b79" : "0x86fa049857e0209aa7d9e616f7eb3b3b78ecfdb0"));
        coins.put("erc20-eos", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "ethereum");
        attrs.put("transfer.gaslimit", 150000);
        attrs.put("contract.address", (_testnetfun) (testnet -> testnet ? "0x2c7bbacca71a6799feda581fd8fd69a785f60ecf" : "0x4e15361fd6b4bb609fa63c81a2be19d873717870"));
        coins.put("erc20-fantom", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "ethereum");
        attrs.put("decimals", 2);
        attrs.put("transfer.gaslimit", 150000);
        attrs.put("contract.address", (_testnetfun) (testnet -> testnet ? "0x6b4159cb8f3bb460e3fed5fd145c7d8312a8b980" : "0x056fd409e1d7a124bd7017459dfea2f387b6d5cd"));
        coins.put("erc20-geminidollar", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "ethereum");
        attrs.put("transfer.gaslimit", 150000);
        attrs.put("contract.address", (_testnetfun) (testnet -> testnet ? "0x47a4cd1239d3e89ba2767d9bbd188ab6dcca39ed" : "0xa74476443119A942dE498590Fe1f2454d7D4aC0d"));
        coins.put("erc20-golem", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "ethereum");
        attrs.put("transfer.gaslimit", 150000);
        attrs.put("contract.address", (_testnetfun) (testnet -> testnet ? "0x1bf884dd8541487540889c0e27459986546a56c2" : "0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2"));
        coins.put("erc20-maker", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "ethereum");
        attrs.put("transfer.gaslimit", 150000);
        attrs.put("contract.address", (_testnetfun) (testnet -> testnet ? "0xdf47bd229d3b2789e0ecb598c1f80910c5392f73" : "0xd26114cd6EE289AccF82350c8d8487fedB8A0C07"));
        coins.put("erc20-omisego", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "ethereum");
        attrs.put("transfer.gaslimit", 150000);
        attrs.put("contract.address", (_testnetfun) (testnet -> testnet ? "0x5a89997f38429b5866809dc40a6d677c521ebab9" : "0x89d24a6b4ccb1b6faa2625fe562bdd9a23260359"));
        coins.put("erc20-sai", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "ethereum");
        attrs.put("transfer.gaslimit", 150000);
        attrs.put("contract.address", (_testnetfun) (testnet -> testnet ? "0xfa4ff93882d2035661e90763cc2cd92ffeca7cb3" : "0x744d70fdbe2ba4cf95131626614a1763df805b9e"));
        coins.put("erc20-status", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "ethereum");
        attrs.put("decimals", 6);
        attrs.put("transfer.gaslimit", 150000);
        attrs.put("contract.address", (_testnetfun) (testnet -> testnet ? "0x6ee856ae55b6e1a249f04cd3b947141bc146273c" : "0xdac17f958d2ee523a2206206994597c13d831ec7"));
        coins.put("erc20-tether", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "ethereum");
        attrs.put("decimals", 6);
        attrs.put("transfer.gaslimit", 150000);
        attrs.put("contract.address", (_testnetfun) (testnet -> testnet ? "0xb37a76e727ad2c2dd09549cf30ef4433e2ee87a1" : "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"));
        coins.put("erc20-usdcoin", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "ethereum");
        attrs.put("decimals", 8);
        attrs.put("transfer.gaslimit", 150000);
        attrs.put("contract.address", (_testnetfun) (testnet -> testnet ? "0x65058d7081fcdc3cd8727dbb7f8f9d52cefdd291" : "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599"));
        coins.put("erc20-wrappedbitcoin", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "ethereum");
        attrs.put("decimals", 12);
        attrs.put("transfer.gaslimit", 150000);
        attrs.put("contract.address", (_testnetfun) (testnet -> testnet ? "0x36cb48e26fd55dab1c225ed40254fa0cbdb60c6d" : "0x05f4a42e251f2d52b8ed15e9fedaacfcef1fad27"));
        coins.put("erc20-zilliqa", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "binancecoin");
        attrs.put("transfer.gaslimit", 150000);
        attrs.put("contract.address", (_testnetfun) (testnet -> testnet ? "0x473235419db3991e7e688a6b56389104f14e4026" : "0x101d82428437127bf1608f699cd651e6abf9766e"));
        coins.put("bep20-basicattentiontoken", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "binancecoin");
        attrs.put("transfer.gaslimit", 150000);
        attrs.put("contract.address", (_testnetfun) (testnet -> testnet ? "0x6ce8da28e2f864420840cf74474eff5fd80e65b8" : "0x7130d2a12b9bcbfae4f2634d864a1ee1ce3ead9c"));
        coins.put("bep20-bitcoin", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "binancecoin");
        attrs.put("transfer.gaslimit", 150000);
        attrs.put("contract.address", (_testnetfun) (testnet -> testnet ? "0x4a3c800a8d587166882ce5ee968095dcbbe08000" : "0x8ff795a6f4d97e7887c79bea79aba5cc76444adf"));
        coins.put("bep20-bitcoincash", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "binancecoin");
        attrs.put("transfer.gaslimit", 150000);
        attrs.put("contract.address", (_testnetfun) (testnet -> testnet ? "0x7874a63a2363037ce84b1473aa14f83eb29cf0a4" : "0x3ee2200efb3400fabb9aacf31297cbdd1d435d47"));
        coins.put("bep20-cardano", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "binancecoin");
        attrs.put("transfer.gaslimit", 150000);
        attrs.put("contract.address", (_testnetfun) (testnet -> testnet ? "0x420d87a31f7dc65330b8ce5668ca17ba2029d563" : "0xf8a0bf9cf54bb92f17374d9e9a321e6a111a51bd"));
        coins.put("bep20-chainlink", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "binancecoin");
        attrs.put("transfer.gaslimit", 150000);
        attrs.put("contract.address", (_testnetfun) (testnet -> testnet ? "0xec5dcb5dbf4b114c9d0f65bccab49ec54f6a0867" : "0x1af3f329e8be154074d8769d1ffa4ee058b1dbc3"));
        coins.put("bep20-dai", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "binancecoin");
        attrs.put("decimals", 8);
        attrs.put("transfer.gaslimit", 150000);
        attrs.put("contract.address", (_testnetfun) (testnet -> testnet ? "0x3219c9d7fe0d0745b4381fbb4bba935ca9f2d8fa" : "0xba2ae424d960c26247dd6c32edc70b295c744c43"));
        coins.put("bep20-dogecoin", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "binancecoin");
        attrs.put("transfer.gaslimit", 150000);
        attrs.put("contract.address", (_testnetfun) (testnet -> testnet ? "0x90f87f413ffa32f9002b2935fea9de201c389141" : "0x56b6fb708fc5732dec1afc8d8556423a2edccbd6"));
        coins.put("bep20-eos", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "binancecoin");
        attrs.put("transfer.gaslimit", 150000);
        attrs.put("contract.address", (_testnetfun) (testnet -> testnet ? "0xd66c6b4f0be8ce5b39d52e0fd1344c389929b378" : "0x2170ed0880ac9a755fd29b2688956bd959f933f8"));
        coins.put("bep20-ethereum", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "binancecoin");
        attrs.put("transfer.gaslimit", 150000);
        attrs.put("contract.address", (_testnetfun) (testnet -> testnet ? "0x426e2e210869d2c5f0f8ca3aa704980427115ab0" : "0x3d6545b08693dae087e957cb1180ee38b9e3c25e"));
        coins.put("bep20-ethereumclassic", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "binancecoin");
        attrs.put("transfer.gaslimit", 150000);
        attrs.put("contract.address", (_testnetfun) (testnet -> testnet ? "0x969f147b6b8d81f86175de33206a4fd43df17913" : "0x4338665cbb7b2485a8855a139b75d5e34ab0db94"));
        coins.put("bep20-litecoin", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "binancecoin");
        attrs.put("transfer.gaslimit", 150000);
        attrs.put("contract.address", (_testnetfun) (testnet -> testnet ? "0x3a1595e01084837d79d145126b5ba3234c3064eb" : "0x5f0da599bb2cccfcf6fdfd7d81743b6020864350"));
        coins.put("bep20-maker", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "binancecoin");
        attrs.put("transfer.gaslimit", 150000);
        attrs.put("contract.address", (_testnetfun) (testnet -> testnet ? "0xa83575490d7df4e2f47b7d38ef351a2722ca45b9" : "0x1d2f0da169ceb9fc7b3144628db156f3f6c60dbe"));
        coins.put("bep20-ripple", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "binancecoin");
        attrs.put("transfer.gaslimit", 150000);
        attrs.put("contract.address", (_testnetfun) (testnet -> testnet ? "0x337610d27c682e347c9cd60bd4b3b107c9d34ddd" : "0x55d398326f99059ff775485246999027b3197955"));
        coins.put("bep20-tether", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "binancecoin");
        attrs.put("transfer.gaslimit", 150000);
        attrs.put("contract.address", (_testnetfun) (testnet -> testnet ? "0x64544969ed7ebf5f083679233325356ebe738930" : "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d"));
        coins.put("bep20-usdcoin", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "binancecoin");
        attrs.put("transfer.gaslimit", 150000);
        attrs.put("contract.address", (_testnetfun) (testnet -> testnet ? "0x7cfd0b2aa0ef973df82509cc35db295e25255e8a" : "0x1ba42e5193dfa8b03d15dd1b86a3113bbbef8eeb"));
        coins.put("bep20-zcash", attrs);
    }

    static {
        dict attrs = new dict();
        attrs.put("overloads", "binancecoin");
        attrs.put("decimals", 12);
        attrs.put("transfer.gaslimit", 150000);
        attrs.put("contract.address", (_testnetfun) (testnet -> testnet ? "0x75d84350ced26ef211c85460a415622a307514be" : "0xb86abcb37c3a4b64f74f59301aff131a1becc787"));
        coins.put("bep20-zilliqa", attrs);
    }

    public static <A> A attr(String name, String coin) {
        return attr(name, null, coin, false);
    }

    public static <A> A attr(String name, String coin, boolean testnet) {
        return attr(name, null, coin, testnet);
    }

    @SuppressWarnings("unchecked")
    public static <A> A attr(String name, A def, String coin, boolean testnet) {
        Object value = def;
        for (;;) {
            dict attrs = coins.get(coin);
            if (attrs.has(name)) {
                value = attrs.get(name);
                break;
            }
            if (!attrs.has("overloads")) break;
            coin = attrs.get("overloads");
        }
        if (value == null) throw new IllegalArgumentException("Invalid attribute");
        if (value instanceof _testnetfun) value = ((_testnetfun)value).f(testnet);
        return (A)value;
    }

    private interface _testnetfun<A> {
        A f(boolean testnet);
    }

}
