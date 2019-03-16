package com.raugfer.crypto;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class transaction {

    public static final int SIGHASH_ALL = 0x01;
    public static final int SIGHASH_NONE = 0x02;
    public static final int SIGHASH_SINGLE = 0x03;
    public static final int SIGHASH_FORKID = 0x40;          // bitcoin fork
    public static final int SIGHASH_ANYONECANPAY = 0x80;

    private static void r(byte[] b) {
        for (int i = 0, j = b.length-1; i < j; i++, j--) {
            byte t = b[i];
            b[i] = b[j];
            b[j] = t;
        }
    }

    private static byte[] int8(BigInteger n) {
        return int8(n, true);
    }

    private static byte[] int8(BigInteger n, boolean r) {
        if (n.compareTo(BigInteger.ZERO) < 0 || n.compareTo(BigInteger.ONE.shiftLeft(8)) >= 0) throw new IllegalArgumentException("Invalid constant");
        return binint.n2b(n, 1);
    }

    private static pair<BigInteger, byte[]> parse_int8(byte[] b) {
        return parse_int8(b, true);
    }

    private static pair<BigInteger, byte[]> parse_int8(byte[] b, boolean r) {
        if (b.length < 1) throw new IllegalArgumentException("End of input");
        byte[] t1 = bytes.sub(b, 0, 1);
        byte[] t2 = bytes.sub(b, 1);
        return new pair<>(binint.b2n(t1), t2);
    }

    private static byte[] int16(BigInteger n) {
        return int16(n, true);
    }

    private static byte[] int16(BigInteger n, boolean r) {
        if (n.compareTo(BigInteger.ZERO) < 0 || n.compareTo(BigInteger.ONE.shiftLeft(16)) >= 0) throw new IllegalArgumentException("Invalid constant");
        byte[] b = binint.n2b(n, 2);
        if (r) r(b);
        return b;
    }

    private static pair<BigInteger, byte[]> parse_int16(byte[] b) {
        return parse_int16(b, true);
    }

    private static pair<BigInteger, byte[]> parse_int16(byte[] b, boolean r) {
        if (b.length < 2) throw new IllegalArgumentException("End of input");
        byte[] t1 = bytes.sub(b, 0, 2);
        byte[] t2 = bytes.sub(b, 2);
        if (r) r(t1);
        return new pair<>(binint.b2n(t1), t2);
    }

    private static byte[] int32(BigInteger n) {
        return int32(n, true);
    }

    private static byte[] int32(BigInteger n, boolean r) {
        if (n.compareTo(BigInteger.ZERO) < 0 || n.compareTo(BigInteger.ONE.shiftLeft(32)) >= 0) throw new IllegalArgumentException("Invalid constant");
        byte[] b = binint.n2b(n, 4);
        if (r) r(b);
        return b;
    }

    private static pair<BigInteger, byte[]> parse_int32(byte[] b) {
        return parse_int32(b, true);
    }

    private static pair<BigInteger, byte[]> parse_int32(byte[] b, boolean r) {
        if (b.length < 4) throw new IllegalArgumentException("End of input");
        byte[] t1 = bytes.sub(b, 0, 4);
        byte[] t2 = bytes.sub(b, 4);
        if (r) r(t1);
        return new pair<>(binint.b2n(t1), t2);
    }

    private static byte[] int64(BigInteger n) {
        return int64(n, true);
    }

    private static byte[] int64(BigInteger n, boolean r) {
        if (n.compareTo(BigInteger.ZERO) < 0 || n.compareTo(BigInteger.ONE.shiftLeft(64)) >= 0) throw new IllegalArgumentException("Invalid constant");
        byte[] b = binint.n2b(n, 8);
        if (r) r(b);
        return b;
    }

    private static pair<BigInteger, byte[]> parse_int64(byte[] b) {
        return parse_int64(b, true);
    }

    private static pair<BigInteger, byte[]> parse_int64(byte[] b, boolean r) {
        if (b.length < 8) throw new IllegalArgumentException("End of input");
        byte[] t1 = bytes.sub(b, 0, 8);
        byte[] t2 = bytes.sub(b, 8);
        if (r) r(t1);
        return new pair<>(binint.b2n(t1), t2);
    }

    private static byte[] varint(BigInteger n) {
        if (n.compareTo(BigInteger.ZERO) < 0 || n.compareTo(BigInteger.ONE.shiftLeft(64)) >= 0) throw new IllegalArgumentException("Invalid constant");
        byte[] t1;
        byte[] t2;
        if (n.compareTo(BigInteger.ONE.shiftLeft(32)) >= 0) {
            t1 = int8(BigInteger.valueOf((1<<8)-1));
            t2 = int64(n);
        } else if (n.compareTo(BigInteger.ONE.shiftLeft(16)) >= 0) {
            t1 = int8(BigInteger.valueOf((1<<8)-2));
            t2 = int32(n);
        } else if (n.compareTo(BigInteger.ONE.shiftLeft(8).subtract(BigInteger.valueOf(3))) >= 0) {
            t1 = int8(BigInteger.valueOf((1<<8)-3));
            t2 = int16(n);
        } else {
            t1 = new byte[]{};
            t2 = int8(n);
        }
        return bytes.concat(t1, t2);
    }

    private static pair<BigInteger, byte[]> parse_varint(byte[] b) {
        pair<BigInteger, byte[]> r = parse_int8(b);
        BigInteger n = r.l;
        b = r.r;
        if (n.compareTo(BigInteger.valueOf((1<<8)-1)) == 0) return parse_int64(b);
        if (n.compareTo(BigInteger.valueOf((1<<8)-2)) == 0) return parse_int32(b);
        if (n.compareTo(BigInteger.valueOf((1<<8)-3)) == 0) return parse_int16(b);
        return r;
    }

    private static byte[] nlzint(BigInteger n) {
        if (n.compareTo(BigInteger.ZERO) < 0 || n.compareTo(BigInteger.ONE.shiftLeft(256)) >= 0) throw new IllegalArgumentException("Invalid constant");
        if (n.equals(BigInteger.ZERO)) return new byte[]{ };
        String s = binint.n2h(n);
        if (s.length() % 2 == 1) s = "0" + s;
        return binint.h2b(s);
    }

    private static pair<BigInteger, byte[]> parse_nlzint(byte[] b) {
        return parse_nlzint(b, -1);
    }

    private static pair<BigInteger, byte[]> parse_nlzint(byte[] b, int l) {
        if (l == -1) l = b.length;
        if (b.length < l) throw new IllegalArgumentException("End of input");
        byte[] b1 = bytes.sub(b, 0, l);
        byte[] b2 = bytes.sub(b, l);
        if (b1.length == 0) return new pair<>(BigInteger.ZERO, b2);
        if (b1[0] == 0x00) throw new IllegalArgumentException("Invalid encoding");
        BigInteger n = binint.b2n(b1);
        if (n.compareTo(BigInteger.ONE.shiftLeft(256)) >= 0) throw new IllegalArgumentException("Invalid encoding");
        return new pair<>(n, b2);
    }

    private static byte[] rlp_varlen(int base, int n) {
        if (n > 55) {
            byte[] b = nlzint(BigInteger.valueOf(n));
            byte[] r = int8(BigInteger.valueOf(base + 55 + b.length));
            return bytes.concat(r, b);
        }
        return int8(BigInteger.valueOf(base + n));
    }

    private static byte[] rlp(Object v) {
        if (v instanceof byte[]) {
            byte[] b = (byte[]) v;
            if (b.length == 1) {
                pair<BigInteger, byte[]> r = parse_int8(b);
                BigInteger n = r.l;
                if (n.intValue() < 0x80) return b;
            }
            byte[] r = rlp_varlen(0x80, b.length);
            return bytes.concat(r, b);
        }
        if (v instanceof Object[]) {
            Object[] l = (Object[]) v;
            byte[][] a = new byte[l.length][];
            int length = 0;
            for (int i = 0; i < l.length; i++) {
                a[i] = rlp(l[i]);
                length += a[i].length;
            }
            byte[] b = new byte[length];
            int offset = 0;
            for (int i = 0; i < l.length; i++) {
                System.arraycopy(a[i], 0, b, offset, a[i].length);
                offset += a[i].length;
            }
            byte[] r = rlp_varlen(0xc0, b.length);
            return bytes.concat(r, b);
        }
        throw new IllegalArgumentException("Unsupported datatype");
    }

    private static Object[] rlp_parse_varlen(byte[] b) {
        pair<BigInteger, byte[]> r = parse_int8(b);
        int n = r.l.intValue();
        b = r.r;
        if (n >= 0xc0 + 56) {
            r = parse_nlzint(b, n - (0xc0 + 56) + 1);
            BigInteger l = r.l;
            b = r.r;
            if (l.compareTo(BigInteger.valueOf(56)) < 0) throw new IllegalArgumentException("Invalid encoding");
            return new Object[]{ "list", l, b };
        }
        if (n >= 0xc0) {
            BigInteger l = BigInteger.valueOf(n - 0xc0);
            return new Object[]{ "list", l, b };
        }
        if (n >= 0x80 + 56) {
            r = parse_nlzint(b, n - (0x80 + 56) + 1);
            BigInteger l = r.l;
            b = r.r;
            if (l.compareTo(BigInteger.valueOf(56)) < 0) throw new IllegalArgumentException("Invalid encoding");
            return new Object[]{ "str", l, b };
        }
        if (n >= 0x80) {
            BigInteger l = BigInteger.valueOf(n - 0x80);
            if (l.equals(BigInteger.ONE)) {
                r = parse_int8(b);
                n = r.l.intValue();
                if (n < 0x80) throw new IllegalArgumentException("Invalid encoding");
            }
            return new Object[]{ "str", l, b };
        }
        byte[] v = int8(BigInteger.valueOf(n));
        return new Object[]{ "str", BigInteger.ONE, bytes.concat(v, b) };
    }

    private static pair<Object, byte[]> parse_rlp(byte[] b) {
        Object[] r = rlp_parse_varlen(b);
        String t = (String) r[0];
        int l = ((BigInteger) r[1]).intValue();
        b = (byte[]) r[2];
        if (l > b.length) throw new IllegalArgumentException("End of input");
        byte[] b1 = bytes.sub(b, 0, l);
        byte[] b2 = bytes.sub(b, l);
        if (t.equals("str")) return new pair<>(b1, b2);
        if (t.equals("list")) {
            List<Object> list = new ArrayList<>();
            while (b1.length > 0) {
                pair<Object, byte[]> s = parse_rlp(b1);
                Object v = s.l;
                b1 = s.r;
                list.add(v);
            }
            Object[] vs = list.toArray();
            return new pair<>(vs, b2);
        }
        throw new IllegalArgumentException("Unknown type");
    }

    private static final String[][] RIPPLE_FIELDS = {
        {"1", "2", "TransactionType"},
        {"2", "2", "Flags"},
        {"2", "4", "Sequence"},
        {"2", "e", "DestinationTag"},
        {"2", "01b", "LastLedgerSequence"},
        {"5", "011", "InvoiceID"},
        {"6", "1", "Amount"},
        {"6", "8", "Fee"},
        {"7", "3", "SigningPubKey"},
        {"7", "4", "TxnSignature"},
        {"8", "1", "Account"},
        {"8", "3", "Destination"},
    };

    private static byte[] serial_varlen(int n) {
        if (n <= 0xc0) return binint.n2b(BigInteger.valueOf(n), 1);
        if (n <= 0x30c0) return binint.n2b(BigInteger.valueOf((0xc1 << 8) + (n - 0xc1)), 2);
        if (n <= 0x0e30c0) return binint.n2b(BigInteger.valueOf((0xf1 << 16) + (n - 0x30c1)), 3);
        throw new IllegalArgumentException("Capacity overflow");
    }

    private static byte[] serial(dict fields) {
        List<byte[]> items = new ArrayList<>();
        for (String[] ripple_field : RIPPLE_FIELDS) {
            String mode = ripple_field[0];
            String code = ripple_field[1];
            String name = ripple_field[2];
            if (!fields.has(name)) continue;
            byte[] prefix = binint.h2b(mode + code);
            byte[] item;
            if (mode.equals("1")) {
                BigInteger value = fields.get(name);
                item = int16(value, false);
            } else if (mode.equals("2") || mode.equals("5")) {
                BigInteger value = fields.get(name);
                item = int32(value, false);
            } else if (mode.equals("6")) {
                BigInteger value = fields.get(name);
                item = int64(value, false);
            } else if (mode.equals("7") || mode.equals("8")) {
                byte[] data = fields.get(name);
                byte[] b = serial_varlen(data.length);
                item = bytes.concat(b, data);
            } else {
                throw new IllegalArgumentException("Unknown mode");
            }
            items.add(bytes.concat(prefix, item));
        }
        int length = 0;
        for (byte[] item: items) length += item.length;
        byte[] b = new byte[length];
        int offset = 0;
        for (byte[] item: items) {
            System.arraycopy(item, 0, b, offset, item.length);
            offset += item.length;
        }
        return b;
    }

    private static pair<Integer, byte[]> serial_parse_varlen(byte[] b) {
        pair<BigInteger, byte[]> r = parse_int8(b, false);
        int n = r.l.intValue();
        b = r.r;
        if (n <= 0xc0) {
            return new pair<>(n, b);
        }
        if (n <= 0xf0) {
            pair<BigInteger, byte[]> t = parse_int8(b, false);
            int k = t.l.intValue();
            b = t.r;
            n = (n << 8) + k;
            return new pair<>((n + 0xc1) - (0xc1 << 8), b);
        }
        if (n <= 0xfe) {
            pair<BigInteger, byte[]> t = parse_int16(b, false);
            int k = t.l.intValue();
            b = t.r;
            n = (n << 16) + k;
            return new pair<>((n + 0x30c1) - (0xf1 << 16), b);
        }
        throw new IllegalArgumentException("Invalid encoding");
    }

    private static Object[] serial_parse_prefix(byte[] b) {
        for (String[] ripple_field : RIPPLE_FIELDS) {
            String mode = ripple_field[0];
            String code = ripple_field[1];
            String name = ripple_field[2];
            byte[] prefix = binint.h2b(mode + code);
            int l = prefix.length;
            if (l > b.length) continue;
            byte[] b1 = bytes.sub(b, 0, l);
            byte[] b2 = bytes.sub(b, l);
            if (Arrays.equals(b1, prefix)) {
                return new Object[]{mode, code, name, b2};
            }
        }
        throw new IllegalArgumentException("Unsupported prefix");
    }

    private static dict parse_serial(byte[] b) {
        dict fields = new dict();
        while (b.length > 0) {
            Object[] r = serial_parse_prefix(b);
            String mode = (String) r[0];
            String code = (String) r[1];
            String name = (String) r[2];
            b = (byte[]) r[3];
            Object value;
            if (mode.equals("1")) {
                pair<BigInteger, byte[]> t = parse_int16(b, false);
                value = t.l;
                b = t.r;
            } else if (mode.equals("2") || mode.equals("5")) {
                pair<BigInteger, byte[]> t = parse_int32(b, false);
                value = t.l;
                b = t.r;
            } else if (mode.equals("6")) {
                pair<BigInteger, byte[]> t = parse_int64(b, false);
                value = t.l;
                b = t.r;
            } else if (mode.equals("7") || mode.equals("8")) {
                pair<Integer, byte[]> t = serial_parse_varlen(b);
                int l = t.l;
                b = t.r;
                if (b.length < l) throw new IllegalArgumentException("End of input");
                byte[] b1 = bytes.sub(b, 0, l);
                byte[] b2 = bytes.sub(b, l);
                value = b1;
                b = b2;
            } else {
                throw new IllegalArgumentException("Unknown mode");
            }
            fields.put(name, value);
        }
        return fields;
    }

    private static byte[] inout_input_encode(dict fields, BigInteger default_sequence) {
        String txnid = fields.get("txnid");
        BigInteger index = fields.get("index", BigInteger.ZERO);
        byte[] inscript = fields.get("script", new byte[]{});
        BigInteger sequence = fields.get("sequence", default_sequence);
        byte[] b1 = binint.h2b(txnid);
        r(b1);
        byte[] b2 = int32(index);
        byte[] b3 = varint(BigInteger.valueOf(inscript.length));
        byte[] b4 = inscript;
        byte[] b5 = int32(sequence);
        return bytes.concat(b1, b2, b3, b4, b5);
    }

    private static byte[] inout_output_encode(dict fields, String coin, boolean testnet) {
        BigInteger amount = fields.get("amount", BigInteger.ZERO);
        byte[] outscript = fields.get("script", null);
        if (outscript == null) {
            String address = fields.get("address", null);
            String message = fields.get("message", null);
            outscript = script.scriptpubkey(address, message, coin, testnet);
        }
        byte[] b1 = int64(amount);
        byte[] b2 = varint(BigInteger.valueOf(outscript.length));
        byte[] b3 = outscript;
        return bytes.concat(b1, b2, b3);
    }

    private static byte[] dcrinout_input_encode(dict fields, BigInteger default_sequence) {
        String txnid = fields.get("txnid");
        BigInteger index = fields.get("index", BigInteger.ZERO);
        BigInteger tree = fields.get("tree", BigInteger.ZERO);
        BigInteger sequence = fields.get("sequence", default_sequence);
        byte[] b1 = bytes.rev(binint.h2b(txnid));
        byte[] b2 = int32(index);
        byte[] b3 = int8(tree);
        byte[] b4 = int32(sequence);
        return bytes.concat(b1, b2, b3, b4);
    }

    private static byte[] dcrinout_output_encode(dict fields, String coin, boolean testnet) {
        BigInteger amount = fields.get("amount", BigInteger.ZERO);
        BigInteger version = fields.get("version", BigInteger.ZERO);
        byte[] outscript = fields.get("script", null);
        if (outscript == null) {
            String address = fields.get("address", null);
            String message = fields.get("message", null);
            outscript = script.scriptpubkey(address, message, coin, testnet);
        }
        byte[] b1 = int64(amount);
        byte[] b2 = int16(version);
        byte[] b3 = varint(BigInteger.valueOf(outscript.length));
        byte[] b4 = outscript;
        return bytes.concat(b1, b2, b3, b4);
    }

    private static byte[] dcrinout_witness_encode(dict fields) {
        BigInteger amount = fields.get("amount", BigInteger.ZERO);
        BigInteger blockheight = fields.get("blockheight", BigInteger.ZERO);
        BigInteger blockindex = fields.get("blockindex", BigInteger.valueOf(0x0ffffffffL));
        byte[] inscript = fields.get("script", new byte[]{});
        byte[] b1 = int64(amount);
        byte[] b2 = int32(blockheight);
        byte[] b3 = int32(blockindex);
        byte[] b4 = varint(BigInteger.valueOf(inscript.length));
        byte[] b5 = inscript;
        return bytes.concat(b1, b2, b3, b4, b5);
    }

    private static byte[] neoinout_input_encode(dict fields) {
        String txnid = fields.get("txnid");
        BigInteger index = fields.get("index", BigInteger.ZERO);
        byte[] b1 = bytes.rev(binint.h2b(txnid));
        byte[] b2 = int16(index);
        return bytes.concat(b1, b2);
    }

    private static byte[] neoinout_output_encode(dict fields, String coin, boolean testnet) {
        String asset = fields.get("asset");
        BigInteger amount = fields.get("amount", BigInteger.ZERO);
        String address = fields.get("address");
        pair<BigInteger, String> t = wallet.address_decode(address, coin, testnet);
        BigInteger h = t.l;
        String kind = t.r;
        byte[] b1 = bytes.rev(binint.h2b(asset));
        byte[] b2 = int64(amount);
        byte[] b3 = binint.n2b(h, 20);
        return bytes.concat(b1, b2, b3);
    }

    private static byte[] neoinout_script_encode(dict fields) {
        byte[] invocation_script = fields.get("invocation");
        byte[] verification_script = fields.get("verification");
        byte[] b1 = varint(BigInteger.valueOf(invocation_script.length));
        byte[] b2 = invocation_script;
        byte[] b3 = varint(BigInteger.valueOf(verification_script.length));
        byte[] b4 = verification_script;
        return bytes.concat(b1, b2, b3, b4);
    }

    public static byte[] transaction_encode(dict fields, String coin, boolean testnet) {
        String fmt = coins.attr("transaction.format", coin, testnet);
        if (fmt.equals("inout")) {
            int default_version = coins.attr("transaction.version", 1, coin, testnet);
            BigInteger version = fields.get("version", BigInteger.valueOf(default_version & 0x0ffffffffL));
            dict[] inputs = fields.get("inputs", new dict[]{ });
            dict[] outputs = fields.get("outputs", new dict[]{ });
            BigInteger locktime = fields.get("locktime", BigInteger.ZERO);
            BigInteger default_sequence = locktime.compareTo(BigInteger.ZERO) > 0 ? BigInteger.ZERO : BigInteger.valueOf(0x0ffffffffL);
            if (version.equals(BigInteger.valueOf(0x080000004L))) { // zcash sapling
                int default_groupid = coins.attr("transaction.groupid", coin, testnet);
                BigInteger groupid = fields.get("groupid", BigInteger.valueOf(default_groupid & 0x0ffffffffL));
                BigInteger expiryheight = fields.get("expiryheight", BigInteger.ZERO);
                byte[] b1 = int32(version);
                byte[] b2 = int32(groupid);
                byte[] b3 = varint(BigInteger.valueOf(inputs.length));
                int inputs_length = 0;
                byte[][] b_inputs = new byte[inputs.length][];
                for (int i = 0; i < inputs.length; i++) {
                    byte[] b_input = inout_input_encode(inputs[i], default_sequence);
                    b_inputs[i] = b_input;
                    inputs_length += b_input.length;
                }
                byte[] b4 = new byte[inputs_length];
                int inputs_offset = 0;
                for (byte[] b_input : b_inputs) {
                    System.arraycopy(b_input, 0, b4, inputs_offset, b_input.length);
                    inputs_offset += b_input.length;
                }
                byte[] b5 = varint(BigInteger.valueOf(outputs.length));
                int outputs_length = 0;
                byte[][] b_outputs = new byte[outputs.length][];
                for (int i = 0; i < outputs.length; i++) {
                    byte[] b_output = inout_output_encode(outputs[i], coin, testnet);
                    b_outputs[i] = b_output;
                    outputs_length += b_output.length;
                }
                byte[] b6 = new byte[outputs_length];
                int outputs_offset = 0;
                for (byte[] b_output : b_outputs) {
                    System.arraycopy(b_output, 0, b6, outputs_offset, b_output.length);
                    outputs_offset += b_output.length;
                }
                byte[] b7 = int32(locktime);
                byte[] b8 = int32(expiryheight);
                byte[] b9 = int64(BigInteger.ZERO);
                byte[] b10 = varint(BigInteger.ZERO);
                byte[] b11 = varint(BigInteger.ZERO);
                byte[] b12 = varint(BigInteger.ZERO);
                return bytes.concat(bytes.concat(b1, b2, b3, b4, b5, b6), bytes.concat(b7, b8, b9, b10, b11, b12));
            }
            byte[] b1 = int32(version);
            byte[] b2 = varint(BigInteger.valueOf(inputs.length));
            int inputs_length = 0;
            byte[][] b_inputs = new byte[inputs.length][];
            for (int i = 0; i < inputs.length; i++) {
                byte[] b_input = inout_input_encode(inputs[i], default_sequence);
                b_inputs[i] = b_input;
                inputs_length += b_input.length;
            }
            byte[] b3 = new byte[inputs_length];
            int inputs_offset = 0;
            for (byte[] b_input : b_inputs) {
                System.arraycopy(b_input, 0, b3, inputs_offset, b_input.length);
                inputs_offset += b_input.length;
            }
            byte[] b4 = varint(BigInteger.valueOf(outputs.length));
            int outputs_length = 0;
            byte[][] b_outputs = new byte[outputs.length][];
            for (int i = 0; i < outputs.length; i++) {
                byte[] b_output = inout_output_encode(outputs[i], coin, testnet);
                b_outputs[i] = b_output;
                outputs_length += b_output.length;
            }
            byte[] b5 = new byte[outputs_length];
            int outputs_offset = 0;
            for (byte[] b_output : b_outputs) {
                System.arraycopy(b_output, 0, b5, outputs_offset, b_output.length);
                outputs_offset += b_output.length;
            }
            byte[] b6 = int32(locktime);
            return bytes.concat(b1, b2, b3, b4, b5, b6);
        }
        if (fmt.equals("dcrinout")) {
            BigInteger version = fields.get("version", BigInteger.ONE);
            dict[] inputs = fields.get("inputs", new dict[]{ });
            dict[] outputs = fields.get("outputs", new dict[]{ });
            BigInteger locktime = fields.get("locktime", BigInteger.ZERO);
            BigInteger expiryheight = fields.get("expiryheight", BigInteger.ZERO);
            dict[] witnesses = fields.get("witnesses", null);
            BigInteger default_sequence = locktime.compareTo(BigInteger.ZERO) > 0 ? BigInteger.ZERO : BigInteger.valueOf(0x0ffffffffL);
            byte[] b1 = int32(version);
            byte[] b2 = varint(BigInteger.valueOf(inputs.length));
            int inputs_length = 0;
            byte[][] b_inputs = new byte[inputs.length][];
            for (int i = 0; i < inputs.length; i++) {
                byte[] b_input = dcrinout_input_encode(inputs[i], default_sequence);
                b_inputs[i] = b_input;
                inputs_length += b_input.length;
            }
            byte[] b3 = new byte[inputs_length];
            int inputs_offset = 0;
            for (byte[] b_input : b_inputs) {
                System.arraycopy(b_input, 0, b3, inputs_offset, b_input.length);
                inputs_offset += b_input.length;
            }
            byte[] b4 = varint(BigInteger.valueOf(outputs.length));
            int outputs_length = 0;
            byte[][] b_outputs = new byte[outputs.length][];
            for (int i = 0; i < outputs.length; i++) {
                byte[] b_output = dcrinout_output_encode(outputs[i], coin, testnet);
                b_outputs[i] = b_output;
                outputs_length += b_output.length;
            }
            byte[] b5 = new byte[outputs_length];
            int outputs_offset = 0;
            for (byte[] b_output : b_outputs) {
                System.arraycopy(b_output, 0, b5, outputs_offset, b_output.length);
                outputs_offset += b_output.length;
            }
            byte[] b6 = int32(locktime);
            byte[] b7 = int32(expiryheight);
            byte[] b8 = new byte[]{};
            byte[] b9 = new byte[]{};
            if (witnesses != null) {
                b8 = varint(BigInteger.valueOf(witnesses.length));
                int witnesses_length = 0;
                byte[][] b_witnesses = new byte[witnesses.length][];
                for (int i = 0; i < witnesses.length; i++) {
                    byte[] b_witness = dcrinout_witness_encode(witnesses[i]);
                    b_witnesses[i] = b_witness;
                    witnesses_length += b_witness.length;
                }
                b9 = new byte[witnesses_length];
                int witnesses_offset = 0;
                for (byte[] b_witness : b_witnesses) {
                    System.arraycopy(b_witness, 0, b9, witnesses_offset, b_witness.length);
                    witnesses_offset += b_witness.length;
                }
            }
            return bytes.concat(bytes.concat(b1, b2, b3, b4, b5, b6), b7, b8, b9);
        }
        if (fmt.equals("neoinout")) {
            BigInteger txtype = fields.get("type", BigInteger.valueOf(0x80));
            BigInteger version = fields.get("version", BigInteger.ZERO);
            dict[] inputs = fields.get("inputs", new dict[]{ });
            dict[] outputs = fields.get("outputs", new dict[]{ });
            dict[] scripts = fields.get("scripts", null);
            byte[] b1 = int8(txtype);
            byte[] b2 = int8(version);
            byte[] b3 = varint(BigInteger.ZERO);
            byte[] b4 = varint(BigInteger.valueOf(inputs.length));
            int inputs_length = 0;
            byte[][] b_inputs = new byte[inputs.length][];
            for (int i = 0; i < inputs.length; i++) {
                byte[] b_input = neoinout_input_encode(inputs[i]);
                b_inputs[i] = b_input;
                inputs_length += b_input.length;
            }
            byte[] b5 = new byte[inputs_length];
            int inputs_offset = 0;
            for (byte[] b_input : b_inputs) {
                System.arraycopy(b_input, 0, b5, inputs_offset, b_input.length);
                inputs_offset += b_input.length;
            }
            byte[] b6 = varint(BigInteger.valueOf(outputs.length));
            int outputs_length = 0;
            byte[][] b_outputs = new byte[outputs.length][];
            for (int i = 0; i < outputs.length; i++) {
                byte[] b_output = neoinout_output_encode(outputs[i], coin, testnet);
                b_outputs[i] = b_output;
                outputs_length += b_output.length;
            }
            byte[] b7 = new byte[outputs_length];
            int outputs_offset = 0;
            for (byte[] b_output : b_outputs) {
                System.arraycopy(b_output, 0, b7, outputs_offset, b_output.length);
                outputs_offset += b_output.length;
            }
            if (scripts == null) {
                return bytes.concat(bytes.concat(b1, b2, b3, b4, b5, b6), b7);
            }
            byte[] b8 = varint(BigInteger.valueOf(scripts.length));
            int scripts_length = 0;
            byte[][] b_scripts = new byte[scripts.length][];
            for (int i = 0; i < scripts.length; i++) {
                byte[] b_script = neoinout_script_encode(scripts[i]);
                b_scripts[i] = b_script;
                scripts_length += b_script.length;
            }
            byte[] b9 = new byte[scripts_length];
            int scripts_offset = 0;
            for (byte[] b_script : b_scripts) {
                System.arraycopy(b_script, 0, b9, scripts_offset, b_script.length);
                scripts_offset += b_script.length;
            }
            return bytes.concat(bytes.concat(b1, b2, b3, b4, b5, b6), b7, b8, b9);
        }
        if (fmt.equals("rlp")) {
            BigInteger nonce = fields.get("nonce", BigInteger.ZERO);
            BigInteger gasprice = fields.get("gasprice", BigInteger.ZERO);
            BigInteger gaslimit = fields.get("gaslimit", BigInteger.ZERO);
            String to = fields.get("to", null);
            BigInteger value = fields.get("value", BigInteger.ZERO);
            byte[] data = fields.get("data", new byte[]{ });
            byte[] v = fields.get("v", new byte[]{ });
            byte[] r = fields.get("r", new byte[]{ });
            byte[] s = fields.get("s", new byte[]{ });
            byte[] b = { };
            if (to != null) {
                pair<BigInteger, String> t = wallet.address_decode(to, coin, testnet);
                BigInteger h = t.l;
                String kind = t.r;
                b = binint.n2b(h, 20);
            }
            boolean signed = v.length+r.length+s.length > 0;
            Object[] l = new Object[signed ? 9 : 6];
            l[0] = nlzint(nonce);
            l[1] = nlzint(gasprice);
            l[2] = nlzint(gaslimit);
            l[3] = b;
            l[4] = nlzint(value);
            l[5] = data;
            if (signed) {
                l[6] = v;
                l[7] = r;
                l[8] = s;
            }
            return rlp(l);
        }
        if (fmt.equals("serial")) {
            BigInteger amount = fields.get("Amount", null);
            BigInteger fee = fields.get("Fee", null);
            String account = fields.get("Account", null);
            String destination = fields.get("Destination", null);
            String signingpubkey = fields.get("SigningPubKey", null);
            String txnsignature = fields.get("TxnSignature", null);
            if (amount != null) {
                amount = amount.or(BigInteger.ONE.shiftLeft(62));
            }
            if (fee != null) {
                fee = fee.or(BigInteger.ONE.shiftLeft(62));
            }
            byte[] b_account = null;
            if (account != null) {
                pair<BigInteger, String> t = wallet.address_decode(account, coin, testnet);
                BigInteger h = t.l;
                String kind = t.r;
                b_account = binint.n2b(h, 20);
            }
            byte[] b_destination = null;
            if (destination != null) {
                pair<BigInteger, String> t = wallet.address_decode(destination, coin, testnet);
                BigInteger h = t.l;
                String kind = t.r;
                b_destination = binint.n2b(h, 20);
            }
            byte[] b_signingpubkey = null;
            if (signingpubkey != null) {
                pair<BigInteger[], Boolean> t = wallet.publickey_decode(signingpubkey, coin, testnet);
                BigInteger[] P = t.l;
                boolean compressed = t.r;
                BigInteger x = P[0], y = P[1];
                boolean odd = y.and(BigInteger.ONE).equals(BigInteger.ONE);
                byte[] prefix = odd ? new byte[]{0x03} : new byte[]{0x02};
                byte[] b = binint.n2b(x, 32);
                b_signingpubkey = bytes.concat(prefix, b);
            }
            byte[] b_txnsignature = null;
            if (txnsignature != null) {
                b_txnsignature = binint.h2b(txnsignature);
            }
            dict f = new dict(fields);
            if (amount != null) f.put("Amount", amount);
            if (fee != null) f.put("Fee", fee);
            if (b_account != null) f.put("Account", b_account);
            if (b_destination != null) f.put("Destination", b_destination);
            if (b_signingpubkey != null) f.put("SigningPubKey", b_signingpubkey);
            if (b_txnsignature != null) f.put("TxnSignature", b_txnsignature);
            return serial(f);
        }
        if (fmt.equals("xdr")) {
            String account = fields.get("Account");
            pair<BigInteger, String> t = wallet.address_decode(account, coin, testnet);
            BigInteger p = t.l;
            String kind = t.r;
            byte[] b_account = binint.n2b(p, 32);
            BigInteger fee = fields.get("Fee");
            BigInteger sequence = fields.get("Sequence");
            dict[] operations = fields.get("Operations");
            byte[] b_operations = new byte[]{ };
            for (dict operation : operations) {
                String optype = operation.get("Type");
                // TODO generalize
                if (optype.equals("CREATE_ACCOUNT")) {
                    String destination = operation.get("Destination");
                    pair<BigInteger, String> _t = wallet.address_decode(destination, coin, testnet);
                    BigInteger _p = _t.l;
                    String _kind = _t.r;
                    byte[] b_destination = binint.n2b(_p, 32);
                    BigInteger amount = operation.get("Amount");
                    byte[] b1 = int32(BigInteger.ZERO, false); // source address count
                    byte[] b2 = int32(BigInteger.ZERO, false); // CREATE_ACCOUNT
                    byte[] b3 = int32(BigInteger.ZERO, false); // PUBLIC_KEY_TYPE_ED25519
                    byte[] b4 = b_destination;
                    byte[] b5 = int64(amount, false);
                    b_operations = bytes.concat(b_operations, b1, b2, b3, b4, b5);
                }
                else
                if (optype.equals("PAYMENT")) {
                    String destination = operation.get("Destination");
                    pair<BigInteger, String> _t = wallet.address_decode(destination, coin, testnet);
                    BigInteger _p = _t.l;
                    String _kind = _t.r;
                    byte[] b_destination = binint.n2b(_p, 32);
                    BigInteger amount = operation.get("Amount");
                    byte[] b1 = int32(BigInteger.ZERO, false); // source address count
                    byte[] b2 = int32(BigInteger.ONE, false); // PAYMENT
                    byte[] b3 = int32(BigInteger.ZERO, false); // PUBLIC_KEY_TYPE_ED25519
                    byte[] b4 = b_destination;
                    byte[] b5 = int32(BigInteger.ZERO, false); // ASSET_TYPE_NATIVE
                    byte[] b6 = int64(amount, false);
                    b_operations = bytes.concat(b_operations, bytes.concat(b1, b2, b3, b4, b5, b6));
                }
                else {
                    throw new IllegalArgumentException("Unsupported operation type");
                }
            }
            byte[] sigs = new byte[]{ };
            if (fields.has("Signatures")) {
                dict[] signatures = fields.get("Signatures");
                sigs = int32(BigInteger.valueOf(signatures.length), false);
                for (dict sigobject : signatures) {
                    byte[] hint = sigobject.get("Hint");
                    byte[] signature = sigobject.get("Signature");
                    byte[] len_signature = int32(BigInteger.valueOf(signature.length), false);
                    sigs = bytes.concat(sigs, hint, len_signature, signature);
                }
            }
            byte[] b1 = int32(BigInteger.ZERO, false); // PUBLIC_KEY_TYPE_ED25519
            byte[] b2 = b_account;
            byte[] b3 = int32(fee, false);
            byte[] b4 = int64(sequence, false);
            byte[] b5 = int32(BigInteger.ZERO, false); // time bounds count
            byte[] b6 = int32(BigInteger.ZERO, false); // MEMO_NONE
            byte[] b7 = int32(BigInteger.valueOf(operations.length), false);
            byte[] b8 = b_operations;
            byte[] b9 = int32(BigInteger.ZERO, false);
            byte[] b10 = sigs;
            return bytes.concat(bytes.concat(b1, b2, b3, b4, b5, b6), bytes.concat(b7, b8, b9, b10));
        }
        if (fmt.equals("raiblock")) {
            BigInteger preamble = BigInteger.valueOf(6);
            String account = fields.get("account");
            String previous = fields.get("previous", binint.n2h(BigInteger.ZERO, 32));
            String representative = fields.get("representative");
            BigInteger balance = fields.get("balance");
            String link = fields.get("link", binint.n2h(BigInteger.ZERO, 32));
            byte[] signature = fields.get("signature", new byte[]{ });
            byte[] work = fields.get("work", new byte[]{ });
            pair<BigInteger, String> t = wallet.address_decode(account, coin, testnet);
            BigInteger a = t.l;
            String kind = t.r;
            t = wallet.address_decode(representative, coin, testnet);
            BigInteger r = t.l;
            kind = t.r;
            byte[] b1 = binint.n2b(preamble, 32);
            byte[] b2 = binint.n2b(a, 32);
            byte[] b3 = binint.h2b(previous);
            byte[] b4 = binint.n2b(r, 32);
            byte[] b5 = binint.n2b(balance, 16);
            byte[] b6 = binint.h2b(link);
            byte[] b7 = signature;
            byte[] b8 = work;
            return bytes.concat(bytes.concat(b1, b2, b3, b4, b5, b6), b7, b8);
        }
        if (fmt.equals("liskdatablock")) {
            BigInteger txtype = BigInteger.ZERO; // transmit
            BigInteger timestamp = fields.get("timestamp");
            String publickey = fields.get("publickey", "");
            String recipient = fields.get("recipient");
            BigInteger amount = fields.get("amount");
            byte[] signature = fields.get("signature", new byte[]{ });
            pair<BigInteger, String> t = wallet.address_decode(recipient, coin, testnet);
            BigInteger r = t.l;
            String kind = t.r;
            byte[] b1 = binint.n2b(txtype, 1);
            byte[] b2 = bytes.rev(binint.n2b(timestamp, 4));
            byte[] b3 = binint.h2b(publickey);
            byte[] b4 = binint.n2b(r, 8);
            byte[] b5 = bytes.rev(binint.n2b(amount, 8));
            byte[] b6 = signature;
            return bytes.concat(b1, b2, b3, b4, b5, b6);
        }
        if (fmt.equals("wavestx")) {
            int txtype = 4;
            BigInteger version = fields.get("version", BigInteger.valueOf(1));
            String publickey = fields.get("publickey", null);
            String asset = fields.get("asset", null);
            String fee_asset = fields.get("fee_asset", null);
            BigInteger timestamp = fields.get("timestamp");
            BigInteger amount = fields.get("amount");
            BigInteger fee = fields.get("fee");
            String recipient = fields.get("recipient");
            String attachment = fields.get("attachment", null);
            byte[] b_signature = fields.get("signature", new byte[]{ });
            byte[] b_publickey = publickey != null ? base58.decode(publickey) : new byte[32];
            byte[] b_asset = asset != null ? bytes.concat(new byte[]{ 1 }, base58.decode(asset)) : new byte[]{ 0 };
            byte[] b_fee_asset = fee_asset != null ? bytes.concat(new byte[]{ 1 }, base58.decode(fee_asset)) : new byte[]{ 0 };
            byte[] b_recipient = base58.decode(recipient);
            byte[] b_attachment = attachment != null ? base58.decode(attachment) : new byte[]{ };
            byte[] b0 = binint.n2b(version, 1);
            byte[] b1 = binint.n2b(BigInteger.valueOf(txtype), 1);
            byte[] b2 = version.compareTo(BigInteger.ONE) > 0 ? binint.n2b(version, 1) : new byte[]{ };
            byte[] b3 = b_publickey;
            byte[] b4 = b_asset;
            byte[] b5 = b_fee_asset;
            byte[] b6 = binint.n2b(timestamp, 8);
            byte[] b7 = binint.n2b(amount, 8);
            byte[] b8 = binint.n2b(fee, 8);
            byte[] b9 = b_recipient;
            byte[] b10 = binint.n2b(BigInteger.valueOf(b_attachment.length), 2);
            byte[] b11 = b_attachment;
            byte[] b12 = b_signature;
            return bytes.concat(b0, bytes.concat(b1, b2, b3, b4, b5, b6), bytes.concat(b7, b8, b9, b10, b11, b12));
        }
        if (fmt.equals("cbor")) {
            dict[] ins = fields.get("inputs");
            List<Object> inputs = new ArrayList<>();
            for (dict in : ins) {
                String txnid = in.get("txnid");
                BigInteger index = in.get("index", BigInteger.ZERO);
                Object pair = new Object[]{ binint.h2b(txnid), index };
                Object item = new Object[]{ BigInteger.ZERO, new cbor.Tag(BigInteger.valueOf(24), cbor.dumps(pair)) };
                inputs.add(item);
            }
            dict[] outs = fields.get("outputs");
            List<Object> outputs = new ArrayList<>();
            for (dict out : outs) {
                BigInteger amount = out.get("amount", BigInteger.ZERO);
                String address = out.get("address");
                Object struct = cbor.loads(base58.decode(address));
                Object item = new Object[]{ struct, amount };
                outputs.add(item);
            }
            Object data = new Object[]{ inputs, outputs, new HashMap<>() };
            if (fields.has("witnesses")) {
                dict[] wits = fields.get("witnesses");
                Object[] witnesses = new Object[wits.length];
                for (int i = 0; i < wits.length; i++) {
                    dict wit = wits[i];
                    String publickey = wit.get("publickey");
                    String chaincode = wit.get("chaincode");
                    byte[] signature = wit.get("signature");
                    Object pair = new Object[]{ binint.h2b(publickey + chaincode), signature };
                    Object item = new Object[]{ BigInteger.ZERO, new cbor.Tag(BigInteger.valueOf(24), cbor.dumps(pair)) };
                    witnesses[i] = item;
                }
                data = new Object[]{ data, witnesses };
            }
            return cbor.dumps(data);
        }
        if (fmt.equals("protobuf")) {
            pair<BigInteger, String> r1 = wallet.address_decode(fields.get("owner_address"), coin, testnet);
            BigInteger h1 = r1.l;
            String kind1 = r1.r;
            byte[] prefix1 = coins.attr(kind1 + ".base58.prefix", coin, testnet);
            pair<BigInteger, String> r2 = wallet.address_decode(fields.get("to_address"), coin, testnet);
            BigInteger h2 = r2.l;
            String kind2 = r2.r;
            byte[] prefix2 = coins.attr(kind2 + ".base58.prefix", coin, testnet);
            Map<Integer, Object> message_params = new HashMap<>();
            message_params.put(1, bytes.concat(prefix1, binint.n2b(h1, 20)));
            message_params.put(2, bytes.concat(prefix2, binint.n2b(h2, 20)));
            message_params.put(3, fields.get("amount"));
            Map<Integer, Object> message = new HashMap<>();
            message.put(1, "type.googleapis.com/protocol.TransferContract".getBytes());
            message.put(2, message_params);
            Map<Integer, Object> contract = new HashMap<>();
            contract.put(1, BigInteger.ONE);
            contract.put(2, message);
            Map<Integer, Object> data = new HashMap<>();
            data.put(1, fields.get("ref_block_bytes"));
            data.put(4, fields.get("ref_block_hash"));
            data.put(8, fields.get("expiration"));
            data.put(11, contract);
            if (fields.has("signature")) {
                Map<Integer, Object> signed_data = new HashMap<>();
                signed_data.put(1, data);
                signed_data.put(2, fields.get("signature"));
                data = signed_data;
            }
            return protobuf.dumps(data);
        }
        throw new IllegalStateException("Unknown format");
    }

    private static pair<dict, byte[]> inout_input_decode(byte[] txn) {
        int size1 = 32;
        if (size1 > txn.length) throw new IllegalArgumentException("End of input");
        byte[] b1 = bytes.sub(txn, 0, size1);
        byte[] t = bytes.sub(txn, size1);
        r(b1);
        String txnid = binint.b2h(b1);
        txn = t;
        pair<BigInteger, byte[]> r1 = parse_int32(txn);
        BigInteger index = r1.l;
        txn = r1.r;
        pair<BigInteger, byte[]> r2 = parse_varint(txn);
        int size2 = r2.l.intValue();
        txn = r2.r;
        if (size2 > txn.length) throw new IllegalArgumentException("End of input");
        byte[] inscript = bytes.sub(txn, 0, size2);
        byte[] b2 = bytes.sub(txn, size2);
        txn = b2;
        pair<BigInteger, byte[]> r3 = parse_int32(txn);
        BigInteger sequence = r3.l;
        txn = r3.r;
        dict fields = new dict();
        fields.put("txnid", txnid);
        fields.put("index", index);
        fields.put("script", inscript);
        fields.put("sequence", sequence);
        return new pair<>(fields, txn);
    }

    private static pair<dict, byte[]> inout_output_decode(byte[] txn) {
        pair<BigInteger, byte[]> r1 = parse_int64(txn);
        BigInteger amount = r1.l;
        txn = r1.r;
        pair<BigInteger, byte[]> r2 = parse_varint(txn);
        int size = r2.l.intValue();
        txn = r2.r;
        if (size > txn.length) throw new IllegalArgumentException("End of input");
        byte[] outscript = bytes.sub(txn, 0, size);
        byte[] b = bytes.sub(txn, size);
        txn = b;
        dict fields = new dict();
        fields.put("amount", amount);
        fields.put("script", outscript);
        return new pair<>(fields, txn);
    }

    private static pair<dict, byte[]> dcrinout_input_decode(byte[] txn) {
        int size1 = 32;
        if (size1 > txn.length) throw new IllegalArgumentException("End of input");
        String txnid = binint.b2h(bytes.rev(bytes.sub(txn, 0, size1)));
        txn = bytes.sub(txn, size1);
        pair<BigInteger, byte[]> r1 = parse_int32(txn);
        BigInteger index = r1.l;
        txn = r1.r;
        pair<BigInteger, byte[]> r2 = parse_int8(txn);
        BigInteger tree = r2.l;
        txn = r2.r;
        pair<BigInteger, byte[]> r3 = parse_int32(txn);
        BigInteger sequence = r3.l;
        txn = r3.r;
        dict fields = new dict();
        fields.put("txnid", txnid);
        fields.put("index", index);
        fields.put("tree", tree);
        fields.put("sequence", sequence);
        return new pair<>(fields, txn);
    }

    private static pair<dict, byte[]> dcrinout_output_decode(byte[] txn) {
        pair<BigInteger, byte[]> r1 = parse_int64(txn);
        BigInteger amount = r1.l;
        txn = r1.r;
        pair<BigInteger, byte[]> r2 = parse_int16(txn);
        BigInteger version = r2.l;
        txn = r2.r;
        pair<BigInteger, byte[]> r3 = parse_varint(txn);
        int size = r3.l.intValue();
        txn = r3.r;
        if (size > txn.length) throw new IllegalArgumentException("End of input");
        byte[] outscript = bytes.sub(txn, 0, size);
        txn = bytes.sub(txn, size);
        dict fields = new dict();
        fields.put("amount", amount);
        fields.put("version", version);
        fields.put("script", outscript);
        return new pair<>(fields, txn);
    }

    private static pair<dict, byte[]> dcrinout_witness_decode(byte[] txn) {
        pair<BigInteger, byte[]> r1 = parse_int64(txn);
        BigInteger amount = r1.l;
        txn = r1.r;
        pair<BigInteger, byte[]> r2 = parse_int32(txn);
        BigInteger blockheight = r2.l;
        txn = r2.r;
        pair<BigInteger, byte[]> r3 = parse_int32(txn);
        BigInteger blockindex = r3.l;
        txn = r3.r;
        pair<BigInteger, byte[]> r4 = parse_varint(txn);
        int size4 = r4.l.intValue();
        txn = r4.r;
        if (size4 > txn.length) throw new IllegalArgumentException("End of input");
        byte[] inscript = bytes.sub(txn, 0, size4);
        txn = bytes.sub(txn, size4);
        dict fields = new dict();
        fields.put("amount", amount);
        fields.put("blockheight", blockheight);
        fields.put("blockindex", blockindex);
        fields.put("script", inscript);
        return new pair<>(fields, txn);
    }

    private static pair<dict, byte[]> neoinout_input_decode(byte[] txn) {
        int size = 32;
        if (size > txn.length) throw new IllegalArgumentException("End of input");
        String txnid = binint.b2h(bytes.rev(bytes.sub(txn, 0, size)));
        txn = bytes.sub(txn, size);
        pair<BigInteger, byte[]> t = parse_int16(txn);
        BigInteger index = t.l;
        txn = t.r;
        dict fields = new dict();
        fields.put("txnid", txnid);
        fields.put("index", index);
        return new pair<>(fields, txn);
    }

    private static pair<dict, byte[]> neoinout_output_decode(byte[] txn, String coin, boolean testnet) {
        int asset_size = 32;
        if (asset_size > txn.length) throw new IllegalArgumentException("End of input");
        String asset = binint.b2h(bytes.rev(bytes.sub(txn, 0, asset_size)));
        txn = bytes.sub(txn, asset_size);
        pair<BigInteger, byte[]> t = parse_int64(txn);
        BigInteger amount = t.l;
        txn = t.r;
        int address_size = 20;
        if (address_size > txn.length) throw new IllegalArgumentException("End of input");
        BigInteger h = binint.b2n(bytes.sub(txn, 0, address_size));
        txn = bytes.sub(txn, address_size);
        String address = wallet.address_encode(h, "address", coin, testnet);
        dict fields = new dict();
        fields.put("asset", asset);
        fields.put("amount", amount);
        fields.put("address", address);
        return new pair<>(fields, txn);
    }

    private static pair<dict, byte[]> neoinout_script_decode(byte[] txn) {
        pair<BigInteger, byte[]> r1 = parse_varint(txn);
        int invocation_size = r1.l.intValue();
        txn = r1.r;
        if (invocation_size > txn.length) throw new IllegalArgumentException("End of input");
        byte[] invocation_script = bytes.sub(txn, 0, invocation_size);
        txn = bytes.sub(txn, invocation_size);
        pair<BigInteger, byte[]> r2 = parse_varint(txn);
        int verification_size = r2.l.intValue();
        txn = r2.r;
        if (verification_size > txn.length) throw new IllegalArgumentException("End of input");
        byte[] verification_script = bytes.sub(txn, 0, verification_size);
        txn = bytes.sub(txn, verification_size);
        dict fields = new dict();
        fields.put("invocation", invocation_script);
        fields.put("verification", verification_script);
        return new pair<>(fields, txn);
    }

    public static dict transaction_decode(byte[] txn, String coin, boolean testnet) {
        String fmt = coins.attr("transaction.format", coin, testnet);
        if (fmt.equals("inout")) {
            pair<BigInteger, byte[]> r1 = parse_int32(txn);
            BigInteger version = r1.l;
            txn = r1.r;
            BigInteger groupid = null;
            if (version.equals(BigInteger.valueOf(0x080000004L))) { // zcash sapling
                pair<BigInteger, byte[]> r2 = parse_int32(txn);
                groupid = r2.l;
                txn = r2.r;
            }
            pair<BigInteger, byte[]> r2 = parse_varint(txn);
            int input_count = r2.l.intValue();
            txn = r2.r;
            dict[] inputs = new dict[input_count];
            for (int i = 0; i < inputs.length; i++) {
                pair<dict, byte[]> r3 = inout_input_decode(txn);
                dict fields = r3.l;
                txn = r3.r;
                inputs[i] = fields;
            }
            pair<BigInteger, byte[]> r3 = parse_varint(txn);
            int output_count = r3.l.intValue();
            txn = r3.r;
            dict[] outputs = new dict[output_count];
            for (int i = 0; i < outputs.length; i++) {
                pair<dict, byte[]> r4 = inout_output_decode(txn);
                dict fields = r4.l;
                txn = r4.r;
                outputs[i] = fields;
            }
            pair<BigInteger, byte[]> r4 = parse_int32(txn);
            BigInteger locktime = r4.l;
            txn = r4.r;
            BigInteger expiryheight = null;
            if (version.equals(BigInteger.valueOf(0x080000004L))) { // zcash sapling
                pair<BigInteger, byte[]> r5 = parse_int32(txn);
                expiryheight = r5.l;
                txn = r5.r;
                pair<BigInteger, byte[]> r6 = parse_int64(txn);
                BigInteger valuebalance = r6.l;
                txn = r6.r;
                if (!valuebalance.equals(BigInteger.ZERO)) throw new IllegalArgumentException("Invalid transaction");
                pair<BigInteger, byte[]> r7 = parse_varint(txn);
                BigInteger vshieldedspend = r7.l;
                txn = r7.r;
                if (!vshieldedspend.equals(BigInteger.ZERO)) throw new IllegalArgumentException("Invalid transaction");
                pair<BigInteger, byte[]> r8 = parse_varint(txn);
                BigInteger vshieldedoutput = r8.l;
                txn = r8.r;
                if (!vshieldedoutput.equals(BigInteger.ZERO)) throw new IllegalArgumentException("Invalid transaction");
                pair<BigInteger, byte[]> r9 = parse_varint(txn);
                BigInteger vjoinsplit = r9.l;
                txn = r9.r;
                if (!vjoinsplit.equals(BigInteger.ZERO)) throw new IllegalArgumentException("Invalid transaction");
            }
            if (txn.length != 0) throw new IllegalArgumentException("Invalid transaction");
            dict fields = new dict();
            fields.put("version", version);
            if (groupid != null) fields.put("groupid", groupid);
            fields.put("inputs", inputs);
            fields.put("outputs", outputs);
            fields.put("locktime", locktime);
            if (expiryheight != null) fields.put("expiryheight", expiryheight);
            return fields;
        }
        if (fmt.equals("dcrinout")) {
            pair<BigInteger, byte[]> r1 = parse_int32(txn);
            BigInteger version = r1.l;
            txn = r1.r;
            pair<BigInteger, byte[]> r2 = parse_varint(txn);
            int input_count = r2.l.intValue();
            txn = r2.r;
            dict[] inputs = new dict[input_count];
            for (int i = 0; i < inputs.length; i++) {
                pair<dict, byte[]> r3 = dcrinout_input_decode(txn);
                dict fields = r3.l;
                txn = r3.r;
                inputs[i] = fields;
            }
            pair<BigInteger, byte[]> r3 = parse_varint(txn);
            int output_count = r3.l.intValue();
            txn = r3.r;
            dict[] outputs = new dict[output_count];
            for (int i = 0; i < outputs.length; i++) {
                pair<dict, byte[]> r4 = dcrinout_output_decode(txn);
                dict fields = r4.l;
                txn = r4.r;
                outputs[i] = fields;
            }
            pair<BigInteger, byte[]> r4 = parse_int32(txn);
            BigInteger locktime = r4.l;
            txn = r4.r;
            pair<BigInteger, byte[]> r5 = parse_int32(txn);
            BigInteger expiryheight = r5.l;
            txn = r5.r;
            dict[] witnesses = null;
            if (txn.length > 0) {
                pair<BigInteger, byte[]> r6 = parse_varint(txn);
                int witness_count = r6.l.intValue();
                txn = r6.r;
                witnesses = new dict[witness_count];
                for (int i = 0; i < witnesses.length; i++) {
                    pair<dict, byte[]> r7 = dcrinout_witness_decode(txn);
                    dict fields = r7.l;
                    txn = r7.r;
                    witnesses[i] = fields;
                }
            }
            if (txn.length != 0) throw new IllegalArgumentException("Invalid transaction");
            dict fields = new dict();
            fields.put("version", version);
            fields.put("inputs", inputs);
            fields.put("outputs", outputs);
            fields.put("locktime", locktime);
            fields.put("expiryheight", expiryheight);
            fields.put("witnesses", witnesses);
            return fields;
        }
        if (fmt.equals("neoinout")) {
            pair<BigInteger, byte[]> r1 = parse_int8(txn);
            BigInteger txtype = r1.l;
            txn = r1.r;
            if (!txtype.equals(BigInteger.valueOf(0x80))) throw new IllegalArgumentException("Invalid transaction");
            pair<BigInteger, byte[]> r2 = parse_int8(txn);
            BigInteger version = r2.l;
            txn = r2.r;
            if (!version.equals(BigInteger.ZERO)) throw new IllegalArgumentException("Invalid transaction");
            pair<BigInteger, byte[]> r3 = parse_varint(txn);
            int attr_count = r3.l.intValue();
            txn = r3.r;
            if (attr_count != 0) throw new IllegalArgumentException("Unsupported attributes");
            pair<BigInteger, byte[]> r4 = parse_varint(txn);
            int input_count = r4.l.intValue();
            txn = r4.r;
            dict[] inputs = new dict[input_count];
            for (int i = 0; i < inputs.length; i++) {
                pair<dict, byte[]> r5 = neoinout_input_decode(txn);
                dict fields = r5.l;
                txn = r5.r;
                inputs[i] = fields;
            }
            pair<BigInteger, byte[]> r6 = parse_varint(txn);
            int output_count = r6.l.intValue();
            txn = r6.r;
            dict[] outputs = new dict[output_count];
            for (int i = 0; i < outputs.length; i++) {
                pair<dict, byte[]> r7 = neoinout_output_decode(txn, coin, testnet);
                dict fields = r7.l;
                txn = r7.r;
                outputs[i] = fields;
            }
            if (txn.length == 0) {
                dict fields = new dict();
                fields.put("type", txtype);
                fields.put("version", version);
                fields.put("inputs", inputs);
                fields.put("outputs", outputs);
                return fields;
            }
            pair<BigInteger, byte[]> r8 = parse_varint(txn);
            int script_count = r8.l.intValue();
            txn = r8.r;
            dict[] scripts = new dict[script_count];
            for (int i = 0; i < scripts.length; i++) {
                pair<dict, byte[]> r7 = neoinout_script_decode(txn);
                dict fields = r7.l;
                txn = r7.r;
                scripts[i] = fields;
            }
            if (txn.length != 0) throw new IllegalArgumentException("Invalid transaction");
            dict fields = new dict();
            fields.put("type", txtype);
            fields.put("version", version);
            fields.put("inputs", inputs);
            fields.put("outputs", outputs);
            fields.put("scripts", scripts);
            return fields;
        }
        if (fmt.equals("rlp")) {
            pair<Object, byte[]> r = parse_rlp(txn);
            Object o = r.l;
            txn = r.r;
            if (txn.length != 0) throw new IllegalArgumentException("Invalid transaction");
            if (!(o instanceof Object[])) throw new IllegalArgumentException("Invalid transaction");
            Object[] l = (Object[]) o;
            if (l.length != 6 && l.length != 9) throw new IllegalArgumentException("Invalid transaction");
            dict fields = new dict();
            fields.put("nonce", parse_nlzint((byte[]) l[0]).l);
            fields.put("gasprice", parse_nlzint((byte[]) l[1]).l);
            fields.put("gaslimit", parse_nlzint((byte[]) l[2]).l);
            byte[] b = (byte[]) l[3];
            if (b.length > 0) {
                if (b.length != 20) throw new IllegalArgumentException("Invalid transaction");
                BigInteger h = binint.b2n(b);
                fields.put("to", wallet.address_encode(h, "address", coin, testnet));
            }
            fields.put("value", parse_nlzint((byte[]) l[4]).l);
            fields.put("data", l[5]);
            if (l.length > 6) {
                fields.put("v", l[6]);
                fields.put("r", l[7]);
                fields.put("s", l[8]);
            }
            return fields;
        }
        if (fmt.equals("serial")) {
            dict fields = parse_serial(txn);
            BigInteger amount = fields.get("Amount", null);
            BigInteger fee = fields.get("Fee", null);
            byte[] b_account = fields.get("Account", null);
            byte[] b_destination = fields.get("Destination", null);
            byte[] b_signingpubkey = fields.get("SigningPubKey", null);
            byte[] b_txnsignature = fields.get("TxnSignature", null);
            if (amount != null) {
                amount = amount.subtract(BigInteger.ONE.shiftLeft(62));
            }
            if (fee != null) {
                fee = fee.subtract(BigInteger.ONE.shiftLeft(62));
            }
            String account = null;
            if (b_account != null) {
                BigInteger h = binint.b2n(b_account);
                account = wallet.address_encode(h, "address", coin, testnet);
            }
            String destination = null;
            if (b_destination != null) {
                BigInteger h = binint.b2n(b_destination);
                destination = wallet.address_encode(h, "address", coin, testnet);
            }
            String signingpubkey = null;
            if (b_signingpubkey != null) {
                byte prefix = b_signingpubkey[0];
                byte[] b = new byte[b_signingpubkey.length-1];
                System.arraycopy(b_signingpubkey, 1, b, 0, b.length);
                if (prefix != 0x02 && prefix != 0x03) throw new IllegalArgumentException("Invalid prefix");
                boolean odd = prefix != 0x02;
                BigInteger x = binint.b2n(b);
                BigInteger y = secp256k1.fnd(x, odd);
                BigInteger[] P = new BigInteger[]{x, y};
                signingpubkey = wallet.publickey_encode(P, true, coin, testnet);
            }
            String txnsignature = null;
            if (b_txnsignature != null) {
                txnsignature = binint.b2h(b_txnsignature);
            }
            if (amount != null) fields.put("Amount", amount);
            if (fee != null) fields.put("Fee", fee);
            if (account != null) fields.put("Account", account);
            if (destination != null) fields.put("Destination", destination);
            if (signingpubkey != null) fields.put("SigningPubKey", signingpubkey);
            if (txnsignature != null) fields.put("TxnSignature", txnsignature);
            return fields;
        }
        if (fmt.equals("xdr")) {
            pair<BigInteger, byte[]> t = parse_int32(txn, false);
            BigInteger keytype = t.l;
            txn = t.r;
            if (!keytype.equals(BigInteger.ZERO)) throw new IllegalArgumentException("Unsupported keytype");
            if (32 > txn.length) throw new IllegalArgumentException("End of input");
            BigInteger h = binint.b2n(bytes.sub(txn, 0, 32));
            txn = bytes.sub(txn, 32);
            String account = wallet.address_encode(h, "address", coin, testnet);
            t = parse_int32(txn, false);
            BigInteger fee = t.l;
            txn = t.r;
            t = parse_int64(txn, false);
            BigInteger sequence = t.l;
            txn = t.r;
            t = parse_int32(txn, false);
            BigInteger count = t.l;
            txn = t.r;
            if (!count.equals(BigInteger.ZERO)) throw new IllegalArgumentException("Unsupported time bounds count");
            t = parse_int32(txn, false);
            BigInteger memotype = t.l;
            txn = t.r;
            if (!memotype.equals(BigInteger.ZERO)) throw new IllegalArgumentException("Unsupported memo type");
            t = parse_int32(txn, false);
            count = t.l;
            txn = t.r;
            dict[] operations = new dict[count.intValue()];
            for (int i = 0; i < operations.length; i++) {
                dict operation = new dict();
                // TODO generalize
                t = parse_int32(txn, false);
                count = t.l;
                txn = t.r;
                if (!count.equals(BigInteger.ZERO)) throw new IllegalArgumentException("Unsupported sources count");
                t = parse_int32(txn, false);
                BigInteger optype = t.l;
                txn = t.r;
                if (optype.equals(BigInteger.ZERO)) {
                    t = parse_int32(txn, false);
                    keytype = t.l;
                    txn = t.r;
                    if (!keytype.equals(BigInteger.ZERO)) throw new IllegalArgumentException("Unsupported keytype");
                    if (32 > txn.length) throw new IllegalArgumentException("End of input");
                    h = binint.b2n(bytes.sub(txn, 0, 32));
                    txn = bytes.sub(txn, 32);
                    String destination = wallet.address_encode(h, "address", coin, testnet);
                    t = parse_int64(txn, false);
                    BigInteger amount = t.l;
                    txn = t.r;
                    operation.put("Type", "CREATE_ACCOUNT");
                    operation.put("Destination", destination);
                    operation.put("Amount", amount);
                }
                else
                if (optype.equals(BigInteger.ONE)) {
                    t = parse_int32(txn, false);
                    keytype = t.l;
                    txn = t.r;
                    if (!keytype.equals(BigInteger.ZERO)) throw new IllegalArgumentException("Unsupported keytype");
                    if (32 > txn.length) throw new IllegalArgumentException("End of input");
                    h = binint.b2n(bytes.sub(txn, 0, 32));
                    txn = bytes.sub(txn, 32);
                    String destination = wallet.address_encode(h, "address", coin, testnet);
                    t = parse_int32(txn, false);
                    BigInteger assettype = t.l;
                    txn = t.r;
                    if (!assettype.equals(BigInteger.ZERO)) throw new IllegalArgumentException("Unsupported asset type");
                    t = parse_int64(txn, false);
                    BigInteger amount = t.l;
                    txn = t.r;
                    operation.put("Type", "PAYMENT");
                    operation.put("Destination", destination);
                    operation.put("Amount", amount);
                }
                else {
                    throw new IllegalArgumentException("Unsupported operation type");
                }
                operations[i] = operation;
            }
            t = parse_int32(txn, false);
            BigInteger flag = t.l;
            txn = t.r;
            if (!flag.equals(BigInteger.ZERO)) throw new IllegalArgumentException("Unsupported flag");
            dict fields= new dict();
            fields.put("Account", account);
            fields.put("Fee", fee);
            fields.put("Sequence", sequence);
            fields.put("Operations", operations);
            if (txn.length > 0) {
                t = parse_int32(txn, false);
                count = t.l;
                txn = t.r;
                dict[] signatures = new dict[count.intValue()];
                for (int i = 0; i < signatures.length; i++) {
                    if (4 > txn.length) throw new IllegalArgumentException("End of input");
                    byte[] hint = bytes.sub(txn, 0, 4);
                    txn = bytes.sub(txn, 4);
                    t = parse_int32(txn, false);
                    BigInteger size = t.l;
                    txn = t.r;
                    if (size.intValue() != 64) throw new IllegalArgumentException("Invalid signature size");
                    if (64 > txn.length) throw new IllegalArgumentException("End of input");
                    byte[] signature = bytes.sub(txn, 0, 64);
                    txn = bytes.sub(txn, 64);
                    dict sigobject = new dict();
                    sigobject.put("Hint", hint);
                    sigobject.put("Signature", signature);
                    signatures[i] = sigobject;
                }
                fields.put("Signatures", signatures);
                if (txn.length != 0) throw new IllegalArgumentException("Invalid transaction");
            }
            return fields;
        }
        if (fmt.equals("raiblock")) {
            if (txn.length != 176 && txn.length != 184 && txn.length != 240 && txn.length != 248)
                throw new IllegalArgumentException("Invalid transaction");
            BigInteger preamble = binint.b2n(bytes.sub(txn, 0, 32));
            txn = bytes.sub(txn, 32);
            BigInteger a = binint.b2n(bytes.sub(txn, 0, 32));
            txn = bytes.sub(txn, 32);
            String previous = binint.b2h(bytes.sub(txn, 0, 32));
            txn = bytes.sub(txn, 32);
            BigInteger r = binint.b2n(bytes.sub(txn, 0, 32));
            txn = bytes.sub(txn, 32);
            BigInteger balance = binint.b2n(bytes.sub(txn, 0, 16));
            txn = bytes.sub(txn, 16);
            String link = binint.b2h(bytes.sub(txn, 0, 32));
            txn = bytes.sub(txn, 32);
            if (!preamble.equals(BigInteger.valueOf(6))) throw new IllegalArgumentException("Invalid preamble");
            String account = wallet.address_encode(a, "address", coin, testnet);
            String representative = wallet.address_encode(r, "address", coin, testnet);
            dict fields = new dict();
            fields.put("account", account);
            fields.put("previous", previous);
            fields.put("representative", representative);
            fields.put("balance", balance);
            fields.put("link", link);
            if (txn.length >= 64) {
                byte[] signature = bytes.sub(txn, 0, 64);
                txn = bytes.sub(txn, 64);
                fields.put("signature", signature);
            }
            if (txn.length >= 8) {
                byte[] work = bytes.sub(txn, 0, 8);
                txn = bytes.sub(txn, 8);
                fields.put("work", work);
            }
            assert txn.length == 0;
            return fields;
        }
        if (fmt.equals("liskdatablock")) {
            if (txn.length != 21 && txn.length != 53 && txn.length != 85 && txn.length != 117)
                throw new IllegalArgumentException("Invalid transaction");
            BigInteger txtype = binint.b2n(bytes.sub(txn, 0, 1));
            txn = bytes.sub(txn, 1);
            BigInteger timestamp = binint.b2n(bytes.rev(bytes.sub(txn, 0, 4)));
            txn = bytes.sub(txn, 4);
            String publickey = null;
            if (txn.length == 48 || txn.length == 112) {
                publickey = binint.b2h(bytes.sub(txn, 0, 32));
                txn = bytes.sub(txn, 32);
            }
            BigInteger r = binint.b2n(bytes.sub(txn, 0, 8));
            txn = bytes.sub(txn, 8);
            BigInteger amount = binint.b2n(bytes.rev(bytes.sub(txn, 0, 8)));
            txn = bytes.sub(txn, 8);
            if (!txtype.equals(BigInteger.ZERO)) throw new IllegalArgumentException("Invalid type");
            String recipient = wallet.address_encode(r, "address", coin, testnet);
            dict fields = new dict();
            fields.put("timestamp", timestamp);
            fields.put("recipient", recipient);
            fields.put("amount", amount);
            if (publickey != null) fields.put("publickey", publickey);
            if (txn.length >= 64) {
                byte[] signature = bytes.sub(txn, 0, 64);
                txn = bytes.sub(txn, 64);
                fields.put("signature", signature);
            }
            assert txn.length == 0;
            return fields;
        }
        if (fmt.equals("wavestx")) {
            if (txn.length < 1) throw new IllegalArgumentException("End of input");
            BigInteger version = binint.b2n(bytes.sub(txn, 0, 1));
            txn = bytes.sub(txn, 1);
            if (txn.length < 1) throw new IllegalArgumentException("End of input");
            int txtype = binint.b2n(bytes.sub(txn, 0, 1)).intValue();
            txn = bytes.sub(txn, 1);
            if (txtype != 4) throw new IllegalArgumentException("Invalid type");
            if (version.compareTo(BigInteger.ONE) > 0) {
                if (txn.length < 1) throw new IllegalArgumentException("End of input");
                version = binint.b2n(bytes.sub(txn, 0, 1));
                txn = bytes.sub(txn, 1);
            }
            if (version.compareTo(BigInteger.valueOf(2)) > 0) throw new IllegalArgumentException("Invalid version");
            if (txn.length < 32) throw new IllegalArgumentException("End of input");
            byte[] b_publickey = bytes.sub(txn, 0, 32);
            txn = bytes.sub(txn, 32);
            String publickey = bytes.equ(b_publickey, new byte[32]) ? null : base58.encode(b_publickey);
            if (txn.length < 1) throw new IllegalArgumentException("End of input");
            int has_asset = binint.b2n(bytes.sub(txn, 0, 1)).intValue();
            txn = bytes.sub(txn, 1);
            if (has_asset > 1) throw new IllegalArgumentException("Invalid asset marker");
            String asset = null;
            if (has_asset == 1) {
                if (txn.length < 32) throw new IllegalArgumentException("End of input");
                asset = base58.encode(bytes.sub(txn, 0, 32));
                txn = bytes.sub(txn, 32);
            }
            if (txn.length < 1) throw new IllegalArgumentException("End of input");
            int has_fee_asset = binint.b2n(bytes.sub(txn, 0, 1)).intValue();
            txn = bytes.sub(txn, 1);
            if (has_fee_asset > 1) throw new IllegalArgumentException("Invalid asset marker");
            String fee_asset = null;
            if (has_fee_asset == 1) {
                if (txn.length < 32) throw new IllegalArgumentException("End of input");
                fee_asset = base58.encode(bytes.sub(txn, 0, 32));
                txn = bytes.sub(txn, 32);
            }
            if (txn.length < 8) throw new IllegalArgumentException("End of input");
            BigInteger timestamp = binint.b2n(bytes.sub(txn, 0, 8));
            txn = bytes.sub(txn, 8);
            if (txn.length < 8) throw new IllegalArgumentException("End of input");
            BigInteger amount = binint.b2n(bytes.sub(txn, 0, 8));
            txn = bytes.sub(txn, 8);
            if (txn.length < 8) throw new IllegalArgumentException("End of input");
            BigInteger fee = binint.b2n(bytes.sub(txn, 0, 8));
            txn = bytes.sub(txn, 8);
            if (txn.length < 26) throw new IllegalArgumentException("End of input");
            String recipient = base58.encode(bytes.sub(txn, 0, 26));
            txn = bytes.sub(txn, 26);
            if (txn.length < 2) throw new IllegalArgumentException("End of input");
            int size = binint.b2n(bytes.sub(txn, 0, 2)).intValue();
            txn = bytes.sub(txn, 2);
            if (txn.length < size) throw new IllegalArgumentException("End of input");
            String attachment = base58.encode(bytes.sub(txn, 0, size));
            txn = bytes.sub(txn, size);
            byte[] signature = null;
            if (txn.length != 0) {
                if (txn.length < 64) throw new IllegalArgumentException("End of input");
                signature = bytes.sub(txn, 0, 64);
                txn = bytes.sub(txn, 64);
                assert txn.length == 0;
            }
            dict fields = new dict();
            fields.put("version", version);
            if (publickey != null) fields.put("publickey", publickey);
            if (asset != null) fields.put("asset", asset);
            if (fee_asset != null) fields.put("fee_asset", fee_asset);
            fields.put("timestamp", timestamp);
            fields.put("amount", amount);
            fields.put("fee", fee);
            fields.put("recipient", recipient);
            if (attachment.length() > 0) fields.put("attachment", attachment);
            if (signature != null) fields.put("signature", signature);
            return fields;
        }
        if (fmt.equals("cbor")) {
            dict fields = new dict();
            Object[] data = (Object[]) cbor.loads(txn);
            if (data.length == 2) {
                Object[] witnesses = (Object[]) data[1];
                data = (Object[]) data[0];
                dict[] wits = new dict[witnesses.length];
                for (int i = 0; i < witnesses.length; i++) {
                    Object[] witness = (Object[]) witnesses[i];
                    if (witness.length != 2) throw new IllegalArgumentException("Invalid input");
                    BigInteger typ = (BigInteger) witness[0];
                    cbor.Tag obj = (cbor.Tag) witness[1];
                    if (typ.compareTo(BigInteger.ZERO) != 0) throw new IllegalArgumentException("Unknown type");
                    if (obj.tag.compareTo(BigInteger.valueOf(24)) != 0) throw new IllegalArgumentException("Unknown tag");
                    Object[] r = (Object[]) cbor.loads((byte[]) obj.value);
                    if (r.length != 2) throw new IllegalArgumentException("Invalid input");
                    byte[] b = (byte[]) r[0];
                    byte[] signature = (byte[]) r[1];
                    dict wit = new dict();
                    wit.put("publickey", binint.b2h(bytes.sub(b, 0, 32)));
                    wit.put("chaincode", binint.b2h(bytes.sub(b, 32)));
                    wit.put("signature", signature);
                    wits[i] = wit;
                }
                fields.put("witnesses", wits);
            }
            List<Object> inputs = (List<Object>) data[0];
            dict[] ins = new dict[inputs.size()];
            for (int i = 0; i < inputs.size(); i++) {
                Object[] input = (Object[]) inputs.get(i);
                if (input.length != 2) throw new IllegalArgumentException("Invalid input");
                BigInteger typ = (BigInteger) input[0];
                cbor.Tag obj = (cbor.Tag) input[1];
                if (typ.compareTo(BigInteger.ZERO) != 0) throw new IllegalArgumentException("Unknown type");
                if (obj.tag.compareTo(BigInteger.valueOf(24)) != 0) throw new IllegalArgumentException("Unknown tag");
                Object[] r = (Object[]) cbor.loads((byte[]) obj.value);
                byte[] b = (byte[]) r[0];
                BigInteger index = (BigInteger) r[1];
                dict in = new dict();
                in.put("txnid", binint.b2h(b));
                in.put("index", index);
                ins[i] = in;
            }
            fields.put("inputs", ins);
            List<Object> outputs = (List<Object>) data[1];
            dict[] outs = new dict[outputs.size()];
            for (int i = 0; i < outputs.size(); i++) {
                Object[] output = (Object[]) outputs.get(i);
                if (output.length != 2) throw new IllegalArgumentException("Invalid input");
                Object[] struct = (Object[]) output[0];
                BigInteger amount = (BigInteger) output[1];
                if (struct.length != 2) throw new IllegalArgumentException("Invalid input");
                cbor.Tag obj = (cbor.Tag) struct[0];
                BigInteger checksum = (BigInteger) struct[1];
                if (obj.tag.compareTo(BigInteger.valueOf(24)) != 0) throw new IllegalArgumentException("Unknown tag");
                BigInteger expected_checksum = binint.b2n(crc32.crc32xmodem((byte[]) obj.value));
                if (checksum.compareTo(expected_checksum) != 0) throw new IllegalArgumentException("Inconsistent checksum");
                String address = base58.encode(cbor.dumps(struct));
                dict out = new dict();
                out.put("address", address);
                out.put("amount", amount);
                outs[i] = out;
            }
            fields.put("outputs", outs);
            Map<Object, Object> attrs = (Map<Object, Object>) data[2];
            if (attrs.size() > 0) throw new IllegalArgumentException("Unsupported attributes");
            return fields;
        }
        if (fmt.equals("protobuf")) {
            Map<Integer, Object> meta_1 = new HashMap<>();
            Map<Integer, Object> meta_2 = new HashMap<>();
            meta_2.put(2, meta_1);
            Map<Integer, Object> meta_3 = new HashMap<>();
            meta_3.put(2, meta_2);
            Map<Integer, Object> meta = new HashMap<>();
            meta.put(11, meta_3);
            dict fields = new dict();
            Map<Integer, Object> data = (Map<Integer, Object>) protobuf.loads(txn, meta);
            if (!data.containsKey(11)) {
                fields.put("signature", data.get(2));
                data = (Map<Integer, Object>) protobuf.loads((byte[]) data.get(1), meta);
            }
            fields.put("ref_block_bytes", data.get(1));
            fields.put("ref_block_hash", data.get(4));
            fields.put("expiration", data.get(8));
            Map<Integer, Object> contract = (Map<Integer, Object>) data.get(11);
            BigInteger contract_type = (BigInteger) contract.get(1);
            if (contract_type.compareTo(BigInteger.ONE) != 0) throw new IllegalArgumentException("Unsupported contract type");
            Map<Integer, Object> message = (Map<Integer, Object>) contract.get(2);
            byte[] message_type = (byte[]) message.get(1);
            if (!bytes.equ(message_type, "type.googleapis.com/protocol.TransferContract".getBytes())) throw new IllegalArgumentException("Unsupported message type");
            Map<Integer, Object> message_params = (Map<Integer, Object>) message.get(2);
            String[] kinds = coins.attr("address.kinds", new String[]{ "address" }, coin, testnet);
            byte[] owner_address = (byte[]) message_params.get(1);
            for (String kind : kinds) {
                byte[] prefix = coins.attr(kind + ".base58.prefix", coin, testnet);
                if (!bytes.equ(bytes.sub(owner_address, 0, prefix.length), prefix)) continue;
                fields.put("owner_address", wallet.address_encode(binint.b2n(bytes.sub(owner_address, prefix.length)), kind, coin, testnet));
            }
            if (!fields.has("owner_address")) throw new IllegalArgumentException("Unsupported owner address");
            byte[] to_address = (byte[]) message_params.get(2);
            for (String kind : kinds) {
                byte[] prefix = coins.attr(kind + ".base58.prefix", coin, testnet);
                if (!bytes.equ(bytes.sub(to_address, 0, prefix.length), prefix)) continue;
                fields.put("to_address", wallet.address_encode(binint.b2n(bytes.sub(to_address, prefix.length)), kind, coin, testnet));
            }
            if (!fields.has("to_address")) throw new IllegalArgumentException("Unsupported to address");
            fields.put("amount", message_params.get(3));
            return fields;
        }
        throw new IllegalStateException("Unknown format");
    }

    public static String txnid(byte[] txn, String coin, boolean testnet) {
        String txnfmt = coins.attr("transaction.format", coin, testnet);
        if (txnfmt.equals("neoinout")) {
            dict fields = transaction_decode(txn, coin, testnet);
            if (fields.has("scripts")) fields.del("scripts");
            txn = transaction_encode(fields, coin, testnet);
        }
        if (txnfmt.equals("dcrinout")) {
            dict fields = transaction_decode(txn, coin, testnet);
            BigInteger version = fields.get("version");
            version = version.or(BigInteger.ONE.shiftLeft(16));
            fields.put("version", version);
            fields.put("witnesses", null);
            txn = transaction_encode(fields, coin, testnet);
        }
        if (txnfmt.equals("xdr")) {
            dict fields = transaction_decode(txn, coin, testnet);
            if (fields.has("Signatures")) fields.del("Signatures");
            txn = transaction_encode(fields, coin, testnet);
        }
        if (txnfmt.equals("raiblock")) {
            dict fields = transaction_decode(txn, coin, testnet);
            if (fields.has("signature")) fields.del("signature");
            if (fields.has("work")) fields.del("work");
            txn = transaction_encode(fields, coin, testnet);
        }
        if (txnfmt.equals("wavestx")) {
            dict fields = transaction_decode(txn, coin, testnet);
            if (fields.has("signature")) fields.del("signature");
            txn = transaction_encode(fields, coin, testnet);
            txn = bytes.sub(txn, 1);
        }
        if (txnfmt.equals("cbor")) {
            dict fields = transaction_decode(txn, coin, testnet);
            if (fields.has("witnesses")) fields.del("witnesses");
            txn = transaction_encode(fields, coin, testnet);
        }
        if (txnfmt.equals("protobuf")) {
            dict fields = transaction_decode(txn, coin, testnet);
            if (fields.has("signature")) fields.del("signature");
            txn = transaction_encode(fields, coin, testnet);
        }
        String fun = coins.attr("transaction.hashing", coin, testnet);
        byte[] prefix = coins.attr("transaction.hashing.prefix", new byte[]{ }, coin, testnet);
        byte[] b;
        switch (fun) {
            case "hash256": b = hashing.hash256(bytes.concat(prefix, txn)); break;
            case "keccak256": b = hashing.keccak256(bytes.concat(prefix, txn)); break;
            case "sha256": b = hashing.sha256(bytes.concat(prefix, txn)); break;
            case "sha512h": b = hashing.sha512h(bytes.concat(prefix, txn)); break;
            case "blake1s": b = hashing.blake1s(bytes.concat(prefix, txn)); break;
            case "blake2b256": b = hashing.blake2b(bytes.concat(prefix, txn), 32); break;
            default: throw new IllegalStateException("Unknown hashing function");
        }
        boolean reverse = coins.attr("transaction.hashing.reverse", false, coin, testnet);
        if (reverse) r(b);
        int bits = coins.attr("transaction.id.bits", 256, coin, testnet);
        b = bytes.sub(b, b.length - bits / 8);
        String fmt = coins.attr("transaction.id.format", "hex", coin, testnet);
        switch (fmt) {
            case "hex": return binint.b2h(b);
            case "decimal": return binint.b2n(b).toString();
            case "base58": return base58.encode(b);
            default: throw new IllegalStateException("Unknown format");
        }
    }

    private static byte[] sighash_default(dict fields, int i, byte[] inscript, BigInteger amount, int flag, String coin, boolean testnet) {
        dict[] inputs = fields.get("inputs");
        inputs[i].put("script", inscript);
        byte[] txn = transaction_encode(fields, coin, testnet);
        inputs[i].put("script", new byte[]{ });
        byte[] f = int32(BigInteger.valueOf(flag));
        return bytes.concat(txn, f);
    }

    private static byte[] sighash_forkid(dict fields, int i, byte[] inscript, BigInteger amount, int flag, String coin, boolean testnet) {
        if (amount == null) throw new IllegalArgumentException("Amount required");
        BigInteger version = fields.get("version");
        dict[] inputs = fields.get("inputs");
        dict[] outputs = fields.get("outputs");
        BigInteger locktime = fields.get("locktime");
        int t2_length = (32 + 4)*inputs.length;
        byte[] t2 = new byte[t2_length];
        int t2_offset = 0;
        for (dict input : inputs) {
            byte[] txnid = binint.h2b(input.get("txnid"));
            r(txnid);
            byte[] b = int32(input.get("index"));
            System.arraycopy(txnid, 0, t2, t2_offset, txnid.length); t2_offset += txnid.length;
            System.arraycopy(b, 0, t2, t2_offset, b.length); t2_offset += b.length;
        }
        int t3_length = 4*inputs.length;
        byte[] t3 = new byte[t3_length];
        int t3_offset = 0;
        for (dict input : inputs) {
            byte[] b = int32(input.get("sequence"));
            System.arraycopy(b, 0, t3, t3_offset, b.length); t3_offset += b.length;
        }
        int t10_length = 0;
        for (dict output : outputs) {
            byte[] outscript = output.get("script");
            t10_length += 8 + varint(BigInteger.valueOf(outscript.length)).length + outscript.length;
        }
        byte[] t10 = new byte[t10_length];
        int t10_offset = 0;
        for (dict output : outputs) {
            byte[] b = int64(output.get("amount"));
            byte[] outscript = output.get("script");
            byte[] l = varint(BigInteger.valueOf(outscript.length));
            System.arraycopy(b, 0, t10, t10_offset, b.length); t10_offset += b.length;
            System.arraycopy(l, 0, t10, t10_offset, l.length); t10_offset += l.length;
            System.arraycopy(outscript, 0, t10, t10_offset, outscript.length); t10_offset += outscript.length;
        }
        dict subfields = inputs[i];
        byte[] txnid = binint.h2b(subfields.get("txnid"));
        r(txnid);
        BigInteger index = subfields.get("index");
        BigInteger sequence = subfields.get("sequence");
        byte[] b1 = int32(version);
        byte[] b2 = hashing.hash256(t2);
        byte[] b3 = hashing.hash256(t3);
        byte[] b4 = txnid;
        byte[] b5 = int32(index);
        byte[] b6 = varint(BigInteger.valueOf(inscript.length));
        byte[] b7 = inscript;
        byte[] b8 = int64(amount);
        byte[] b9 = int32(sequence);
        byte[] b10 = hashing.hash256(t10);
        byte[] b11 = int32(locktime);
        byte[] b12 = int32(BigInteger.valueOf(flag));
        return bytes.concat(bytes.concat(b1, b2, b3, b4, b5, b6), bytes.concat(b7, b8, b9, b10, b11, b12));
    }

    private static byte[] sighash_sapling(dict fields, int i, byte[] inscript, BigInteger amount, int flag, String coin, boolean testnet) {
        if (amount == null) throw new IllegalArgumentException("Amount required");
        BigInteger version = fields.get("version");
        BigInteger groupid = fields.get("groupid");
        dict[] inputs = fields.get("inputs");
        dict[] outputs = fields.get("outputs");
        BigInteger locktime = fields.get("locktime");
        BigInteger expiryheight = fields.get("expiryheight");
        int t3_length = (32 + 4)*inputs.length;
        byte[] t3 = new byte[t3_length];
        int t3_offset = 0;
        for (dict input : inputs) {
            byte[] txnid = binint.h2b(input.get("txnid"));
            r(txnid);
            byte[] b = int32(input.get("index"));
            System.arraycopy(txnid, 0, t3, t3_offset, txnid.length); t3_offset += txnid.length;
            System.arraycopy(b, 0, t3, t3_offset, b.length); t3_offset += b.length;
        }
        int t4_length = 4*inputs.length;
        byte[] t4 = new byte[t4_length];
        int t4_offset = 0;
        for (dict input : inputs) {
            byte[] b = int32(input.get("sequence"));
            System.arraycopy(b, 0, t4, t4_offset, b.length); t4_offset += b.length;
        }
        int t5_length = 0;
        for (dict output : outputs) {
            byte[] outscript = output.get("script");
            t5_length += 8 + varint(BigInteger.valueOf(outscript.length)).length + outscript.length;
        }
        byte[] t5 = new byte[t5_length];
        int t5_offset = 0;
        for (dict output : outputs) {
            byte[] b = int64(output.get("amount"));
            byte[] outscript = output.get("script");
            byte[] l = varint(BigInteger.valueOf(outscript.length));
            System.arraycopy(b, 0, t5, t5_offset, b.length); t5_offset += b.length;
            System.arraycopy(l, 0, t5, t5_offset, l.length); t5_offset += l.length;
            System.arraycopy(outscript, 0, t5, t5_offset, outscript.length); t5_offset += outscript.length;
        }
        dict subfields = inputs[i];
        byte[] txnid = binint.h2b(subfields.get("txnid"));
        r(txnid);
        BigInteger index = subfields.get("index");
        BigInteger sequence = subfields.get("sequence");
        byte[] b1 = int32(version);
        byte[] b2 = int32(groupid);
        byte[] b3 = hashing.blake2b(t3, "ZcashPrevoutHash".getBytes(), 32);
        byte[] b4 = hashing.blake2b(t4, "ZcashSequencHash".getBytes(), 32);
        byte[] b5 = hashing.blake2b(t5, "ZcashOutputsHash".getBytes(), 32);
        byte[] b6 = new byte[32];
        byte[] b7 = new byte[32];
        byte[] b8 = new byte[32];
        byte[] b9 = int32(locktime);
        byte[] b10 = int32(expiryheight);
        byte[] b11 = int64(BigInteger.ZERO);
        byte[] b12 = int32(BigInteger.valueOf(flag));
        byte[] b13 = txnid;
        byte[] b14 = int32(index);
        byte[] b15 = varint(BigInteger.valueOf(inscript.length));
        byte[] b16 = inscript;
        byte[] b17 = int64(amount);
        byte[] b18 = int32(sequence);
        return bytes.concat(bytes.concat(b1, b2, b3, b4, b5, b6), bytes.concat(b7, b8, b9, b10, b11, b12), bytes.concat(b13, b14, b15, b16, b17, b18));
    }

    private static byte[] dcrsighash_default(dict fields, int i, byte[] inscript, BigInteger amount, int flag, String coin, boolean testnet) {
        BigInteger version = fields.get("version");
        fields.put("version", version.or(BigInteger.ONE.shiftLeft(16)));
        byte[] txn = transaction_encode(fields, coin, testnet);
        fields.put("version", version);
        dict[] inputs = fields.get("inputs");
        byte[] b = int32(version.or(BigInteger.valueOf(3).shiftLeft(16)));
        b = bytes.concat(b, varint(BigInteger.valueOf(inputs.length)));
        for (int index = 0; index < inputs.length; index++) {
            byte[] s = index == i ? inscript : new byte[]{};
            b = bytes.concat(b, varint(BigInteger.valueOf(s.length)), s);
        }
        byte[] b1 = int32(BigInteger.valueOf(flag));
        byte[] b2 = hashing.blake1s(txn);
        byte[] b3 = hashing.blake1s(b);
        return bytes.concat(b1, b2, b3);
    }

    public static byte[] transaction_sign(byte[] txn, Object params, String coin, boolean testnet) {
        String fmt = coins.attr("transaction.format", coin, testnet);
        if (fmt.equals("inout")) {
            int sighashflag = SIGHASH_ALL;
            String method = coins.attr("sighash.method", coin, testnet);
            sighashfun sighashfunc;
            if (method.equals("default")) sighashfunc = transaction::sighash_default;
            else
            if (method.equals("sapling")) sighashfunc = transaction::sighash_sapling;
            else
            if (method.equals("forkid")) {
                sighashfunc = transaction::sighash_forkid;
                int forkid = coins.attr("sighash.forkid", coin, testnet);
                sighashflag |= (forkid << 8) | SIGHASH_FORKID;
            }
            else {
                throw new IllegalStateException("Unknown method");
            }
            dict fields = transaction_decode(txn, coin, testnet);
            dict[] inputs = fields.get("inputs");
            if (!(params instanceof Object[])) {
                Object[] t = new Object[inputs.length];
                for (int i = 0; i < t.length; i++) t[i] = params;
                params = t;
            }
            Object[] _params = (Object[]) params;
            for (dict subfields : inputs) {
                subfields.put("script", new byte[]{ });
            }
            byte[][] inscripts = new byte[inputs.length][];
            for (int i = 0; i < inputs.length; i++) {
                Object param = _params[i];
                if (!(param instanceof dict)) {
                    String privatekey = null;
                    BigInteger amount = null;
                    if (param instanceof String) {
                        privatekey = (String) param;
                    }
                    if (param instanceof Object[]) {
                        Object[] tuple = (Object[]) param;
                        privatekey = (String) tuple[0];
                        amount = (BigInteger) tuple[1];
                    }
                    String publickey = wallet.publickey_from_privatekey(privatekey, coin, testnet);
                    String address = wallet.address_from_publickey(publickey, coin, testnet);
                    dict _dict = new dict();
                    _dict.put("privatekeys", new String[]{ privatekey });
                    _dict.put("script", script.scriptpubkey(address, null, coin, testnet));
                    _dict.put("scriptsigfun", (scriptsigfun) (signatures -> script.scriptsig(signatures[0], publickey)));
                    _dict.put("amount", amount);
                    param = _dict;
                }
                dict _dict = (dict)param;
                String[] privatekeys = _dict.get("privatekeys");
                byte[] inscript = _dict.get("script");
                scriptsigfun scriptsigfun = _dict.get("scriptsigfun");
                BigInteger amount = _dict.get("amount", null);
                byte[] sighashdata = sighashfunc.f(fields, i, inscript, amount, sighashflag, coin, testnet);
                byte[][] signatures = new byte[privatekeys.length][];
                for (int j = 0; j < privatekeys.length; j++) {
                    String privatekey = privatekeys[j];
                    byte[] signature = signing.signature_create(privatekey, sighashdata, null, coin, testnet);
                    byte[] f = int8(BigInteger.valueOf(sighashflag & 0xff));
                    signatures[j] = bytes.concat(signature, f);
                }
                inscript = scriptsigfun.f(signatures);
                inscripts[i] = inscript;
            }
            for (int i = 0; i < inputs.length; i++) {
                dict subfields = inputs[i];
                subfields.put("script", inscripts[i]);
            }
            return transaction_encode(fields, coin, testnet);
        }
        if (fmt.equals("dcrinout")) {
            int sighashflag = SIGHASH_ALL;
            String method = coins.attr("sighash.method", coin, testnet);
            sighashfun sighashfunc;
            if (method.equals("default")) sighashfunc = transaction::dcrsighash_default;
            else {
                throw new IllegalStateException("Unknown method");
            }
            dict fields = transaction_decode(txn, coin, testnet);
            if (fields.has("witnesses")) fields.del("witnesses");
            dict[] inputs = fields.get("inputs");
            if (!(params instanceof Object[])) {
                Object[] t = new Object[inputs.length];
                for (int i = 0; i < t.length; i++) t[i] = params;
                params = t;
            }
            Object[] _params = (Object[]) params;
            dict[] witnesses = new dict[inputs.length];
            for (int i = 0; i < inputs.length; i++) {
                Object param = _params[i];
                if (!(param instanceof dict)) {
                    String privatekey = null;
                    BigInteger amount = BigInteger.ZERO;
                    if (param instanceof String) {
                        privatekey = (String) param;
                    }
                    if (param instanceof Object[]) {
                        Object[] tuple = (Object[]) param;
                        privatekey = (String) tuple[0];
                        amount = (BigInteger) tuple[1];
                    }
                    String publickey = wallet.publickey_from_privatekey(privatekey, coin, testnet);
                    String address = wallet.address_from_publickey(publickey, coin, testnet);
                    pair<BigInteger[], Boolean> t1 = wallet.publickey_decode(publickey, coin,testnet);
                    BigInteger[] P = t1.l;
                    boolean compressed = t1.r;
                    pair<BigInteger, Boolean> t2 = secp256k1.enc(P);
                    BigInteger p = t2.l;
                    boolean odd = t2.r;
                    byte[] prefix = odd ? new byte[]{ (byte)0x03 } : new byte[]{ (byte)0x02 };
                    byte[] b = bytes.concat(prefix, binint.n2b(p, 32));
                    String publickey_sec2 = binint.b2h(b);
                    dict _dict = new dict();
                    _dict.put("privatekeys", new String[]{ privatekey });
                    _dict.put("script", script.scriptpubkey(address, null, coin, testnet));
                    _dict.put("scriptsigfun", (scriptsigfun) (signatures -> script.scriptsig(signatures[0], publickey_sec2)));
                    _dict.put("amount", amount);
                    param = _dict;
                }
                dict _dict = (dict)param;
                String[] privatekeys = _dict.get("privatekeys");
                byte[] inscript = _dict.get("script");
                scriptsigfun scriptsigfun = _dict.get("scriptsigfun");
                BigInteger amount = _dict.get("amount", BigInteger.ZERO);
                byte[] sighashdata = sighashfunc.f(fields, i, inscript, amount, sighashflag, coin, testnet);
                byte[][] signatures = new byte[privatekeys.length][];
                for (int j = 0; j < privatekeys.length; j++) {
                    String privatekey = privatekeys[j];
                    byte[] signature = signing.signature_create(privatekey, sighashdata, null, coin, testnet);
                    byte[] f = int8(BigInteger.valueOf(sighashflag & 0xff));
                    signatures[j] = bytes.concat(signature, f);
                }
                inscript = scriptsigfun.f(signatures);
                dict witness = new dict();
                if (_dict.has("amount")) witness.put("amount", _dict.get("amount"));
                if (_dict.has("blockheight")) witness.put("blockheight", _dict.get("blockheight"));
                if (_dict.has("blockindex")) witness.put("blockindex", _dict.get("blockindex"));
                witness.put("script", inscript);
                witnesses[i] = witness;
            }
            fields.put("witnesses", witnesses);
            return transaction_encode(fields, coin, testnet);
        }
        if (fmt.equals("neoinout")) {
            dict fields = transaction_decode(txn, coin, testnet);
            dict[] inputs = fields.get("inputs");
            if (fields.has("scripts")) fields.del("scripts");
            txn = transaction_encode(fields, coin, testnet);
            if (!(params instanceof Object[])) {
                Object[] t = new Object[inputs.length];
                for (int i = 0; i < t.length; i++) t[i] = params;
                params = t;
            }
            Object[] _params = (Object[]) params;
            List<String> hashset = new ArrayList<>();
            Map<String, dict> scriptmap = new HashMap<>();
            for (Object param : _params) {
                String privatekey = null;
                BigInteger amount = null;
                if (param instanceof String) {
                    privatekey = (String) param;
                }
                if (param instanceof Object[]) {
                    Object[] tuple = (Object[]) param;
                    privatekey = (String) tuple[0];
                    amount = (BigInteger) tuple[1];
                }
                String publickey = wallet.publickey_from_privatekey(privatekey, coin, testnet);
                String address = wallet.address_from_publickey(publickey, coin, testnet);
                pair<BigInteger, String> t = wallet.address_decode(address, coin, testnet);
                BigInteger h = t.l;
                String kind = t.r;
                String hash160 = binint.b2h(bytes.rev(binint.n2b(h, 20)));
                if (hashset.contains(hash160)) continue;
                byte[] signature = signing.signature_create(privatekey, txn, null, coin, testnet);
                byte[] invocation_script = script.OP_PUSHDATA(signature);
                byte[] verification_script = bytes.concat(script.OP_PUSHDATA(binint.h2b(publickey)), script.OP_CHECKSIG);
                hashset.add(hash160);
                dict map = new dict();
                map.put("invocation", invocation_script);
                map.put("verification", verification_script);
                scriptmap.put(hash160, map);
            }
            Collections.sort(hashset);
            List<dict> scripts = new ArrayList<>();
            for (String hash160 : hashset) {
                scripts.add(scriptmap.get(hash160));
            }
            fields.put("scripts", scripts.toArray(new dict[]{ }));
            return transaction_encode(fields, coin, testnet);
        }
        if (fmt.equals("rlp")) {
            dict fields = transaction_decode(txn, coin, testnet);
            if (fields.has("v")) fields.del("v");
            if (fields.has("r")) fields.del("r");
            if (fields.has("s")) fields.del("s");
            // chain id protects against replay attacks EIP 155
            int chain_id = coins.attr("chain.id", -1, coin, testnet);
            if (chain_id != -1) {
                fields.put("v", binint.n2b(BigInteger.valueOf(chain_id), 1));
                fields.put("r", new byte[0]);
                fields.put("s", new byte[0]);
            }
            String privatekey = (String) params;
            txn = transaction_encode(fields, coin, testnet);
            byte[] signature = signing.signature_create(privatekey, txn, null, coin, testnet);
            Object[] t = signing.signature_decode(signature, coin, testnet);
            BigInteger r = (BigInteger) t[0];
            BigInteger s = (BigInteger) t[1];
            boolean odd = (boolean) t[2];
            int v = 27 + (odd ? 1 : 0);
            if (chain_id != -1) v += 8 + 2 * chain_id;
            fields.put("v", binint.n2b(BigInteger.valueOf(v), 1));
            fields.put("r", binint.n2b(r, 32));
            fields.put("s", binint.n2b(s, 32));
            return transaction_encode(fields, coin, testnet);
        }
        if (fmt.equals("serial")) {
            dict fields = transaction_decode(txn, coin, testnet);
            if (fields.has("TxnSignature")) fields.del("TxnSignature");
            String privatekey = (String) params;
            fields.put("Flags", BigInteger.valueOf(0x80000000L)); // tfFullyCanonicalSig
            fields.put("SigningPubKey", wallet.publickey_from_privatekey(privatekey, coin, testnet));
            txn = transaction_encode(fields, coin, testnet);
            byte[] signature = signing.signature_create(privatekey, txn, null, coin, testnet);
            fields.put("TxnSignature", binint.b2h(signature));
            return transaction_encode(fields, coin, testnet);
        }
        if (fmt.equals("xdr")) {
            dict fields = transaction_decode(txn, coin, testnet);
            String account = fields.get("Account");
            pair<BigInteger, String> t = wallet.address_decode(account, coin, testnet);
            BigInteger p = t.l;
            String kind = t.r;
            byte[] b_account = binint.n2b(p, 32);
            if (fields.has("Signatures")) fields.del("Signatures");
            String privatekey = (String) params;
            txn = transaction_encode(fields, coin, testnet);
            byte[] signature = signing.signature_create(privatekey, txn, null, coin, testnet);
            byte[] hint = bytes.sub(b_account, -4);
            dict sigobject = new dict();
            sigobject.put("Hint", hint);
            sigobject.put("Signature", signature);
            fields.put("Signatures", new dict[]{ sigobject });
            return transaction_encode(fields, coin, testnet);
        }
        if (fmt.equals("raiblock")) {
            dict fields = transaction_decode(txn, coin, testnet);
            byte[] work = fields.get("work", null);
            if (fields.has("signature")) fields.del("signature");
            if (fields.has("work")) fields.del("work");
            String privatekey = (String) params;
            txn = transaction_encode(fields, coin, testnet);
            byte[] signature = signing.signature_create(privatekey, txn, null, coin, testnet);
            fields.put("signature", signature);
            if (work == null) {
                long threshold = coins.attr("transaction.pow.threshold", coin, testnet);
                BigInteger _threshold = BigInteger.valueOf(threshold);
                if (_threshold.compareTo(BigInteger.ZERO) < 0) {
                    _threshold = BigInteger.ONE.shiftLeft(64).add(_threshold);
                }
                byte[] previous = binint.h2b((String) fields.get("previous"));
                if (binint.b2n(previous).equals(BigInteger.ZERO)) {
                    String account = (String) fields.get("account");
                    pair<BigInteger, String> t = wallet.address_decode(account, coin, testnet);
                    BigInteger h = t.l;
                    String kind = t.r;
                    previous = binint.n2b(h, 32);
                }
                BigInteger i = BigInteger.ZERO;
                while (true) {
                    work = binint.n2b(i, 8);
                    byte[] b = bytes.rev(hashing.blake2b(bytes.concat(bytes.rev(work), previous), 8));
                    if (binint.b2n(b).compareTo(_threshold) > 0) break;
                    i = i.add(BigInteger.ONE);
                }
            }
            fields.put("work", work);
            return transaction_encode(fields, coin, testnet);
        }
        if (fmt.equals("liskdatablock")) {
            dict fields = transaction_decode(txn, coin, testnet);
            if (fields.has("signature")) fields.del("signature");
            String privatekey = (String) params;
            String publickey = wallet.publickey_from_privatekey(privatekey, coin, testnet);
            fields.put("publickey", publickey);
            txn = transaction_encode(fields, coin, testnet);
            byte[] signature = signing.signature_create(privatekey, txn, null, coin, testnet);
            fields.put("signature", signature);
            return transaction_encode(fields, coin, testnet);
        }
        if (fmt.equals("wavestx")) {
            dict fields = transaction_decode(txn, coin, testnet);
            if (fields.has("signature")) fields.del("signature");
            String privatekey = (String) params;
            String publickey = wallet.publickey_from_privatekey(privatekey, coin, testnet);
            fields.put("publickey", publickey);
            txn = transaction_encode(fields, coin, testnet);
            txn = bytes.sub(txn, 1);
            byte[] signature = signing.signature_create(privatekey, txn, null, coin, testnet);
            fields.put("signature", signature);
            return transaction_encode(fields, coin, testnet);
        }
        if (fmt.equals("cbor")) {
            dict fields = transaction_decode(txn, coin, testnet);
            if (fields.has("witnesses")) fields.del("witnesses");
            txn = transaction_encode(fields, coin, testnet);
            dict[] inputs = fields.get("inputs");
            if (!(params instanceof Object[])) {
                Object[] t = new Object[inputs.length];
                for (int i = 0; i < t.length; i++) t[i] = params;
                params = t;
            }
            Object[] _params = (Object[]) params;
            dict[] witnesses = new dict[inputs.length];
            for (int i = 0; i < inputs.length; i++) {
                Object param = _params[i];
                String privatekey = null;
                if (param instanceof String) {
                    privatekey = (String) param;
                }
                if (param instanceof Object[]) {
                    Object[] tuple = (Object[]) param;
                    privatekey = (String) tuple[0];
                }
                String publickey = wallet.publickey_from_privatekey(privatekey, coin, testnet);
                byte[] signature = signing.signature_create(privatekey, txn, null, coin, testnet);
                dict witness = new dict();
                witness.put("publickey", publickey);
                witness.put("chaincode", binint.b2h(new byte[32]));
                witness.put("signature", signature);
                witnesses[i] = witness;
            }
            fields.put("witnesses", witnesses);
            return transaction_encode(fields, coin, testnet);
        }
        if (fmt.equals("protobuf")) {
            dict fields = transaction_decode(txn, coin, testnet);
            if (fields.has("signature")) fields.del("signature");
            String privatekey = (String) params;
            txn = transaction_encode(fields, coin, testnet);
            byte[] signature = signing.signature_create(privatekey, txn, null, coin, testnet);
            fields.put("signature", signature);
            return transaction_encode(fields, coin, testnet);
        }
        throw new IllegalStateException("Unknown format");
    }

    public interface sighashfun {
        byte[] f(dict fields, int i, byte[] inscript, BigInteger amount, int sighashflag, String coin, boolean testnet);
    }

    public interface scriptsigfun {
        byte[] f(byte[][] signatures);
    }

}
