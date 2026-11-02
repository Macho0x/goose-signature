// BIP-143 SegWit v0 sighash. The caller supplies scriptCode (P2WPKH or
// P2WSH) and the spent amount. The signature tail is strict DER.

import std;
import crypto.sha256;
import crypto.secp256k1;
import btc_legacy;

namespace btc_segwit;

fn append_u32(out: u8[>..]&, v: u32) {
    out.push((v & 0xff) as u8);
    out.push(((v >> 8) & 0xff) as u8);
    out.push(((v >> 16) & 0xff) as u8);
    out.push((v >> 24) as u8);
}

fn append_cs(out: u8[>..]&, n: i64) {
    if n < 253 {
        out.push(n as u8);
        return;
    }
    out.push(253);
    out.push((n & 0xff) as u8);
    out.push(((n >> 8) & 0xff) as u8);
}

fn read_cs(b: u8[:], at: i64) -> i64, i64, bool {
    if at >= b.len { return 0, at, false; }
    let n = b[at];
    if n < 253 { return n, at + 1, true; }
    if n == 253 {
        if at + 3 > b.len { return 0, at, false; }
        let b0: i64 = b[at + 1];
        let b1: i64 = b[at + 2];
        return b0 | (b1 << 8), at + 3, true;
    }
    return 0, at, false;
}

fn hash256(data: u8[:]) -> u8[32] { sha256::hash256(data) }

fn zeros() -> u8[32] { return [0; 32]; }

fn sighash(raw: u8[:], script: u8[:], amount: u8[:], n_in: i64, hash_type: u32) -> u8[32], bool {
    if raw.len < 10 || amount.len != 8 || n_in < 0 { return [0; 32], false; }
    let n_in_count, at1, ok1 = read_cs(raw, 4);
    if !ok1 { return [0; 32], false; }
    var prevs: u8[>..] = [];
    var seqs: u8[>..] = [];
    var at = at1;
    for i in 0..n_in_count {
        if at + 36 > raw.len { return [0; 32], false; }
        prevs.append(raw[at..at + 36]);
        at += 36;
        let sl, at2, ok = read_cs(raw, at);
        if !ok || at2 + sl + 4 > raw.len { return [0; 32], false; }
        at = at2 + sl;
        seqs.append(raw[at..at + 4]);
        at += 4;
    }
    let n_out, at3, ok3 = read_cs(raw, at);
    if !ok3 || n_in >= n_in_count { return [0; 32], false; }
    at = at3;
    var outs: u8[>..] = [];
    var olen: i64[>..] = [];
    var ostart: i64[>..] = [];
    for i in 0..n_out {
        let start = outs.len;
        if at + 8 > raw.len { return [0; 32], false; }
        outs.append(raw[at..at + 8]);
        at += 8;
        let sl, at2, ok = read_cs(raw, at);
        if !ok || at2 + sl > raw.len { return [0; 32], false; }
        append_cs(outs, sl);
        outs.append(raw[at2..at2 + sl]);
        at = at2 + sl;
        let nlen = olen.len;
        olen.resize(nlen + 1, 0);
        ostart.resize(nlen + 1, 0);
        olen[nlen] = outs.len - start;
        ostart[nlen] = start;
    }
    if at + 4 != raw.len { return [0; 32], false; }
    let base = hash_type & 0x1f;
    let anyone = (hash_type & 0x80) != 0;
    var pre: u8[>..] = [];
    pre.append(raw[..4]);
    if anyone {
        pre.append(zeros());
    } else {
        pre.append(hash256(prevs));
    }
    if anyone || base == 2 || base == 3 {
        pre.append(zeros());
    } else {
        pre.append(hash256(seqs));
    }
    pre.append(prevs[n_in * 36..(n_in + 1) * 36]);
    append_cs(pre, script.len);
    pre.append(script);
    pre.append(amount);
    pre.append(seqs[n_in * 4..(n_in + 1) * 4]);
    if base == 2 || (base == 3 && n_in >= n_out) {
        pre.append(zeros());
    } else if base == 3 {
        pre.append(hash256(outs[ostart[n_in]..ostart[n_in] + olen[n_in]]));
    } else {
        pre.append(hash256(outs));
    }
    pre.append(raw[raw.len - 4..]);
    append_u32(pre, hash_type);
    return hash256(pre), true;
}

fn sign(secret: u8[:], raw: u8[:], script: u8[:], amount: u8[:], n_in: i64, hash_type: u32, out: u8[>..]&) -> bool {
    let dig, ok = sighash(raw, script, amount, n_in, hash_type);
    if !ok { return false; }
    let sig, sok, _ = secp256k1::sign(secret, dig);
    if !sok { return false; }
    return btc_legacy::encode_der(sig, hash_type, out);
}
