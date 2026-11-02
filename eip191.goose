// EIP-191 personal_sign. The digest is keccak256 of
// "\x19Ethereum Signed Message:\n" || decimal(length) || message.
// sign returns r || s || v, with v in 27..30.

import std;
import crypto.keccak256;
import crypto.secp256k1;

namespace eip191;

fn write_dec(dst: u8[:], at: i64, n: i64) -> i64 {
    if n == 0 {
        dst[at] = '0';
        return 1;
    }
    var v = n;
    var digits = 0;
    while v > 0 {
        v /= 10;
        digits += 1;
    }
    v = n;
    for i in 0..digits {
        dst[at + digits - 1 - i] = ('0' + (v % 10)) as! u8;
        v /= 10;
    }
    return digits;
}

fn digest(message: u8[:]) -> u8[32] {
    let prefix = "\x19Ethereum Signed Message:\n";
    var buf: u8[>..] = [];
    buf.append(prefix);
    var digits: u8[20] = [0; 20];
    let nd = write_dec(digits, 0, message.len);
    buf.append(digits[..nd]);
    buf.append(message);
    return keccak256::hash(buf);
}

fn sign(secret: u8[:], message: u8[:]) -> u8[65], bool {
    let dig = digest(message);
    let sig, ok, v = secp256k1::sign(secret, dig);
    if !ok { return [0; 65], false; }
    var out: u8[65] = [0; 65];
    for i in 0..64 { out[i] = sig[i]; }
    out[64] = v;
    return out, true;
}

fn verify(public: u8[:], message: u8[:], sig: u8[:]) -> bool {
    if sig.len != 65 || sig[64] < 27 || sig[64] > 30 { return false; }
    return secp256k1::verify(public, digest(message), sig[..64]);
}
