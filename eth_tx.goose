// Ethereum transaction signing hashes. One RLP writer covers legacy
// transactions, EIP-155, and typed transactions 0x01, 0x02, 0x03, 0x04.
// An EIP-7702 authorization is the 0x05 payload. Blob sidecars are not
// encoded: type 0x03 hashes the versioned hashes only. Typed y-parity is
// v - 27, so 0..3. Legacy v is 27..30, and EIP-155 v is
// chainId * 2 + 35 + recid. Ethereum consensus accepts recid 0 and 1 only.

import std;
import crypto.keccak256;
import crypto.secp256k1;

namespace eth_tx;

fn rlp_head(out: u8[>..]&, base: i64, n: i64) {
    if n < 56 {
        out.push((base + n) as u8);
        return;
    }
    var be: u8[8] = [0; 8];
    var v = n;
    var c = 0;
    while v > 0 {
        be[7 - c] = (v & 255) as u8;
        v = v >> 8;
        c += 1;
    }
    out.push((base + 55 + c) as u8);
    out.append(be[8 - c..]);
}

fn rlp_bytes(out: u8[>..]&, data: u8[:]) {
    if data.len == 1 && data[0] < 0x80 {
        out.push(data[0]);
        return;
    }
    rlp_head(out, 0x80, data.len);
    out.append(data);
}

fn rlp_u64(out: u8[>..]&, n: u64) {
    if n == 0 {
        rlp_bytes(out, []);
        return;
    }
    var tmp: u8[8] = [0; 8];
    var v = n;
    var i = 8;
    while v > 0 {
        i -= 1;
        tmp[i] = (v & 0xff) as u8;
        v = v >> 8;
    }
    rlp_bytes(out, tmp[i..]);
}

fn rlp_int(out: u8[>..]&, src: u8[:]) {
    var i = 0;
    while i < src.len && src[i] == 0 { i += 1; }
    rlp_bytes(out, src[i..]);
}

fn rlp_list(out: u8[>..]&, payload: u8[:]) {
    rlp_head(out, 0xc0, payload.len);
    out.append(payload);
}

fn hash_legacy(list: u8[:]) -> u8[32] { keccak256::hash(list) }

fn hash_typed(ty: u8, list: u8[:]) -> u8[32] {
    var b: u8[>..] = [];
    b.push(ty);
    b.append(list);
    return keccak256::hash(b);
}

fn sign_hash(secret: u8[:], dig: u8[:]) -> u8[65], bool {
    let sig, ok, v = secp256k1::sign(secret, dig);
    if !ok || v < 27 || v > 30 { return [0; 65], false; }
    var out: u8[65] = [0; 65];
    for i in 0..64 { out[i] = sig[i]; }
    out[64] = v;
    return out, true;
}

fn eip155_v(chain_id: u64, v: u8) -> u64 { chain_id * 2 + 35 + (v - 27) }
