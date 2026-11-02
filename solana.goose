// Solana messages signed with Ed25519. Legacy and v0 transactions use
// compact-u16 lengths. A v0 message starts with 0x80 and ends with
// address-table lookups. Off-chain messages start with the 16-byte
// "\xffsolana offchain" domain from the current message spec.

import std;
import crypto.blake3;
import crypto.ed25519;

namespace solana;

enum Message { Legacy, V0 }

fn append_cu16(out: u8[>..]&, n: i64) {
    var v = n;
    while true {
        let e = v & 0x7f;
        v = v >> 7;
        if v == 0 {
            out.push(e as u8);
            return;
        }
        out.push((e | 0x80) as u8);
    }
}

fn push_key(out: u8[>..]&, first: u8) {
    out.push(first);
    let n = out.len;
    out.resize(n + 31, 0);
}

fn begin(out: u8[>..]&, message: Message, required: u8, ro_signed: u8, ro_unsigned: u8, n_keys: i64) {
    if message == Message.V0 { out.push(0x80); }
    out.push(required);
    out.push(ro_signed);
    out.push(ro_unsigned);
    append_cu16(out, n_keys);
}

fn end_keys(out: u8[>..]&, recenthash: u8[:], n_ix: i64) {
    out.append(recenthash);
    append_cu16(out, n_ix);
}

fn push_ix(out: u8[>..]&, program: u8, accounts: u8[:], data: u8[:]) {
    out.push(program);
    append_cu16(out, accounts.len);
    out.append(accounts);
    append_cu16(out, data.len);
    out.append(data);
}

fn begin_lookups(out: u8[>..]&, n: i64) { append_cu16(out, n); }

fn push_lookup(out: u8[>..]&, table: u8[:], writable: u8[:], readonly: u8[:]) {
    out.append(table);
    append_cu16(out, writable.len);
    out.append(writable);
    append_cu16(out, readonly.len);
    out.append(readonly);
}

fn offchain(format: u8, message: u8[:], out: u8[>..]&) {
    out.append("\xffsolana offchain");
    out.push(0);
    out.push(format);
    out.push((message.len & 0xff) as! u8);
    out.push(((message.len >> 8) & 0xff) as! u8);
    out.append(message);
}

fn sign(seed: u8[:], message: u8[:]) -> u8[64], bool { return ed25519::sign(seed, message); }
