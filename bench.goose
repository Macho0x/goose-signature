// Times this package. One untimed batch, then batches until the window
// elapses. The sink keeps the call alive.
// Build with clang on the revision before a change, then again after:
//   goose build -o signature-bench bench.goose --cc clang
//   ./signature-bench
// Row names stay fixed. TinyCC (goose bench.goose) is not a timing result.
// ponytail: a fixed window, not a sampled harness. Rows under a microsecond
// move from run to run; lengthen the window before trusting them.

import os;
import crypto from "../crypto";
import eth_tx;
import eip191;
import eip712;
import solana;

var secp: u8[32] = [
    0x4c, 0x08, 0x83, 0xa6, 0x91, 0x02, 0x93, 0x7d, 0x62, 0x31, 0x47, 0x1b, 0x5d, 0xbb, 0x62, 0x04,
    0xfe, 0x51, 0x29, 0x61, 0x70, 0x82, 0x79, 0x2a, 0xe4, 0x68, 0xd0, 0x1a, 0x3f, 0x36, 0x23, 0x18,
];
var ed: u8[32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
var hello_dig: u8[32] = [
    0xd9, 0xeb, 0xa1, 0x6e, 0xd0, 0xec, 0xae, 0x43, 0x2b, 0x71, 0xfe, 0x00, 0x8c, 0x98, 0xcc, 0x87,
    0x2b, 0xb4, 0xcc, 0x21, 0x4d, 0x32, 0x20, 0xa3, 0x6f, 0x36, 0x53, 0x26, 0xcf, 0x80, 0x7d, 0x68,
];
var msg32: u8[32] = [0x11; 32];
var msg4k: u8[4096] = [0x61; 4096];
var dom: u8[32] = [0x22; 32];
var word: u8[32] = [0x33; 32];

fn mark(b: u8, ok: bool) -> u64 {
    if !ok { return 0; }
    let v: u64 = b;
    return v + 1;
}

fn time_batch<F>(batch: i64, ms: i64) -> i64, u64 {
    var sink: u64 = 0;
    var k = 0;
    while k < batch {
        sink += F();
        k += 1;
    }
    var n: i64 = 0;
    var dt: i64 = 0;
    let end = clock_ns() + ms * 1000000;
    while true {
        let t0 = clock_ns();
        k = 0;
        while k < batch {
            sink += F();
            k += 1;
        }
        dt += clock_ns() - t0;
        n += batch;
        if clock_ns() >= end { break; }
    }
    return dt / n, sink;
}

fn row<F>(name: u8[:], batch: i64, ms: i64) -> u64 {
    let ns, part = time_batch(batch, ms, F);
    var line: u8[>..] = [];
    format(line, name);
    while line.len < 28 { line.push(' '); }
    format_int(line, ns, 10, 12, ' ');
    format(line, "\n");
    write_stdout(line);
    return part;
}

fn eip_short() -> u64 {
    msg32[0] += 1;
    let d = eip191::digest(msg32);
    return mark(d[0], true);
}

fn eip_4k() -> u64 {
    msg4k[0] += 1;
    let d = eip191::digest(msg4k);
    return mark(d[0], true);
}

fn eip_sign() -> u64 {
    msg32[1] += 1;
    let sig, ok = eip191::sign(secp, msg32);
    if !ok { return 0; }
    return mark(sig[0], true);
}

fn typed_4k() -> u64 {
    msg4k[1] += 1;
    let d = eth_tx::hash_typed(2, msg4k);
    return mark(d[0], true);
}

fn eth_sign() -> u64 {
    msg32[2] += 1;
    let sig, ok = eth_tx::sign_hash(secp, msg32);
    if !ok { return 0; }
    return mark(sig[0], true);
}

fn sol_sign() -> u64 {
    msg32[3] += 1;
    let sig, ok = solana::sign(ed, msg32);
    if !ok { return 0; }
    return mark(sig[0], true);
}

fn eip712_dig() -> u64 {
    word[0] += 1;
    let d, ok = eip712::digest(dom, word);
    return mark(d[0], ok);
}

fn ready() -> bool {
    if eip191::digest("hello world") != hello_dig { return false; }
    let sig, ok = eip191::sign(secp, "hello world");
    if !ok || sig.len != 65 { return false; }
    let ss, sok = solana::sign(ed, msg32);
    if !sok || ss.len != 64 { return false; }
    let dig, dok = eip712::digest(dom, word);
    if !dok || dig.len != 32 { return false; }
    return eth_tx::hash_typed(2, msg4k).len == 32;
}

fn ::main() {
    if !ready() { print("bench FAIL"); exit(1); }
    write_stdout("operation                       ns/call\n");
    var sink: u64 = 0;
    sink += row("eip191 digest 32B", 32, 200, eip_short);
    sink += row("eip191 digest 4KB", 8, 200, eip_4k);
    sink += row("eip191 sign", 1, 800, eip_sign);
    sink += row("eth hash_typed 4KB", 8, 200, typed_4k);
    sink += row("eth sign_hash", 1, 800, eth_sign);
    sink += row("solana sign", 1, 400, sol_sign);
    sink += row("eip712 digest", 32, 200, eip712_dig);
    var tail: u8[>..] = [];
    format(tail, "sink ");
    format(tail, sink);
    format(tail, "\n");
    write_stdout(tail);
}
