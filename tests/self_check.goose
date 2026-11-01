import crypto from "../../crypto";
import signature from "..";
import signature.eip712;
import .eip712;
import signature.eip191;
import .eip191;
import signature.eth_tx;
import .eth_tx;
import signature.btc_legacy;
import .btc_legacy;
import signature.btc_segwit;
import .btc_segwit;
import signature.btc_taproot;
import .btc_taproot;
import signature.bip322;
import .bip322;
import signature.solana;
import .solana;

import os;

fn go(name: u8[:], ok: bool) -> bool {
    var line: u8[>..] = [];
    format(line, name);
    if ok { format(line, " ok\n"); } else { format(line, " FAIL\n"); }
    write_stdout(line);
    return ok;
}

fn ::main() {
    var all = true;
    if !go("eip712", eip712::self_check()) { all = false; }
    if !go("eip191", eip191::self_check()) { all = false; }
    if !go("eth_tx", eth_tx::self_check()) { all = false; }
    if !go("btc_legacy", btc_legacy::self_check()) { all = false; }
    if !go("btc_segwit", btc_segwit::self_check()) { all = false; }
    if !go("btc_taproot", btc_taproot::self_check()) { all = false; }
    if !go("bip322", bip322::self_check()) { all = false; }
    if !go("solana", solana::self_check()) { all = false; }
    if !all { exit(1); }
    write_stdout("signature ok\n");
}
