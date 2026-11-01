# goose-signature

Version 0.1.

Transaction and typed-data signing in [Goose](https://github.com/aardappel/goose). Hashes and key algorithms live in [goose-crypto](../crypto). This package calls them. The implementations are Goose, with no foreign calls and no vendored C. The tests in `tests/` check each module against a published vector.

Copyright 2026 Macho0x. Licensed under Apache-2.0, the same license as Goose.

## Check

Install the Goose compiler, then from this directory:

```sh
goose tests/self_check.goose
```

A good run prints `signature ok`. Each file in `tests/` can also be run on its own.

`import eip191` loads `eip191.goose` from the directory of the program you pass to goose. From a program in another directory:

```goose
import crypto from "../crypto";
import signature from "../signature";
import signature.eip191;

fn main() {
    var secret: u8[32] = [1; 32];
    let sig, ok = eip191::sign(secret, "hello world");
    print(ok, " ", sig);
}
```

`signature.goose` is the package entry. Importing the package loads that file alone. `import signature.eip191` loads a signer. The entry declares `import crypto from "../crypto"`. A file in `tests/` declares `import crypto from "../../crypto"` and `import signature from ".."`.

## Modules

| Module | What it does |
| --- | --- |
| `eip191` | `personal_sign` |
| `eip712` | Typed-data digest and signature |
| `eth_tx` | RLP, and signing hashes for legacy, EIP-155, and type 1, 2, 3, and 4 transactions, plus EIP-7702 authorization |
| `btc_legacy` | Legacy sighash and strict DER |
| `btc_segwit` | BIP-143 |
| `btc_taproot` | BIP-341 key-path and script-path |
| `bip322` | Simple BIP-322 proofs for P2PKH, P2WPKH, and P2TR |
| `solana` | Legacy and v0 transaction messages, and off-chain messages |

Bitcoin sighash flags are ALL, NONE, SINGLE, and ANYONECANPAY. Callers pass the script, the keys, and the message. There is no script interpreter, no UTXO set, no HD derivation, and no address codec. BIP-322 is simple proofs only. An EIP-4844 signature covers the transaction fields and the blob versioned hashes, not the blob payload. A Dogecoin legacy signature is `btc_legacy`. BNB Smart Chain is `eth_tx` with chain id 56.

`eip191`, `eip712`, and `eth_tx` call `keccak256` and `secp256k1` in goose-crypto. `btc_legacy` and `btc_segwit` call `sha256` and `secp256k1`. `btc_taproot` calls `sha256`, `secp256k1`, and `bip340`. `bip322` calls `sha256`, `secp256k1`, `bip340`, `btc_legacy`, `btc_segwit`, and `btc_taproot`. `solana` calls `blake3` and `ed25519`.
