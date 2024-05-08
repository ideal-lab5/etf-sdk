# Crypto

Crypto primtives used by the etf network and sdk.

The repo is organized as:
- Encryption
    - Hashed El Gamal 
    - BF-IBE (FullIdent)
    - Tlock 
- Proofs
    - Hashed El Gamal Sigma Protocol
- DPSS: dynamic committee proactive secret sharing implementation

This repo has not been audited for security and should not yet be used in production.

## Build

``` shell
cargo build
```

## Benchmarks

``` shell
cargo benchmark
```

## Test

``` shell
cargo test
```
