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

## Setup

This code is only guaranteed to work in Linux environments. If you have a windows OS, use WSL and install Ubuntu.

Install rust and build-essentials:

``` bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
sudo apt-get update
sudo apt install build-essential
```

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
