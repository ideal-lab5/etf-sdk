# Crypto

Crypto primtives used by the etf network and sdk.

The repo is organized as:
- Encryption
    - AES-GCM 
    - RMVEC
    - BF-IBE (FullIdent)
- Proofs
    - DLEQ proofs
    - El Gamal Sigma Protocol
    - Paillier Sigma Protocols
- DPSS: The dynamic committee proactive secret sharing implementation
- Client: Timelock Encryption Implementation

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

``` rust
cargo build
```

## Test

``` rust
cargo +nightly test
```
