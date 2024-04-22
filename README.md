# etf-sdk
This is an SDK to build protocols on top of the EtF network. Specifically, it contains cryptographic primitives used by the etf network, as well as implements timelock encryption via AES-GCM with SSS, where shares are encrypted for futures slots using IBE. It is wasm-compilable and so able to be called from both rust and javascript contexts.

It consists of two packages:

- `etf-crypto-primitives` contains implementations in arkworks
- `etf-sdk` is an API to expose timelock encryption and DLEQ proof verification, and make compilable to wasm

> :warning: This library is a WIP and should not be considered safe for production use.

## Testing

We aim for a minimum of 85% coverage on all lines. To check coverage, we use tarpaulin with opt-level=0:

``` bash
cargo tarpaulin --rustflags="-C opt-level=0"
```

## Benchmarks

Navigate to the etf-crypto-primitives directory and run:

```
cargo bench
```

See [the benches dir](./etf-crypto-primitives/benches/) for more info.