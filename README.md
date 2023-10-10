# etf-sdk
This is an SDK to build on top of the EtF protocol. Specifically, it contains cryptographic primitives used by the etf network, as well as enables timelock encryption. It is wasm-compilable and so able to be called from both rust and javascript contexts.

It consists of two packages:

- `crypto` contains implementations in arkworks
- `api` is an API to expose timelock encryption and DLEQ proof verification, and make compilable to wasm

