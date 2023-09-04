# etf-sdk
This is an SDK to build on top of the EtF protocol. It contains cryptographic primitives to enable timelock encryption on top of the network. This repo consists of two packages:
- `crypto` contains implementations in arkworks
- `api` is an API to expose timelock encryption and DLEQ proof verification, and make compilable to wasm

