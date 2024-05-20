# ETF API

Traits and impls for interacting with the [ETF network](https://ideal-lab5.github.io). In particular, to verify proofs + slot secrets, encrypt messages, and to decrypt them.

- verify(slot_secret, id, proof)
- encrypt(message, slot_id_list)
- decrypt(ciphertext, secret_key)

## Tests

Run the wasm tests with wasm-pack: `wasm-pack test --node`

## Deploy

run the `wasm-build.sh` script to generate the wasm-build (in pkg directory)
