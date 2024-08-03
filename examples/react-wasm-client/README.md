# Tlock Demo

This is an demonstration of using the etf-sdk to run timelock encryption and decryption (against drand) in the browser.

## TODOs

- get drand public params from URI
- get new drand pulses (we can just query, don't need to listen to them)
- Encrypt: Form (input) => TLE(input, drand_id = sha256(round))
- Ciphertext => TLD(ct, getPulse(round).signature)