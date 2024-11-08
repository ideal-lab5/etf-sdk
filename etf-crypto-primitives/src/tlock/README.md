# Timelock Encryption

Currently the scheme supports two flavors of beacons, including the Drand 'quicknet', which uses BLS381 keys, and the Ideal Network beacon, which uses BLS377 keys. Both beacons use a BLS variant with tiny 48 byte signatures and 96 byte public keys, with sigantures being elements of $\mathbb{G}_1$ and public keys in $\mathbb{G}_2$. 

This flavor of timelock encryption is a hybrid encryption scheme, using AES_GCM to efficiently encrypt and decrypt and size ciphertexts, while secret keys are encrypted for identities of future beacon pulses.