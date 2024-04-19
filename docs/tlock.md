# Timelock Encryption

Our timelock encryption scheme is a hybrid cryptosystem using both AES-GCM and FullIdent (Identity based encryption). The goal is to be able to encrypt any-length messages for future rounds of the ETF post finality gadget.

## Background

To keep things simple, we will not go into detail about AES-GCM or IBE, however, we can represent them with the following algorithms:

### AES-GCM
AES-GCM is a symmetric stream cipher, meaning you need to use the same key and nonce to encrypt and decrypt messages.

1. $ct \leftarrow AES.Enc(message, key, nonce)$
2. $m \leftarrow AES.Dec(ct, key, nonce)$


### BF-IBE

## Tlock

### Encryption

### Decryption
