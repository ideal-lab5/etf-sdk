# Timelock Encryption

Our timelock encryption scheme is a hybrid cryptosystem using both AES-GCM and FullIdent (Identity based encryption). The goal is to be able to encrypt any-length messages for future rounds of the ETF post finality gadget.

## Background

To keep things simple, we will not go into detail about AES-GCM or IBE, however, we can represent them with the following algorithms:

### AES-GCM
AES-GCM is a symmetric stream cipher, meaning you need to use the same key and nonce to encrypt and decrypt messages.

1. $ct \leftarrow AES.Enc(message, key, nonce)$
2. $m \leftarrow AES.Dec(ct, key, nonce)$


### BF-IBE

Let $H_1: \{0, 1\}^* \to \mathbb{G}_1$ be a hash to G1 function.

## Tlock

### Encryption

We want to encrypt a message $m \in \{0, 1\}^*$ for an identity $ID \in \{0, 1\}^*$ with some threshold $t > 0$.

1. Choose $s \xleftarrow{R} \mathbb{Z}_p$ and broadcast $P_{pub} = sQ_{ID}$ where $Q_{ID} = H_1(ID)$.
2. Calculate a polynomial $f(x) = \sum_{i=0}^t a_ix^i$ such that $f(0) = s$ . Then calculate and distribute shares $u_i := f(i)$ to each respective $c_i$ (e.g. using [ACSS](./acss.md)).
3.

### Decryption
