# Timelock Encryption

Our timelock encryption scheme is a hybrid cryptosystem using both AES-GCM and FullIdent (Identity based encryption). The goal is to be able to encrypt any-length messages for future rounds of the ETF post finality gadget.

## Background

### AES-GCM
AES-GCM is a symmetric stream cipher, meaning you need to use the same key and nonce to encrypt and decrypt messages.

1. $ct \leftarrow AES.Enc(message, key, nonce)$
2. $m \leftarrow AES.Dec(ct, key, nonce)$


### BF-IBE


Identity based encryption is a scheme were a message can be encrypted for an arbitrary string, rather than some specific public key. For example, a message could be encrypted for "bob@encryptme.com" so that only the owner of the identity "bob@encryptme.com" is able to decrypt the message. Our construction uses the BF-IBE "FullIdent" scheme, which is IND-ID-CCA secure. 

The scheme is instantiated with a private input of a master secret key and public input as the output of a bilinear Diffie-Hellman parameter generator, which is PPT algorithm that outputs a prime number $q$, the description of two groups $G_1$, $G_2$ of order $q$, and the description of an admissible bilinear map $\hat{e} : G_1 \times G_1 \to G_2$. In our case, we will instead us a bilinear map $e: G_1 \times G_2 \to G_2$ (a type III pairing).

It consists of four PPT algorithms (Setup, Extract, Encrypt, Decrypt) defined as:

- $(pp, s) \leftarrow Setup(1^\lambda)$ where $\lambda$ is the security parameter, $pp$ is the output (system) params and $s$ is the IBE master secret key. The system params are a generator $G \in \mathbb{G}_1$ and commitment to the master key, $P_{pub} = sG$.

- $sk_{ID} \leftarrow Extract(mk, ID)$ outputs the private key for an $ID \in \{0, 1\}^*$.

- $Encrypt(pp, ID, m) \to ct$ outputs the ciphertext $ct$ for any message $m \in \{0, 1\}^*$.

- $Decrypt(sk_{ID}, ct) \to m$ outputs the decrypted message $m$

We use the BF-IBE "FullIdent" scheme to encrypt messages such that their decryption key is broadcast as the output of at specific future time step of the computational reference clock. FullIdent is IND-ID-CCA secure. In FullIdent, public parameters are stored in $\mathbb{G}_1$, and the scheme uses type 1 pairings. We will instead use type 3 pairings, so our public parameters are in $\mathbb{G}_2$ instead.

$\mathbf{Setup}$

Let $e: \mathbb{G}_1 \times \mathbb{G}_2 \to \mathbb{G}_2$ be a bilinear map, $H_1: \{0, 1\}^* \to \mathbb{G}_1$ a hash-to-G1 function, $H_2: \mathbb{G}_2 \to \{0, 1\}^n$ for some $n$, $H_3: \{0, 1\}^n \times \{0, 1\}^n \to \mathbb{Z}_q$, and a cryptographic hash function $H_4: \{0, 1\}^n \to \{0, 1\}^n$. Choose a random $s \xleftarrow{R} \mathbb{Z}_p$ and a generator $P \xleftarrow{R} \mathbb{G}_1$. Then, broadcast the value $P_{pub} = sP$.

$\mathbf{Extract}$

Compute the IBE secret for an identity $ID$ with $d_{ID} = sQ_{ID}$ where $Q_{ID} = H_1(ID)$

$\mathbf{Encryption}$

Let $M \in \{0, 1\}^n$ be the message and $t > 0$ be some future time slot in the CRC $\mathcal{C}$ for which we want to encrypt a message and assume it has a unique id, $ID_t$.

- Compute $Q_{ID_t} = H_1(ID_t) \in \mathbb{G}_1$
- Choose a random $\sigma \in \{0, 1\}^n$
- set $r = H_4(\sigma, M)$
    - Calculate the ciphertext
        $C = \left<U, V, W\right> = \left< rP, \sigma \oplus H_2(g^r_{ID}), M \oplus H_4(\sigma) \right>$


where $g_{ID} = e(Q_{ID}, P_{pub}) \in \mathbb{G}_2$

$\mathbf{Decryption}$
A benefit of the FullIdent scheme is that the decryption algorithm allows for verification that the ciphertext was properly encrypted, so it's not possible to attempt to decrypt data that isn't yours.

For a ciphertext $C = \left <U, V, W\right >$ encrypted using the time slot $t$. Then $C$ can be decrypted with the private key $d_{ID_t} = s Q_{ID_t} \in \mathbb{G}_1$, where $s$ is the IBE master secret, as such:


- Compute $V \oplus H_2(e(d_{ID_t}, U)) = \sigma$
- Compute $W \oplus H_4(\sigma) = M$
- Set $r = H_3(\sigma, M)$. Check if $U = rP$. If not, reject the ciphertext.
- Output $M$ as the decryption of $C$


## Tlock

### Encryption

We want to encrypt a message $m \in \{0, 1\}^*$ for an identity $ID \in \{0, 1\}^*$ with some threshold $t > 0$.

1. Choose $s \xleftarrow{R} \mathbb{Z}_p$ and broadcast $P_{pub} = sP$ where $P \in \mathbb{G}_2$ is a commonly agreed on generator. Also randomly sample a 96-bit nonce, $N$.
2. Encrypt the message using AES-GCM, producing: $ct \leftarrow AES.Enc(m, s, N)$
3. Encrypt the AES key for the identity using IBE: $ct' \leftarrow IBE.Enc(s, ID)$

Then the ciphertext contains $(ct, ct')$.

### Decryption

Timelock decryption can occur when a threshold of signers have produced valid BLS signatures for the given identity. 

Given ciphertexts $(ct, ct')$, a nonce $N$ and an identity $ID$, decryption is as follows:
1. Collect at least a thresold of BLS sigantures and DLEQ proofs. Interpolate the signatures and aggregate the proofs to get $(\sigma = interpolate(\{\sigma_i\}_{i \in [n]}), \pi = \sum_i \pi_i)$ and verify the proof. If it is invalid, then do not proceed.
2. The signature $\sigma$ is the IBE secret associated with the public key $P_{pub}$. Then use the secret to decrypt the ciphertext $ct'$ to recover the AES key: $k \leftarrow IBE.Decrypt(P_{pub}, ct', \sigma)$. If decryption fails, then we stop.
3. Use the recovered $k$ to attempt to decrypt the ciphertext $ct$: $m \leftarrow AES.Decrypt(ct, N, k)$.

