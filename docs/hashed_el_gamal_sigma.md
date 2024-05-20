# Hashed El Gamal Sigma Protocol

Let $\mathbb{G}$ be an elliptic curve group over a finite field $\mathbb{Z}_p$. Suppose Alice chooses some $d \xleftarrow{R} \mathbb{Z}_p$ as a secret key and calculates a public key $Q = dP$ for some generator $P \in \mathbb{G}$. The public key is broadcast to all participants.

## Hashed El Gamal Encryption

[jump to implementation](../etf-crypto-primitives/src/encryption/hashed_el_gamal.rs)

Note that this scheme could be improved in various ways. We plan to introduce an F.O. transform similar to how the BF-IBE FullIdent scheme works.

This scheme consists of two functions, Encrypt and Decrypt.

1. $ct = <U, V> \leftarrow HEG.Enc(m; r, Q)$ produces a ciphertext for the message $m$ with entropy $r$ for the public key $Q$
2. $m' \leftarrow HEG.Dec(ct, s)$ returns a message $m'$

Correctness requires that:

$Pr \left [m = m ' | m ' = HEG.Dec(HEG.Enc(m;r, Q), d) \right ] = 1$

Let $H: \{0, 1\}^* \to \{0, 1\}^l$ be a cryptographic hash function.

**Encrypt**

Let $m \in \{0, 1\}^l$. Encryption of the message $m$ for Alice is as follows:

1. Choose $r \xleftarrow{R} \mathbb{Z}_p$
2. Calculate $C = <U, V> = <rP, m \oplus H(rQ)>$

Output the ciphertext $C$.

**Decrypt**

To decrypt a ciphertext $C$ under a valid secret key $d$, perform the following operations:

1. Calculate $s = dU$
2. Calculate $m = W \oplus H(s)$

output $m$


## Hashed El Gamal Sigma Protocol

[jump to implementation](../etf-crypto-primitives/src/proofs/hashed_el_gamal_sigma.rs)

Here we present the protocol under a single secret input $s$. While our scheme works using two secret inputs, it is a simple extension of the following protocol.

**Prove**

The goal is that, given a secret $s$:
1. we want to produce a publicly verifiable proof that a given commitment is a commitment to the preimage of a ciphertext. 
2. The ciphertext should only be decryptable by the intended party.
3. The intended recipient should be able to recover a scalar field element and not a group element.

This protocol is very similar to a DLEQ proof, as it is a Sigma protocol with a Fiat-Shamir transform applied to it.

Given a private input $m \in \mathbb{Z}_p$ and public inputs $P, Q \in \mathbb{G}$ where $P$ is a generator and $Q = sP$ is a public key with corresponding secret $s$.

There are two stages: first we prepare the ciphertext and commitment, and then we prepare the proof.

1. Choose $r \xleftarrow{R} \mathbb{Z}_p$ and calculate the ciphertext $ct = HEG.Enc(m; r, Q)$
2. Calculate a commitment $C = mP + mQ$
3. Choose $k \xleftarrow{R} \mathbb{Z}_p$ and calculate $s = kP$, $t = kQ$
4. Compute the hash $e = H(s, t, c_1, c_2)$
5. Compute the witness $z = k + em$
6. Output the proof $\pi = (s, t, z, c)$ and ciphertext $ct$

**Verify**

Given a proof $\pi = (s, t, z, c)$, ciphertext $ct$, and public key $Q$, we can verify that the commitment $c$ is a commitment to the preimage of the ciphertext as follows:

1. Compute $e = H(\pi)$
2. Check if $zP + zQ == s + t + ec$

If the equality holds, then the proof has been verified, otherwise it is invalid.