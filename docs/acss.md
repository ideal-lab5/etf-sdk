# Async Committee Secret Sharing

[jump to implementation](../etf-crypto-primitives/src/dpss/acss.rs)

We use a *high threshold* async committee secret sharing. 

This consists of two algorithms, (Reshare, Recover).

Let $C = \{c_i\}_{i \in [m]}$ be an initial committee for some $m > 0$. Assume each participant has a BLS keypair $kp_i$. 

## Reshare

The goal of the reshare algorithm is to produce an encrypted, publicly verifiable, 'resharing' of two input secrets to a new committee. By making it publicly verifiable, we can later on verify the proofs onchain while allowing nodes to decrypt the actual ciphertexts offchain.

The protocol is as follows:

1. Choose random $s, \hat{s} \xleftarrow{R} \mathbb{Z}_p$
2. Choose random t degree polynomials $\phi(x), \hat{\phi}(x) \xleftarrow{R} \mathbb{Z}_p[X]^t$ where $0 < t \leq m$ is the threshold (in the sense of Shamir) and $\phi(0) = s$, $\hat{\phi}(0) = \hat{s}$
3. For each $i \in [m]$, produce a 'resharing' of the secrets by calculating:
    1. $u_i := \phi(i)$, $\hat{u}_i = \hat{\phi}(i)$
    2. $\{v_i, \hat{v}_i, \pi_i, c_i\} \leftarrow HEGS.Prove(u_i, \hat{u}_i, PK_i)$ where $PK_i$ is the public key of committee member $c_i$

4. Finally broadcast all resharings $\{v_i, \hat{v}_i, \pi_i, c_i\}_{i \in [m]}$

## Recover

Given some $\{v_i, \hat{v}_i, \pi_i, c_i\}_{i \in [n]}$ for some $0 < t < n \leq m$ and knowledge of the corresponding secret key, the goal is to recover secret shares of the polynomials. The idea is that we are receiving a threshold resharing from a committee. In the simplest condition, a committee could have a single member, and there is no strict upper limit to the size of committee membership.

So first, we must agree on a thresold $t$ and wait until we have received at least $t$ resharings from the old committee. Once sufficiently many have been received, we can continue. Then, for each $j \in [m]$, perform the following:

1. Verify each of the shares and report and invalid shares. If more than $n - t$ of the proofs are invalid, then we fail early as we need at least $t$ shares to recover the secrets through Lagrange interpolation. This is done by running $b_i \leftarrow HEGS.Verify(\pi_i, v_i, \hat{v}_i, Q)$, where $Q$ is the expected recipient's public key.

2. If sufficiently many valid proofs are found,  then decrypt each ciphertext to recover shares of the secret key: $s_{j, Q}, \hat{s}_{j, Q} \leftarrow HEG.BatchDecrypt(v_i, \hat{v}_i, SK_j)$ where $SK_j$ is the committee member $c_j$'s  secret key.

3. Finally after recovering at least a thresold of shares, run lagrange interpolation to get your round public key.