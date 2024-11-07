# Permissioned Extract IBE

This is a 'tweak' of the FullIdent scheme of the BF-IBE construction. It applies an additional key exchange when computing the IBE.Extract function. As a result, the 'actual' key for the underlying IBE scheme can only be recovered by the party who owns the secret key whose public key was used in the key exchange. This is useful for constructing a 'permissioned' beacon protocol, where output signatures should only be available to authorized parties. 

### Permissioned-Extract-IBE

Just as in FullIdent, the scheme is instantiated with a private input of a master secret key and public input as the output of a bilinear Diffie-Hellman parameter generator, which is PPT algorithm that outputs a prime number $q$, the description of two groups $G_1$, $G_2$ of order $q$, and the description of an admissible bilinear map $\hat{e} : G_1 \times G_1 \to G_2$. In our case, we will instead us a bilinear map $e: G_1 \times G_2 \to G_2$ (a type III pairing).

It consists of four PPT algorithms (Setup, Extract, Encrypt, Decrypt) defined as:

- $(pp, s) \leftarrow Setup(1^\lambda)$ where $\lambda$ is the security parameter, $pp$ is the output (system) params and $s$ is the IBE master secret key. The system params are a generator $G \in \mathbb{G}_1$ and commitment to the master key, $P_{pub} = sG$.

- $(sk_{ID, pk}, ) \leftarrow Extract(s, ID, pk)$ outputs the private key for an $ID \in \{0, 1\}^*$ which is recoverable with knowledge of the secret corresponding to $pk$.

- $Encrypt(pp, ID, m) \to ct$ outputs the ciphertext $ct$ for any message $m \in \{0, 1\}^*$.

- $Decrypt(sk, ct) \to m$ outputs the decrypted message $m$

We use the BF-IBE "FullIdent" scheme to encrypt messages such that their decryption key is broadcast as the output of at specific future time step of the computational reference clock. FullIdent is IND-ID-CCA secure. In FullIdent, public parameters are stored in $\mathbb{G}_1$, and the scheme uses type 1 pairings. We will instead use type 3 pairings, so our public parameters are in $\mathbb{G}_2$ instead.

$\mathbf{Setup}$

Let $e: \mathbb{G}_1 \times \mathbb{G}_2 \to \mathbb{G}_2$ be a bilinear map, $H_1: \{0, 1\}^* \to \mathbb{G}_1$ a hash-to-G1 function, $H_2: \mathbb{G}_2 \to \{0, 1\}^n$ for some $n$, $H_3: \{0, 1\}^n \times \{0, 1\}^n \to \mathbb{Z}_q$, and a cryptographic hash function $H_4: \{0, 1\}^n \to \{0, 1\}^n$. Choose a random $s \xleftarrow{R} \mathbb{Z}_p$ and a generator $P \xleftarrow{R} \mathbb{G}_1$. Then, broadcast the value $P_{pub} = sP$.

$\mathbf{Extract}$

Compute the IBE secret for an identity $ID$ with $d_{ID} = sQ_{ID}$ where $Q_{ID} = H_1(ID)$. Then, mask the secret with a provided public key. For some $t \xleftarrow{R} \mathbb{Z}_p^*, T = tP \in \mathbb{G}_1$, choose a random $r \xleftarrow{R} \mathbb{Z}_p$ then set $c_1 = d_{ID} + rT$ and $c_2 = rP$, where $P \in \mathbb{G}_1$ is a generator. Output the pair $(c_1, c_2)$.

$\mathbf{Encryption}$
In this form of IBE, a message is encrypted once for any number of identities simultaneously and then  decrypted by others as they are granted permission, as each identity extracts a "permissioned" secret key. The encryption step is nearly identical to FullIdent.

Let $M \in \{0, 1\}^n$ be the message and $ID_0 \in \{0, 1\}^*$, $ID_1 \in \{0, 1\}^*$ be well-defined identities. 

1. Compute $Q_{ID_0} = H_1(ID_0) \in \mathbb{G}_1$ and $Q_{ID_1} = H_1(ID_1) \in \mathbb{G}_1$
2. Choose a random $\sigma \in \{0, 1\}^n$
3. set $r = H_4(\sigma, M)$
4. Calculate the ciphertext
    $C = \left<U, V, W\right> = \left< rP, \sigma \oplus H_2(g^r_{ID_{0, 1}}), M \oplus H_4(\sigma) \right>$


where $g_{ID_{0, 1}} = e(Q_{ID_0} + Q_{ID_1}, P_{pub, 0} + P_{pub, 1}) \in \mathbb{G}_2$

In the case that both identities are produced on the same secret, we only need $P_{pub, 0}$.

$\mathbf{Decryption}$

A benefit of the FullIdent scheme is that the decryption algorithm allows for verification that the ciphertext was properly encrypted, so it's not possible to attempt to decrypt data that isn't yours.

For a ciphertext $C = \left <U, V, W\right >$ encrypted using the time slot $t$. Then $C$ can be decrypted with the private key $d_{ID_t} = s Q_{ID_t} \in \mathbb{G}_1$, where $s$ is the IBE master secret, as such:


- Compute $V \oplus H_2(e(d_{ID_t}, U)) = \sigma$
- Compute $W \oplus H_4(\sigma) = M$
- Set $r = H_3(\sigma, M)$. Check if $U = rP$. If not, reject the ciphertext.
- Output $M$ as the decryption of $C$
