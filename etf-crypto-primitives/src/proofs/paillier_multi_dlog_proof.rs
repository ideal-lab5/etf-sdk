#[cfg(feature = "paillier")]
/*
 * Copyright 2024 by Ideal Labs, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use curv::arithmetic::traits::*;
use curv::BigInt;
use serde::{Deserialize, Serialize};
use kzen_paillier::EncryptWithChosenRandomness;
use kzen_paillier::Paillier;
use kzen_paillier::{EncryptionKey, Randomness, RawPlaintext};
use sha2::{Digest, Sha256};

use crate::alloc::string::ToString;

use ark_bls12_381::{Fr, G1Projective as G};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_ff::{BigInteger, PrimeField};
use ark_std::{
    iter,
    ops::{Mul, Neg},
    vec::Vec,
};

#[derive(Debug)]
pub enum Error {
    InvalidT,
    InvalidZ,
    InvalidCommitment,
    InvalidCiphertext,
}

/// NIZK Proof of knowledge that 
/// a discrete log is a commitment to the preimage of a ciphertext
///
/// https://eprint.iacr.org/2022/971.pdf
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct MultiDLogProof {
    t: (Vec<u8>, BigInt, BigInt),
    z: BigInt,
    z_prime: BigInt,
    w: BigInt,
    w_prime: BigInt,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MultiDLogStatement {
    /// a (serialized) generator of the elliptic curve group
    pub g: Vec<u8>,
    /// a (serialized) generator of the elliptic curve group
    pub h: Vec<u8>,
    /// Y = G^x u^N
    pub ciphertext: BigInt,
    pub ciphertext_prime: BigInt,
    /// (serialized) y = g ^ x mod p \in \mathbb{G}
    pub dlog: Vec<u8>,
    /// a Paillier encryption key's 'n' value
    pub ek_n: BigInt,
}

impl MultiDLogProof {

    pub fn prove(
        statement: &MultiDLogStatement, 
        u: &BigInt, 
        u_prime: &BigInt,
        x: &BigInt,
        x_prime: &BigInt,
    ) -> MultiDLogProof {
        // let r = BigInt::sample_below(&statement.params.0);
        // using A = N
        let modulus = BigInt::from_bytes(Fr::MODULUS.to_bytes_be().as_slice());
        // r in [0, A = N^3]
        let ek = EncryptionKey::from(&statement.ek_n);
        let r = BigInt::sample_below(&(ek.n.clone() * ek.nn.clone()));
        let r_prime = BigInt::sample_below(&(ek.n.clone() * ek.nn.clone()));
        // s in [0, p - 1]
        let s = BigInt::sample_below(&(modulus.clone() - 1));        
        let s_prime = BigInt::sample_below(&(modulus - 1));
        // representation of r as a field element (for arkworks)
        let r_scalar = Fr::from_be_bytes_mod_order(&r.to_bytes());
        let r_prime_scalar = Fr::from_be_bytes_mod_order(&r_prime.to_bytes());
        // elliptic curve group generators
        let g = G::deserialize_compressed(&statement.g[..]).unwrap();
        let h = G::deserialize_compressed(&statement.h[..]).unwrap();
        // y' = g^r h^{r'} mod p, the commitment 
        let p = g.mul(r_scalar) + h.mul(r_prime_scalar);
        let mut p_bytes = Vec::new();
        p.serialize_compressed(&mut p_bytes).unwrap();
        // Y' = G^r s^N mod N^2 = enc(r;s)
        let q = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(r.clone()),
            &Randomness(s.clone())
        ).0.into_owned();
        let q_prime = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(r_prime.clone()),
            &Randomness(s_prime.clone())
        ).0.into_owned();
        let t = (p_bytes.clone(), q.clone(), q_prime.clone());
        // e = H(g, G, y, Y, t.0, t.1)
        let e = compute_digest(
            iter::once(statement.g.as_slice()) // g
            .chain(iter::once(statement.h.as_slice())) // h
            .chain(iter::once(ek.n.clone().to_string().as_bytes())) // G
            .chain(iter::once(statement.dlog.as_slice())) // y = g^x
            .chain(iter::once(statement.ciphertext.to_string().as_bytes())) // Y = G^x u^N
            .chain(iter::once(statement.ciphertext_prime.to_string().as_bytes())) // Y = G^x u^N
            .chain(iter::once(p_bytes.as_slice())) // g^r mod p => commitment to r
            .chain(iter::once(q.to_string().as_bytes())) // G^r s^N mod N^2 = enc(r;s)
            .chain(iter::once(q_prime.to_string().as_bytes())) // G^r s^N mod N^2 = enc(r;s)
        );

        // z = r + ex
        let z = r + e.clone() * x;
        // z' = r' + ex
        let z_prime = r_prime + e.clone() * x_prime;

        // w = su^e mod N
        let w = s * BigInt::mod_pow(u, &e, &ek.n);
        // w' = s'u'^e mod N
        let w_prime = s_prime * BigInt::mod_pow(u_prime, &e, &ek.n);

        MultiDLogProof {
            t, z, z_prime, w, w_prime,
        }
    }

    /// verify the proof
    pub fn verify(&self, statement: &MultiDLogStatement) -> Result<(), Error> {
        let ek = EncryptionKey::from(&statement.ek_n);
        // 1. Check z < A && z' < A
        if self.z >= (ek.n.clone() * ek.nn.clone()) ||
        self.z_prime >= (ek.n.clone() * ek.nn.clone()) {
            return Err(Error::InvalidZ);
        }

        let g = G::deserialize_compressed(&statement.g[..]).unwrap();
        let h = G::deserialize_compressed(&statement.h[..]).unwrap();

        // e = H(g, G, y, Y, t.0, t.1)
        let e: BigInt = compute_digest(
            iter::once(statement.g.as_slice()) // g
            .chain(iter::once(statement.h.as_slice())) // h
            .chain(iter::once(ek.n.clone().to_string().as_bytes())) // G I think?
            .chain(iter::once(statement.dlog.as_slice())) // y = g^x
            .chain(iter::once(statement.ciphertext.to_string().as_bytes())) // Y = G^x u^N
            .chain(iter::once(statement.ciphertext_prime.to_string().as_bytes())) // Y = G^x u^N
            .chain(iter::once(self.t.0.as_slice())) // g^r mod p => commitment to r
            .chain(iter::once(self.t.1.to_string().as_bytes())) // G^r s^N mod N^2 = enc(r;s)
            .chain(iter::once(self.t.2.to_string().as_bytes())) // G^r s^N mod N^2 = enc(r;s)
        );

        let e_scalar = Fr::from_be_bytes_mod_order(&e.to_bytes());
        // y' = g^r h^{r'}
        let gr = G::deserialize_compressed(&self.t.0[..]).unwrap();
        // y = g^x h^{x'}
        let y = G::deserialize_compressed(&statement.dlog[..]).unwrap();

        // 2. CHECK t.0 = g^r h^{r'} mod p == g^z h^{z'} y^{-e} mod p
        let group_check = 
            g.mul(Fr::from_be_bytes_mod_order(&self.z.to_bytes())) 
            + h.mul(Fr::from_be_bytes_mod_order(&self.z_prime.to_bytes())) 
            + y.mul(e_scalar.neg());
        if !group_check.eq(&gr) {
            return Err(Error::InvalidCommitment)
        }
        // 3. CHECK t.1 = enc(r;s) == enc(z,w) Y^{-e} mod N^2   
        check_ciphertext(
            &e.clone(),
            self.z.clone(),
            self.w.clone(), 
            &statement.ciphertext,
            &self.t.1,
            ek.clone(),
        )?;

        // 4. CHECK t.2 = enc(r';s') == enc(z',w') Y'^{-e} mod N^2   
        check_ciphertext(
            &e.clone(),
            self.z_prime.clone(),
            self.w_prime.clone(), 
            &statement.ciphertext_prime,
            &self.t.2,
            ek.clone(),
        )?;

        Ok(())
    }
}

/// Given Y = enc(x; u) (ciphertext), e = H(...) , z = r + ex, w = su^e mod N 
/// Check that:
///     enc(z;w) * Y^{-e} mod N^2 === verification_ciphertext
/// 
/// in our case, the verification ciphertext looks like enc(r;s)
///
fn check_ciphertext(
    e: &BigInt,
    z: BigInt, 
    w: BigInt, 
    ciphertext: &BigInt,
    verification_ciphertext: &BigInt,
    ek: EncryptionKey,
) -> Result<(), Error> {
     // enc(z,w) Y^{-e} mod N^2
     let ezw = Paillier::encrypt_with_chosen_randomness(
        &ek,
        RawPlaintext::from(z.clone()),
        &Randomness(w.clone()),
    ).0.into_owned();

    // enc(z;w) * [(Y^e mod N^2)^{-1} mod N^2]
    let field_check = ezw as BigInt * 
        BigInt::mod_inv(
            &BigInt::mod_pow(ciphertext, e, &ek.nn), 
            &ek.nn
        ).unwrap() % &ek.nn;

    if !field_check.eq(verification_ciphertext) {
        return Err(Error::InvalidCiphertext);
    }

    Ok(())
}

pub fn compute_digest<'a, I>(byte_slices: I) -> BigInt
    where I: Iterator<Item = &'a [u8]> {
    let mut hasher = Sha256::new();

    for byte_slice in byte_slices {
        hasher.update(byte_slice);
    }

    let result_bytes = hasher.finalize();
    BigInt::from_bytes(&result_bytes[..])
}

#[cfg(test)]
mod tests {

    use super::*;
    use kzen_paillier::KeyGeneration;
    use kzen_paillier::Paillier;

    use ark_ec::Group;
    use ark_ff::UniformRand;
    use ark_std::test_rng;

    #[test]
    fn test_correct_dlog_proof() {
        // SB/A < 1/2^{k'} negl. => overwhelming chance of verifiability

        // // should be safe primes (not sure if there is actual attack)
        // ((G, N), (p, q))
        let (ek, _dk) = kzen_paillier::keypair().keys();
        // x \in [0, G]
        let x = BigInt::sample_below(&ek.n);
        let x_prime = BigInt::sample_below(&ek.n);
        let u = BigInt::sample_below(&ek.n);
        let u_prime = BigInt::sample_below(&ek.n);
        // enc(x;u)
        let enc_xu = kzen_paillier::encrypt_with_chosen_randomness(
            &ek, 
            RawPlaintext::from(x.clone()),
            &Randomness(u.clone()),
        );

        let enc_xu_prime = kzen_paillier::encrypt_with_chosen_randomness(
            &ek, 
            RawPlaintext::from(x_prime.clone()),
            &Randomness(u_prime.clone()),
        );

        let x_scalar = Fr::from_be_bytes_mod_order(&x.to_bytes());
        let x_prime_scalar = Fr::from_be_bytes_mod_order(&x_prime.to_bytes());

        let g = G::generator();
        let h = G::rand(&mut test_rng());

        let mut g_bytes = Vec::new();
        g.serialize_compressed(&mut g_bytes).unwrap();
        let mut h_bytes = Vec::new();
        h.serialize_compressed(&mut h_bytes).unwrap();

        let dlog = g.mul(x_scalar) + h.mul(x_prime_scalar);
        let mut dlog_bytes = Vec::new();
        dlog.serialize_compressed(&mut dlog_bytes).unwrap();

        // A >= B * S + k'
        // currently using A = N
        let statement = MultiDLogStatement {
            g: g_bytes, 
            h: h_bytes,
            ciphertext: enc_xu.into(),
            ciphertext_prime: enc_xu_prime.into(),
            dlog: dlog_bytes,
            ek_n: ek.n,
        };
        let proof = MultiDLogProof::prove(
            &statement, 
            &u, &u_prime,
            &x, &x_prime,
        );
        let verification = proof.verify(&statement);
        assert!(verification.is_ok());
    }

}
