#![allow(dead_code)]
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
use ark_ec::Group;
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
/// https://www.di.ens.fr/~stern/data/St93.pdf
/// the prove wants to convince a verifier that:
// y = g ^ x mod p is the dlog of the preimage of the encryption G^s u^N 
#[derive(Debug, Serialize, Deserialize, Clone)]
struct DLogProof {
    t: (Vec<u8>, BigInt),
    z: BigInt,
    w: BigInt,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DLogStatement {
    /// Y = G^x u^N
    pub ciphertext: BigInt,
    /// (serialized) y = g ^ x mod p \in \mathbb{G}
    pub dlog: Vec<u8>,
    /// a Paillier encryption key
    pub ek: EncryptionKey,
}

impl DLogProof {

    pub fn prove(
        statement: &DLogStatement, 
        u: &BigInt, 
        x: &BigInt, 
    ) -> DLogProof {
        // let r = BigInt::sample_below(&statement.params.0);
        // using A = N
        let modulus = BigInt::from_bytes(Fr::MODULUS.to_bytes_be().as_slice());
        // r in [0, A = N^3]
        let r = BigInt::sample_below(&(statement.ek.n.clone() * statement.ek.nn.clone()));
        // s in [0, p - 1]
        let s = BigInt::sample_below(&(modulus - 1));
        // representation of r as a field element (for arkworks)
        let r_prime = Fr::from_be_bytes_mod_order(&r.to_bytes());
        // convert generator to bytes
        let g = G::generator();
        let mut g_bytes = Vec::new();
        g.serialize_compressed(&mut g_bytes).unwrap();

        // y' = g^r mod p
        let p = g.mul(r_prime);
        let mut p_bytes = Vec::new();
        p.serialize_compressed(&mut p_bytes).unwrap();
        // Y' = G^r s^N mod N^2 = enc(r;s)
        let q = kzen_paillier::encrypt_with_chosen_randomness(
            &statement.ek,
            RawPlaintext::from(r.clone()),
            &Randomness(s.clone())
        ).0.into_owned();
        let t = (p_bytes.clone(), q.clone());
        // e = H(g, G, y, Y, t.0, t.1)
        let e = compute_digest(
            iter::once(g_bytes.as_slice()) // g
            .chain(iter::once(statement.ek.n.clone().to_string().as_bytes())) // G
            .chain(iter::once(statement.dlog.as_slice())) // y = g^x
            .chain(iter::once(statement.ciphertext.to_string().as_bytes())) // Y = G^x u^N
            .chain(iter::once(p_bytes.as_slice())) // g^r mod p => commitment to r
            .chain(iter::once(q.to_string().as_bytes())) // G^r s^N mod N^2 = enc(r;s)
        );

        // z = r + ex
        let z = r + e.clone() * x;
        // w = su^e mod N
        let w = s * BigInt::mod_pow(u, &e, &statement.ek.n);

        DLogProof {
            t, z, w,
        }
    }

    /// verify the proof
    pub fn verify(&self, statement: &DLogStatement) -> Result<(), Error> {

        // 1. Check Z < A
        if self.z >= (statement.ek.n.clone() * statement.ek.nn.clone()) {
            return Err(Error::InvalidZ);
        }

        let g = G::generator();
        let mut g_bytes = Vec::new();
        g.serialize_compressed(&mut g_bytes).unwrap();

        // e = H(g, G, y, Y, t.0, t.1)
        let e: BigInt = compute_digest(
            iter::once(g_bytes.as_slice()) // g
            .chain(iter::once(statement.ek.n.clone().to_string().as_bytes())) // G I think?
            .chain(iter::once(statement.dlog.as_slice())) // y = g^x
            .chain(iter::once(statement.ciphertext.to_string().as_bytes())) // Y = G^x u^N
            .chain(iter::once(self.t.0.as_slice())) // g^r mod p => commitment to r
            .chain(iter::once(self.t.1.to_string().as_bytes())) // G^r s^N mod N^2 = enc(r;s)
        );

        let e_scalar = Fr::from_be_bytes_mod_order(&e.to_bytes());
        // y' = g^r
        let gr = G::deserialize_compressed(&self.t.0[..]).unwrap();
        // y = g^x
        let y = G::deserialize_compressed(&statement.dlog[..]).unwrap();
        // 2. CHECK t.0 = g^r == g^z y^{-e} mod p
        let group_check = g.mul(Fr::from_be_bytes_mod_order(&self.z.to_bytes())) + y.mul(e_scalar.neg());
        if !group_check.eq(&gr) {
            return Err(Error::InvalidCommitment)
        }
        // 3. CHECK t.1 = enc(r;s) == enc(z,w) Y^{-e} mod N^2
        let ezw = kzen_paillier::encrypt_with_chosen_randomness(
            &statement.ek,
            RawPlaintext::from(self.z.clone()),
            &Randomness(self.w.clone()),
        ).0.into_owned();

        // enc(z;w) * [(Y^e mod N^2)^{-1} mod N^2]
        let field_check = ezw as BigInt * 
            BigInt::mod_inv(
                &BigInt::mod_pow(&statement.ciphertext, &e.clone(), &statement.ek.nn), 
                &statement.ek.nn
            ).unwrap() % &statement.ek.nn;

        if !field_check.eq(&self.t.1) {
            return Err(Error::InvalidCiphertext);
        }

        Ok(())
    }
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

    #[test]
    fn test_correct_dlog_proof() {
        // SB/A < 1/2^{k'} negl. => overwhelming chance of verifiability

        // // should be safe primes (not sure if there is actual attack)
        // ((G, N), (p, q))
        let (ek, dk) = kzen_paillier::keypair().keys();
        // x \in [0, G]
        let x = BigInt::sample_below(&ek.n);
        let u = BigInt::sample_below(&ek.n);
        // enc(x;u)
        let ciphertext = kzen_paillier::encrypt_with_chosen_randomness(
            &ek, 
            RawPlaintext::from(x.clone()),
            &Randomness(u.clone()),
        );

        let x_scalar = Fr::from_be_bytes_mod_order(&x.to_bytes());
        let dlog = G::generator().mul(x_scalar);
        let mut dlog_bytes = Vec::new();
        dlog.serialize_compressed(&mut dlog_bytes).unwrap();

        // A >= B * S + k'
        // currently using A = N
        let statement = DLogStatement {
            ciphertext: ciphertext.into(),
            dlog: dlog_bytes,
            ek: ek,
            // params: ()
        };
        let proof = DLogProof::prove(&statement, &u, &x);
        let verification = proof.verify(&statement);
        assert!(verification.is_ok());
    }

}
