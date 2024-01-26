#![allow(non_snake_case)]
/*
    etf-sdk

    Copyright 2024 by Ideal Labs

    etf-sdk is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/ideal-lab5/etf-sdk/blob/main/LICENSE>
*/

use ark_std::iter;
use crate::alloc::string::ToString;

use curv::arithmetic::traits::*;
use curv::BigInt;
use serde::{Deserialize, Serialize};
use paillier::EncryptWithChosenRandomness;
use paillier::Paillier;
use paillier::{EncryptionKey, Randomness, RawCiphertext, RawPlaintext};
use curv::cryptographic_primitives::hashing::DigestExt;
use sha2::{Digest, Sha256};

const K: usize = 128;
const K_PRIME: usize = 128;
const SAMPLE_S: usize = 256;

#[derive(Debug)]
pub enum Error {
    InvalidT,
    InvalidZ,
    InvalidZPrime,
}

/// NIZK Proof of knowledge of discrete log with composite modulus.
///
/// We follow the scheme in Appendix F from:
/// https://eprint.iacr.org/2022/971.pdf
///
/// which is an extension of:
/// https://hal.science/inria-00565274
///
/// The prover wants to prove knowledge of two secrets s, s' given private r, r' and public Y = g^s h^{s'} mod N, c = enc(s; r), c' = enc(s'; r')  for composite N
/// where g, h are elements of Zp
#[derive(Debug, Serialize, Deserialize, Clone)]
struct MultiDLogProof {
    y: BigInt,
    c: BigInt,
    c_prime: BigInt,
    t: BigInt,
    e_u: BigInt,
    e_u_prime: BigInt,
    z: BigInt,
    z_prime: BigInt,
    w: BigInt,
    w_prime: BigInt,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DLogStatement {
    pub g: BigInt,
    pub h: BigInt,
    pub ek: EncryptionKey,
}

impl MultiDLogProof {
    pub fn prove(statement: &DLogStatement, sk: &BigInt, sk_prime: &BigInt) -> MultiDLogProof {
        // Y = g^{x} h^{x'}
        let y = BigInt::mod_pow(&statement.g, &sk, &statement.ek.nn)
            * BigInt::mod_pow(&statement.h, &sk_prime, &statement.ek.nn);
        // r, r' <- Z_n
        let r = BigInt::sample_below(&statement.ek.n);
        let r_prime = BigInt::sample_below(&statement.ek.n);
        // c = enc(x;r), c' = enc(x';r')
        let c = Paillier::encrypt_with_chosen_randomness(
            &statement.ek,
            RawPlaintext::from(sk),
            &Randomness(r.clone()),
        ).0.into_owned();
        let c_prime = Paillier::encrypt_with_chosen_randomness(
            &statement.ek,
            RawPlaintext::from(sk_prime),
            &Randomness(r_prime.clone()),
        ).0.into_owned();

        // (u, u', s, s') <- Z_n
        let u = BigInt::sample_below(&statement.ek.n);
        let u_prime = BigInt::sample_below(&statement.ek.n);
        let s = BigInt::sample_below(&statement.ek.n);
        let s_prime = BigInt::sample_below(&statement.ek.n);

        let t = BigInt::mod_pow(&statement.g, &u, &statement.ek.n)
            * BigInt::mod_pow(&statement.h, &u_prime, &statement.ek.n);
        
        let e_u = Paillier::encrypt_with_chosen_randomness(
            &statement.ek,
            RawPlaintext::from(u.clone()),
            &Randomness(s.clone()),
        ).0.into_owned();
        let e_u_prime = Paillier::encrypt_with_chosen_randomness(
            &statement.ek,
            RawPlaintext::from(u_prime.clone()),
            &Randomness(s_prime.clone()),
        ).0.into_owned();
        
        let e = compute_digest(
            iter::once(t.to_string().as_bytes())
                .chain(iter::once(e_u.to_string().as_bytes()))
                .chain(iter::once(e_u_prime.to_string().as_bytes()))
        );

        let z = u + e.clone() * sk;
        let z_prime = u_prime + e.clone() * sk_prime;
        // w = sr^e mod N^2
        let w = s * BigInt::mod_pow(&r, &e, &statement.ek.nn);
        // w' = s'r'^e mod N^2
        let w_prime = s_prime * BigInt::mod_pow(&r_prime, &e, &statement.ek.nn);

        MultiDLogProof {
            y,
            c,
            c_prime,
            t,
            e_u,
            e_u_prime,
            z,
            z_prime,
            w,
            w_prime,
        }
    }

    /// verify the proof
    pub fn verify(&self, statement: &DLogStatement) -> Result<(), Error> {
        let e = compute_digest(
            iter::once(self.t.to_string().as_bytes())
                .chain(iter::once(self.e_u.to_string().as_bytes()))
                .chain(iter::once(self.e_u_prime.to_string().as_bytes()))
        );

        let t = BigInt::mod_pow(&statement.g, &self.z, &statement.ek.n)
        * BigInt::mod_pow(&statement.h, &self.z_prime, &statement.ek.n)
        / BigInt::mod_pow(&self.y, &e.clone(), &statement.ek.n);

        if !t.eq(&self.t) {
            return Err(Error::InvalidT);
        }

        let e_z = Paillier::encrypt_with_chosen_randomness(
            &statement.ek,
            RawPlaintext::from(self.z.clone()),
            &Randomness(self.w.clone()),
        ).0.into_owned();

        let check = self.e_u.clone() * BigInt::mod_pow(&self.c, &e, &statement.ek.n);

        if !e_z.eq(&check) {
            return Err(Error::InvalidZ);
        }

        let e_z_prime = Paillier::encrypt_with_chosen_randomness(
            &statement.ek,
            RawPlaintext::from(self.z_prime.clone()),
            &Randomness(self.w_prime.clone()),
        ).0.into_owned();

        let check_prime = self.e_u_prime.clone() * BigInt::mod_pow(&self.c_prime, &e, &statement.ek.n);

        if !e_z_prime.eq(&check_prime) {
            return Err(Error::InvalidZPrime);
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
    use paillier::KeyGeneration;
    use paillier::Paillier;

    use ark_ff::UniformRand;
    use ark_bls12_381::{Fr, G1Projective as G};
    use ark_std::test_rng;

    #[test]
    fn test_correct_multi_dlog_proof() {
        // should be safe primes (not sure if there is actual attack)
        let (ek, dk) = Paillier::keypair().keys();

        // choose two group elements at random
        let g_p = Fr::rand(&mut test_rng());
        let h_p = Fr::rand(&mut test_rng());

        panic!("{:?}", g_p.to_big_int());


        // NO -> I need to get two group elements (from bls12-381)
        // let g = BigInt::sample_below(&ek.n);
        // let h = BigInt::sample_below(&ek.n);

        // let statement = DLogStatement {
        //     g,
        //     h,
        //     ek: ek.clone(),
        // };

        // let secret = BigInt::sample_below(&ek.n);
        // let secret_prime = BigInt::sample_below(&ek.n);
        // let proof = MultiDLogProof::prove(&statement, &secret, &secret_prime);
        // let v = proof.verify(&statement);
        // panic!("{:?}", v);
        // assert!(v.is_ok());
    }

    // #[test]
    // #[should_panic]
    // fn test_bad_dlog_proof() {
    //     let (ek, dk) = Paillier::keypair().keys();
    //     let one = BigInt::one();
    //     let S = BigInt::from(2).pow(SAMPLE_S as u32);
    //     // Per definition 3 in the paper we need to make sure h1 is asymmetric basis:
    //     // Jacobi symbol should be -1.
    //     let mut h1 = BigInt::sample_range(&one, &(&ek.n - &one));
    //     let mut jacobi_symbol = legendre_symbol(&h1, &dk.p) * legendre_symbol(&h1, &dk.q);
    //     while jacobi_symbol != -1 {
    //         h1 = BigInt::sample_range(&one, &(&ek.n - &one));
    //         jacobi_symbol = legendre_symbol(&h1, &dk.p) * legendre_symbol(&h1, &dk.q);
    //     }
    //     let secret = BigInt::sample_below(&S);
    //     // here we use "+secret", instead of "-secret".
    //     let h2 = BigInt::mod_pow(&h1, &(secret), &ek.n);
    //     let statement = DLogStatement {
    //         N: ek.n,
    //         g: h1,
    //         ni: h2,
    //     };
    //     let proof = CompositeDLogProof::prove(&statement, &secret);
    //     let v = proof.verify(&statement);
    //     assert!(v.is_ok());
    // }

    // #[test]
    // #[should_panic]
    // fn test_bad_dlog_proof_2() {
    //     let (ek, dk) = Paillier::keypair().keys();
    //     let one = BigInt::one();
    //     let S = BigInt::from(2).pow(SAMPLE_S as u32);
    //     // Per definition 3 in the paper we need to make sure h1 is asymmetric basis:
    //     // Jacobi symbol should be -1.
    //     let mut h1 = BigInt::sample_range(&one, &(&ek.n - &one));
    //     let mut jacobi_symbol = legendre_symbol(&h1, &dk.p) * legendre_symbol(&h1, &dk.q);
    //     while jacobi_symbol != -1 {
    //         h1 = BigInt::sample_range(&one, &(&ek.n - &one));
    //         jacobi_symbol = legendre_symbol(&h1, &dk.p) * legendre_symbol(&h1, &dk.q);
    //     }
    //     let secret = BigInt::sample_below(&S);
    //     // here we let h2 to be sampled in random
    //     let h2 = BigInt::sample_range(&one, &(&ek.n - &one));

    //     let statement = DLogStatement {
    //         N: ek.n,
    //         g: h1,
    //         ni: h2,
    //     };
    //     let proof = CompositeDLogProof::prove(&statement, &secret);
    //     let v = proof.verify(&statement);
    //     assert!(v.is_ok());
    // }
}
