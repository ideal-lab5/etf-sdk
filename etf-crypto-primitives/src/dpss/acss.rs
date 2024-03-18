
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

use ark_bls12_381::{Fr, G1Projective as G};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_poly::{
    polynomial::univariate::DensePolynomial,
    DenseUVPolynomial, Polynomial,
};
use ark_ec::{CurveGroup, Group};
use ark_std::{
    cmp::Ordering,
    ops::Mul,
    vec::Vec, 
    rand::{CryptoRng, Rng, SeedableRng},
    collections::BTreeMap,
};
use scale_info::TypeInfo;
use alloc::boxed::Box;

use serde_json::from_slice;
use serde::{Deserialize, Serialize};

use codec::{Encode, Decode};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    XChaCha20Poly1305, XNonce
};
use crate::{
    proofs::hashed_el_gamal_sigma::BatchPoK,
    types::ProtocolParams as ACSSParams,
    utils::convert_to_bytes,
};


pub type PublicKey<G> = G;

/// errors for the DPSS reshare algorithm
#[derive(Debug)]
pub enum ACSSError {
    /// the ciphertext could not be decrypted
    InvalidCiphertext,
    /// the commitment could not be verified
    InvalidCommitment,
    /// the proof could not be verified
    InvalidProof,
}

// /// represents the data that an old committee member
// /// passes to a new one
// #[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
// pub struct Capsule {
//    pub ciphertext: Vec<u8>,
//    pub ciphertext_prime: Vec<u8>,
//    pub commitment: Vec<u8>,
// }

// #[cfg(feature = "std")]
// impl AsRef<[u8]> for Capsule {
//     fn as_ref(&self) -> &[u8] {
//         // Serialize the Capsule struct into a Vec<u8>
//         let serialized = serde_json::to_vec(self).unwrap();
//         // Convert the vector into a boxed slice and return a reference to it
//         Box::leak(serialized.into_boxed_slice())
//     }
// }

// #[cfg(feature = "std")]
// #[derive(Serialize, Deserialize)]
// pub enum CapsuleError {
//     /// the byte array could not be converted to a Capsule
//     SerializationError,
// }

// #[cfg(feature = "std")]
// impl Capsule {
//     pub fn from_bytes(bytes: &[u8]) -> Result<Capsule, CapsuleError> {
//         from_slice(bytes).map_err(|_| CapsuleError::SerializationError)?
//     }
// }

/// the high threshold asynchronous complete secret sharing struct
pub struct HighThresholdACSS { }

impl HighThresholdACSS {

    /// Acting as a semi-trusted dealer, construct shares for the next committee
    ///
    /// `params`: ACSS Params
    /// `msk`: the master secret key
    /// `msk_hat`: the blinding secret key
    /// `next_committee`: The next committee to generate shares for
    /// `t`: The threshold (t <= n)
    /// `rng`: A random number generator
    ///
    pub fn reshare<R: Rng + Sized>(
        msk: Fr, 
        msk_hat: Fr,
        next_committee: &[PublicKey<G>],
        t: u8,
        mut rng: R,
    ) -> Vec<BatchPoK<G>> {
        // f(x) -> [f(0), {(1, f(1)), ..., (n, f(n))}]
        let evals: BTreeMap<Fr, Fr> = generate_shares_checked(
            msk, next_committee.len() as u8, t, &mut rng);
        // f_hat(x) (blinding polynomial) -> [f'(0), {1, f'(1), ...}]
        let evals_hat: BTreeMap<Fr, Fr> = generate_shares_checked(
            msk_hat, next_committee.len() as u8, t, &mut rng);
        // map to aggregate the outputs
        // let mut result: Vec<Capsule> = Vec::new();
        // let mut secrets = Vec::new();

        // TODO: check that evals.len == evals_hat.len == next_committe.len ?
        // TODO: error handling
        let poks: Vec<BatchPoK<G>> = next_committee.iter().enumerate().map(|(idx, pk)| {
            // the committee member's 'position' as a scalar field element
            let i = Fr::from((idx as u8) + 1);
            // calculate shares
            let x = evals.get(&i).unwrap();
            let x_prime = evals_hat.get(&i).unwrap();
            BatchPoK::prove(&vec![*x, *x_prime], *pk, &mut rng)
        }).collect::<Vec<_>>();

        poks
    }

    /// decrypt shares + authenticate
    /// outputs the new share and its blinding share
    pub fn recover(
    ) -> Result<(Fr, Fr), ACSSError>  {

        // // TODO: store bytes in the struct instead?
        // let mut g_bytes = Vec::new();
        // params.g.serialize_compressed(&mut g_bytes).unwrap();
        // let mut h_bytes = Vec::new();
        // params.h.serialize_compressed(&mut h_bytes).unwrap();

        // let statement = MultiDLogStatement {
        //     g: g_bytes, 
        //     h: h_bytes,
        //     ciphertext: capsule.enc_xu.clone(),
        //     ciphertext_prime: capsule.enc_xu_prime.clone(),
        //     dlog: capsule.dlog,
        //     ek_n: capsule.ek_n,
        // };

        // capsule.proof.verify(&statement)
        //     .map_err(|_| ACSSError::InvalidProof)?;

        // let x = Paillier::decrypt(
        //     &dk, 
        //     RawCiphertext::from(&capsule.enc_xu)
        // ).0.into_owned();
        // let x_prime = Paillier::decrypt(
        //     &dk, 
        //     RawCiphertext::from(&capsule.enc_xu_prime)
        // ).0.into_owned();

        // let s: Fr = Fr::from_be_bytes_mod_order(&x.to_bytes());
        // let s_prime: Fr = Fr::from_be_bytes_mod_order(&x_prime.to_bytes());

        // Ok((s, s_prime))
        Err(ACSSError::InvalidProof)
    }
}

pub fn generate_shares_checked<R: Rng + Sized>(
    s: Fr, n: u8, t: u8, mut rng: R
) -> BTreeMap<Fr, Fr> {
    let mut coeffs: Vec<Fr> = (0..t+1).map(|_| Fr::rand(&mut rng)).collect();
    coeffs[0] = s;
//
    let f = DensePolynomial::<Fr>::from_coefficients_vec(coeffs);
    let mut out: BTreeMap<Fr, Fr> = BTreeMap::new();
    (1..n+1).for_each(|i| {
        let idx = Fr::from(i);
        let eval = f.evaluate(&idx);
        out.insert(idx, eval);
    });
    out
}

#[cfg(test)]
pub mod tests {

    use super::*;
    use ark_std::vec::Vec;
    use ark_ec::Group;
    use ark_std::{test_rng, rand::SeedableRng};

    use ark_poly::{
        polynomial::univariate::DensePolynomial,
        DenseUVPolynomial, Polynomial,
    };

    // we want to show:
    // Given a committee that holds a secret msk where each member has  secret share,
    // we want to share the msk with a new committee while only providing new shares
    #[test]
    pub fn basic_reshare_works() {
        let m = 2;
        let n = 5;

        let msk = Fr::rand(&mut test_rng());

    }
}
