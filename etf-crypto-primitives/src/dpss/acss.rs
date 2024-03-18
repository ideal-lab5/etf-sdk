
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
    encryption::hashed_el_gamal::HashedElGamal,
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
    ) -> Vec<(PublicKey<G>, Fr, BatchPoK<G>)> {
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
        let poks: Vec<(PublicKey<G>, Fr, BatchPoK<G>)> = 
            next_committee.iter().enumerate().map(|(idx, pk)| {
            // the committee member's 'position' as a scalar field element
            let i = Fr::from((idx as u8) + 1);
            // calculate shares
            let x = evals.get(&i).unwrap();
            let x_prime = evals_hat.get(&i).unwrap();
            (*pk, i, BatchPoK::prove(&vec![*x, *x_prime], *pk, &mut rng))
        }).collect::<Vec<_>>();

        poks
    }

    /// decrypt shares + authenticate from a collection of batched HEG NIZK PoKs
    /// outputs the new share and its blinding share
    /// assumes default the generator is used
    //
    pub fn recover(
        sk: Fr, 
        idx: Fr, 
        poks: Vec<BatchPoK<G>>,
    ) -> Result<(Fr, Fr), ACSSError>  {

        let q = G::generator() * sk;

        let mut secrets = Vec::new();
        let mut blinding_secrets = Vec::new();

        for pok in poks {
            if !pok.verify(q) {
                return Err(ACSSError::InvalidProof);
            }
            secrets.push((idx, HashedElGamal::decrypt(sk, pok.ciphertexts[0].clone())));
            blinding_secrets.push((idx, HashedElGamal::decrypt(sk, pok.ciphertexts[1].clone())));
        }

        let s = crate::utils::interpolate::<G>(secrets);
        let s_prime = crate::utils::interpolate::<G>(blinding_secrets);
        Ok((s, s_prime))
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

    use rand_chacha::ChaCha20Rng;
    use ark_poly::{
        polynomial::univariate::DensePolynomial,
        DenseUVPolynomial, Polynomial,
    };

    // we want to show:
    // Given a committee that holds a secret msk where each member has  secret share,
    // we want to share the msk with a new committee while only providing new shares
    #[test]
    pub fn basic_reshare_and_recover_works() {
        let m = 2;
        let n = 5;

        let mut rng = ChaCha20Rng::seed_from_u64(0);

        let msk = Fr::rand(&mut rng);
        let msk_prime = Fr::rand(&mut rng);

        let initial_committee_secret_keys = (0..m).map(|i| (Fr::rand(&mut rng)))
            .collect::<Vec<_>>();

        let initial_committee_public_keys = initial_committee_secret_keys.iter()
            .map(|sk| G::generator().mul(sk))
            .collect::<Vec<_>>();

        // panic!("{:?}", initial_committee_public_keys);

        // first we reshare to the first committee
        let poks = HighThresholdACSS::reshare(
            msk, 
            msk_prime, 
            &initial_committee_public_keys,
            m,
            &mut rng
        );
        assert_eq!(m, poks.len() as u8);
        assert_eq!(initial_committee_public_keys[0], poks[0].0);
        assert_eq!(initial_committee_public_keys[1], poks[1].0);

        // and finally we interpolate the recovered secrets to get back msk and msk_primes
        let mut recovered_shares: Vec<(Fr, Fr)> = Vec::new();
        let mut recovered_blinding_shares: Vec<(Fr, Fr)> = Vec::new();

        // then each committee member should be able to reconsruct their shares
        initial_committee_secret_keys.iter().enumerate().for_each(|(idx, sk)| {
            // identify your PoKs based on public key
            let pk = G::generator().mul(sk);

            let my_poks: Vec<(Fr, BatchPoK<G>)> = poks.clone()
                .into_iter()
                .filter(|p| p.0 == pk)
                .map(|p| (p.1, p.2.clone()))
                .collect::<Vec<_>>();

            let f_elem = my_poks[0].0;
            match HighThresholdACSS::recover(*sk, f_elem, my_poks.iter().map(|p| p.1.clone()).collect::<Vec<_>>()) {
                Ok(data) => {
                    recovered_shares.push((f_elem, data.0));
                    recovered_blinding_shares.push((f_elem, data.1));
                }, 
                Err(_) => panic!("the secrets should be recoverable"),
            }
        });

        let final_recovered_msk = crate::utils::interpolate::<G>(recovered_shares);
        let final_recovered_msk_prime = crate::utils::interpolate::<G>(recovered_blinding_shares);

        assert_eq!(msk, final_recovered_msk);
        assert_eq!(msk_prime, final_recovered_msk_prime);
    }
}
