
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
use ark_ec::Group;
use ark_std::{
    cmp::Ordering,
    ops::Mul,
    vec::Vec, 
    rand::Rng,
    collections::BTreeMap,
};
use scale_info::TypeInfo;
#[cfg(feature = "std")]
use curv::arithmetic::traits::*;
// #[cfg(feature = "std")]
use curv::arithmetic::Converter;
use curv::BigInt;
#[cfg(feature = "std")]
use kzen_paillier::{
    Decrypt,
    DecryptionKey,
    Paillier,
    EncryptWithChosenRandomness,
    RawCiphertext,
    RawPlaintext,
    Randomness,
};
use alloc::boxed::Box;
use kzen_paillier::EncryptionKey;

use serde_json::from_slice;
use serde::{Deserialize, Serialize};

use codec::{Encode, Decode};
#[cfg(feature = "std")]
use crate::proofs::{MultiDLogProof, MultiDLogStatement};
use crate::types::WrappedEncryptionKey;


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

/// represents the data that an old committee member
/// passes to a new one
#[cfg(feature = "std")]
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Capsule {
    /// the 'n' value of the encryption key (EK = (n, n^2))
    pub ek_n: BigInt,
    // /// field element where evaluation took place
    // pub eval: Vec<u8>,
    /// an encrypted secret
    pub enc_xu: BigInt,
    /// an encrypted secret (blinding)
    pub enc_xu_prime: BigInt,
    /// pedersen committment bytes: g^x h^{x'} 
    pub dlog: Vec<u8>,
    /// a NIZK PoK that the dlog is a commitment to both ciphertexts
    pub proof: MultiDLogProof,
}

#[cfg(feature = "std")]
impl AsRef<[u8]> for Capsule {
    fn as_ref(&self) -> &[u8] {
        // Serialize the Capsule struct into a Vec<u8>
        let serialized = serde_json::to_vec(self).unwrap();
        // Convert the vector into a boxed slice and return a reference to it
        Box::leak(serialized.into_boxed_slice())
    }
}

#[cfg(feature = "std")]
#[derive(Serialize, Deserialize)]
pub enum CapsuleError {
    /// the byte array could not be converted to a Capsule
    SerializationError,
}

#[cfg(feature = "std")]
impl Capsule {
    pub fn from_bytes(bytes: &[u8]) -> Result<Capsule, CapsuleError> {
        from_slice(bytes).map_err(|_| CapsuleError::SerializationError)?
    }
}

#[derive(Clone, PartialEq, CanonicalDeserialize, CanonicalSerialize)]
pub struct ACSSParams {
    g: G,
    h: G,
}

impl ACSSParams {
    pub fn rand<R: Rng + Sized>(mut rng: R) -> Self {
        Self {
            g: G::generator(),
            h: G::rand(&mut rng)
        }
    }
}

/// the high threshold asynchronous complete secret sharing struct
#[cfg(feature = "std")]
pub struct HighThresholdACSS { }
#[cfg(feature = "std")]
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
        params: ACSSParams,
        msk: Fr, 
        msk_hat: Fr,
        next_committee: &[WrappedEncryptionKey],
        t: u8,
        mut rng: R,
    ) -> Vec<Capsule> {
        // f(x) -> [f(0), {(1, f(1)), ..., (n, f(n))}]
        let evals: BTreeMap<Fr, Fr> = generate_shares_checked(
            msk, next_committee.len() as u8, t, &mut rng);
        // f_hat(x) (blinding polynomial) -> [f'(0), {1, f'(1), ...}]
        let evals_hat: BTreeMap<Fr, Fr> = generate_shares_checked(
            msk_hat, next_committee.len() as u8, t, &mut rng);
        // map to merge the evaluations
        let mut result: Vec<Capsule> = Vec::new();

        // TODO: check that evals.len == evals_hat.len == next_committe.len ?

        for (idx, member) in next_committee.iter().enumerate() {
            let f_elem = Fr::from((idx as u8) + 1);
            // TODO: handle error
            let x = evals.get(&f_elem).unwrap();
            let x_p = BigInt::from_bytes(&x.into_bigint().to_bytes_be());
            // let x_bytes: Vec<u8> = x.into_bigint().to_bytes_be();
            // x.serialize_compressed(&mut x_bytes).unwrap();

            // let x_bytes_64 = x_bytes.iter().map(|u| *u as u64).collect::<Vec<_>>();

            let x_prime = evals_hat.get(&f_elem).unwrap();
            let x_prime_p = BigInt::from_bytes(&x_prime.into_bigint().to_bytes_be());

            // let mut x_hat_bytes: Vec<u8> = Vec::new();
            // u_hat.serialize_compressed(&mut x_hat_bytes).unwrap();

            // let x_hat_bytes_64 = x_hat_bytes.iter().map(|u| *u as u64).collect::<Vec<_>>();

            // (u, u') <- [0, A]
            let u = BigInt::sample_below(&member.clone().into_inner().n);
            let u_prime = BigInt::sample_below(&member.clone().into_inner().n);
            // encryption
            let enc_xu = Paillier::encrypt_with_chosen_randomness(
                &member.clone().into_inner(), 
                RawPlaintext::from(&x_p),
                &Randomness(u.clone())
            ).0.into_owned();
            let enc_xu_prime = Paillier::encrypt_with_chosen_randomness(
                &member.clone().into_inner(), 
                RawPlaintext::from(&x_prime_p),
                &Randomness(u_prime.clone())
            ).0.into_owned();
            // TODO: ZKPoK
            let dlog = params.g.mul(x) + params.h.mul(x_prime);

            let mut g_bytes = Vec::new();
            params.g.serialize_compressed(&mut g_bytes).unwrap();
            let mut h_bytes = Vec::new();
            params.h.serialize_compressed(&mut h_bytes).unwrap();
    
            // let dlog = selfg.mul(x_scalar) + h.mul(x_prime_scalar);
            let mut dlog_bytes = Vec::new();
            dlog.serialize_compressed(&mut dlog_bytes).unwrap();

            let statement = MultiDLogStatement {
                g: g_bytes, 
                h: h_bytes,
                ciphertext: enc_xu.clone(),
                ciphertext_prime: enc_xu_prime.clone(),
                dlog: dlog_bytes,
                ek_n: member.clone().into_inner().n,
            };
            let proof = MultiDLogProof::prove(
                &statement, 
                &u, &u_prime,
                &x_p, &x_prime_p,
            );

            let dlog_bytes = crate::utils::convert_to_bytes::<G, 48>(dlog).to_vec();

            result.push(
                Capsule {
                    // eval: eval_bytes,
                    enc_xu, 
                    enc_xu_prime,
                    dlog: dlog_bytes,
                    proof,
                    ek_n: member.clone().into_inner().n,
                }
            );
        };

        result
    }

    /// decrypt shares + authenticate
    /// outputs the new share and its blinding share
    pub fn recover(
        params: ACSSParams, 
        dk: DecryptionKey,
        capsule: Capsule
    ) -> Result<(Fr, Fr), ACSSError>  {

        // TODO: store bytes in the struct instead?
        let mut g_bytes = Vec::new();
        params.g.serialize_compressed(&mut g_bytes).unwrap();
        let mut h_bytes = Vec::new();
        params.h.serialize_compressed(&mut h_bytes).unwrap();

        let statement = MultiDLogStatement {
            g: g_bytes, 
            h: h_bytes,
            ciphertext: capsule.enc_xu.clone(),
            ciphertext_prime: capsule.enc_xu_prime.clone(),
            dlog: capsule.dlog,
            ek_n: capsule.ek_n,
        };

        capsule.proof.verify(&statement)
            .map_err(|_| ACSSError::InvalidProof)?;

        let x = Paillier::decrypt(
            &dk, 
            RawCiphertext::from(&capsule.enc_xu)
        ).0.into_owned();
        let x_prime = Paillier::decrypt(
            &dk, 
            RawCiphertext::from(&capsule.enc_xu_prime)
        ).0.into_owned();

        let s: Fr = Fr::from_be_bytes_mod_order(&x.to_bytes());
        let s_prime: Fr = Fr::from_be_bytes_mod_order(&x_prime.to_bytes());

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
    use ark_std::test_rng;

    use kzen_paillier::{BigInt, KeyGeneration, EncryptionKey};
    use ark_poly::{
        polynomial::univariate::DensePolynomial,
        DenseUVPolynomial, Polynomial,
    };

    // we want to show:
    // Given a committee that holds a secret msk where each member has  secret share,
    // we want to share the msk with a new committee while only providing new shares
    #[test]
    pub fn basic_reshare_works() {
        // generate initial committee keys
        let initial_committee_keys: Vec<(EncryptionKey, DecryptionKey)> 
            = (0..3).map(|_| { Paillier::keypair().keys() }).collect();
        let next_committee_keys: Vec<(EncryptionKey, DecryptionKey)> 
            = (0..5).map(|_| { Paillier::keypair().keys() }).collect();
        // then flatmap to public keys
        let initial_committee: Vec<WrappedEncryptionKey> = initial_committee_keys
            .iter()
            .map(|c| WrappedEncryptionKey(c.0.n.clone()))
            .collect::<Vec<_>>();
        let next_committee = next_committee_keys
            .iter()
            .map(|c| WrappedEncryptionKey(c.0.n.clone()))
            .collect::<Vec<_>>();

        let initial_committee_threshold = 2u8;
        let next_committee_threshold = 3u8;
        let g = G::generator();
        // // TODO: we need to find another generator...
        let h = G::generator();
        let params = ACSSParams { g, h };

        let msk = Fr::rand(&mut test_rng());
        let msk_hat = Fr::rand(&mut test_rng());

        let initial_committee_shares: Vec<Capsule> = 
            HighThresholdACSS::reshare(
                params.clone(), 
                msk, 
                msk_hat, 
                &initial_committee, 
                initial_committee_threshold, 
                test_rng()
            );

        // simulate a public broadcast channel
        let mut simulated_broadcast: 
            BTreeMap<WrappedEncryptionKey, Vec<Capsule>> = BTreeMap::new();
        // each member of the initial committee 'owns' a secret (identified by matching indices)
        initial_committee_keys.iter().enumerate().for_each(|(idx, c)| {
            let member_secrets = &initial_committee_shares[idx];
            // authenticate + decrypt shares
            let (u, u_hat) = HighThresholdACSS::recover(
                params.clone(), c.1.clone(), member_secrets.clone(),
            ).unwrap();
            // and they each create a resharing of their secrets
            let next_committee_resharing: Vec <Capsule> = 
                HighThresholdACSS::reshare(
                    params.clone(),
                    u,
                    u_hat, 
                    &next_committee, 
                    next_committee_threshold, 
                    test_rng(),
            );
            assert!(next_committee_resharing.len().eq(&next_committee.len()));
            simulated_broadcast.insert(
                WrappedEncryptionKey(c.0.n.clone()), 
                next_committee_resharing,
            );
        });

        let mut new_committee_sks = Vec::new();
        let mut new_committee_blinding_sks = Vec::new();

        // now, next committee members verify + derive
        next_committee_keys.iter().for_each(|(ek, dk)| {
            // collect each new member's shares from the old committee
            let mut coeffs: Vec<Fr> = Vec::new();
            let mut blinding_coeffs: Vec<Fr> = Vec::new();

            initial_committee.iter().enumerate().for_each(|(idx, old_member)| {
                // get the share they gave us
                let capsule = simulated_broadcast.get(old_member).unwrap()
                    .iter().filter(|m| m.ek_n.eq(&ek.n))
                    .collect::<Vec<_>>()[0];
                
                // [idx];

                // //

                // authenticate and decrypt
                let (u, u_hat) = HighThresholdACSS::recover(
                    params.clone(),
                    dk.clone(),
                    capsule.clone(),
                ).unwrap();
                // store somewhere
                coeffs.push(u);
                blinding_coeffs.push(u_hat);
            });

            // then each member of the new committee interpolates their new secrets
            let evals = coeffs.iter().enumerate().map(|(i, c)| (Fr::from((i as u8) + 1), *c)).collect::<Vec<_>>();
            let blinding_evals = blinding_coeffs.iter().enumerate().map(|(i, c)| (Fr::from((i as u8) + 1), *c)).collect::<Vec<_>>();
            
            let sk = crate::encryption::aes::interpolate(evals);
            new_committee_sks.push(sk);
            
            let blinding_sk = crate::encryption::aes::interpolate(blinding_evals.clone());
            new_committee_blinding_sks.push(blinding_sk);
        });

        // // then we can interpolate these sks and blinding_sks to recover the original msk, msk_hat
        let new_committee_evals = new_committee_sks.iter().enumerate().map(|(idx, item)| {
            (Fr::from((idx as u8) + 1), *item)
        }).collect::<Vec<_>>();

        let recovered_sk = crate::encryption::aes::interpolate(new_committee_evals);
        assert_eq!(msk, recovered_sk);

        let new_committee_blinding_evals = new_committee_blinding_sks.iter().enumerate().map(|(idx, item)| {
            (Fr::from((idx as u8) + 1), *item)
        }).collect::<Vec<_>>();

        let recovered_blinding_sk = crate::encryption::aes::interpolate(new_committee_blinding_evals);
        assert_eq!(msk_hat, recovered_blinding_sk);
    }
}
