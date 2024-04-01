
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
    marker::PhantomData,
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

/// the high threshold asynchronous complete secret sharing struct
pub struct HighThresholdACSS<G: CurveGroup> {
    _curve_group: PhantomData<G>,
}

impl<G: CurveGroup> HighThresholdACSS<G> {

    /// Acting as a semi-trusted dealer, construct shares for the next committee
    ///
    /// `params`: ACSS Params
    /// `msk`: the master secret key
    /// `msk_hat`: the blinding secret key
    /// `next_committee`: The next committee to generate shares for
    /// `t`: The threshold (t <= n)
    /// `rng`: A random number generator
    ///
    pub fn reshare<R: CryptoRng + Rng>(
        msk: G::ScalarField, 
        msk_hat: G::ScalarField,
        next_committee: &[PublicKey<G>],
        t: u8,
        mut rng: R,
    ) -> Vec<(PublicKey<G>, BatchPoK<G>)> {
        // f(x) -> [f(0), {(1, f(1)), ..., (n, f(n))}]
        let evals: BTreeMap<G::ScalarField, G::ScalarField> = generate_shares_checked::<G, R>(
            msk, next_committee.len() as u8, t, &mut rng);
        // panic!("{:?}", evals);
        // f_hat(x) (blinding polynomial) -> [f'(0), {(1, f'(1)), ...(n, f'(n))}]
        let evals_hat: BTreeMap<G::ScalarField, G::ScalarField> = generate_shares_checked::<G, R>(
            msk_hat, next_committee.len() as u8, t, &mut rng);
        // TODO: check that evals.len == evals_hat.len == next_committe.len ?
        // TODO: error handling
        let poks: Vec<(PublicKey<G>, BatchPoK<G>)> = next_committee
            .iter()
            .enumerate()
            .map(|(idx, pk)| {
                // we need to increment by 1 because f(0) is our secret
                let i = G::ScalarField::from((idx as u8) + 1);
                // calculate shares
                let x = evals.get(&i).unwrap();
                // panic!("x1 {:?}", x);
                let x_prime = evals_hat.get(&i).unwrap();
                (*pk, BatchPoK::prove(&vec![*x, *x_prime], *pk, &mut rng))
            }).collect::<Vec<_>>();

        poks
    }

    /// decrypt shares + authenticate from a collection of batched PoKs
    /// outputs the new share and its blinding share
    /// assumes default the generator is used
    //
    pub fn recover(
        sk: G::ScalarField,
        poks: Vec<BatchPoK<G>>,
    ) -> Result<(G::ScalarField, G::ScalarField), ACSSError>  {

        let q = G::generator() * sk;

        let mut secrets = Vec::new();
        let mut blinding_secrets = Vec::new();

        let mut invalid_poks = Vec::new();

        // we can't perform interpolation if there is only a single point
        if poks.len() == 1 {
            let pok = poks[0].clone();
            if !pok.verify(q) {
                return Err(ACSSError::InvalidProof);
            }

            // TODO: this should just loop over the ciphertexts
            // very unsafe code, but fine for testing...
            let s_bytes = HashedElGamal::decrypt(sk, pok.ciphertexts[0].clone());

            let s = G::ScalarField::deserialize_compressed(&s_bytes[..]).unwrap();

            let s_prime_bytes = HashedElGamal::decrypt(sk, pok.ciphertexts[1].clone());

            let s_prime = G::ScalarField::deserialize_compressed(&s_prime_bytes[..]).unwrap();

            return Ok((s, s_prime));
        }

        poks.iter().enumerate().for_each(|(idx, pok)| {
            // we can continue as long as a threshold of proofs are valid...
            if !pok.verify(q) {
                invalid_poks.push(pok);
                // return Err(ACSSError::InvalidProof);
            }

            let f = G::ScalarField::from(idx as u8 + 1);
            let r_bytes = HashedElGamal::decrypt(sk, pok.ciphertexts[0].clone());
            let r = G::ScalarField::deserialize_compressed(&r_bytes[..]).unwrap();
            secrets.push((f, r));

            let r_prime_bytes = HashedElGamal::decrypt(sk, pok.ciphertexts[1].clone());
            let r_prime = G::ScalarField::deserialize_compressed(&r_prime_bytes[..]).unwrap();
            blinding_secrets.push((f, r_prime));
        });

        let s = crate::utils::interpolate::<G>(secrets);
        let s_prime = crate::utils::interpolate::<G>(blinding_secrets);
        Ok((s, s_prime))
    }
}

/// randomly sample coefficients for a degree t polynomial `f(x)` such that `f(0) = s`
/// then output points {(1, f(1), ..., (n, f(n)))}
/// 
/// `s`: The secret (value of poly at 0)
/// `n`: The number of shares to generate
/// `t`: The threshold (degree of the polynomial)
/// `rng`: A cryptographically secure rng
///
pub fn generate_shares_checked<G: CurveGroup, R: Rng + Sized>(
    s: G::ScalarField, n: u8, t: u8, rng: &mut R,
) -> BTreeMap<G::ScalarField, G::ScalarField> {
    let mut coeffs: Vec<G::ScalarField> = 
        (0..t).map(|_| G::ScalarField::rand(rng)).collect();
    coeffs[0] = s;
//
    let f = DensePolynomial::<G::ScalarField>::from_coefficients_vec(coeffs);
    let mut out: BTreeMap<G::ScalarField, G::ScalarField> = BTreeMap::new();
    (1..n+1).for_each(|i| {
        let idx = G::ScalarField::from(i);
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
    pub fn basic_reshare_and_recover_works_from_semi_trusted_dealer() {
        let m = 3;
        let mut rng = ChaCha20Rng::seed_from_u64(0);

        let msk = Fr::rand(&mut rng);
        let msk_prime = Fr::rand(&mut rng);

        let (initial_committee_secret_keys, initial_committee_public_keys) = create_committee(m, &mut rng);
        // first we reshare to the first committee
        let poks = HighThresholdACSS::reshare(
            msk, msk_prime, &initial_committee_public_keys, m - 1, &mut rng);

        // we initialize some data structs to mimic each participant in the initial committee's local storage
        let mut initial_committee_secrets: Vec<Fr> = Vec::new();
        let mut initial_committee_blinding_secrets: Vec<Fr> = Vec::new();

        assert_eq!(m, poks.len() as u8);
        assert_eq!(initial_committee_public_keys[0], poks[0].0);
        assert_eq!(initial_committee_public_keys[1], poks[1].0);

        // we will manually decrypt the ciphertexts so we can compare them with the 
        // output of the recover algorithm
        // recover committee member 0 secret
        let ct_00 = poks[0].1.ciphertexts[0].clone();
        let u_00 = HashedElGamal::decrypt(initial_committee_secret_keys[0], ct_00);
        let ct_01 = poks[0].1.ciphertexts[1].clone();
        let u_01 = HashedElGamal::decrypt(initial_committee_secret_keys[0], ct_01);

        let ct_10 = poks[1].1.ciphertexts[0].clone();
        let u_10 = HashedElGamal::decrypt(initial_committee_secret_keys[1], ct_10);
        let ct_11 = poks[1].1.ciphertexts[1].clone();
        let u_11 = HashedElGamal::decrypt(initial_committee_secret_keys[1], ct_11);

        // then the first committe member runs ACSSRecover and gets u_00, u_01
        let sk0 = initial_committee_secret_keys[0].clone();
        if let Ok(data) = HighThresholdACSS::recover(sk0, vec![poks[0].1.clone()]) {
            let mut data0_bytes = Vec::new();
            data.0.serialize_compressed(&mut data0_bytes).unwrap();
            assert_eq!(u_00.to_vec(), data0_bytes);
            initial_committee_secrets.push(data.0);

            let mut data1_bytes = Vec::new();
            data.1.serialize_compressed(&mut data1_bytes).unwrap();
            assert_eq!(u_01.to_vec(), data1_bytes);
            initial_committee_blinding_secrets.push(data.1);

        }

        // and so can the second member
        let sk1 = initial_committee_secret_keys[1].clone();
        if let Ok(data) = HighThresholdACSS::recover(sk1, vec![poks[1].1.clone()]) {
            
            let mut data0_bytes = Vec::new();
            data.0.serialize_compressed(&mut data0_bytes).unwrap();
            assert_eq!(u_10.to_vec(), data0_bytes);
            initial_committee_secrets.push(data.0);
            
            let mut data1_bytes = Vec::new();
            data.1.serialize_compressed(&mut data1_bytes).unwrap();
            assert_eq!(u_11.to_vec(), data1_bytes);
            initial_committee_blinding_secrets.push(data.1);
        }


        let u00_scalar = Fr::deserialize_compressed(&u_00[..]).unwrap();
        let u01_scalar = Fr::deserialize_compressed(&u_01[..]).unwrap();
        let u10_scalar = Fr::deserialize_compressed(&u_10[..]).unwrap();
        let u11_scalar = Fr::deserialize_compressed(&u_11[..]).unwrap();

        let final_recovered_msk = crate::utils::interpolate::<G>(
            vec![
                (Fr::from(1u8), u00_scalar),
                (Fr::from(2u8), u10_scalar),
            ]);

        let final_recovered_msk_prime = crate::utils::interpolate::<G>(
            vec![
                (Fr::from(1u8), u01_scalar),
                (Fr::from(2u8), u11_scalar),
            ]);

        assert_eq!(msk, final_recovered_msk);
        assert_eq!(msk_prime, final_recovered_msk_prime);

        // // now the 'm' sized committee will share the secret with an 'n' sized one
        // let n = m + 4;
        // let (next_committee_sks, next_committee_pks) = create_committee(n, &mut test_rng());

        // // we simulate a public channel to which messages (poks) are broadcast
        // // Vec<(intended_recipient, PoK)>
        // let mut public_broadcast = Vec::new();

        // initial_committee_public_keys.iter().enumerate().for_each(|(idx, pk)| {
        //     let msk = initial_committee_secrets[idx];
        //     let msk_prime = initial_committee_blinding_secrets[idx];
        //     let poks = HighThresholdACSS::reshare(
        //         msk, msk_prime,
        //         &next_committee_pks, 
        //         n - 2, 
        //         &mut rng);
        //     public_broadcast.push(poks);
        // });

        // then each committee member should be able to reconsruct their shares
        // initial_committee_secret_keys.iter().enumerate().for_each(|(idx, sk)| {
        //     // identify your PoKs based on public key
        //     let pk = G::generator().mul(sk);
        //     // just a single element
        //     let my_poks: Vec<BatchPoK<G>> = poks.clone()
        //         .into_iter()
        //         .filter(|p| p.0 == pk)
        //         .map(|p| p.1.clone())
        //         .collect::<Vec<_>>();

        //     assert_eq!(1, my_poks.len());
        //     if let Ok(data) = HighThresholdACSS::recover(*sk, vec![my_poks[0].clone()]) {
        //         recovered_shares.push(data.0);
        //         recovered_blinding_shares.push(data.1);
        //     }

        //     // let f_elem = Fr::from(recovered_shares.len() as u8);

        //     // match HighThresholdACSS::recover(*sk, my_poks.iter().map(|p| p.1.clone()).collect::<Vec<_>>()) {
        //     //     Ok(data) => {
        //     //         recovered_shares.push((f_elem, data.0));
        //     //         recovered_blinding_shares.push((f_elem, data.1));
        //     //     }, 
        //     //     Err(_) => panic!("the secrets should be recoverable"),
        //     // }
        // });

        // assert_eq!(2, recovered_shares.len());
        // assert_eq!(2, recovered_blinding_shares.len());
        // // panic!("{:?}", recovered_shares);
    }

    fn create_committee<R: Rng + Sized>(size: u8, mut rng: R) -> (Vec<Fr>, Vec<G>) {
        let initial_committee_secret_keys = (0..size)
            .map(|i| (Fr::rand(&mut rng)))
            .collect::<Vec<_>>();

        let initial_committee_public_keys = initial_committee_secret_keys.iter()
            .map(|sk| G::generator().mul(sk))
            .collect::<Vec<_>>();

        (initial_committee_secret_keys, initial_committee_public_keys)
    }
}
