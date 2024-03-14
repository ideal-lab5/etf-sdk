
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
use ring::{agreement, agreement::{PublicKey, X25519}};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    XChaCha20Poly1305, XNonce
};
use crate::{
    proofs::el_gamal_sigma::PoK,
    types::ProtocolParams as ACSSParams,
    utils::convert_to_bytes,
};


// pub type PublicKey = [u8;32];

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

#[derive(Clone, PartialEq, Debug)]
pub struct Resharing<C: CurveGroup> {
    pub capsules: Vec<Capsule>,
    pub proof: PoK<C>,
}

/// represents the data that an old committee member
/// passes to a new one
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Capsule {
   pub ciphertext: Vec<u8>,
   pub ciphertext_prime: Vec<u8>,
   pub commitment: Vec<u8>,
}

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
    pub fn reshare<R: ring::rand::SecureRandom>(
        params: ACSSParams<G>,
        msk: Fr, 
        msk_hat: Fr,
        next_committee: &[PublicKey],
        t: u8,
        mut rng: R,
    ) -> Resharing<G> {
        // let mut buffer = Vec::new();
        // rng.fill(&mut buffer);
        // panic!("{:?}", buffer);
        // let mut bytes = [0u8;32];
        // // 32
        // bytes[..32].copy_from_slice(&buffer[..32]);
        let mut chacha = rand_chacha::ChaCha20Rng::from_seed([0;32]);
        // f(x) -> [f(0), {(1, f(1)), ..., (n, f(n))}]
        let evals: BTreeMap<Fr, Fr> = generate_shares_checked(
            msk, next_committee.len() as u8, t, &mut chacha);
        // f_hat(x) (blinding polynomial) -> [f'(0), {1, f'(1), ...}]
        let evals_hat: BTreeMap<Fr, Fr> = generate_shares_checked(
            msk_hat, next_committee.len() as u8, t, &mut chacha);
        // map to aggregate the outputs
        let mut result: Vec<Capsule> = Vec::new();
        let mut secrets = Vec::new();

        // TODO: check that evals.len == evals_hat.len == next_committe.len ?
        // TODO: error handling
        for (idx, member) in next_committee.iter().enumerate() {
            // the committee member's 'position' as a scalar field element
            let f_elem = Fr::from((idx as u8) + 1);
            // calculate shares
            let x = evals.get(&f_elem).unwrap();
            let x_prime = evals_hat.get(&f_elem).unwrap();
            // we will use these later to construct the batched PoK
            secrets.push(*x);
            secrets.push(*x_prime);
            let commitment = params.clone().g.mul(x) + params.clone().h.mul(x_prime);
            // perform a key exchange with the pubkey
            // and finally calculate the ciphertexts
            let protocol_ephem_private_key = 
                agreement::EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
            let peer_public_key = agreement::UnparsedPublicKey::new(&X25519, member);
            agreement::agree_ephemeral(
                protocol_ephem_private_key,
                &peer_public_key,
                |key_material| {
                    // In a real application, we'd apply a KDF to the key material and the
                    // public keys (as recommended in RFC 7748) and then derive session
                    // keys from the result. We omit this here (for now).
                                
                    let key = generic_array::GenericArray::from_slice(&key_material);
                    let cipher = XChaCha20Poly1305::new(&key);
                    let nonce = XChaCha20Poly1305::generate_nonce(&mut chacha); // 192-bits; unique per message
                    // convert scalars to bytes
                    let x_bytes = convert_to_bytes::<Fr, 32>(*x).to_vec();
                    let x_prime_bytes = convert_to_bytes::<Fr, 32>(*x_prime).to_vec();
                    let ciphertext = cipher.encrypt(&nonce, x_bytes.as_ref()).unwrap();
                    let ciphertext_prime = cipher.encrypt(&nonce, x_prime_bytes.as_ref()).unwrap();
                    result.push(Capsule {
                        ciphertext,
                        ciphertext_prime,
                        commitment: convert_to_bytes::<G, 48>(commitment).into(),
                    });
                },
            ).unwrap();  
        }

        let proof = crate::proofs::el_gamal_sigma::PoK::batch_prove(
            secrets.iter().map(|s| *s).collect::<Vec<_>>().as_slice(), 
            params.clone(), 
            &mut chacha
        );

        Resharing {
            capsules: result,
            proof
        }
    }

    /// decrypt shares + authenticate
    /// outputs the new share and its blinding share
    pub fn recover(
        params: ACSSParams<G>, 
        // dk: DecryptionKey,
        capsule: Capsule
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
    use ark_std::rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use ring::{
        agreement::{Algorithm, X25519, EphemeralPrivateKey},
        rand::SystemRandom,
    };

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
        let m = 2;
        let n = 5;
        // generate keys for the committees
        let mut sys_rng = SystemRandom::new();
        let mut rng = ChaCha20Rng::seed_from_u64(0);

        let alg: &Algorithm = &X25519;

        let initial_committee_keys = (0..m).map(|_| EphemeralPrivateKey::generate(alg, &mut sys_rng).unwrap())
            .collect::<Vec<_>>();
        let initial_committee_public = initial_committee_keys
            .iter()
            .map(|key| key.compute_public_key().unwrap())
            .collect::<Vec<_>>();

        let next_committee_keys = (0..n).map(|_| EphemeralPrivateKey::generate(alg, &mut sys_rng).unwrap())
            .collect::<Vec<_>>();
        let next_committee_public = next_committee_keys
            .iter()
            .map(|key| key.compute_public_key().unwrap())
            .collect::<Vec<_>>();

        let initial_committee_threshold = 2u8;
        let next_committee_threshold = 3u8;
        let params = ACSSParams::rand(&mut rng);

        // generate the master secrets
        let msk = Fr::rand(&mut rng);
        let msk_hat = Fr::rand(&mut rng);

        let initial_committee_resharing: Resharing<G> = 
            HighThresholdACSS::reshare(
                params.clone(),
                msk,
                msk_hat,
                &initial_committee_public, 
                initial_committee_threshold, 
                sys_rng,
            );
        // // simulate a public broadcast channel
        // let mut simulated_broadcast: 
        //     BTreeMap<WrappedEncryptionKey, Vec<Capsule>> = BTreeMap::new();
        // // each member of the initial committee 'owns' a secret (identified by matching indices)
        initial_committee_resharing.capsules.iter().enumerate().for_each(|(idx, c)| {
            // let member_secrets = &initial_committee_shares[idx];
            // // authenticate + decrypt shares
            // let (u, u_hat) = HighThresholdACSS::recover(
            //     params.clone(), c.1.clone(), member_secrets.clone(),
            // ).unwrap();
            // // and they each create a resharing of their secrets
            // let next_committee_resharing: Vec <Capsule> = 
            //     HighThresholdACSS::reshare(
            //         params.clone(),
            //         u,
            //         u_hat, 
            //         &next_committee, 
            //         next_committee_threshold, 
            //         test_rng(),
            // );
            // assert!(next_committee_resharing.len().eq(&next_committee.len()));
            // simulated_broadcast.insert(
            //     WrappedEncryptionKey(c.0.n.clone()), 
            //     next_committee_resharing,
            // );
        });

        // let mut new_committee_sks = Vec::new();
        // let mut new_committee_blinding_sks = Vec::new();

        // // now, next committee members verify + derive
        // next_committee_keys.iter().for_each(|(ek, dk)| {
        //     // collect each new member's shares from the old committee
        //     let mut coeffs: Vec<Fr> = Vec::new();
        //     let mut blinding_coeffs: Vec<Fr> = Vec::new();

        //     initial_committee.iter().enumerate().for_each(|(idx, old_member)| {
        //         // get the share they gave us
        //         let capsule = simulated_broadcast.get(old_member).unwrap()
        //             .iter().filter(|m| m.ek_n.eq(&ek.n))
        //             .collect::<Vec<_>>()[0];
                
        //         // [idx];

        //         // //

        //         // authenticate and decrypt
        //         let (u, u_hat) = HighThresholdACSS::recover(
        //             params.clone(),
        //             dk.clone(),
        //             capsule.clone(),
        //         ).unwrap();
        //         // store somewhere
        //         coeffs.push(u);
        //         blinding_coeffs.push(u_hat);
        //     });

        //     // then each member of the new committee interpolates their new secrets
        //     let evals = coeffs.iter().enumerate().map(|(i, c)| (Fr::from((i as u8) + 1), *c)).collect::<Vec<_>>();
        //     let blinding_evals = blinding_coeffs.iter().enumerate().map(|(i, c)| (Fr::from((i as u8) + 1), *c)).collect::<Vec<_>>();
            
        //     let sk = crate::encryption::aes::interpolate(evals);
        //     new_committee_sks.push(sk);
            
        //     let blinding_sk = crate::encryption::aes::interpolate(blinding_evals.clone());
        //     new_committee_blinding_sks.push(blinding_sk);
        // });

        // // // then we can interpolate these sks and blinding_sks to recover the original msk, msk_hat
        // let new_committee_evals = new_committee_sks.iter().enumerate().map(|(idx, item)| {
        //     (Fr::from((idx as u8) + 1), *item)
        // }).collect::<Vec<_>>();

        // let recovered_sk = crate::encryption::aes::interpolate(new_committee_evals);
        // assert_eq!(msk, recovered_sk);

        // let new_committee_blinding_evals = new_committee_blinding_sks.iter().enumerate().map(|(idx, item)| {
        //     (Fr::from((idx as u8) + 1), *item)
        // }).collect::<Vec<_>>();

        // let recovered_blinding_sk = crate::encryption::aes::interpolate(new_committee_blinding_evals);
        // assert_eq!(msk_hat, recovered_blinding_sk);
    }
}
