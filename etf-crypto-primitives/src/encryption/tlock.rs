
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
use crate::{
    encryption::{aes, aes::AESOutput},
    ibe::fullident::{Identity, IBECiphertext, IBESecret},
    utils::convert_to_bytes,
};

use ark_ff::{UniformRand, Field, One, Zero};
use ark_poly::{
    DenseUVPolynomial,
    Polynomial,
    univariate::DensePolynomial
};

use ark_serialize::CanonicalDeserialize;
use serde::{Deserialize, Serialize};

use ark_std::{
    vec::Vec,
    rand::{CryptoRng, Rng},
};

use w3f_bls::EngineBLS;

/// a secret key used for encryption/decryption
pub type OpaqueSecretKey = Vec<u8>;

/// the result of successful decryption of a timelocked ciphertext
#[derive(Serialize, Deserialize, Debug)]
pub struct DecryptionResult {
    /// the recovered plaintext 
    pub message: Vec<u8>,
    /// the recovered secret key
    pub secret: OpaqueSecretKey,
}

// #[derive(Serialize, Deserialize, Debug)]
// #[derive(CanonicalDeserialize, CanonicalSerialize, Debug)]
#[derive(Debug)]
pub struct TLECiphertext<E: EngineBLS> {
    pub aes_ct: AESOutput,
    pub etf_ct: Vec<IBECiphertext<E>>
}

#[derive(Debug, PartialEq)]
pub enum ClientError {
    AesEncryptError,
    DeserializationError,
    DeserializationErrorG1,
    DeserializationErrorG2,
    DeserializationErrorFr,
    DecryptionError,
    VectorDimensionMismatch,
    Other,
}

pub struct Tlock<E: EngineBLS> {
    _p: core::marker::PhantomData<E>,
}

impl<E: EngineBLS> Tlock<E> {
    pub fn encrypt<R: Rng + CryptoRng + Sized>(
        p_pub: E::PublicKeyGroup,
        message: &[u8],
        ids: Vec<Identity>,
        threshold: u8,
        mut rng: R,
    ) -> Result<TLECiphertext<E>, ClientError> {
        // TODO: check 1 < t <= ids
        let (msk, shares) = generate_secrets::<E, R>(ids.len() as u8, threshold, &mut rng);
        let msk_bytes = convert_to_bytes::<E::Scalar, 32>(msk);
        let ct_aes = aes::encrypt(message, msk_bytes, &mut rng)
            .map_err(|_| ClientError::AesEncryptError)?;
            
        let mut out: Vec<IBECiphertext<E>> = Vec::new();
        for (idx, id) in ids.iter().enumerate() {
            let b: [u8;32] = convert_to_bytes::<E::Scalar, 32>(shares[idx].1);
            let ct: IBECiphertext<E> = id.encrypt(&b, p_pub, &mut rng);
            out.push(ct);
        }
        Ok(TLECiphertext { aes_ct: ct_aes, etf_ct: out })
    }

    /// the order of the ibe_secrets should match the order 
    /// in which the ciphertexts were created
    pub fn decrypt(
        // ibe_pp: Vec<u8>,
        ciphertext: TLECiphertext<E>,
        ibe_secrets: Vec<IBESecret<E>>,
    ) -> Result<DecryptionResult, ClientError> {
        let mut dec_secrets: Vec<(E::Scalar, E::Scalar)> = Vec::new();

        for (idx, sk) in ibe_secrets.iter().enumerate() {
            let expected_ct = &ciphertext.etf_ct[idx];

            let share_bytes = sk.decrypt(expected_ct)
                .map_err(|_| ClientError::DecryptionError)?;

            let share = E::Scalar::deserialize_compressed(&share_bytes[..])
                .map_err(|_| ClientError::DeserializationError)?;

            dec_secrets.push((E::Scalar::from((idx + 1) as u8), share));
        }

        let secret_scalar = interpolate::<E>(dec_secrets);
        let o = convert_to_bytes::<E::Scalar, 32>(secret_scalar);

        if let Ok(plaintext) = aes::decrypt(AESOutput{
            ciphertext: ciphertext.aes_ct.ciphertext, 
            nonce: ciphertext.aes_ct.nonce, 
            key: o.to_vec(),
        }) {
            return Ok(DecryptionResult{
                message: plaintext,
                secret: o.to_vec(),
            });
        }
        Err(ClientError::DecryptionError)
    }
}

/// Generate a random polynomial f and return evalulations (f(0), (1, f(1), ..., n, f(n)))
/// f(0) is the 'secret' and the shares can be used to recover the secret with `let s = interpolate(shares);`
///
/// * `n`: The number of shares to generate
/// * `t`: The degree of the polynomial (i.e. the threhsold)
/// * `rng`: A random number generator
///
pub fn generate_secrets<
    E: EngineBLS, 
    R: Rng + Sized + CryptoRng
>(
    n: u8, t: u8, mut rng: &mut R
) -> (E::Scalar, Vec<(E::Scalar, E::Scalar)>) {
    
    if n == 1 {
        let r = E::Scalar::rand(&mut rng);
        return (r, vec![(E::Scalar::zero(), r)]);
    }

    let f = DensePolynomial::<E::Scalar>::rand(t as usize, &mut rng);
    let msk = f.evaluate(&E::Scalar::zero());
    let evals: Vec<(E::Scalar, E::Scalar)> = (1..n+1)
        .map(|i| {
            let e = E::Scalar::from(i);
            (e, f.evaluate(&e))
        }).collect();
    (msk, evals)
}

/// interpolate a polynomial from the input and evaluate it at 0
/// P(X) = sum_{i = 0} ^n y_i * (\prod_{j=0}^n [j != i] (x-xj/xi - xj))
///
/// * `evalulation`: a vec of (x, f(x)) pairs
///
pub fn interpolate<E: EngineBLS>(points: Vec<(E::Scalar, E::Scalar)>) -> E::Scalar {
    let n = points.len();

    // Calculate the Lagrange basis polynomials evaluated at 0
    let mut lagrange_at_zero: Vec<E::Scalar> = Vec::with_capacity(n);
    for i in 0..n {

        // build \prod_{j=0}^n [j != i] (x-xj/xi - xj)
        let mut basis_value = E::Scalar::one();
        for j in 0..n {
            if j != i {
                let denominator = points[i].0 - points[j].0;
                // Check if the denominator is zero before taking the inverse
                if denominator.is_zero() {
                    // Handle the case when the denominator is zero (or very close to zero)
                    return E::Scalar::zero();
                }
                let numerator = E::Scalar::zero() - points[j].0;
                // Use the precomputed inverse
                basis_value *= numerator * denominator.inverse().unwrap();
            }
        }
        lagrange_at_zero.push(basis_value);
    }

    // Interpolate the value at 0
    // compute  sum_{i = 0} ^n (y_i * sum... )
    let mut interpolated_value = E::Scalar::zero();
    for i in 0..n {
        interpolated_value += points[i].1 * lagrange_at_zero[i];
    }

    interpolated_value
}

#[cfg(test)]
mod test {

    use super::*;
    use ark_bls12_381::{Fr, G2Projective as G2};
    use ark_ff::UniformRand;
    use ark_ec::Group;
    use rand_chacha::ChaCha20Rng;

    use ark_bls12_377::Bls12_377;
    use ark_bls12_381::Bls12_381;
    use ark_ec::bls12::Bls12Config;
    use ark_ec::hashing::curve_maps::wb::{WBConfig, WBMap};
    use ark_ec::hashing::map_to_curve_hasher::MapToCurve;
    use ark_ec::pairing::Pairing as PairingEngine;

    use w3f_bls::TinyBLS377;

    use ark_std::{test_rng, rand::{RngCore, SeedableRng}};
    use rand_core::OsRng;

    fn basic_tlock_works<E: EngineBLS>() {
        let mut rng = ChaCha20Rng::from_seed([4;32]);
        let message = b"this is a test message".to_vec();
        let id = Identity::new(b"id1");
        let ids = vec![id.clone()];
        let t = 1;
        // setup the IBE system
        let msk = <E as EngineBLS>::Scalar::rand(&mut test_rng());
        // // then we need out p_pub = msk * P \in G_1
        let p_pub = <<E as EngineBLS>::PublicKeyGroup as Group>::generator() * msk;

        let sk = id.extract::<E>(msk);

        match Tlock::<E>::encrypt(p_pub, &message, ids, t, &mut rng) {
            Ok(ct) => {
                match Tlock::<E>::decrypt(ct, vec![sk]) {
                    Ok(output) => {
                        assert_eq!(output.message, message);
                    }, 
                    Err(_) => {
                        panic!("The test should pass but failed to run tlock decrypt.");        
                    }
                }
            },
            Err(_) => {
                panic!("The test should pass but failed to run tlock encrypt");
            }
        }
    }

    fn threshold_tlock_works<E: EngineBLS, R: Rng + Sized + CryptoRng>() {
        // let mut rng = ChaCha20Rng::from_seed([4;32]);
        let message = b"this is a test message".to_vec();
        let id1 = Identity::new(b"id1");
        let id2 = Identity::new(b"id2");
        let id3 = Identity::new(b"id3");

        // let ids = vec![id1.clone(), id2.clone(), id3.clone()];
        let ids = vec![id1.clone()];
        let t = 3;
        // then we need to create a resharing to each of the participants
        // in reality this is done with the ACSS algorithm
        // for testing, we just use basic Shamir
        let (msk, shares) = generate_secrets::<E, OsRng>(ids.len() as u8, t, &mut OsRng);
        // // then we need out p_pub = msk * P \in G_1
        let p_pub = <<E as EngineBLS>::PublicKeyGroup as Group>::generator() * msk;
        // e.g. s_1 * Q, s_2 * Q, ..., s_n * Q where Q = H_1(identity string)
        let ibe_secrets: Vec<IBESecret<E>> = 
            shares.iter()
                .enumerate()
                .map(|(idx, share)| ids[idx].extract(share.1))
                .collect::<Vec<_>>();
    
        match Tlock::<E>::encrypt(p_pub, &message, ids, t, &mut OsRng) {
            Ok(ct) => {
                match Tlock::<E>::decrypt(ct, ibe_secrets) {
                    Ok(output) => {
                        assert_eq!(output.message, message);
                    }, 
                    Err(e) => {
                        panic!("The test should pass but failed to run tlock decrypt {:?}.", e);        
                    }
                }
            },
            Err(_) => {
                panic!("The test should pass but failed to run tlock encrypt");
            }
        }
    }

    #[test]
    pub fn client_can_encrypt_decrypt_with_single_identity() {
        basic_tlock_works::<TinyBLS377>();
    }

    #[test]
    pub fn client_can_encrypt_decrypt_with_many_identities_full_threshold() {
        threshold_tlock_works::<TinyBLS377, OsRng>();
    }

//     #[test]
//     pub fn client_can_encrypt_decrypt_with_many_keys() {
//         let rng = ChaCha20Rng::from_seed([4;32]);
//         let message = b"this is a test";
//         let ids = vec![
//             b"id1".to_vec(), 
//             b"id2".to_vec(), 
//             b"id3".to_vec(),
//         ];
//         let t = 2;

//         let ibe_pp: G2 = G2::generator().into();
//         let s = Fr::rand(&mut test_rng());
//         let p_pub: G2 = ibe_pp.mul(s).into();

//         let ibe_pp_bytes = convert_to_bytes::<G2, 96>(ibe_pp);
//         let p_pub_bytes = convert_to_bytes::<G2, 96>(p_pub);

//         match DefaultTlock::<BfIbe>::encrypt(
//             ibe_pp_bytes.to_vec(), p_pub_bytes.to_vec(),
//             message, ids.clone(), t, rng
//         ) {
//             Ok(ct) => {
//                 // calculate secret keys: Q = H1(id), d = sQ
//                 let secrets: Vec<Vec<u8>> = ids.iter().map(|id| {
//                     let q = hash_to_g1(&id);
//                     let d = q.mul(s);
//                     convert_to_bytes::<G1, 48>(d.into()).to_vec()
//                 }).collect::<Vec<_>>();
//                 match DefaultTlock::<BfIbe>::decrypt(
//                     ibe_pp_bytes.to_vec(), ct.aes_ct.ciphertext, ct.aes_ct.nonce, ct.etf_ct, secrets, 
//                 ) {
//                     Ok(decryption_result) => {
//                         assert_eq!(message.to_vec(), decryption_result.message);
//                     }, 
//                     Err(e) => {
//                         panic!("Decryption should work but was: {:?}", e);
//                     }
//                 }
//             },
//             Err(e) => {
//                 panic!("Encryption should work but was {:?}", e);
//             }
//         }
//     }

//     #[test]
//     pub fn client_encrypt_fails_with_bad_encoding() {
//         let rng = ChaCha20Rng::from_seed([4;32]);
//         let ibe_pp: G2 = G2::generator();
//         let p_pub_bytes = convert_to_bytes::<G2, 96>(ibe_pp);

//         // bad 'p'
//         match DefaultTlock::<BfIbe>::encrypt(
//             vec![],
//             p_pub_bytes.to_vec(),
//             b"test", vec![], 2, rng.clone()
//         ) {
//             Ok(_) => {
//                panic!("should be an error");
//             },
//             Err(e) => {
//                 assert_eq!(e, ClientError::DeserializationError);
//             }
//         }

//         // bad 'q' 
//         match DefaultTlock::<BfIbe>::encrypt(
//             p_pub_bytes.to_vec(),
//             vec![],
//             b"test", vec![], 2, rng,
//         ) {k(_) => {
//                panic!("should be an error");
//             },
//            
//             O Err(e) => {
//                 assert_eq!(e, ClientError::DeserializationError);
//             }
//         }
//     }

//     #[test]
//     pub fn client_decrypt_fails_with_bad_encoding_p() {
//         // bad 'p'
//         match DefaultTlock::<BfIbe>::decrypt(
//             vec![], vec![], vec![], vec![], vec![], 
//         ) {
//             Ok(_) => {
//                 panic!("should be an error");
//             }, 
//             Err(e) => {
//                 assert_eq!(e, ClientError::DeserializationErrorG2);
//             }
//         }  
//     }

//     #[test]
//     pub fn client_decrypt_fails_with_bad_encoded_capsule_ct() {
//         let ibe_pp: G2 = G2::generator();
//         let p_pub_bytes = convert_to_bytes::<G2, 96>(ibe_pp);
//         let cap = vec![vec![1,2,3]];
//         let sks = vec![vec![1]];
//         // bad capsule
//         match DefaultTlock::<BfIbe>::decrypt(
//             p_pub_bytes.to_vec(), vec![], vec![], cap, sks, 
//         ) {
//             Ok(_) => {
//                 panic!("should be an error");
//             }, 
//             Err(e) => {
//                 assert_eq!(e, ClientError::DeserializationError);
//             }
//         }
//     }

//     #[test]
//     pub fn client_decrypt_fails_with_bad_slot_secrets() {
//         let message = b"this is a test";
//         let ids = vec![
//             b"id1".to_vec(), 
//             b"id2".to_vec(), 
//             b"id3".to_vec(),
//         ];
//         let t = 2;

//         let rng = ChaCha20Rng::from_seed([4;32]);

//         let ibe_pp: G2 = G2::generator().into();
//         let s = Fr::rand(&mut test_rng());
//         let p_pub: G2 = ibe_pp.mul(s).into();

//         let ibe_pp_bytes = convert_to_bytes::<G2, 96>(ibe_pp);
//         let p_pub_bytes = convert_to_bytes::<G2, 96>(p_pub);

//         match DefaultTlock::<BfIbe>::encrypt(
//             ibe_pp_bytes.to_vec(), p_pub_bytes.to_vec(),
//             message, ids.clone(), t, rng,
//         ) {
//             Ok(ct) => {
//                 // calculate secret keys: Q = H1(id), d = sQ
//                 let b = Fr::rand(&mut test_rng());
//                 let mut secrets: Vec<Vec<u8>> = ids.iter().map(|id| {
//                     let q = hash_to_g1(&id);
//                     let d = q.mul(b);
//                     convert_to_bytes::<G1, 48>(d.into()).to_vec()
//                 }).collect::<Vec<_>>();
//                 secrets[0] = vec![];
//                 match DefaultTlock::<BfIbe>::decrypt(
//                     ibe_pp_bytes.to_vec(), ct.aes_ct.ciphertext, 
//                     ct.aes_ct.nonce, ct.etf_ct, secrets, 
//                 ) {
//                     Ok(_) => {
//                         panic!("should be an error");
//                     }, 
//                     Err(e) => {
//                         assert_eq!(e, ClientError::DeserializationErrorG1);
//                     }
//                 }
//             },
//             Err(e) => {
//                 panic!("Encryption should work but was {:?}", e);
//             }
//         }
//     }

//     #[test]
//     pub fn client_decrypt_fails_with_bad_nonce() {
//         let message = b"this is a test";
//         let ids = vec![
//             b"id1".to_vec(), 
//             b"id2".to_vec(), 
//             b"id3".to_vec(),
//         ];
//         let t = 2;
//         let rng = ChaCha20Rng::from_seed([4;32]);
//         let ibe_pp: G2 = G2::generator().into();
//         let s = Fr::rand(&mut test_rng());
//         let p_pub: G2 = ibe_pp.mul(s).into();

//         let ibe_pp_bytes = convert_to_bytes::<G2, 96>(ibe_pp);
//         let p_pub_bytes = convert_to_bytes::<G2, 96>(p_pub);

//         match DefaultTlock::<BfIbe>::encrypt(
//             ibe_pp_bytes.to_vec(), p_pub_bytes.to_vec(),
//             message, ids.clone(), t, rng,
//         ) {
//             Ok(ct) => {
//                 // calculate secret keys: Q = H1(id), d = sQ
//                 let secrets: Vec<Vec<u8>> = ids.iter().map(|id| {
//                     let q = hash_to_g1(&id);
//                     let d = q.mul(s);
//                     convert_to_bytes::<G1, 48>(d.into()).to_vec()
//                 }).collect::<Vec<_>>();
//                 match DefaultTlock::<BfIbe>::decrypt(
//                     ibe_pp_bytes.to_vec(), ct.aes_ct.ciphertext, 
//                     vec![0,0,0,0,0,0,0,0,0,0,0,0], ct.etf_ct, secrets, 
//                 ) {
//                     Ok(_) => {
//                         panic!("should be an error");
//                     }, 
//                     Err(e) => {
//                         assert_eq!(e, ClientError::DecryptionError);
//                     }
//                 }
//             },
//             Err(e) => {
//                 panic!("Encryption should work but was {:?}", e);
//             }
//         }
//     }

//     #[test]
//     pub fn client_decrypt_fails_with_bad_ciphertext() {
//         let message = b"this is a test";
//         let ids = vec![
//             b"id1".to_vec(), 
//             b"id2".to_vec(), 
//             b"id3".to_vec(),
//         ];
//         let t = 2;
//         let rng = ChaCha20Rng::from_seed([4;32]);
//         let ibe_pp: G2 = G2::generator().into();
//         let s = Fr::rand(&mut test_rng());
//         let p_pub: G2 = ibe_pp.mul(s).into();

//         let ibe_pp_bytes = convert_to_bytes::<G2, 96>(ibe_pp);
//         let p_pub_bytes = convert_to_bytes::<G2, 96>(p_pub);

//         match DefaultTlock::<BfIbe>::encrypt(
//             ibe_pp_bytes.to_vec(), 
//             p_pub_bytes.to_vec(),
//             message, 
//             ids.clone(), 
//             t,
//             rng,
//         ) {
//             Ok(ct) => {
//                 // calculate secret keys: Q = H1(id), d = sQ
//                 let secrets: Vec<Vec<u8>> = ids.iter().map(|id| {
//                     let q = hash_to_g1(&id);
//                     let d = q.mul(s);
//                     convert_to_bytes::<G1, 48>(d.into()).to_vec()
//                 }).collect::<Vec<_>>();
//                 match DefaultTlock::<BfIbe>::decrypt(
//                     ibe_pp_bytes.to_vec(), vec![], 
//                     ct.aes_ct.nonce, ct.etf_ct, secrets, 
//                 ) {
//                     Ok(_) => {
//                         panic!("should be an error");
//                     }, 
//                     Err(e) => {
//                         assert_eq!(e, ClientError::DecryptionError);
//                     }
//                 }
//             },
//             Err(e) => {
//                 panic!("Encryption should work but was {:?}", e);
//             }
//         }
//     }
}