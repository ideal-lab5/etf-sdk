
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
    /// the identity for which the ciphertext was encrypted
    pub identity: Identity,
    pub aes_ct: AESOutput,
    pub etf_ct: IBECiphertext<E>
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
        id: Identity,
        mut rng: R,
    ) -> Result<TLECiphertext<E>, ClientError> {
        let msk = E::Scalar::rand(&mut rng);
        let msk_bytes = convert_to_bytes::<E::Scalar, 32>(msk);
        let ct_aes = aes::encrypt(message, msk_bytes, &mut rng)
            .map_err(|_| ClientError::AesEncryptError)?;

        let b: [u8;32] = convert_to_bytes::<E::Scalar, 32>(msk);
        let ct: IBECiphertext<E> = id.encrypt(&b, p_pub, &mut rng);
        Ok(TLECiphertext { 
            identity: id, 
            aes_ct: ct_aes, 
            etf_ct: ct
        })
    }

    /// assumes the order of the ibe_secrets should match the order 
    /// in which the ciphertexts were created
    pub fn decrypt(
        ciphertext: TLECiphertext<E>,
        ibe_secrets: Vec<IBESecret<E>>,
    ) -> Result<DecryptionResult, ClientError> {
        let mut dec_secrets: Vec<(E::Scalar, E::Scalar)> = Vec::new();
        // interpolate the ibe_secrets
        let shares: Vec<(E::Scalar, E::SignatureGroup)> = 
            ibe_secrets.iter().enumerate().map(|(idx, share)| 
                (E::Scalar::from(idx as u8 + 1), share.0)
            ).collect();
        let sig = crate::utils::interpolate_threshold_bls::<E>(shares);
        let secret_bytes = IBESecret(sig).decrypt(&ciphertext.etf_ct)
            .map_err(|_| ClientError::DecryptionError)?;
        let secret_scalar = E::Scalar::deserialize_compressed(&secret_bytes[..])
                .map_err(|_| ClientError::DeserializationError)?;
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
    n: u8, 
    t: u8, 
    mut rng: &mut R
) -> (E::Scalar, Vec<(E::Scalar, E::Scalar)>) {    
    if n == 1 {
        let r = E::Scalar::rand(&mut rng);
        return (r, vec![(E::Scalar::zero(), r)]);
    }

    let f = DensePolynomial::<E::Scalar>::rand(t as usize - 1, &mut rng);
    let msk = f.evaluate(&E::Scalar::zero());
    let evals: Vec<(E::Scalar, E::Scalar)> = (0..n)
        .map(|i| {
            // we need to offset by 1 to avoid evaluation of the msk
            let e = E::Scalar::from(i + 1);
            (e, f.evaluate(&e))
        }).collect();
    (msk, evals)
}

/// interpolate a polynomial from the input and evaluate it at 0
/// P(X) = sum_{i = 0} ^n (y_i * (\prod_{j=0}^n [j != i] (x-xj/xi - xj)))
///
/// * `evalulation`: a vec of (x, f(x)) pairs
///
///
pub fn interpolate_threshold_bls_sigs<E: EngineBLS>(
    points: Vec<(E::Scalar, E::SignatureGroup)>
) -> E::SignatureGroup {
    let n = points.len();
    // Calculate the Lagrange basis polynomials evaluated at 0
    let mut interpolated_value = E::SignatureGroup::zero();

    for i in 0..n {
        // build \prod_{j=0}^n [j != i] (x-xj/xi - xj)
        let mut basis_value = E::Scalar::one();
        for j in 0..n {
            if j != i {
                let numerator = points[j].0;
                let denominator = points[j].0 - points[i].0;
                // Check if the denominator is zero before taking the inverse
                if denominator.is_zero() {
                    // Handle the case when the denominator is zero (or very close to zero)
                    return E::SignatureGroup::zero();
                }
                basis_value *= numerator * denominator.inverse().unwrap();
            }
        }
        interpolated_value += points[i].1 * basis_value;
    }

    interpolated_value
}


/// interpolate a polynomial from the input and evaluate it at 0
/// P(X) = sum_{i = 0} ^n (y_i * (\prod_{j=0}^n [j != i] (x-xj/xi - xj)))
///
/// * `evalulation`: a vec of (x, f(x)) pairs
///
///
pub fn interpolate<E: EngineBLS>(
    points: Vec<(E::Scalar, E::Scalar)>
) -> E::Scalar {
    let n = points.len();
    // Calculate the Lagrange basis polynomials evaluated at 0
    let mut interpolated_value = E::Scalar::zero();

    for i in 0..n {
        // build \prod_{j=0}^n [j != i] (x-xj/xi - xj)
        let mut basis_value = E::Scalar::one();
        for j in 0..n {
            if j != i {
                let numerator = points[j].0;
                let denominator = points[j].0 - points[i].0;
                // Check if the denominator is zero before taking the inverse
                if denominator.is_zero() {
                    // Handle the case when the denominator is zero (or very close to zero)
                    return E::Scalar::zero();
                }
                basis_value *= numerator * denominator.inverse().unwrap();
            }
        }
        interpolated_value += points[i].1 * basis_value;
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

    enum TestStatusReport {
        InterpolationComplete{ msk: Vec<u8>, recovered_msk: Vec<u8> }
    }

    fn tlock_test<E: EngineBLS, R: Rng + Sized + CryptoRng>(
        n: u8,
        t: u8,
        m: u8,
    ) {
        // let mut rng = ChaCha20Rng::from_seed([4;32]);
        let message = b"this is a test message".to_vec();
        let id = Identity::new(b"id");
        // the total number of shares
        // let n = 5;
        // the threshold required to interpolate later on
        // let t = 3;
        let (msk, shares) = generate_secrets::<E, OsRng>(n, t, &mut OsRng);
        // let msk = E::Scalar::generate(&mut OsRng);
        // // then we need out p_pub = msk * P \in G_1
        let p_pub = <<E as EngineBLS>::PublicKeyGroup as Group>::generator() * msk;
        // e.g. s_1 * Q, s_2 * Q, ..., s_n * Q where Q = H_1(identity string)
        let threshold_signatures = (0..m).map(|i| id.extract::<E>(shares[i as usize].1))
            .collect();
        match Tlock::<E>::encrypt(p_pub, &message, id, &mut OsRng) {
            Ok(ct) => {
                match Tlock::<E>::decrypt(ct, threshold_signatures) {
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
    pub fn tlock_can_encrypt_decrypt_with_full_sigs_present() {
        tlock_test::<TinyBLS377, OsRng>(5, 5, 5);
    }

    #[test]
    pub fn tlock_can_encrypt_decrypt_with_many_identities_full_threshold() {
        tlock_test::<TinyBLS377, OsRng>(5, 3, 3);
    }

    /// n: full committee size
    /// t: the threshold value
    /// m: the actual number of participants (who will submit signatures)
    fn threshold_bls_interpolation_test<E: EngineBLS>(
        n: u8,
        t: u8,
        m: u8,
        handler: &dyn Fn(TestStatusReport) -> (),
    ) {

        // f(x) = 12 + x + x^2
        // f(0)  = 12
        // f(1) = 12 + 1 + 1 = 14
        // f(2) = 12 + 2 + 4 = 18
        // f(3) = 12 + 3 + 9 = 24
        //
        // let points = vec![
        //     (E::Scalar::from(1u8), E::Scalar::from(14u8)),
        //     (E::Scalar::from(2u8), E::Scalar::from(18u8)),
        //     (E::Scalar::from(3u8), E::Scalar::from(24u8)),
        // ];

        // let interpolated_value = interpolate::<E>(points);
        // assert_eq!(interpolated_value, E::Scalar::from(12u8));
        let mut rng = ChaCha20Rng::from_seed([0;32]);
        // essentially the message being signed
        let id = Identity::new(b"id");
        let (msk, shares) = generate_secrets::<E, ChaCha20Rng>(n, t, &mut rng);
        // then we truncate the shares
        let mut truncated_shares = &shares[0..m as usize];
        // then we should be able to interpolate the msk from the shares in the scalar field
        // let recovered_msk = interpolate::<E>(truncated_shares.to_vec());
        // assert_eq!(msk, recovered_msk);
        // s * Q_{ID}, a BLS sig
        let p_pub: IBESecret<E> = id.extract(msk);
        // e.g. s_1 * Q, s_2 * Q, ..., s_n * Q where Q = H_1(identity string)
        let threshold_signatures = (0..m).map(|i| 
            (
                shares[i as usize].0,
                id.extract::<E>(shares[i as usize].1).0
            )
        ).collect();
        let interpolated_sig = crate::utils::interpolate_threshold_bls::<E>(
            threshold_signatures
        );

        handler(TestStatusReport::InterpolationComplete{ 
            msk: crate::utils::convert_to_bytes::<E::SignatureGroup, 48>(p_pub.0).to_vec(), 
            recovered_msk: crate::utils::convert_to_bytes::<E::SignatureGroup, 48>(interpolated_sig).to_vec(),
        });
    }

    #[test]
    pub fn test_threshold_bls_works_with_all_sigs_present() {
        threshold_bls_interpolation_test::<TinyBLS377>(5, 5, 5,
            &|status: TestStatusReport| {
                match status {
                    TestStatusReport::InterpolationComplete{ msk, recovered_msk } => {
                        assert_eq!(recovered_msk, msk);
                    },
                    _ => panic!("all other conditions invalid"),
                }
            });
    }
    
    #[test]
    pub fn test_threshold_bls_works_with_threshold_sigs_present() {
        threshold_bls_interpolation_test::<TinyBLS377>(5, 3, 3,
            &|status: TestStatusReport| {
                match status {
                    TestStatusReport::InterpolationComplete{ msk, recovered_msk } => {
                        assert_eq!(recovered_msk, msk);
                    },
                    _ => panic!("all other conditions invalid"),
                }
            });
    }

    #[test]
    pub fn test_threshold_bls_fails_with_less_than_threshold_sigs_present() {
        threshold_bls_interpolation_test::<TinyBLS377>(5, 3, 2,
            &|status: TestStatusReport| {
                match status {
                    TestStatusReport::InterpolationComplete{ msk, recovered_msk } => {
                        assert!(recovered_msk != msk);
                    },
                    _ => panic!("all other conditions invalid"),
                }
            });
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