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
};

use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use serde::{Deserialize, Serialize};

use ark_std::{
    vec::Vec,
    rand::{CryptoRng, Rng},
};

use w3f_bls::EngineBLS;

/// a secret key used for encryption/decryption
pub type OpaqueSecretKey = [u8;32];

/// the result of successful decryption of a timelocked ciphertext
#[derive(Serialize, Deserialize, Debug)]
pub struct DecryptionResult {
    /// the recovered plaintext 
    pub message: Vec<u8>,
    /// the recovered secret key
    pub secret: OpaqueSecretKey,
}

// #[derive(Serialize, Deserialize, Debug)]
#[derive(CanonicalDeserialize, CanonicalSerialize, Debug)]
// #[derive(Debug)]
pub struct TLECiphertext<E: EngineBLS> {
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
    InvalidSignature,
    Other,
}

// /// construct a secret key from a scalar
// pub fn new(sk: E::Scalar) -> Self {
//     Self(sk)
// }

/// encrypt a message for an identity
///
/// * `p_pub`: the public key commitment for the IBE system (i.e. the setup phase)
/// * `message`: The message to encrypt
/// * `id`: the identity to encrypt for
/// * `rng`: a CSPRNG
///
pub fn tle<E, R: Rng + CryptoRng + Sized>(
    p_pub: E::PublicKeyGroup,
    aes_secret_key: OpaqueSecretKey,
    message: &[u8],
    id: Identity,
    mut rng: R,
) -> Result<TLECiphertext<E>, ClientError> 
where E: EngineBLS {
    let ct_aes = aes::encrypt(message, aes_secret_key, &mut rng)
        .map_err(|_| ClientError::AesEncryptError)?; // not sure how to test this line...
    let ct: IBECiphertext<E> = id.encrypt(&aes_secret_key, p_pub, &mut rng);
    Ok(TLECiphertext {
        aes_ct: ct_aes, 
        etf_ct: ct
    })
}

impl<E: EngineBLS> TLECiphertext<E> {
    /// decrypt a ciphertext created as a result of timelock encryption
    /// the signature should be equivalent to the output of IBE.Extract(ID)
    /// where ID is the identity for which the message was created
    pub fn tld(
        &self,
        sig: E::SignatureGroup,
    ) -> Result<DecryptionResult, ClientError> {
        let secret_bytes = IBESecret(sig)
            .decrypt(&self.etf_ct)
            .map_err(|_| ClientError::InvalidSignature)?;

        let secret_array: [u8;32] = secret_bytes.clone()
            .try_into()
            .unwrap_or([0u8;32]);

        if let Ok(plaintext) = aes::decrypt(AESOutput {
            ciphertext: self.aes_ct.ciphertext.clone(), 
            nonce: self.aes_ct.nonce.clone(), 
            key: secret_bytes,
        }) {
            return Ok(DecryptionResult{
                message: plaintext,
                secret: secret_array,
            });
        }
        Err(ClientError::DecryptionError)
    }
}

// /// Generate a random polynomial f and return evalulations (f(0), (1, f(1), ..., n, f(n)))
// /// f(0) is the 'secret' and the shares can be used to recover the secret with `let s = interpolate(shares);`
// ///
// /// * `n`: The number of shares to generate
// /// * `t`: The degree of the polynomial (i.e. the threhsold)
// /// * `rng`: A random number generator
// ///
// pub fn generate_secrets<
//     E: EngineBLS, 
//     R: Rng + Sized + CryptoRng
// >(
//     n: u8, 
//     t: u8, 
//     mut rng: &mut R
// ) -> (E::Scalar, Vec<(E::Scalar, E::Scalar)>) {    
//     if  n == 1 {
//         let r = E::Scalar::rand(&mut rng);
//         return (r, vec![(E::Scalar::zero(), r)]);
//     }

//     let f = DensePolynomial::<E::Scalar>::rand(t as usize - 1, &mut rng);
//     let msk = f.evaluate(&E::Scalar::zero());
//     let evals: Vec<(E::Scalar, E::Scalar)> = (0..n)
//         .map(|i| {
//             // we need to offset by 1 to avoid evaluation of the msk
//             let e = E::Scalar::from(i + 1);
//             (e, f.evaluate(&e))
//         }).collect();
//     (msk, evals)
// }

// /// interpolate a polynomial from the input and evaluate it at 0
// /// P(X) = sum_{i = 0} ^n (y_i * (\prod_{j=0}^n [j != i] (x-xj/xi - xj)))
// ///
// /// * `points`: a vec of (x, f(x)*Q <- BLS.sign(ID)) pairs
// ///
// pub fn interpolate_threshold_bls_sigs<E: EngineBLS>(
//     points: Vec<(E::Scalar, E::SignatureGroup)>
// ) -> E::SignatureGroup {
//     let n = points.len();
//     // Calculate the Lagrange basis polynomials evaluated at 0
//     let mut interpolated_value = E::SignatureGroup::zero();

//     for i in 0..n {
//         // build \prod_{j=0}^n [j != i] (x-xj/xi - xj)
//         let mut basis_value = E::Scalar::one();
//         for j in 0..n {
//             if j != i {
//                 let numerator = points[j].0;
//                 let denominator = points[j].0 - points[i].0;
//                 // Check if the denominator is zero before taking the inverse
//                 if denominator.is_zero() {
//                     // Handle the case when the denominator is zero (or very close to zero)
//                     return E::SignatureGroup::zero();
//                 }
//                 basis_value *= numerator * denominator.inverse().unwrap();
//             }
//         }
//         interpolated_value += points[i].1 * basis_value;
//     }

//     interpolated_value
// }

#[cfg(test)]
mod test {

    use super::*;
    use alloc::vec;
    use rand_chacha::ChaCha20Rng;
    use w3f_bls::{Signature, TinyBLS377, TinyBLS381};
    use ark_std::rand::SeedableRng;
    use rand_core::OsRng;
    use ark_ec::Group;
    use ark_ff::UniformRand;

    use sha2::{Digest, Sha256};

    use hex;

    #[test]
    fn delete_me() {
        // private sk => public pk
        // sig = sk.sign(msg) where msg = H_1(Sha256(round))
        // then by encryptin for Sha256(round) we should be able to decrypt with the signature
        // but it isn't working...

        let pk_hex_str = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";
        let round: u32 = 10024141; 
        let sig_hex_str = "8c87caf26bb4f5e9fdfad5ddf739ff8683344f8cf04a8c381225ff067557b5d9d51937eed765fcef21971bf5ddef44bb";

        let mut hasher = Sha256::default();
        hasher.update(round.to_be_bytes());
        let message = hasher.finalize().to_vec();

        let mut pk_bytes = hex::decode(pk_hex_str).unwrap();
        let sig_bytes = hex::decode(&sig_hex_str).unwrap();
        // let message = b"this is a test message".to_vec();
        let id = Identity::new(&message);
        // let sk = E::Scalar::rand(&mut OsRng);
        let p_pub = <TinyBLS381 as EngineBLS>::PublicKeyGroup::deserialize_compressed(&mut &pk_bytes[..]).unwrap();

        // key used for aes encryption
        let aes_sk = [1;32];
        
        let sig = <TinyBLS381 as EngineBLS>::SignatureGroup::deserialize_compressed(&mut &sig_bytes[..]).unwrap();
        // let sig = id.extract::<TinyBLS381>(assk).0;
        // sanity check: signature verification
        assert!(Signature::<TinyBLS381>(sig).verify(
            
            // &w3f_bls::Message::new(b"", &round.to_be_bytes()), 
            &w3f_bls::PublicKey(p_pub))
        );


        let ct: TLECiphertext<TinyBLS381> = tle(p_pub, aes_sk, &message, id, OsRng).unwrap();
        let pt = ct.tld(sig).unwrap();
    }
    
    // specific conditions that we want to test/verify
    enum TestStatusReport {
        InterpolationComplete { msk: Vec<u8>, recovered_msk: Vec<u8> },
        DecryptSuccess { actual: Vec<u8>, expected: Vec<u8> },
        DecryptionFailed { error: ClientError }
    }

    fn tlock_test<E: EngineBLS, R: Rng + Sized + CryptoRng>(
        n: u8,
        m: u8,
        inject_bad_ct: bool,
        inject_bad_nonce: bool,
        handler: &dyn Fn(TestStatusReport) -> (),
    ) {
        let message = b"this is a test message".to_vec();
        let id = Identity::new(b"id");
        let sk = E::Scalar::rand(&mut OsRng);
        let p_pub: <E as EngineBLS>::PublicKeyGroup = E::PublicKeyGroup::generator() * sk;

        // key used for aes encryption
        let msk = [1;32];
        
        let sig: E::SignatureGroup = id.extract::<E>(sk).0;

        match tle::<E, OsRng>(p_pub, msk, &message, id, OsRng) {
            Ok(mut ct) => {

                // create error scenarios here
                if inject_bad_ct {
                    ct.aes_ct.ciphertext = vec![];
                }

                if inject_bad_nonce {
                    ct.aes_ct.nonce = vec![];
                }
            
                match ct.tld(sig) {
                    Ok(output) => {
                        handler(TestStatusReport::DecryptSuccess{
                            actual: output.message, 
                            expected: message
                        });
                    }, 
                    Err(e) => {
                        handler(TestStatusReport::DecryptionFailed{ error: e });
                    }
                }
            },
            Err(_) => {
                panic!("The test should pass but failed to run tlock encrypt");
            }
        }
    }

    #[test]
    pub fn tlock_can_encrypt_decrypt_with_single_sig() {
        tlock_test::<TinyBLS377, OsRng>(1, 1, false, false,
            &|status: TestStatusReport| {
                match status {
                    TestStatusReport::DecryptSuccess{ actual, expected } => {
                        assert_eq!(actual, expected);
                    },
                    _ => panic!("all other conditions invalid"),
                }
            }
        );
    }

    #[test]
    pub fn tlock_can_encrypt_decrypt_with_full_sigs_present() {
        tlock_test::<TinyBLS377, OsRng>(5, 5, false, false,
            &|status: TestStatusReport| {
                match status {
                    TestStatusReport::DecryptSuccess{ actual, expected } => {
                        assert_eq!(actual, expected);
                    },
                    _ => panic!("all other conditions invalid"),
                }
            }
        );
    }

    #[test]
    pub fn tlock_can_encrypt_decrypt_with_many_identities_at_threshold() {
        tlock_test::<TinyBLS377, OsRng>(5, 3, false, false,
            &|status: TestStatusReport| {
                match status {
                    TestStatusReport::DecryptSuccess{ actual, expected } => {
                        assert_eq!(actual, expected);
                    },
                    _ => panic!("all other conditions invalid"),
                }
            }
        );
    }

    #[test]
    pub fn tlock_decryption_fails_with_bad_ciphertext() {
        tlock_test::<TinyBLS377, OsRng>(5, 5, true, false,
            &|status: TestStatusReport| {
                match status {
                    TestStatusReport::DecryptionFailed{ error } => {
                        assert_eq!(error, ClientError::DecryptionError);
                    },
                    _ => panic!("all other conditions invalid"),
                }
            }
        );
    }

    
    #[test]
    pub fn tlock_decryption_fails_with_bad_nonce() {
        tlock_test::<TinyBLS377, OsRng>(5, 5, false, true,
            &|status: TestStatusReport| {
                match status {
                    TestStatusReport::DecryptionFailed{ error } => {
                        assert_eq!(error, ClientError::DecryptionError);
                    },
                    _ => panic!("all other conditions invalid"),
                }
            }
        );
    }

    // /// n: full committee size
    // /// t: the threshold value
    // /// m: the actual number of participants (who will submit signatures)
    // fn threshold_bls_interpolation_test<E: EngineBLS>(
    //     n: u8,
    //     t: u8,
    //     m: u8,
    //     handler: &dyn Fn(TestStatusReport) -> (),
    // ) {
    //     let mut rng = ChaCha20Rng::from_seed([0;32]);
    //     // essentially the message being signed
    //     let id = Identity::new(b"id");
    //     let (msk, shares) = generate_secrets::<E, ChaCha20Rng>(n, t, &mut rng);
    //     // s * Q_{ID}, a BLS sig
    //     let p_pub: IBESecret<E> = id.extract(msk);
    //     // e.g. s_1 * Q, s_2 * Q, ..., s_n * Q where Q = H_1(identity string)
    //     let threshold_signatures = (0..m).map(|i| 
    //         (
    //             shares[i as usize].0,
    //             id.extract::<E>(shares[i as usize].1).0
    //         )
    //     ).collect();
    //     let interpolated_sig = crate::utils::interpolate_threshold_bls::<E>(
    //         threshold_signatures
    //     );

    //     handler(TestStatusReport::InterpolationComplete{ 
    //         msk: crate::utils::convert_to_bytes::<E::SignatureGroup, 48>(p_pub.0).to_vec(), 
    //         recovered_msk: crate::utils::convert_to_bytes::<E::SignatureGroup, 48>(
    //             interpolated_sig
    //         ).to_vec(),
    //     });
    // }

    // #[test]
    // pub fn test_threshold_bls_works_with_all_sigs_present() {
    //     threshold_bls_interpolation_test::<TinyBLS377>(5, 5, 5,
    //         &|status: TestStatusReport| {
    //             match status {
    //                 TestStatusReport::InterpolationComplete{ msk, recovered_msk } => {
    //                     assert_eq!(recovered_msk, msk);
    //                 },
    //                 _ => panic!("all other conditions invalid"),
    //             }
    //         });
    // }
    
    // #[test]
    // pub fn test_threshold_bls_works_with_threshold_sigs_present() {
    //     threshold_bls_interpolation_test::<TinyBLS377>(5, 3, 3,
    //         &|status: TestStatusReport| {
    //             match status {
    //                 TestStatusReport::InterpolationComplete{ msk, recovered_msk } => {
    //                     assert_eq!(recovered_msk, msk);
    //                 },
    //                 _ => panic!("all other conditions invalid"),
    //             }
    //         });
    // }

    // #[test]
    // pub fn test_threshold_bls_fails_with_less_than_threshold_sigs_present() {
    //     threshold_bls_interpolation_test::<TinyBLS377>(5, 3, 2,
    //         &|status: TestStatusReport| {
    //             match status {
    //                 TestStatusReport::InterpolationComplete{ msk, recovered_msk } => {
    //                     assert!(recovered_msk != msk);
    //                 },
    //                 _ => panic!("all other conditions invalid"),
    //             }
    //         });
    // }
}
