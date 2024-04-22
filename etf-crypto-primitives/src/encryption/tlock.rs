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

use ark_ec::Group;
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

// can we make this not public? will do later on..
pub struct SecretKey<E: EngineBLS>(pub E::Scalar);

impl<E: EngineBLS> SecretKey<E> {

    /// construct a secret key from a scalar
    pub fn new(sk: E::Scalar) -> Self {
        Self(sk)
    }

    /// encrypt a message for an identity
    ///
    /// * `p_pub`: the public key commitment for the IBE system (i.e. the setup phase)
    /// * `message`: The message to encrypt
    /// * `id`: the identity to encrypt for
    /// * `rng`: a CSPRNG
    ///
    pub fn encrypt<R: Rng + CryptoRng + Sized>(
        &self,
        // p_pub: E::PublicKeyGroup,
        message: &[u8],
        id: Identity,
        mut rng: R,
    ) -> Result<TLECiphertext<E>, ClientError> {
        // let msk = E::Scalar::rand(&mut rng);
        let msk = self.0;

        let msk_bytes = convert_to_bytes::<E::Scalar, 32>(msk);
        let ct_aes = aes::encrypt(message, msk_bytes, &mut rng)
            .map_err(|_| ClientError::AesEncryptError)?; // not sure how to test this line...

        let p_pub = <<E as EngineBLS>::PublicKeyGroup as Group>::generator() * msk;
        let b: [u8;32] = convert_to_bytes::<E::Scalar, 32>(msk);
        let ct: IBECiphertext<E> = id.encrypt(&b, p_pub, &mut rng);
        Ok(TLECiphertext { 
            identity: id, 
            aes_ct: ct_aes, 
            etf_ct: ct
        })
    }
}

impl<E: EngineBLS> TLECiphertext<E> {
    /// assumes the order of the ibe_secrets should match the order 
    /// in which the ciphertexts were created
    pub fn decrypt(
        &self,
        ibe_secrets: Vec<IBESecret<E>>,
    ) -> Result<DecryptionResult, ClientError> {
        let shares: Vec<(E::Scalar, E::SignatureGroup)> = 
            ibe_secrets.iter().enumerate().map(|(idx, share)| 
                (E::Scalar::from(idx as u8 + 1), share.0)
            ).collect();
        let sig = interpolate_threshold_bls_sigs::<E>(shares);
        let secret_bytes = IBESecret(sig).decrypt(&self.etf_ct)
            .map_err(|_| ClientError::DecryptionError)?;
        let secret_scalar = E::Scalar::deserialize_compressed(&secret_bytes[..])
                .map_err(|_| ClientError::DeserializationError)?;
        let o = convert_to_bytes::<E::Scalar, 32>(secret_scalar);

        if let Ok(plaintext) = aes::decrypt(AESOutput{
            ciphertext: self.aes_ct.ciphertext.clone(), 
            nonce: self.aes_ct.nonce.clone(), 
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
    if  n == 1 {
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
/// * `points`: a vec of (x, f(x)*Q <- BLS.sign(ID)) pairs
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

#[cfg(test)]
mod test {

    use super::*;
    use rand_chacha::ChaCha20Rng;
    use w3f_bls::TinyBLS377;
    use ark_std::rand::SeedableRng;
    use rand_core::OsRng;

    // specific conditions that we want to test/verify
    enum TestStatusReport {
        InterpolationComplete { msk: Vec<u8>, recovered_msk: Vec<u8> },
        DecryptSuccess { actual: Vec<u8>, expected: Vec<u8> },
        DecryptionFailed { error: ClientError }
    }

    fn tlock_test<E: EngineBLS, R: Rng + Sized + CryptoRng>(
        n: u8,
        t: u8,
        m: u8,
        inject_bad_ct: bool,
        inject_bad_nonce: bool,
        handler: &dyn Fn(TestStatusReport) -> (),
    ) {
        // let mut rng = ChaCha20Rng::from_seed([4;32]);
        let message = b"this is a test message".to_vec();
        let id = Identity::new(b"id");
        let (sk, shares) = generate_secrets::<E, OsRng>(n, t, &mut OsRng);
        let msk = SecretKey::<E>(sk);
        // then we need out p_pub = msk * P \in G_1
        // let p_pub = <<E as EngineBLS>::PublicKeyGroup as Group>::generator() * msk;
        // e.g. s_1 * Q, s_2 * Q, ..., s_n * Q where Q = H_1(identity string)
        let threshold_signatures = (0..m).map(|i| id.extract::<E>(shares[i as usize].1))
            .collect();
        match msk.encrypt(&message, id, &mut OsRng) {
            Ok(mut ct) => {

                // create error scenarios here
                if inject_bad_ct {
                    ct.aes_ct.ciphertext = vec![];
                }

                if inject_bad_nonce {
                    ct.aes_ct.nonce = vec![];
                }
            
                match ct.decrypt(threshold_signatures) {
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
    pub fn tlock_can_encrypt_decrypt_with_full_sigs_present() {
        tlock_test::<TinyBLS377, OsRng>(5, 5, 5, false, false,
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
        tlock_test::<TinyBLS377, OsRng>(5, 3, 3, false, false,
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

    // this is equivalent to testing something like `tlock_decryption_fails_with_bad_sig`
    #[test]
    pub fn tlock_decryption_fails_with_less_than_threshold_sigs() {
        tlock_test::<TinyBLS377, OsRng>(5, 3, 1, false, false,
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
    pub fn tlock_decryption_fails_with_bad_ciphertext() {
        tlock_test::<TinyBLS377, OsRng>(5, 5, 5, true, false,
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
        tlock_test::<TinyBLS377, OsRng>(5, 5, 5, false, true,
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

    /// n: full committee size
    /// t: the threshold value
    /// m: the actual number of participants (who will submit signatures)
    fn threshold_bls_interpolation_test<E: EngineBLS>(
        n: u8,
        t: u8,
        m: u8,
        handler: &dyn Fn(TestStatusReport) -> (),
    ) {
        let mut rng = ChaCha20Rng::from_seed([0;32]);
        // essentially the message being signed
        let id = Identity::new(b"id");
        let (msk, shares) = generate_secrets::<E, ChaCha20Rng>(n, t, &mut rng);
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
            recovered_msk: crate::utils::convert_to_bytes::<E::SignatureGroup, 48>(
                interpolated_sig
            ).to_vec(),
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
}
