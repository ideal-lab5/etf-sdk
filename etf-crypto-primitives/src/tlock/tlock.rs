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
    ibe::fullident::{IBECiphertext, IBESecret, Identity},
    tlock::{aes, aes::AESOutput},
};

use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use serde::{Deserialize, Serialize};

use ark_std::{
    rand::{CryptoRng, Rng},
    vec::Vec,
};

use w3f_bls::EngineBLS;

/// a secret key used for encryption/decryption
pub type OpaqueSecretKey = [u8; 32];

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
    pub etf_ct: IBECiphertext<E>,
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

/// encrypt a message for an identity
///
/// * `p_pub`: the public key commitment for the IBE system (i.e. the setup phase)
/// * `message`: The message to encrypt
/// * `id`: the identity to encrypt for
/// * `rng`: a CSPRNG
///
pub fn tle<E, R: Rng + CryptoRng + Sized>(
    p_pub: E::PublicKeyGroup,
    secret_key: OpaqueSecretKey,
    message: &[u8],
    id: Identity,
    mut rng: R,
) -> Result<TLECiphertext<E>, ClientError>
where
    E: EngineBLS,
{
    let ct_aes =
        aes::encrypt(message, secret_key, &mut rng).map_err(|_| ClientError::AesEncryptError)?; // not sure how to test this line...
    let ct: IBECiphertext<E> = id.encrypt(&secret_key, p_pub, &mut rng);
    Ok(TLECiphertext {
        aes_ct: ct_aes,
        etf_ct: ct,
    })
}

impl<E: EngineBLS> TLECiphertext<E> {
    /// decrypt a ciphertext created as a result of timelock encryption
    /// the signature should be equivalent to the output of IBE.Extract(ID)
    /// where ID is the identity for which the message was created
    pub fn tld(&self, sig: E::SignatureGroup) -> Result<DecryptionResult, ClientError> {
        let secret_bytes = IBESecret(sig)
            .decrypt(&self.etf_ct)
            .map_err(|_| ClientError::InvalidSignature)?;

        return Self::aes_decrypt(&self, secret_bytes);
    }

    /// TODO: make t his take secret_bytes: [u8;32] instead
    /// decrypt a ciphertext created as a result of timelock encryption.
    /// requires user to know the secret key beforehand
    pub fn aes_decrypt(&self, secret_bytes: Vec<u8>) -> Result<DecryptionResult, ClientError> {
        let secret_array: [u8; 32] = secret_bytes.clone().try_into().unwrap_or([0u8; 32]);

        if let Ok(plaintext) = aes::decrypt(AESOutput {
            ciphertext: self.aes_ct.ciphertext.clone(),
            nonce: self.aes_ct.nonce.clone(),
            key: secret_bytes,
        }) {
            return Ok(DecryptionResult {
                message: plaintext,
                secret: secret_array,
            });
        }
        Err(ClientError::DecryptionError)
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use ark_ec::Group;
    use ark_ff::UniformRand;
    use rand_core::OsRng;
    use w3f_bls::TinyBLS377;

    // specific conditions that we want to test/verify
    enum TestStatusReport {
        DecryptSuccess { actual: Vec<u8>, expected: Vec<u8> },
        DecryptionFailed { error: ClientError },
    }

    fn tlock_test<E: EngineBLS, R: Rng + Sized + CryptoRng>(
        inject_bad_ct: bool,
        inject_bad_nonce: bool,
        handler: &dyn Fn(TestStatusReport) -> (),
    ) {
        let message = b"this is a test message".to_vec();
        let id = Identity::new(b"", vec![b"id".to_vec()]);
        let sk = E::Scalar::rand(&mut OsRng);
        let p_pub = E::PublicKeyGroup::generator() * sk;

        // key used for aes encryption
        let msk = [1; 32];

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
                        handler(TestStatusReport::DecryptSuccess {
                            actual: output.message,
                            expected: message,
                        });
                    }
                    Err(e) => {
                        handler(TestStatusReport::DecryptionFailed { error: e });
                    }
                }
            }
            Err(_) => {
                panic!("The test should pass but failed to run tlock encrypt");
            }
        }
    }

    #[test]
    pub fn tlock_can_encrypt_decrypt_with_single_sig() {
        tlock_test::<TinyBLS377, OsRng>(false, false, &|status: TestStatusReport| match status {
            TestStatusReport::DecryptSuccess { actual, expected } => {
                assert_eq!(actual, expected);
            }
            _ => panic!("all other conditions invalid"),
        });
    }

    #[test]
    pub fn tlock_can_encrypt_decrypt_with_full_sigs_present() {
        tlock_test::<TinyBLS377, OsRng>(false, false, &|status: TestStatusReport| match status {
            TestStatusReport::DecryptSuccess { actual, expected } => {
                assert_eq!(actual, expected);
            }
            _ => panic!("all other conditions invalid"),
        });
    }

    #[test]
    pub fn tlock_can_encrypt_decrypt_with_many_identities_at_threshold() {
        tlock_test::<TinyBLS377, OsRng>(false, false, &|status: TestStatusReport| match status {
            TestStatusReport::DecryptSuccess { actual, expected } => {
                assert_eq!(actual, expected);
            }
            _ => panic!("all other conditions invalid"),
        });
    }

    #[test]
    pub fn tlock_decryption_fails_with_bad_ciphertext() {
        tlock_test::<TinyBLS377, OsRng>(true, false, &|status: TestStatusReport| match status {
            TestStatusReport::DecryptionFailed { error } => {
                assert_eq!(error, ClientError::DecryptionError);
            }
            _ => panic!("all other conditions invalid"),
        });
    }

    #[test]
    pub fn tlock_decryption_fails_with_bad_nonce() {
        tlock_test::<TinyBLS377, OsRng>(false, true, &|status: TestStatusReport| match status {
            TestStatusReport::DecryptionFailed { error } => {
                assert_eq!(error, ClientError::DecryptionError);
            }
            _ => panic!("all other conditions invalid"),
        });
    }
}
