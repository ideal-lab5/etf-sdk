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

use ark_serialize::CanonicalSerialize;
use serde::Deserialize;
use codec::Encode;
use wasm_bindgen::prelude::*;
use etf_crypto_primitives::{self, encryption::tlock::{DecryptionResult, TLECiphertext, tle}, ibe::fullident::{IBESecret, Identity}, utils::{self, *}};
use w3f_bls::{EngineBLS, TinyBLS377};
use rand_chacha::ChaCha20Rng;
use ark_std::rand::SeedableRng;
use w3f_bls::{DoublePublicKey, DoublePublicKeyScheme};
use serde::Serialize;
use serde_big_array::BigArray;
use ark_serialize::CanonicalDeserialize;
// use sp_consensus_beefy_etf::{Commitment, Payload, known_payloads};

/// The encrypt wrapper used by the WASM blob to call tlock.rs encrypt function in etf-crypto-primitives
/// * 'id_js': ID string for which the message will be encrypted
/// * 'message_js': Message which will be encrypted
/// * 'sk_js': secret key passed in from UI. This should be obtained elsewhere later on.
/// * 'p_pub_js': the public key commitment for the IBE system
#[wasm_bindgen]
pub fn encrypt( 
    id_js: JsValue,
    message_js: JsValue, // &[u8]
    sk_js: JsValue,
    p_pub_js: JsValue
) -> Result<JsValue, JsError> {
    // msk => master secret key
    let msk_bytes: [u8;32] = serde_wasm_bindgen::from_value(sk_js.clone())
        .map_err(|_| JsError::new("could not decode secret key"))?;
    let rng: ChaCha20Rng = ChaCha20Rng::from_seed(msk_bytes);
    // let msk = convert_from_bytes::<<TinyBLS377 as EngineBLS>::Scalar,32>(&msk_bytes.clone()).ok_or(JsError::new("Could not convert secret key"))?;
    // let secret_key = SecretKey::<TinyBLS377>(msk);
    let pp_conversion: Vec<u8> = serde_wasm_bindgen::from_value(p_pub_js.clone())
        .map_err(|_| JsError::new("could not decode p_pub"))?;
    let pp_bytes: [u8;144] = pp_conversion.try_into().map_err(|_| JsError::new("could not convert public params"))?;
    let double_pub_key = convert_from_bytes::<DoublePublicKey<TinyBLS377>, 144>(&pp_bytes.clone()).ok_or(JsError::new("Could not convert secret key"))?;
    let pp = double_pub_key.1;
    let id_bytes: Vec<u8> = serde_wasm_bindgen::from_value(id_js.clone())
        .map_err(|_| JsError::new("could not decode id"))?;
    let identity = Identity::new(&id_bytes);
    let message_bytes: Vec<u8> = serde_wasm_bindgen::from_value(message_js.clone())
        .map_err(|_| JsError::new("could not decode message"))?;
    let mut ciphertext_bytes: Vec<_> = Vec::new();
    // let ciphertext = secret_key.encrypt(pp, &message_bytes, identity, rng).map_err(|_| JsError::new("encryption has failed"))?;
    let ciphertext: TLECiphertext<TinyBLS377> = tle(pp, msk_bytes, &message_bytes, identity, rng)
        .map_err(|_| JsError::new("encryption failed"))?;
    
    ciphertext.serialize_compressed(&mut ciphertext_bytes).map_err(|_| JsError::new("ciphertext serialization has failed"))?;
    
    serde_wasm_bindgen::to_value(&ciphertext_bytes).map_err(|_| JsError::new("could not convert ciphertext to JsValue"))
}

/// The decrypt wrapper used by the WASM blob to call tlock.rs encrypt function in etf-crypto-primitives
/// * 'ciphertext_js': The string to be decrypted
/// * 'sig_vec_js': The array of BLS signatures required to rebuild the secret key and decrypt the message
#[wasm_bindgen]
pub fn decrypt(
    ciphertext_js: JsValue,
    sig_vec_js: JsValue
) -> Result<JsValue, JsError>{

    let sig_conversion: Vec<u8> = serde_wasm_bindgen::from_value(sig_vec_js.clone())
         .map_err(|_| JsError::new("could not decode secret key"))?;
    // let sig_value = sig_conversion.get(0).unwrap();

    let sig_bytes = sig_conversion.as_slice();
    let sig_point = <TinyBLS377 as EngineBLS>::SignatureGroup::deserialize_compressed(sig_bytes)
        .map_err(|_| JsError::new("could not deserialize sig_vec"))?;
    
    let ciphertext_vec: Vec<u8> = serde_wasm_bindgen::from_value(ciphertext_js.clone())
        .map_err(|_| JsError::new("could not decode ciphertext"))?;
    let ciphertext_bytes: &[u8] = ciphertext_vec.as_slice();

    let ciphertext:TLECiphertext<TinyBLS377> = TLECiphertext::deserialize_compressed(ciphertext_bytes).map_err(|_| JsError::new("Could not deserialize ciphertext"))?;
    // let decrypt_result: DecryptionResult= ciphertext.decrypt(sig_vec).map_err(|_| JsError::new("decryption has failed"))?;
    let decrypt_result: DecryptionResult= ciphertext.tld(sig_point)
        .map_err(|e| JsError::new(&format!("decryption has failed {:?}", e)))?;
    let message: Vec<u8> = decrypt_result.message;
    let plaintext: String = String::from_utf8(message).map_err(|_| JsError::new("Plaintext could not be converted to a string"))?;

    serde_wasm_bindgen::to_value(&plaintext).map_err(|_| JsError::new("plaintext conversion has failed"))
}

/// Temporary logging struct
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

/// Struct for testing that allows for the serialization of the double public key type
#[derive(Serialize, CanonicalSerialize, CanonicalDeserialize, Deserialize, Debug)]
pub struct KeyChain {
    #[serde(with = "BigArray")]
    pub double_public: [u8;144],

    pub sk: [u8;32]
}

/// build an encoded commitment for use in timelock encryption and sig verification
// #[wasm_bindgen]
// pub fn build_encoded_commitment(
//     block_number_js: JsValue, 
//     validator_set_id_js: JsValue,
// ) -> Result<JsValue, JsError> {
//     let bn: u32 = serde_wasm_bindgen::from_value(block_number_js.clone())
//         .map_err(|_| JsError::new("could not decode a u32 from the input"))?;
//     let validator_set_id: u64 = serde_wasm_bindgen::from_value(validator_set_id_js.clone())
//         .map_err(|_| JsError::new("could not decode a u32 from the input"))?;
//     let payload = Payload::from_single_entry(known_payloads::ETF_SIGNATURE, Vec::new());
//     let commitment = Commitment { payload, block_number: bn, validator_set_id: validator_set_id };
//     let encoded = commitment.encode();
//     serde_wasm_bindgen::to_value(&encoded)
//         .map_err(|_| JsError::new("could not convert the encoded commitment to json"))
// }

/// This function is used purely for testing purposes. 
/// It takes in a seed and generates a secret key and public params.
#[wasm_bindgen]
pub fn generate_keys(seed: JsValue) -> Result<JsValue, JsError> {
    let seed_vec: Vec<u8> = serde_wasm_bindgen::from_value(seed).map_err(|_| JsError::new("Could not convert seed to string"))?;
    let seed_vec = seed_vec.as_slice();
    let seed_hash : [u8;32]= utils::sha256(seed_vec).try_into().unwrap();
    let mut rng: ChaCha20Rng = ChaCha20Rng::from_seed(seed_hash);
    let keypair = w3f_bls::KeypairVT::<TinyBLS377>::generate(&mut rng);
    let sk_gen: <TinyBLS377 as EngineBLS>::Scalar = keypair.secret.0;
    let double_public: DoublePublicKey<TinyBLS377> =  DoublePublicKey(
        keypair.into_public_key_in_signature_group().0,
        keypair.public.0,
    );
    let mut sk_bytes = Vec::new();
    sk_gen.serialize_compressed(&mut sk_bytes).unwrap();
    let mut double_public_bytes = Vec::new();
    double_public.serialize_compressed(&mut double_public_bytes).unwrap();
    let kc = KeyChain{double_public: double_public_bytes.try_into().unwrap(), sk: sk_bytes.try_into().unwrap()};
    serde_wasm_bindgen::to_value(&kc).map_err(|_| JsError::new("could not convert secret key to JsValue"))
}

/// This function is for the UI specifically; allowing it to obtain the BLS signature based on the secret key.
/// This should be offloaded to another service.
#[wasm_bindgen]
pub fn extract_signature(id: JsValue, sk_js: JsValue) -> Result<JsValue, JsError> {
    let sk: [u8;32] = serde_wasm_bindgen::from_value(sk_js).map_err(|_| JsError::new("Could not sk to array"))?;
    let msk = convert_from_bytes::<<TinyBLS377 as EngineBLS>::Scalar,32>(&sk.clone()).unwrap();
    let identity_vec: Vec<u8> = serde_wasm_bindgen::from_value(id).map_err(|_| JsError::new("Could not convert id to vec"))?;
    let identity = Identity::new(&identity_vec);


    let sig: IBESecret<TinyBLS377> = identity.extract(msk);
    let sig_vec = vec![sig];
    let mut sig_bytes: Vec<_> = Vec::new();
    sig_vec.serialize_compressed(&mut sig_bytes).unwrap();

    serde_wasm_bindgen::to_value(&sig_bytes).map_err(|_| JsError::new("extraction failed"))

}

#[cfg(test)]
mod test {
    use std::any::Any;
    use super::*;
    use wasm_bindgen_test::*;
    use w3f_bls::{
        EngineBLS,
        TinyBLS377, BLS377,
    };

    enum TestStatusReport {
        EncryptSuccess { ciphertext: JsValue },
        DecryptSuccess { plaintext: JsValue},
        EncryptFailure {error: JsError},
        DecryptFailure {error: JsError}
    }

    fn setup_test<E: EngineBLS>(
        identity_vec: Vec<u8>,
        message: Vec<u8>,
        succesful_decrypt: bool,
        handler: &dyn Fn(TestStatusReport) -> ()
    ){

        let seed_bytes = "seeeeeeed".as_bytes();
        let seed = serde_wasm_bindgen::to_value(seed_bytes).unwrap();

        let keys_js = generate_keys(seed).ok().unwrap();
        let key_chain: KeyChain = serde_wasm_bindgen::from_value(keys_js).unwrap();
        let sk: [u8; 32] = key_chain.sk;
        let mut sk_bytes: Vec<u8> = Vec::new();
        sk.serialize_compressed(&mut sk_bytes).unwrap();
        let sk_js: JsValue = serde_wasm_bindgen::to_value(&sk_bytes).unwrap();

        let p_pub: [u8; 144] = key_chain.double_public;
        let mut p_pub_bytes: Vec<u8> = Vec::new(); 
        p_pub.serialize_compressed(&mut p_pub_bytes).unwrap();
        let p_pub_js: JsValue = serde_wasm_bindgen::to_value(&p_pub_bytes).unwrap();
        

        let identity_js: JsValue = serde_wasm_bindgen::to_value(&identity_vec).unwrap();
        let message_js: JsValue = serde_wasm_bindgen::to_value(&message).unwrap();

        let msk:<E as EngineBLS>::Scalar = convert_from_bytes::<<E as EngineBLS>::Scalar,32>(&sk.clone()).unwrap();
        let identity = Identity::new(&identity_vec);

        let sig: E::SignatureGroup = identity.extract::<E>(msk).0;
        let mut sig_bytes: Vec<_> = Vec::new();

        if succesful_decrypt {
            // sig_vec.serialize_compressed(&mut sig_bytes).unwrap();
            sig.serialize_compressed(&mut sig_bytes).unwrap();

        } else {
            let bad_ident_vec = b"bad_ident".to_vec();
            let bad_ident = Identity::new(&bad_ident_vec);
            let bad_sig: E::SignatureGroup = bad_ident.extract::<E>(msk).0;
            let bad_sig_vec = vec![bad_sig];
            bad_sig_vec.serialize_compressed(&mut sig_bytes).unwrap();
        }
        
        let sig_vec_js:JsValue = serde_wasm_bindgen::to_value(&sig_bytes).unwrap();

        

        match encrypt(identity_js, message_js, sk_js, p_pub_js){
            Ok(ciphertext) => {
                let ciphertext_clone = ciphertext.clone();
                handler(TestStatusReport::EncryptSuccess{
                    ciphertext
                });
                match decrypt(ciphertext_clone, sig_vec_js){
                    Ok(plaintext) => {
                        handler(TestStatusReport::DecryptSuccess { 
                            plaintext 
                        })
                    },
                    Err(error) => {
                        handler(TestStatusReport::DecryptFailure { 
                            error
                        })
                    }
                }
            },
            Err(error) => {
                handler(TestStatusReport::EncryptFailure { 
                    error
                })
            }
        }
    }

    #[wasm_bindgen_test]
    pub fn can_encrypt_decrypt() {
        let message: Vec<u8> = b"this is a test message".to_vec();
        let id: Vec<u8> = b"testing purposes".to_vec();
        setup_test::<TinyBLS377>(id, message.clone(), true, &|status: TestStatusReport| {
            match status {
                TestStatusReport::EncryptSuccess { ciphertext } => {
                    let ciphertext_convert: Vec<u8> = serde_wasm_bindgen::from_value(ciphertext.clone()).unwrap();
                    assert!(ciphertext.is_truthy());
                    assert_ne!(ciphertext_convert, message);
                },
                TestStatusReport::DecryptSuccess {plaintext} => {
                    let plaintext_convert: String = serde_wasm_bindgen::from_value(plaintext.clone()).unwrap();
                    let plaintext_compare = plaintext_convert.as_bytes().to_vec();
                    assert_eq!(plaintext_compare, message);
                },
                _=> panic!("The ciphertext is falsy")
            }
        })
    }

    #[wasm_bindgen_test]
    pub fn decrypt_failure() {
        let message: Vec<u8> = b"this is a test message".to_vec();
        let id: Vec<u8> = b"testing purposes".to_vec();
        setup_test::<TinyBLS377>(id, message.clone(), false, &|status: TestStatusReport| {
            match status{
                TestStatusReport::EncryptSuccess { ciphertext } => {
                    let ciphertext_convert: Vec<u8> = serde_wasm_bindgen::from_value(ciphertext.clone()).unwrap();
                    assert!(ciphertext.is_truthy());
                    assert_ne!(ciphertext_convert, message);
                },
                TestStatusReport::DecryptFailure { error } => {
                    // This test needs to be updated. As of right now, there doesn't seem to be a way to reliably compare errors
                    // however the test will fail if no error is thrown from decrypt. We just won't know if it was the decrypt function failing.
                    // NOTE: TypeId comes from the std library. 
                    // A `TypeId` represents a globally unique identifier for a type.
                    let error_compare = JsError::new("this is irrelevant. We only check that it's a JsError (which it always is)");
                    let type_id_compare = error_compare.type_id();
                    let type_id = error.type_id();

                    assert_eq!(type_id, type_id_compare);
                },
                _=> panic!("decrypt was successful")
            }
        })
    }

    // #[wasm_bindgen_test]
    // pub fn can_build_encoded_commitment() {
    //     let bn = serde_wasm_bindgen::to_value(1).unwrap();
    //     let vsid = serde_wasm_bindgen::to_value(2).unwrap();

    //     if let Ok(val) = build_encoded_commitment(bn, vsid) {
    //         assert_eq!(vec![0], val);
    //     } else {
    //         panic!("The test should pass");
    //     }
    // }
        
}
