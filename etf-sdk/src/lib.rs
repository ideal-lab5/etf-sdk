use ark_serialize::{CanonicalSerialize, Read};
use serde::Deserialize;
#[cfg_attr(tarpaulin, skip)]
use wasm_bindgen::prelude::*;
use etf_crypto_primitives::{self, encryption::tlock::{SecretKey, TLECiphertext}, ibe::fullident::{IBESecret, Identity}, utils::{self, *}};
use w3f_bls::{EngineBLS, TinyBLS377};
use rand_chacha::ChaCha20Rng;
use ark_std::rand::SeedableRng;
use w3f_bls::{
    DoublePublicKey,
    DoublePublicKeyScheme,
};
use serde::Serialize;
use serde_big_array::BigArray;
use ark_serialize::CanonicalDeserialize;
use core::fmt;

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
    let mut rng: ChaCha20Rng = ChaCha20Rng::from_seed(msk_bytes);
    // // Look into Options and determine how to handle error
    let msk = convert_from_bytes::<<TinyBLS377 as EngineBLS>::Scalar,32>(&msk_bytes.clone()).ok_or(JsError::new("Could not convert secret key"))?;
    let secret_key = SecretKey::<TinyBLS377>(msk);
    // Look into String Formatting
    let pp_conversion: Vec<u8> = serde_wasm_bindgen::from_value(p_pub_js.clone())
        .map_err(|_| JsError::new("could not decode p_pub"))?;
    // //DONT LET THIS PANIC
    let pp_bytes: [u8;144] = pp_conversion.try_into().map_err(|_| JsError::new("could not convert public params"))?;
    let double_pub_key = convert_from_bytes::<DoublePublicKey<TinyBLS377>, 144>(&pp_bytes.clone()).ok_or(JsError::new("Could not convert secret key"))?;
    let pp = double_pub_key.1;
    let id_bytes: Vec<u8> = serde_wasm_bindgen::from_value(id_js.clone())
        .map_err(|_| JsError::new("could not decode id"))?;
    let identity = Identity::new(&id_bytes);
    let message_bytes: Vec<u8> = serde_wasm_bindgen::from_value(message_js.clone())
        .map_err(|_| JsError::new("could not decode message"))?;
    let mut ciphertext_bytes: Vec<_> = Vec::new();
    if let Ok(ciphertext) = secret_key.encrypt(pp, &message_bytes, identity, &mut rng) {
        ciphertext.serialize_compressed(&mut ciphertext_bytes).unwrap();
    }
    return serde_wasm_bindgen::to_value(&ciphertext_bytes).map_err(|_| JsError::new("could not convert ciphertext to JsValue"));
}

#[wasm_bindgen]
pub fn decrypt(
    ciphertext_js: JsValue,
    sig_vec_js: JsValue
) -> Result<JsValue, JsError>{

    let sig_conversion: Vec<u8> = serde_wasm_bindgen::from_value(sig_vec_js.clone())
         .map_err(|_| JsError::new("could not decode secret key"))?;
    // let sig_bytes = sig_conversion.bytes();
    // sig_conversion.
    // let sig_vec: Vec<IBESecret<TinyBLS377>> = sig_conversion.try_into().map_err(|_| JsError::new("sig conversion failed"))?;
    //INTERESTING ----- If you pass in multiple Sigs this will not throw an error so long as the valid signature is the first in the vec
    // let sig_bytes: [u8; 56] = sig_conversion.try_into().map_err(|_| JsError::new("sig conversion failed"))?;
    // let sig_vec = convert_from_bytes::<Vec<IBESecret<TinyBLS377>>, 56>(&sig_bytes).unwrap();

    let sig_bytes = sig_conversion.as_slice();
    let sig_vec: Vec<IBESecret<TinyBLS377>> = Vec::deserialize_compressed(sig_bytes).unwrap();
    
    let ciphertext_vec: Vec<u8> = serde_wasm_bindgen::from_value(ciphertext_js.clone())
        .map_err(|_| JsError::new("could not decode ciphertext"))?;
    let ciphertext_bytes: &[u8] = ciphertext_vec.as_slice();
    let ciphertext: TLECiphertext<TinyBLS377> = TLECiphertext::deserialize_compressed(ciphertext_bytes).unwrap();
    let decrypt_result = ciphertext.decrypt(sig_vec).unwrap();
    let message = decrypt_result.message;
    let plaintext = String::from_utf8(message).unwrap();

    serde_wasm_bindgen::to_value(&plaintext).map_err(|_| JsError::new("could not do that"))
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[derive(Serialize, CanonicalSerialize, CanonicalDeserialize, Deserialize, Debug)]
pub struct KeyChain {
    #[serde(with = "BigArray")]
    pub double_public: [u8;144],

    pub sk: [u8;32]
}


#[wasm_bindgen]
pub fn generate_keys(seed: JsValue) -> Result<JsValue, JsError> {
    let seed_string: String = serde_wasm_bindgen::from_value(seed).unwrap();
    let seed_vec = seed_string.as_bytes();
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



#[cfg(test)]
mod test {
    use super::*;
    use wasm_bindgen_test::*;
    use w3f_bls::{
        EngineBLS,
        TinyBLS377,
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
        handler: &dyn Fn(TestStatusReport) -> ()
    ){

        let seed_string = "seeeeeeed";
        let seed = serde_wasm_bindgen::to_value(seed_string).unwrap();

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

        let msk = convert_from_bytes::<<TinyBLS377 as EngineBLS>::Scalar,32>(&sk.clone()).unwrap();
        let identity = Identity::new(&identity_vec);
        // let ident2 = b"hello".to_vec();
        // let ident3 = b"hello222".to_vec();
        // let identity2 = Identity::new(&ident2);
        // let identity3 = Identity::new(&ident3);
        let sig: IBESecret<TinyBLS377> = identity.extract(msk);
        // let sig2: IBESecret<TinyBLS377> = identity2.extract(msk);
        // let sig3: IBESecret<TinyBLS377> = identity3.extract(msk);
        // let sig_vec = vec![sig, sig2, sig3];
        let sig_vec = vec![sig];
        let mut sig_bytes: Vec<_> = Vec::new();
        sig_vec.serialize_compressed(&mut sig_bytes).unwrap();
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
        setup_test::<TinyBLS377>(id, message.clone(), &|status: TestStatusReport| {
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
        
}

//     // #[wasm_bindgen_test]
//     // pub fn wrapper_can_decrypt() {
//     //     let message_js = serde_wasm_bindgen::to_value(b"test").unwrap();
//     //     let slot_ids = vec![vec![1, 2, 3], vec![2, 3, 4]];
//     //     let slot_ids_js = serde_wasm_bindgen::to_value(&slot_ids).unwrap();

//     //     let s = Fr::rand(&mut test_rng());
//     //     let g = G2::rand(&mut test_rng());
//     //     let p: G2 = g.mul(s).into();
//     //     let g_bytes = convert_to_bytes::<G2, 96>(g).to_vec();
//     //     let p_bytes = convert_to_bytes::<G2, 96>(p).to_vec();
//     //     let x1 = serde_wasm_bindgen::to_value(&g_bytes).unwrap();
//     //     let x2 = serde_wasm_bindgen::to_value(&p_bytes).unwrap();
//     //     let etf = EtfApiWrapper::create(x1, x2);
//     //     match etf.encrypt(message_js, slot_ids_js, 3) {
//     //         Ok(ct) => {
//     //             let t: crypto::client::client::AesIbeCt = serde_wasm_bindgen::from_value(ct).unwrap();
//     //             let ct_bytes = serde_wasm_bindgen::to_value(&t.aes_ct.ciphertext).unwrap();
//     //             let nonce_bytes = serde_wasm_bindgen::to_value(&t.aes_ct.nonce).unwrap();
//     //             let capsule_bytes = serde_wasm_bindgen::to_value(&t.etf_ct).unwrap();
//     //             // calc valid secrets d = sQ
//     //             let secrets: Vec<Vec<u8>> = slot_ids.iter().map(|id| {
//     //                 let q = hash_to_g1(&id);
//     //                 let d = q.mul(s);
//     //                 convert_to_bytes::<G1, 48>(d.into()).to_vec()
//     //             }).collect::<Vec<_>>();

//     //             let sks = serde_wasm_bindgen::to_value(&secrets).unwrap();

//     //             match etf.decrypt(ct_bytes, nonce_bytes, capsule_bytes, sks) {
//     //                 Ok(m_js) => {
//     //                     let m: Vec<u8> = serde_wasm_bindgen::from_value(m_js).unwrap();
//     //                     assert_eq!(m, b"test".to_vec());
//     //                 }, 
//     //                 Err(_) => {
//     //                     panic!("test should pass, but decryption failed");
//     //                 }
//     //             }
//     //         },
//     //         Err(_) => {
//     //             panic!("test should pass, but encryption failed");
//     //         }
//     //     }
//     // }
// }