use ark_serialize::CanonicalSerialize;
use serde::Deserialize;
#[cfg_attr(tarpaulin, skip)]
use wasm_bindgen::prelude::*;
use etf_crypto_primitives::{self, encryption::{aes::AESOutput, tlock::{SecretKey, TLECiphertext, SerdeNArray}}, ibe::fullident::Identity, utils::{self, *}};
use w3f_bls::{EngineBLS, TinyBLS, TinyBLS377};
use rand_chacha::ChaCha20Rng;
use ark_std::rand::SeedableRng;
use ark_ec::Group;
// use ark_serialize::CanonicalDeserialize;
use ark_std::UniformRand;
use w3f_bls::{
    DoublePublicKey,
    DoublePublicKeyScheme,
};
use serde::{Serialize};
use serde_big_array::BigArray;
use ark_serialize::CanonicalDeserialize;

// use ark_bls12_381::{Fr, G1Affine as G1, G2Affine as G2};
// use ark_ec::AffineRepr;
// use etf_crypto_primitives::{
//     ibe::fullident::BfIbe,
//     proofs::verifier::IbeDleqVerifier,
//     encryption::tlock::DefaultTlock,
//     utils::{convert_to_bytes, hash_to_g1},
// };
// use etf_crypto_primitives::{
    
//     utils::{convert_to_bytes, hash_to_g1},
// };
// use serde::{Deserialize, Serialize};

// use crate::api::{
//     EtfApi, DefaultApi,
// };

// pub mod api;

// pub enum ApiError {
//     EncryptionError("you messed up"),
//     WasmBindError,
// }

// // TODO: enhance error types (using thiserror?)

// /// a wrapper around the DefaultTlock so that it can be compiled to wasm
// #[wasm_bindgen]
// pub struct EtfApiWrapper {    
//     pps: (JsValue, JsValue),
// }

// #[wasm_bindgen]
// impl EtfApiWrapper {

//     /// p and q are the IBE parameters, both elements of G2
//     #[wasm_bindgen(constructor)]
//     pub fn create(p: JsValue, q: JsValue) -> Self {
//         // TODO: verification
//         Self { pps: (p, q) }
//     }

//     #[wasm_bindgen]
//     pub fn version(&self) -> JsValue {
//         serde_wasm_bindgen::to_value(b"v0.0.3-dev").unwrap()
//     }

//     /// a wrapper function around the DefaultApi 'encrypt' implementation
//     /// returns a ciphertext blob containing both aes ct and etf ct
//     ///
//     ///  
//     #[wasm_bindgen]
//     pub fn encrypt(
//         &self,
//         message_bytes: JsValue, // &[u8], 
//         slot_id_bytes: JsValue, // Vec<Vec<u8>>,
//         t: u8,
//         seed_bytes: JsValue,
//     ) -> Result<JsValue, JsError> {
//         // // convert JsValue to types
//         // let ibe_pp : Vec<u8> = serde_wasm_bindgen::from_value(self.pps.0.clone())
//         //     .map_err(|_| JsError::new("could not decode ibe pp"))?;
//         // let p_pub : Vec<u8> = serde_wasm_bindgen::from_value(self.pps.1.clone())
//         //     .map_err(|_| JsError::new("could not decode p pub"))?;
//         // let message : Vec<u8> = serde_wasm_bindgen::from_value(message_bytes)
//         //     .map_err(|_| JsError::new("could not decode message"))?;
//         // let slot_ids: Vec<Vec<u8>> = serde_wasm_bindgen::from_value(slot_id_bytes)
//         //     .map_err(|_| JsError::new("could not decode slot ids"))?;
//         // let seed: Vec<u8> = serde_wasm_bindgen::from_value(seed_bytes)
//         //     .map_err(|_| JsError::new("could not decode seed"))?;
//         // // TODO: this should probably be an async future... in the future
//         // let out = 
//         //     DefaultApi::<IbeDleqVerifier, BfIbe, DefaultTlock<BfIbe>>::encrypt(
//         //         ibe_pp, p_pub, &message, slot_ids, t, &seed)
//         //             .map_err(|_| JsError::new("encrypt failed"))?;
//         let out = "out".to_string();
//         println!("{}", out);
//         serde_wasm_bindgen::to_value(&out)
//             .map_err(|_| JsError::new("could not convert to JsValue"))
//     }
//    }

#[derive(Serialize, CanonicalSerialize, CanonicalDeserialize, Deserialize, Debug)]
pub struct KeyChain {
    #[serde(with = "BigArray")]
    pub double_public: [u8;144],

    pub sk: [u8;32]
}

#[wasm_bindgen]
pub fn generate_keys(seed: JsValue) -> Result<JsValue, JsError> {
    println!("GENERATE KEYSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS");
    let seed_vec: Vec<u8> = serde_wasm_bindgen::from_value(seed.clone())
        .map_err(|_| JsError::new("could not convert seed to vec"))?;
    let seed_hash : [u8;32]= utils::sha256(&seed_vec).try_into().unwrap();
    let mut rng: ChaCha20Rng = ChaCha20Rng::from_seed(seed_hash);
    let mut keypair = w3f_bls::KeypairVT::<TinyBLS377>::generate(&mut rng);
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
    // let sk = <TinyBLS377 as EngineBLS>::Scalar::rand(&mut rng);
    // let sk_bytes = convert_to_bytes::<<TinyBLS377 as EngineBLS>::Scalar, 32>(sk);
    serde_wasm_bindgen::to_value(&kc).map_err(|_| JsError::new("could not convert secret key to JsValue"))
}

///take js value, convert into Vec<u8>

 #[wasm_bindgen]
pub fn encrypt( 
    id: JsValue,
    message: JsValue, // &[u8]
    sk: JsValue,
    p_pub: JsValue
) -> Result<JsValue, JsError> {
    // // msk => master secret key
    let msk_bytes: [u8;32] = serde_wasm_bindgen::from_value(sk.clone())
        .map_err(|_| JsError::new("could not decode secret key"))?;
    let message_bytes: Vec<u8> = serde_wasm_bindgen::from_value(message.clone())
        .map_err(|_| JsError::new("could not decode message"))?;
    let mut rng: ChaCha20Rng = ChaCha20Rng::from_seed(msk_bytes);
    // // let msk = SecretKey::<TinyBLS377>;
    // // Look into Options and determine how to handle error
    let msk = convert_from_bytes::<<TinyBLS377 as EngineBLS>::Scalar,32>(&msk_bytes.clone()).unwrap();

    let mut pp_from_js: Vec<u8> = serde_wasm_bindgen::from_value(p_pub.clone())
        .map_err(|_| JsError::new("could not decode p_pub"))?;
    assert!(pp_from_js.len() == 144, "NO");
 
    // //DONT LET THIS PANIC
    // let pp_convert: &[u8;96] = &pp_from_js;
    //.unwrap_or_else(|pp_from_js: Vec<u8>| panic!("Expected a Vec of length {} but it was {}", 96, pp_from_js.len()))
    let mut error_string = String::new();
    error_string =  "Expected a Vec of length 96 ".to_string();
    error_string.push_str("but it was ");
    // error_string.push_str(&pp_from_js.len().to_string());
    error_string.push_str(&pp_from_js.len().to_string());

    let pp_convert: [u8;96] = pp_from_js.try_into().map_err(|_| JsError::new(&error_string))?;

    //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    // const test_array: [u8;96] = [0;96];
    // const test_array_size: usize = test_array.len();
    let temp_holder: SerdeNArray<96> = SerdeNArray{arr: pp_convert};
    //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    // //DONT LET THIS PANIC
    //THIS PANICS!!!!!!
    let pp = convert_from_bytes::<<TinyBLS377 as EngineBLS>::PublicKeyGroup, 96>(&pp_convert.clone()).unwrap();

    let id_convert: Vec<u8> = serde_wasm_bindgen::from_value(id.clone())
        .map_err(|_| JsError::new("could not decode id"))?;
    let identity = Identity::new(&id_convert);
    let secret_key = SecretKey::<TinyBLS377>(msk);
    // //DONT LET THIS PANIC
    let cyphertext = secret_key.encrypt(pp, &message_bytes, identity, &mut rng).unwrap();
    // let mut cyphertext_bytes: Vec<_> = Vec::new();
    // cyphertext.serialize_compressed(&mut cyphertext_bytes).unwrap();
    // cyphertext.serialize_compressed(&mut cyphertext_bytes).unwrap().map_err(|_| JsError::new("failed to compress cyphertext"));
    // let temp_message = "this is a placeholder";
    // serde_wasm_bindgen::to_value(&cyphertext_bytes).map_err(|_| JsError::new("could not convert to JsValue"))
    serde_wasm_bindgen::to_value(&temp_holder).map_err(|_| JsError::new("could not convert to JsValue"))
   

}


//     #[wasm_bindgen]
//     pub fn decrypt(
//         &self,
//         ciphertext_bytes: JsValue, // Vec<u8>
//         nonce_bytes: JsValue, // Vec<u8>
//         capsule_bytes: JsValue, // Vec<Vec<u8>>
//         sks_bytes: JsValue, // Vec<Vec<u8>>
//     ) -> Result<JsValue, JsError> {
//         let ibe_pp : Vec<u8> = serde_wasm_bindgen::from_value(self.pps.0.clone())
//             .map_err(|_| JsError::new("could not decode ibe pp"))?;
//         let ct: Vec<u8>  = serde_wasm_bindgen::from_value(ciphertext_bytes)
//             .map_err(|_| JsError::new("could not decode the ciphertext"))?;
//         let nonce: Vec<u8>  = serde_wasm_bindgen::from_value(nonce_bytes)
//             .map_err(|_| JsError::new("could not decode the nonce"))?;

//         let capsule: Vec<Vec<u8>> = serde_wasm_bindgen::from_value(capsule_bytes)
//             .map_err(|_| JsError::new("could not decode the capsule"))?;
//         let sks: Vec<Vec<u8>> = serde_wasm_bindgen::from_value(sks_bytes)
//             .map_err(|_| JsError::new("could not decode the secret keys"))?;
//         let out = 
//             DefaultApi::<IbeDleqVerifier, BfIbe, DefaultTlock<BfIbe>>::decrypt(
//                 ibe_pp, ct, nonce, capsule, sks)
//                 .map_err(|_| JsError::new("decryption failed"))?;
//         serde_wasm_bindgen::to_value(&out)
//             .map_err(|_| JsError::new("could not convert to JsValue"))
//     }
// }

// #[derive(Debug, Serialize, Deserialize)]
// pub struct IbeTestParams {
//     pub p: Vec<u8>,
//     pub q: Vec<u8>,
//     pub s: Vec<u8>,
// }

// // the functions below are for testing purposes only
// // TODO: wrap this in a feature? how do features work with wasm?
// // #[cfg_attr(tarpaulin, skip)]
// #[wasm_bindgen]
// pub fn random_ibe_params() -> Result<JsValue, JsError> {
//     let ibe_pp: G2 = G2::generator();
//     let s = Fr::rand(&mut test_rng());
//     let p_pub: G2 = ibe_pp.mul(s).into();

//     serde_wasm_bindgen::to_value(&IbeTestParams {
//         p: convert_to_bytes::<G2, 96>(ibe_pp).to_vec(),
//         q: convert_to_bytes::<G2, 96>(p_pub).to_vec(),
//         s: convert_to_bytes::<Fr, 32>(s).to_vec(),
//     }).map_err(|_| JsError::new("could not convert ibe test params to JsValue"))
// }

// // #[cfg_attr(tarpaulin, skip)]
// #[wasm_bindgen]
// pub fn ibe_extract(x: JsValue, ids_bytes: JsValue) -> Result<JsValue, JsError> {
//     let ids: Vec<Vec<u8>> = serde_wasm_bindgen::from_value(ids_bytes)
//         .map_err(|_| JsError::new("could not decode ids"))?;
//     let sk_bytes: Vec<u8> = serde_wasm_bindgen::from_value(x)
//         .map_err(|_| JsError::new("could not decode secret x"))?;
//     let s = Fr::deserialize_compressed(&sk_bytes[..]).unwrap();
//     let mut secrets: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
//     for id in ids {
//         let pk = hash_to_g1(&id);
//         let sk = pk.mul(s);
//         let pk_bytes = convert_to_bytes::<G1, 48>(pk);
//         let sk_bytes = convert_to_bytes::<G1, 48>(sk.into());
//         secrets.push((sk_bytes.to_vec(), pk_bytes.to_vec()));
//     }

//     serde_wasm_bindgen::to_value(&secrets)
//         .map_err(|_| JsError::new("could not convert secrets to JsValue"))
// }

#[cfg(test)]
mod test {
    use super::*;
    use rand_chacha::rand_core::OsRng;
    use wasm_bindgen_test::*;
    use w3f_bls::{
        DoublePublicKey,
        DoublePublicKeyScheme,
        EngineBLS,
        TinyBLS377,
    };

    enum TestStatusReport {
        EncryptSuccess { ciphertext: JsValue },
        EncryptFailure {error: JsError}
    }

    fn setup_test<E: EngineBLS>(
        identity: Vec<u8>,
        message: Vec<u8>,
        // sk: E::Scalar,
        // p_pub: DoublePublicKey<E>,
        handler: &dyn Fn(TestStatusReport) -> ()
    ){
        let seed = serde_wasm_bindgen::to_value("seeeeeeed").unwrap();
        let keys_js = generate_keys(seed).ok().unwrap();
        // let key_chain = serde_wasm_bindgen::from_value(keys_js);
        let identity_js = serde_wasm_bindgen::to_value(&identity).unwrap();
        let message_js = serde_wasm_bindgen::to_value(&message).unwrap();
        let key_chain: KeyChain = serde_wasm_bindgen::from_value(keys_js).unwrap();
        let sk = key_chain.sk;
        let p_pub = key_chain.double_public;
        let mut sk_bytes = Vec::new();
        sk.serialize_compressed(&mut sk_bytes).unwrap();
        let sk_js = serde_wasm_bindgen::to_value(&sk_bytes).unwrap();
        let mut p_pub_bytes = Vec::new();
        p_pub.serialize_compressed(&mut p_pub_bytes).unwrap();
        let p_pub_js = serde_wasm_bindgen::to_value(&p_pub_bytes).unwrap();
        match encrypt(identity_js, message_js, sk_js, p_pub_js){
            Ok(ciphertext) => {
                handler(TestStatusReport::EncryptSuccess{
                    ciphertext
                })
            },
            Err(error) => {
                handler(TestStatusReport::EncryptFailure { 
                    error
                })
            }
        }
    }

    #[wasm_bindgen_test]
    pub fn can_encrypt() {
        let message = b"this is a test message".to_vec();
        let id = b"testing purposes".to_vec();
        // let (sk, shares) = generate_secrets::<TinyBLS377, OsRng>(n, t, &mut OsRng);
        // let mut keypair = w3f_bls::KeypairVT::<TinyBLS377>::generate(&mut OsRng);
        // let sk: <TinyBLS377 as EngineBLS>::Scalar = keypair.secret.0;
        // let double_public: DoublePublicKey<TinyBLS377> =  DoublePublicKey(
	    //     keypair.into_public_key_in_signature_group().0,
	    //     keypair.public.0,
        // );
        // let seed = serde_wasm_bindgen::to_value("seeeeeeed").unwrap();
        // let keys_js = generate_keys(seed).unwrap();

        setup_test::<TinyBLS377>(id, message, &|status: TestStatusReport| {
            match status {
                TestStatusReport::EncryptSuccess { ciphertext } => {
                    assert!(ciphertext.is_truthy())
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