use wasm_bindgen::prelude::*;
use ark_serialize::CanonicalDeserialize;
use ark_std::{test_rng, UniformRand, ops::Mul};
use ark_bls12_381::{Fr, G1Affine as G1, G2Affine as G2};
use ark_ec::AffineRepr;
use crypto::{
    ibe::fullident::BfIbe,
    proofs::verifier::IbeDleqVerifier,
    client::client::DefaultEtfClient,
    utils::{convert_to_bytes, hash_to_g1},
};
use serde::{Deserialize, Serialize};

use crate::api::{
    EtfApi, DefaultApi,
};

pub mod api;

pub enum ApiError {
    EncryptionError,
    WasmBindError,
}

// TODO: enhance error types (using thiserror)

/// a wrapper around the DefaultEtfClient so that it can be compiled to wasm
#[wasm_bindgen]
pub struct EtfApiWrapper {    
    pps: (JsValue, JsValue),
}

#[wasm_bindgen]
impl EtfApiWrapper {

    /// p and q are the IBE parameters, both elements of G2
    #[wasm_bindgen(constructor)]
    pub fn create(p: JsValue, q: JsValue) -> Self {
        // TODO: verification
        Self { pps: (p, q) }
    }

    #[wasm_bindgen]
    pub fn version(&self) -> JsValue {
        serde_wasm_bindgen::to_value(b"v0.0.3-dev").unwrap()
    }

    /// a wrapper function around the DefaultApi 'encrypt' implementation
    /// returns a ciphertext blob containing both aes ct and etf ct
    ///
    ///
    #[wasm_bindgen]
    pub fn encrypt(
        &self,
        message_bytes: JsValue, // &[u8], 
        slot_id_bytes: JsValue, // Vec<Vec<u8>>,
        t: u8,
    ) -> Result<JsValue, JsError> {
        // convert JsValue to types
        let ibe_pp : Vec<u8> = serde_wasm_bindgen::from_value(self.pps.0.clone())
            .map_err(|_| JsError::new("could not decode ibe pp"))?;
        let p_pub : Vec<u8> = serde_wasm_bindgen::from_value(self.pps.1.clone())
            .map_err(|_| JsError::new("could not decode p pub"))?;
        let message : Vec<u8> = serde_wasm_bindgen::from_value(message_bytes)
            .map_err(|_| JsError::new("could not decode message"))?;
        let slot_ids: Vec<Vec<u8>> = serde_wasm_bindgen::from_value(slot_id_bytes)
            .map_err(|_| JsError::new("could not decode slot ids"))?;
        // TODO: this should probably be an async future... in the future
        let out = 
            DefaultApi::<IbeDleqVerifier, BfIbe, DefaultEtfClient<BfIbe>>::encrypt(
                ibe_pp, p_pub, &message, slot_ids, t)
                    .map_err(|_| JsError::new("encrypt failed"))?;
        serde_wasm_bindgen::to_value(&out)
            .map_err(|_| JsError::new("could not convert to JsValue"))
    }

    #[wasm_bindgen]
    pub fn decrypt(
        &self,
        ciphertext_bytes: JsValue, // Vec<u8>
        nonce_bytes: JsValue, // Vec<u8>
        capsule_bytes: JsValue, // Vec<Vec<u8>>
        sks_bytes: JsValue, // Vec<Vec<u8>>
    ) -> Result<JsValue, JsError> {
        let ibe_pp : Vec<u8> = serde_wasm_bindgen::from_value(self.pps.0.clone())
            .map_err(|_| JsError::new("could not decode ibe pp"))?;
        let ct: Vec<u8>  = serde_wasm_bindgen::from_value(ciphertext_bytes)
            .map_err(|_| JsError::new("could not decode the ciphertext"))?;
        let nonce: Vec<u8>  = serde_wasm_bindgen::from_value(nonce_bytes)
            .map_err(|_| JsError::new("could not decode the nonce"))?;

        let capsule: Vec<Vec<u8>> = serde_wasm_bindgen::from_value(capsule_bytes)
            .map_err(|_| JsError::new("could not decode the capsule"))?;
        let sks: Vec<Vec<u8>> = serde_wasm_bindgen::from_value(sks_bytes)
            .map_err(|_| JsError::new("could not decode the secret keys"))?;
        let out = 
            DefaultApi::<IbeDleqVerifier, BfIbe, DefaultEtfClient<BfIbe>>::decrypt(
                ibe_pp, ct, nonce, capsule, sks)
                .map_err(|_| JsError::new("decryption failed"))?;
        serde_wasm_bindgen::to_value(&out)
            .map_err(|_| JsError::new("could not convert to JsValue"))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IbeTestParams {
    pub p: Vec<u8>,
    pub q: Vec<u8>,
    pub s: Vec<u8>,
}

// the functions below are for testing purposes only
// TODO: wrap this in a feature? how do features work with wasm?
// #[cfg_attr(tarpaulin, skip)]
#[wasm_bindgen]
pub fn random_ibe_params() -> Result<JsValue, JsError> {
    let ibe_pp: G2 = G2::generator().into();
    let s = Fr::rand(&mut test_rng());
    let p_pub: G2 = ibe_pp.mul(s).into();

    serde_wasm_bindgen::to_value(&IbeTestParams {
        p: convert_to_bytes::<G2, 96>(ibe_pp).to_vec(),
        q: convert_to_bytes::<G2, 96>(p_pub).to_vec(),
        s: convert_to_bytes::<Fr, 32>(s).to_vec(),
    }).map_err(|_| JsError::new("could not convert ibe test params to JsValue"))
}

// #[cfg_attr(tarpaulin, skip)]
#[wasm_bindgen]
pub fn ibe_extract(x: JsValue, ids_bytes: JsValue) -> Result<JsValue, JsError> {
    let ids: Vec<Vec<u8>> = serde_wasm_bindgen::from_value(ids_bytes)
        .map_err(|_| JsError::new("could not decode ids"))?;
    let sk_bytes: Vec<u8> = serde_wasm_bindgen::from_value(x)
        .map_err(|_| JsError::new("could not decode secret x"))?;
    let s = Fr::deserialize_compressed(&sk_bytes[..]).unwrap();
    let mut secrets: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for id in ids {
        let pk = hash_to_g1(&id);
        let sk = pk.mul(s);
        let pk_bytes = convert_to_bytes::<G1, 48>(pk.into());
        let sk_bytes = convert_to_bytes::<G1, 48>(sk.into());
        secrets.push((sk_bytes.to_vec(), pk_bytes.to_vec()));
    }

    serde_wasm_bindgen::to_value(&secrets)
        .map_err(|_| JsError::new("could not convert secrets to JsValue"))
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_std::test_rng;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    pub fn wrapper_setup_works() {
        let x = serde_wasm_bindgen::to_value(&vec![1,2,3,4]).unwrap();
        let etf = EtfApiWrapper::create(x.clone(), x);
        let v = etf.version();
        let version: Vec<u8> = serde_wasm_bindgen::from_value(v).unwrap();
        assert_eq!(version, b"v0.0.3-dev".to_vec());
    }

    #[wasm_bindgen_test]
    pub fn wrapper_can_encrypt() {
        let message_js = serde_wasm_bindgen::to_value(b"test").unwrap();
        let slot_ids = vec![vec![1,2,3], vec![2,3,4]];
        let slot_ids_js = serde_wasm_bindgen::to_value(&slot_ids).unwrap();

        let s = Fr::rand(&mut test_rng());
        let g = G2::rand(&mut test_rng());
        let p: G2 = g.mul(s).into();
        let g_bytes = convert_to_bytes::<G2, 96>(g).to_vec();
        let p_bytes = convert_to_bytes::<G2, 96>(p).to_vec();
        let x1 = serde_wasm_bindgen::to_value(&g_bytes).unwrap();
        let x2 = serde_wasm_bindgen::to_value(&p_bytes).unwrap();
        let etf = EtfApiWrapper::create(x1, x2);
        match etf.encrypt(message_js, slot_ids_js, 3) {
            Ok(ct) => {
                assert!(!ct.is_null());
            },
            Err(_) =>{
                panic!("test should pass");
            }
        }
    }

    // #[wasm_bindgen_test]
    // pub fn wrapper_can_decrypt() {
    //     let message_js = serde_wasm_bindgen::to_value(b"test").unwrap();
    //     let slot_ids = vec![vec![1, 2, 3], vec![2, 3, 4]];
    //     let slot_ids_js = serde_wasm_bindgen::to_value(&slot_ids).unwrap();

    //     let s = Fr::rand(&mut test_rng());
    //     let g = G2::rand(&mut test_rng());
    //     let p: G2 = g.mul(s).into();
    //     let g_bytes = convert_to_bytes::<G2, 96>(g).to_vec();
    //     let p_bytes = convert_to_bytes::<G2, 96>(p).to_vec();
    //     let x1 = serde_wasm_bindgen::to_value(&g_bytes).unwrap();
    //     let x2 = serde_wasm_bindgen::to_value(&p_bytes).unwrap();
    //     let etf = EtfApiWrapper::create(x1, x2);
    //     match etf.encrypt(message_js, slot_ids_js, 3) {
    //         Ok(ct) => {
    //             let t: crypto::client::client::AesIbeCt = serde_wasm_bindgen::from_value(ct).unwrap();
    //             let ct_bytes = serde_wasm_bindgen::to_value(&t.aes_ct.ciphertext).unwrap();
    //             let nonce_bytes = serde_wasm_bindgen::to_value(&t.aes_ct.nonce).unwrap();
    //             let capsule_bytes = serde_wasm_bindgen::to_value(&t.etf_ct).unwrap();
    //             // calc valid secrets d = sQ
    //             let secrets: Vec<Vec<u8>> = slot_ids.iter().map(|id| {
    //                 let q = hash_to_g1(&id);
    //                 let d = q.mul(s);
    //                 convert_to_bytes::<G1, 48>(d.into()).to_vec()
    //             }).collect::<Vec<_>>();

    //             let sks = serde_wasm_bindgen::to_value(&secrets).unwrap();

    //             match etf.decrypt(ct_bytes, nonce_bytes, capsule_bytes, sks) {
    //                 Ok(m_js) => {
    //                     let m: Vec<u8> = serde_wasm_bindgen::from_value(m_js).unwrap();
    //                     assert_eq!(m, b"test".to_vec());
    //                 }, 
    //                 Err(_) => {
    //                     panic!("test should pass, but decryption failed");
    //                 }
    //             }
    //         },
    //         Err(_) => {
    //             panic!("test should pass, but encryption failed");
    //         }
    //     }
    // }
}