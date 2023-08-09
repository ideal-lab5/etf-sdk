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
        serde_wasm_bindgen::to_value(b"v0.0.1").unwrap()
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

// TODO: wrap this in a feature? how do features work with wasm?
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