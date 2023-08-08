use wasm_bindgen::prelude::*;
use ark_serialize::CanonicalSerialize;
use crypto::{
    ibe::fullident::{BfIbe, Ibe},
    proofs::verifier::IbeDleqVerifier,
    client::client::{AesIbeCt, DefaultEtfClient},
};
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

    #[wasm_bindgen(constructor)]
    pub fn init(p: JsValue, q: JsValue) -> Self {
        Self { pps: (p, q) }
    }

    #[wasm_bindgen]
    pub fn encrypt(
        &self,
        message_bytes: JsValue, // &[u8], 
        slot_id_bytes: JsValue, // Vec<Vec<u8>>,
        t: u8,
    ) -> Result<JsValue, serde_wasm_bindgen::Error> {
        // convert JsValue to types
        let ibe_pp : Vec<u8> = serde_wasm_bindgen::from_value(self.pps.0.clone())?;
        let p_pub : Vec<u8> = serde_wasm_bindgen::from_value(self.pps.1.clone())?;
        let message : Vec<u8> = serde_wasm_bindgen::from_value(message_bytes)?;
        // this is going to get tricky with the wasm build..
        let slot_ids: Vec<Vec<u8>> = serde_wasm_bindgen::from_value(slot_id_bytes)?;

        let out = 
            DefaultApi::<IbeDleqVerifier, BfIbe, DefaultEtfClient<BfIbe>>::encrypt(
                ibe_pp, p_pub, &message, slot_ids, t).unwrap();
        serde_wasm_bindgen::to_value(&out)
    }

    #[wasm_bindgen]
    pub fn decrypt() -> Result<JsValue, serde_wasm_bindgen::Error> {
        // todo!();
    }

}
