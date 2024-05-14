use ark_serialize::CanonicalSerialize;
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

#[derive(Serialize, CanonicalSerialize, CanonicalDeserialize, Deserialize, Debug)]
pub struct KeyChain {
    #[serde(with = "BigArray")]
    pub double_public: [u8;144],

    pub sk: [u8;32]
}

#[wasm_bindgen]
pub fn generate_keys(seed: JsValue) -> Result<JsValue, JsError> {
    log("%%%%%%%%%%%%% generate keys log %%%%%%%%%%%%%");
    let seed_string: String = serde_wasm_bindgen::from_value(seed).unwrap();
    let seed_vec = seed_string.as_bytes();
    log("seed_vec size: ");
    log(&seed_vec.len().to_string());
    let seed_hash : [u8;32]= utils::sha256(seed_vec).try_into().unwrap();
    log("seed_hash size: ");
    log(&seed_hash.len().to_string());
    let mut rng: ChaCha20Rng = ChaCha20Rng::from_seed(seed_hash);
    let keypair = w3f_bls::KeypairVT::<TinyBLS377>::generate(&mut rng);
    let sk_gen: <TinyBLS377 as EngineBLS>::Scalar = keypair.secret.0;
    let double_public: DoublePublicKey<TinyBLS377> =  DoublePublicKey(
        keypair.into_public_key_in_signature_group().0,
        keypair.public.0,
    );
    let mut sk_bytes = Vec::new();
    sk_gen.serialize_compressed(&mut sk_bytes).unwrap();
    log("sk_bytes size: ");
    log(&sk_bytes.len().to_string());
    let mut double_public_bytes = Vec::new();
    double_public.serialize_compressed(&mut double_public_bytes).unwrap();
    let kc = KeyChain{double_public: double_public_bytes.try_into().unwrap(), sk: sk_bytes.try_into().unwrap()};
    serde_wasm_bindgen::to_value(&kc).map_err(|_| JsError::new("could not convert secret key to JsValue"))
}

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
    let msk = convert_from_bytes::<<TinyBLS377 as EngineBLS>::Scalar,32>(&msk_bytes.clone()).unwrap();
    let secret_key = SecretKey::<TinyBLS377>(msk);

    let pp_from_js: Vec<u8> = serde_wasm_bindgen::from_value(p_pub_js.clone())
        .map_err(|_| JsError::new("could not decode p_pub"))?;
    assert!(pp_from_js.len() == 144, "NO");
    // //DONT LET THIS PANIC
    let pp_bytes: [u8;144] = pp_from_js.try_into().map_err(|_| JsError::new("could not convert public params"))?;
    log("pp serialized");
    // //DONT LET THIS PANIC
    //THIS PANICS!!!!!!
    log("pp byte array size");
    log(&pp_bytes.len().to_string());
    let double_pub_key = convert_from_bytes::<DoublePublicKey<TinyBLS377>, 144>(&pp_bytes.clone()).unwrap();
    let pp = double_pub_key.1;

    let id_bytes: Vec<u8> = serde_wasm_bindgen::from_value(id_js.clone())
        .map_err(|_| JsError::new("could not decode id"))?;
    let identity = Identity::new(&id_bytes);

    let message_bytes: Vec<u8> = serde_wasm_bindgen::from_value(message_js.clone())
    .map_err(|_| JsError::new("could not decode message"))?;

    // //DONT LET THIS PANIC
    let ciphertext = secret_key.encrypt(pp, &message_bytes, identity, &mut rng).unwrap();
    let mut ciphertext_bytes: Vec<_> = Vec::new();
    ciphertext.serialize_compressed(&mut ciphertext_bytes).unwrap();

    serde_wasm_bindgen::to_value(&ciphertext_bytes).map_err(|_| JsError::new("could not convert to JsValue"))
   

}

    pub fn print_type_of<T>(_: &T) {
        log("TYPE OF: ");
        log(std::any::type_name::<T>());
    }

    #[wasm_bindgen]
    pub fn decrypt(
        ciphertext_js: JsValue,
        id_js: JsValue,
        sk_js: JsValue
    ) -> Result<JsValue, JsError>{
        log("decrypt");

        let id_bytes: Vec<u8> = serde_wasm_bindgen::from_value(id_js.clone())
        .map_err(|_| JsError::new("could not decode id"))?;
        let identity = Identity::new(&id_bytes);

        let msk_bytes: [u8;32] = serde_wasm_bindgen::from_value(sk_js.clone())
            .map_err(|_| JsError::new("could not decode secret key"))?;
        let msk = convert_from_bytes::<<TinyBLS377 as EngineBLS>::Scalar,32>(&msk_bytes.clone()).unwrap();
        let sig: IBESecret<TinyBLS377> = identity.extract(msk);
        let sig_vec = vec![sig];
        
        let ciphertext_vec: Vec<u8> = serde_wasm_bindgen::from_value(ciphertext_js.clone())
            .map_err(|_| JsError::new("could not decode ciphertext"))?;
        let ciphertext_bytes: &[u8] = ciphertext_vec.as_slice();
        let ciphertext: TLECiphertext<TinyBLS377> = TLECiphertext::deserialize_compressed(ciphertext_bytes).unwrap();

        let decrypt_result = ciphertext.decrypt(sig_vec).unwrap();
        let message = decrypt_result.message;
        let plaintext = String::from_utf8(message).unwrap();
    

        //TODO: Remove this. We shouldn't log plaintext.
        log("*****Decrypted plaintext*****");
        log(&plaintext);
        log("*****************************");

        serde_wasm_bindgen::to_value(&plaintext).map_err(|_| JsError::new("could not do that"))
    }

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
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
        EncryptFailure {error: JsError}
    }

    fn setup_test<E: EngineBLS>(
        identity: Vec<u8>,
        message: Vec<u8>,
        handler: &dyn Fn(TestStatusReport) -> ()
    ){

        let seed_string = "seeeeeeed";
       
        let seed = serde_wasm_bindgen::to_value(seed_string).unwrap();
        let keys_js = generate_keys(seed).ok().unwrap();
        log("key generation complete");
        let identity_js: JsValue = serde_wasm_bindgen::to_value(&identity).unwrap();
        let message_js: JsValue = serde_wasm_bindgen::to_value(&message).unwrap();
        let key_chain: KeyChain = serde_wasm_bindgen::from_value(keys_js).unwrap();
        let sk: [u8; 32] = key_chain.sk;
        let p_pub: [u8; 144] = key_chain.double_public;
        let mut sk_bytes: Vec<u8> = Vec::new();
        sk.serialize_compressed(&mut sk_bytes).unwrap();
        let sk_js: JsValue = serde_wasm_bindgen::to_value(&sk_bytes).unwrap();
        let mut p_pub_bytes: Vec<u8> = Vec::new();
        p_pub.serialize_compressed(&mut p_pub_bytes).unwrap();
        let p_pub_js: JsValue = serde_wasm_bindgen::to_value(&p_pub_bytes).unwrap(); 
        log("calling encrypt");
        match encrypt(identity_js.clone(), message_js, sk_js.clone(), p_pub_js){
            Ok(ciphertext) => {
                decrypt(ciphertext.clone(), identity_js, sk_js);
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
        let id: Vec<u8> = b"testing purposes".to_vec();
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