use crypto::dleq::dleq::DLEQProof;

#[derive(Debug)]
pub enum Error {
    EncryptionError,
    DecryptionError,
}

// these are the funcs that I want to compile to wasm
pub trait EtfApi {
    // input = block header > predigest
    fn verify(
        slot_secret: Vec<u8>, 
        dleq_proof: DLEQProof,
    ) -> bool;

    /// aes encrypt, then VSS on ephemeral secret + encrypt for future slots, returns aggregated ciphertext blob
    fn encrypt(message: &[u8], slot_ids: Vec<Vec<u8>>) -> Result<Vec<u8>, Error>;

    /// 
    fn decrypt(ciphertext: &[u8], sk: Vec<u8>) -> Result<Vec<u8>, Error>;
}

pub struct DummyApi;

// impl EtfApi for DummyApi {
//     fn verify(_: Vec<u8>, _: DLEQProof) -> bool {
//         false
//     }
// }

