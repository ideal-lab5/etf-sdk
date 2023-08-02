pub type DLEQProof = ([u8;48], [u8, 48], [u8;32], [u8;48]);

pub enum Error {
    EncryptionError,
    DecryptionError,
}

// these are the funcs that I want to compile to wasm
pub trait EtfApi {
    // input = block header > predigest
    verify(slot_secret: Vec<u8>, dleq_proof: DLEQProof) -> bool;
    /// maybe return an async future instead?
    encrypt(message: &[u8], slot_id: Vec<u8>) 
        -> Result<Vec<u8>, Error::EncryptionError>;
    decrypt(ciphertext: &[u8], sk: Vec<u8>) 
        -> Restult<Vec<u8>, Error::DecryptionError>;
}

// pub struct DummyApi;

// impl EtfApi for DummyApi {
//     fn verify(_: Vec<u8>, _: DLEQProof) -> bool {
//         false
//     }
// }

