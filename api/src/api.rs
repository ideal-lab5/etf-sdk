use crypto::proofs::dleq::DLEQProof;
use crypto::proofs::verifier::IbeDleqVerifier;
// use crypto::utils::hash_to_g1;

#[derive(Debug)]
pub enum Error {
    EncryptionError,
    DecryptionError,
}

// these are the funcs that I want to compile to wasm
pub trait EtfApi {

    /// verify the DLEQ proof
    fn verify(
        id: Vec<u8>, 
        dleq_proof: DLEQProof,
        extras: Vec<u8>,
    ) -> bool;

    /// encrypt the message for the given slot ids
    fn encrypt(message: &[u8], slot_ids: Vec<Vec<u8>>) 
        -> Result<Vec<u8>, Error>;

    // decrypt the message with the given sk
    fn decrypt(ciphertext: &[u8], sk: Vec<u8>) 
        -> Result<Vec<u8>, Error>;
}

pub struct DefaultApi;
impl EtfApi for DefaultApi {

    fn verify(
        id: Vec<u8>,
        proof: DLEQProof,
        extras: Vec<u8>,
    ) -> bool {
        IbeDleqVerifier::verify(id, proof, extras)
    }

    fn encrypt(
        message: &[u8], 
        slot_ids: Vec<Vec<u8>>,
    ) -> Result<Vec<u8>, Error> {
        Ok(Vec::new())
    }

    fn decrypt(
        ciphertext: &[u8], 
        sk: Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
        Ok(Vec::new())
    }

}