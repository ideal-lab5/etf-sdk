use crypto::{
    proofs::{
        dleq::DLEQProof, 
        verifier::DleqVerifier,
    },
    encryption::aes_encrypt,
    ibe::{
        fullident::Ibe,
        client::IbeClient,
    },
};

#[derive(Debug)]
pub enum Error {
    EncryptionError,
    DecryptionError,
}

// these are the funcs that I want to compile to wasm
pub trait EtfApi<D: DleqVerifier, B: Ibe, C: IbeClient<B>> {
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
impl<D: DleqVerifier, B: Ibe, C: IbeClient<B>> EtfApi<D, B, C> for DefaultApi {

    /// verify a dleq proof using the IbeDleqVerifier
    /// The verifier expects a specific G1 generator and a specific hash to g1 function
    /// which the dleq proof must have used, otherwise it will fail
    fn verify(
        id: Vec<u8>,
        proof: DLEQProof,
        extras: Vec<u8>,
    ) -> bool {
        D::verify(id, proof, extras)
    }

    /// encrypt a message using AES-GCM
    /// with the ephemeral secret split into shares and encrypted for the future slot ids
    ///
    fn encrypt(
        message: &[u8], 
        slot_ids: Vec<Vec<u8>>,
    ) -> Result<Vec<u8>, Error> {
        // (ct, nonce, key)
        let aes_out = aes_encrypt(message);
        // then do sss on aes_out.key

        // let etf_out = C::encrypt(aes_out.key, slot_ids);
        
        Ok(Vec::new())
    }

    fn decrypt(
        ciphertext: &[u8], 
        sk: Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
        Ok(Vec::new())
    }

}