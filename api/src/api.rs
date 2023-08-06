use crypto::{
    proofs::{dleq::DLEQProof, verifier::DleqVerifier},
    ibe::fullident::BfIbe,
    client::EtfClient,
};

#[derive(Debug)]
pub enum Error {
    EncryptionError,
    DecryptionError,
}

// these are the funcs that I want to compile to wasm
pub trait EtfApi<D: DleqVerifier, E: EtfClient> {
    
    fn init(ibe: BfIbe) -> Self;
    /// verify the DLEQ proof
    fn verify(
        id: Vec<u8>, 
        dleq_proof: DLEQProof,
        extras: Vec<u8>,
    ) -> bool;

    /// encrypt the message for the given slot ids
    fn encrypt(&self, message: &[u8], slot_ids: Vec<Vec<u8>>, t: u8,) 
        -> Result<client::AesIbeCt>, Error>;

    // decrypt the message with the given sk
    fn decrypt(ciphertext: &[u8], sk: Vec<u8>) 
        -> Result<Vec<u8>, Error>;
}

///  the default implementation of the etf api
pub struct DefaultApi {
    ibe: BfIbe,
}
impl<D: DleqVerifier, E: EtfClient> EtfApi<D, E> for DefaultApi {


    fn init(ibe: BfIbe) -> Self {
        Self { ibe }
    }

    /// verify a dleq proof using the IbeDleqVerifier
    /// The verifier expects a specific G1 generator and a specific hash to g1 function
    /// which the dleq proof must have used, otherwise it will fail
    ///
    /// * `id`:
    /// * `proof`:
    /// * `extras`: 
    ///
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
        &self,
        message: &[u8], 
        slot_ids: Vec<Vec<u8>>,
        t: u8,
    ) -> Result<client::AesIbeCt, Error> {
        // verification? t > 0
        let res = E::encrypt(self.ibe.clone(), message, slot_ids, t)
            .map_err(|_| Error::EncryptionError)?;
        Ok(res)
    }

    fn decrypt(
        ciphertext: &[u8], 
        sk: Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
        let res = E::decrypt().map_err(|_| Error::DecryptionError)?;
        Ok(res)
    }

}

// #[cfg(test)]
// pub mod tests {
//     #[test]
//     fn default_api_can_verify() {

//         let proof = DLEQProof::new();
//         assert_ok!(DefaultApi::verify(vec![], ));
//     }
// }