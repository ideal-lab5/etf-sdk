use crypto::{
    proofs::{dleq::DLEQProof, verifier::DleqVerifier},
    ibe::fullident::{Ibe, BfIbe},
    client::client::{EtfClient, AesIbeCt},
};

#[derive(Debug)]
pub enum Error {
    EncryptionError,
    DecryptionError,
}

// these are the funcs that I want to compile to wasm
pub trait EtfApi<D: DleqVerifier, E: EtfClient> {
    
    fn init(ibe_pp: &[u8], p_pub: &[u8]) -> Self;
    /// verify the DLEQ proof
    fn verify(
        id: Vec<u8>, 
        dleq_proof: DLEQProof,
        extras: Vec<u8>,
    ) -> bool;

    /// encrypt the message for the given slot ids
    fn encrypt(&self, message: &[u8], slot_ids: Vec<Vec<u8>>, t: u8,) 
        -> Result<AesIbeCt, Error>;

    // decrypt the message with the given sk
    fn decrypt(&self, ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        capsule: Vec<Vec<u8>>, 
        sks: Vec<Vec<u8>>,) 
        -> Result<Vec<u8>, Error>;
}

///  the default implementation of the etf api
pub struct DefaultApi<D: DleqVerifier, E: EtfClient> {
    ibe: BfIbe,
    _d: std::marker::PhantomData<D>,
    _e: std::marker::PhantomData<E>,
}
impl<D: DleqVerifier, E: EtfClient> EtfApi<D, E> for DefaultApi<D, E> {


    fn init(ibe_pp: &[u8], p_pub: &[u8]) -> Self {
        let ibe = BfIbe::new(ibe_pp.to_vec(), p_pub.to_vec());
        Self {
            ibe,
            _d: std::marker::PhantomData,
            _e: std::marker::PhantomData,
        }
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
    ) -> Result<AesIbeCt, Error> {
        // verification? t > 0
        let res = E::encrypt(self.ibe.clone(), message, slot_ids, t)
            .map_err(|_| Error::EncryptionError)?;
        Ok(res)
    }

    fn decrypt(
        &self,
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        capsule: Vec<Vec<u8>>, 
        sks: Vec<Vec<u8>>,
    ) -> Result<Vec<u8>, Error> {
        let res = E::decrypt(self.ibe.clone(), ciphertext, nonce, capsule, sks)
            .map_err(|_| Error::DecryptionError)?;
        Ok(res)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_std::{test_rng, UniformRand, ops::Mul};
    use ark_bls12_381::{G1Affine as G1, G2Affine as G2, Fr};
    use ark_ec::AffineRepr;
    use ark_serialize::CanonicalSerialize;
    use crypto::{
        utils::hash_to_g1,
        client::client::AesIbeCt,
        encryption::encryption::AESOutput,
    };


    // A mock implementation of DleqVerifier trait for testing
    struct MockDleqVerifier;

    impl DleqVerifier for MockDleqVerifier {
        // Implement the required methods for the trait
        fn verify(_id: Vec<u8>, _proof: DLEQProof, _extras: Vec<u8>) -> bool {
            true
        }
    }
 
    // A mock implementation of EtfClient trait for testing
    struct MockEtfClient;

    impl EtfClient for MockEtfClient {
        // Implement the required methods for the trait
 
        fn encrypt(
            _ibe: BfIbe, _m: &[u8], _ids: Vec<Vec<u8>>, _t: u8,
        ) -> Result<AesIbeCt, crypto::client::client::ClientError> {
            Ok(AesIbeCt {
                aes_ct: AESOutput {
                    ciphertext: vec![1, 2, 3],
                    nonce: vec![2, 3, 4],
                    key: vec![3, 4, 5],
                },
                etf_ct:  vec![vec![4], vec![5], vec![6]].into(),
            })
        }
        fn decrypt(
            _ibe: BfIbe, 
            _ct: Vec<u8>, 
            _nonce: Vec<u8>, 
            _capsule: Vec<Vec<u8>>, 
            _secrets: Vec<Vec<u8>>
        ) -> Result<Vec<u8>, crypto::client::client::ClientError> {
            Ok(vec![5, 6, 7])
        }
    }
 
    fn ibe_setup() -> DefaultApi<MockDleqVerifier, MockEtfClient> {
        // create IBE public parameters
        let ibe_pp: G2 = G2::generator().into();
        let s = Fr::rand(&mut test_rng());
        let p_pub: G2 = ibe_pp.mul(s).into();

        let mut ibe_pp_bytes = Vec::new();
        ibe_pp.serialize_compressed(&mut ibe_pp_bytes).unwrap();

        let mut p_pub_bytes = Vec::new();
        p_pub.serialize_compressed(&mut p_pub_bytes).unwrap();

        // Create an instance of DefaultApi
        let api: DefaultApi<MockDleqVerifier, MockEtfClient> = DefaultApi::init(&ibe_pp_bytes, &p_pub_bytes);
        api
    }

    #[test]
    fn default_api_can_verify() {
        let x = Fr::rand(&mut test_rng());
        let id = b"test";
        let g = G1::generator();
        let h = hash_to_g1(id);


        // create IBE public parameters
        let ibe_pp: G2 = G2::generator().into();
        let s = Fr::rand(&mut test_rng());
        let p_pub: G2 = ibe_pp.mul(s).into();

        let mut ibe_pp_bytes = Vec::new();
        ibe_pp.serialize_compressed(&mut ibe_pp_bytes).unwrap();

        let mut p_pub_bytes = Vec::new();
        p_pub.serialize_compressed(&mut p_pub_bytes).unwrap();

         // Create an instance of DefaultApi
        //  let api: DefaultApi<MockDleqVerifier, MockEtfClient> = DefaultApi::init(&ibe_pp_bytes, &p_pub_bytes);

        let proof = DLEQProof::new(x, g, h, vec![], test_rng());
        assert!(DefaultApi::<MockDleqVerifier, MockEtfClient>::verify(id.to_vec(), proof, vec![]) == true);
    }

    #[test]
    fn api_encryption_works() {
        let api: DefaultApi<MockDleqVerifier, MockEtfClient> = ibe_setup();
        let message = b"this is a test";
        let slot_ids = vec![b"sl1".to_vec(), b"sl2".to_vec(), b"sl3".to_vec()];
        let t = 2;
        match api.encrypt(message, slot_ids, t) {
            Ok(_) => { },
            Err(_) => { panic!("the encrypt call should work") },
        }
    }

    #[test]
    fn api_decryption_works() {
        let api: DefaultApi<MockDleqVerifier, MockEtfClient> = ibe_setup();
        match api.decrypt(vec![], vec![], vec![vec![1]], vec![]) {
            Ok(_) => { },
            Err(_) => { panic!("the decrypt call should work") },
        }
    }
}