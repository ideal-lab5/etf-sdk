// a client for the (FullIdent) IBE
use crate::ibe::fullident::{Ibe, BfIbe, Ciphertext};
use ark_bls12_381::G2Affine as G2;
use ark_std::rand::Rng;
use ark_serialize::CanonicalSerialize;
use aes_gcm::aead::OsRng;
use crate::{
    encryption::*, 
    utils::hash_to_g1,
};

pub struct AesIbeCt {
    pub aes_ct: AESOutput,
    pub etf_ct: Vec<Vec<u8>>,
}

pub enum ClientError {
    AesEncryptError,
}

pub trait EtfClient {
    fn encrypt(
        ibe: BfIbe,
        message: &[u8],
        ids: Vec<Vec<u8>>,
        t: u8,
    ) -> Result<AesIbeCt, ClientError>; 

    fn decrypt() -> Result<Vec<u8>, ClientError>;
}

pub struct DefaultEtfClient;

/// a clent to setup and perform IBE functions
/// uses known generator of G2 and other ranomd generator point
impl EtfClient for DefaultEtfClient {
    // fn setup(&self, p_pub: G2) -> Self {
    //     Self {
    //         Ibe::setup(G2::generator(), p_pub)
    //     }
    // }

    ///
    /// * `ibe`: a BF IBE
    /// * `message`: The message to encrypt
    /// * `ids`: The ids to encrypt the message for
    /// * `t`: The threshold (when splitting the secret)
    ///
    fn encrypt(
        ibe: BfIbe,
        message: &[u8],
        ids: Vec<Vec<u8>>,
        t: u8,
    ) -> Result<AesIbeCt, ClientError> {
        let ct_aes = aes_encrypt(message)
            .map_err(|_| ClientError::AesEncryptError)?;
        let shares = shamir(
            ct_aes.key.clone().try_into().expect("should be 32 bytes;qed"), 
            ids.len() as u8, t, &mut OsRng);

        assert!(shares.len() == ids.len());

        let mut out: Vec<Vec<u8>> = Vec::new(); 
        for (idx, id) in ids.iter().enumerate() {
            // convert the share to bytes
            let s = shares[idx];
            let mut b = Vec::with_capacity(s.compressed_size());
            s.serialize_compressed(&mut b).unwrap();

            let ct = ibe.encrypt(&b.try_into().unwrap(), id, OsRng);
            let mut o = Vec::with_capacity(ct.compressed_size());
            // TODO: handle errors
            ct.serialize_compressed(&mut o).unwrap();
            out.push(o);
        }
        Ok(AesIbeCt{ aes_ct: ct_aes, etf_ct: out })
    }

    /// decrypt a ct blob 
    fn decrypt() -> Result<Vec<u8>, ClientError> {
        // first need to recover the secret using decryption from future (i.e. IBE)
        // then use recovered key to call aes_decrypt(...)
        Ok(Vec::new())
    }

}

#[cfg(test)]
mod test {

    use super::*;
    use ark_bls12_381::{Fr, G2Projective as G2};
    use ark_ff::UniformRand;
    use ark_ec::{AffineRepr, Group};
    use ark_std::{test_rng, ops::Mul};

    #[test]
    pub fn client_can_encrypt() {

        let message = b"this is a test";
        let ids = vec![
            b"id1".to_vec(), 
            b"id2".to_vec(), 
            b"id3".to_vec(),
        ];
        let t = 2;

        let ibe_pp: G2 = G2::generator().into();
        let s = Fr::rand(&mut test_rng());
        let p_pub: G2 = ibe_pp.mul(s).into();
        let ibe = BfIbe::setup(ibe_pp, p_pub);
        match DefaultEtfClient::encrypt(ibe.clone(), message, ids, t) {
            Ok(ct) => {
                // we'll test decryption here
            },
            Err(e) => {
                panic!("the test should pass.");
            }
        }
        
    }
}