/// ETF CLIENT

use crate::ibe::fullident::{Ibe, BfIbe, IbeCiphertext};
use ark_bls12_381::{G1Affine as G1, Fr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use aes_gcm::aead::OsRng;
use crate::{
    encryption::encryption::*, 
    utils::convert_to_bytes,
};

pub struct AesIbeCt {
    pub aes_ct: AESOutput,
    pub etf_ct: Vec<Vec<u8>>,
}

#[derive(Debug)]
pub enum ClientError {
    AesEncryptError,
    DeserializationError,
    DecryptionError,
}

pub trait EtfClient {
    fn encrypt(
        ibe: BfIbe,
        message: &[u8],
        ids: Vec<Vec<u8>>,
        t: u8,
    ) -> Result<AesIbeCt, ClientError>; 

    fn decrypt(
        ibe: BfIbe,
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        capsule: Vec<Vec<u8>>,
        secrets: Vec<Vec<u8>>,
    ) -> Result<Vec<u8>, ClientError>;
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
        // todo: verify: t < |ids|
        let (msk, shares) = generate_secrets(ids.len() as u8, t, &mut OsRng);
        let copy = interpolate(shares.clone());
        // assert!(shares.len() == ids.len());
        println!("shares {:?}", shares);
        println!("{:?}", msk);
        println!("{:?}", copy);
        let msk_bytes = convert_to_bytes::<Fr, 32>(msk);
        let ct_aes = aes_encrypt(message, msk_bytes.try_into().expect("should be 32 bytes;qed"))
            .map_err(|_| ClientError::AesEncryptError)?;
        

        let mut out: Vec<Vec<u8>> = Vec::new(); 
        for (idx, id) in ids.iter().enumerate() {
            // convert the share to bytes, but loses the index
            // TODO: consider adding the index here too
            let s = shares[idx].1;
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
    /// * `secrets`: an ordered list of secrets, the order should match the order
    /// used when generating the ciphertext
    fn decrypt(
        ibe: BfIbe,
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        capsule: Vec<Vec<u8>>,
        secrets: Vec<Vec<u8>>,
    ) -> Result<Vec<u8>, ClientError> {
        // first need to recover the secret using decryption from future (i.e. IBE)
        // let mut secret_scalar = Fr::zero();
        let mut dec_secrets: Vec<(Fr, Fr)> = Vec::new();
        for (idx, e) in capsule.iter().enumerate() {
            // convert bytes to Fr
            let ct = IbeCiphertext::deserialize_compressed(&e[..])
                .map_err(|_| ClientError::DeserializationError)?;
            let sk = G1::deserialize_compressed(&secrets[idx][..])
                .map_err(|_| ClientError::DeserializationError)?;
            let share_bytes = ibe.decrypt(ct, sk.into());
            let share = Fr::deserialize_compressed(&share_bytes[..]).unwrap();
            dec_secrets.push((Fr::from((idx + 1) as u8), share));
        }
        let secret_scalar = interpolate(dec_secrets);
        let mut o = Vec::new();
        secret_scalar.serialize_compressed(&mut o).map_err(|_| ClientError::DeserializationError)?;
        let plaintext = aes_decrypt(ciphertext, &nonce, &o)
            .map_err(|_| ClientError::DecryptionError)?;

        Ok(plaintext)
    }

}

#[cfg(test)]
mod test {

    use super::*;
    use ark_bls12_381::{Fr, G2Projective as G2};
    use ark_ff::UniformRand;
    use ark_ec::Group;
    use ark_std::{test_rng, ops::Mul};
    use crate::utils::hash_to_g1;

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

        match DefaultEtfClient::encrypt(ibe.clone(), message, ids.clone(), t) {
            Ok(ct) => {
                // calculate secret keys: Q = H1(id), d = sQ
                let secrets: Vec<Vec<u8>> = ids.iter().map(|id| {
                    let q = hash_to_g1(&id);
                    let d = q.mul(s);
                    let mut o = Vec::with_capacity(d.compressed_size());
                    d.serialize_compressed(&mut o).unwrap();
                    o                    
                }).collect::<Vec<_>>();
                match DefaultEtfClient::decrypt(
                    ibe.clone(), ct.aes_ct.ciphertext,
                    ct.aes_ct.nonce, ct.etf_ct, secrets,
                ) {
                    Ok(m) => {
                        assert_eq!(message.to_vec(), m);
                    }, 
                    Err(e) => {
                        panic!("Decryption should work but was: {:?}", e);
                    }
                }
            },
            Err(e) => {
                panic!("Encryption should work but was {:?}", e);
            }
        }
        
    }
}