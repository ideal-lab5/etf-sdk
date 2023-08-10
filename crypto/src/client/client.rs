/// ETF CLIENT
use crate::{
    encryption::encryption::*,
    ibe::fullident::{Ibe, IbeCiphertext},
    utils::convert_to_bytes,
};
use ark_bls12_381::{G1Affine as G1, G2Affine as G2, Fr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use aes_gcm::aead::OsRng;
use serde::{Deserialize, Serialize};


#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;
#[cfg(not(feature = "std"))]
use ark_std::marker::PhantomData;

#[cfg(feature = "std")]
use std::vec::Vec;
#[cfg(feature = "std")]
use std::marker::PhantomData;

#[derive(Serialize, Deserialize, Debug)]
// #[derive(Debug)]
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

pub trait EtfClient<I: Ibe> {
    fn encrypt(
        ibe_pp: Vec<u8>,
        p_pub: Vec<u8>,
        message: &[u8],
        ids: Vec<Vec<u8>>,
        t: u8,
    ) -> Result<AesIbeCt, ClientError>; 

    fn decrypt(
        ibe_pp: Vec<u8>,
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        capsule: Vec<Vec<u8>>,
        secrets: Vec<Vec<u8>>,
    ) -> Result<Vec<u8>, ClientError>;
}

pub struct DefaultEtfClient<I> {
    _i: PhantomData<I>,
}

/// a clent to setup and perform IBE functions
/// uses known generator of G2 and other ranomd generator point
impl<I: Ibe> EtfClient<I> for DefaultEtfClient<I> {

    ///
    /// * `ibe`: a BF IBE
    /// * `message`: The message to encrypt
    /// * `ids`: The ids to encrypt the message for
    /// * `t`: The threshold (when splitting the secret)
    ///
    // TODO: should pass IbePublicParams type instead of the two vecs
    fn encrypt(
        ibe_pp: Vec<u8>,
        p_pub: Vec<u8>,
        message: &[u8],
        ids: Vec<Vec<u8>>,
        t: u8,
    ) -> Result<AesIbeCt, ClientError> {
        // todo: verify: t < |ids|
        // todo: verify public params, error handling
        let p = G2::deserialize_compressed(&ibe_pp[..])
            .map_err(|_| ClientError::DeserializationError)?;
        let q = G2::deserialize_compressed(&p_pub[..])
            .map_err(|_| ClientError::DeserializationError)?;

        let l = ids.len();
        // if there is only one id, then shares = [msk]
        // and when we loop over the shares and encrypt w/ IBE
        // then we encrypt the msk directly instead
        let (msk, shares) = generate_secrets(ids.len() as u8, t, &mut OsRng);
        let msk_bytes = convert_to_bytes::<Fr, 32>(msk);
        let ct_aes = aes_encrypt(message, msk_bytes.try_into().expect("should be 32 bytes;qed"))
            .map_err(|_| ClientError::AesEncryptError)?;
        

        let mut out: Vec<Vec<u8>> = Vec::new(); 
        for (idx, id) in ids.iter().enumerate() {
            let b = convert_to_bytes::<Fr, 32>(shares[idx].1).to_vec();
            let ct = I::encrypt(p.into(), q.into(), &b.try_into().unwrap(), id, OsRng);
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
        ibe_pp: Vec<u8>,
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        capsule: Vec<Vec<u8>>,
        secrets: Vec<Vec<u8>>,
    ) -> Result<Vec<u8>, ClientError> {
        let mut dec_secrets: Vec<(Fr, Fr)> = Vec::new();
        let p = G2::deserialize_compressed(&ibe_pp[..])
            .map_err(|_| ClientError::DeserializationError)?;
        for (idx, e) in capsule.iter().enumerate() {
            // convert bytes to Fr
            let ct = IbeCiphertext::deserialize_compressed(&e[..])
                .map_err(|_| ClientError::DeserializationError)?;
            let sk = G1::deserialize_compressed(&secrets[idx][..])
                .map_err(|_| ClientError::DeserializationError)?;
            let share_bytes = I::decrypt(p.into(), ct, sk.into());
            let share = Fr::deserialize_compressed(&share_bytes[..])
                .map_err(|_| ClientError::DeserializationError)?;
            dec_secrets.push((Fr::from((idx + 1) as u8), share));
        }
        let secret_scalar = interpolate(dec_secrets);
        let o = convert_to_bytes::<Fr, 32>(secret_scalar);
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
    use crate::ibe::fullident::BfIbe;
    use crate::utils::hash_to_g1;

    #[test]
    pub fn client_can_encrypt_decrypt_with_single_key() {

        let message = b"this is a test";
        let ids = vec![
            b"id1".to_vec(), 
            // b"id2".to_vec(), 
            // b"id3".to_vec(),
        ];
        let t = 1;

        let ibe_pp: G2 = G2::generator().into();
        let s = Fr::rand(&mut test_rng());
        let p_pub: G2 = ibe_pp.mul(s).into();

        let ibe_pp_bytes = convert_to_bytes::<G2, 96>(ibe_pp);
        let p_pub_bytes = convert_to_bytes::<G2, 96>(p_pub);

        match DefaultEtfClient::<BfIbe>::encrypt(
            ibe_pp_bytes.to_vec(), p_pub_bytes.to_vec(),
            message, ids.clone(), t,
        ) {
            Ok(ct) => {
                // calculate secret keys: Q = H1(id), d = sQ
                let secrets: Vec<Vec<u8>> = ids.iter().map(|id| {
                    let q = hash_to_g1(&id);
                    let d = q.mul(s);
                    convert_to_bytes::<G1, 48>(d.into()).to_vec()
                }).collect::<Vec<_>>();
                match DefaultEtfClient::<BfIbe>::decrypt(
                    ibe_pp_bytes.to_vec(), ct.aes_ct.ciphertext, ct.aes_ct.nonce, ct.etf_ct, secrets, 
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

    #[test]
    pub fn client_can_encrypt_decrypt_with_many_keys() {

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

        let ibe_pp_bytes = convert_to_bytes::<G2, 96>(ibe_pp);
        let p_pub_bytes = convert_to_bytes::<G2, 96>(p_pub);

        match DefaultEtfClient::<BfIbe>::encrypt(
            ibe_pp_bytes.to_vec(), p_pub_bytes.to_vec(),
            message, ids.clone(), t,
        ) {
            Ok(ct) => {
                // calculate secret keys: Q = H1(id), d = sQ
                let secrets: Vec<Vec<u8>> = ids.iter().map(|id| {
                    let q = hash_to_g1(&id);
                    let d = q.mul(s);
                    convert_to_bytes::<G1, 48>(d.into()).to_vec()
                }).collect::<Vec<_>>();
                match DefaultEtfClient::<BfIbe>::decrypt(
                    ibe_pp_bytes.to_vec(), ct.aes_ct.ciphertext, ct.aes_ct.nonce, ct.etf_ct, secrets, 
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