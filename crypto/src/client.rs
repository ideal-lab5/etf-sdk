// a client for the (FullIdent) IBE
use crate::ibe::fullident::{Ibe, BfIbe, Ciphertext};
use ark_bls12_381::G2Affine as G2;
use ark_std::rand::Rng;
use ark_serialize::CanonicalSerialize;
use aes_gcm::aead::OsRng;
use crate::utils::hash_to_g1;

pub trait EtfClient {
    fn encrypt(
        ibe: BfIbe,
        data: Vec<([u8;32], Vec<u8>)>,
    ) -> Vec<Vec<u8>>; 
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
    /// * `data`: A map of data to be encrpted to id to encrypt it for
    fn encrypt(
        bfibe: BfIbe,
        data: Vec<([u8;32], Vec<u8>)>,
    ) -> Vec<Vec<u8>> {
        let mut out: Vec<Vec<u8>> = Vec::new();
        for (m, id) in data.iter() {
            // gen new ciphertext
            let ct = bfibe.encrypt(m, id, OsRng);
            let mut o = Vec::with_capacity(ct.compressed_size());
            // TODO: handle errors
            ct.serialize_compressed(&mut o).unwrap();
            out.push(o);
        }
        out
    }

}

// #[cfg(tests)]
// pub mod tests {
//     #[test]
//     fn can_setup_and_encrypt() {

//     }
// }