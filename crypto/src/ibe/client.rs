// a client for the (FullIdent) IBE
use super::fullident::{Ibe, Ciphertext};
use ark_bls12_381::G2Affine as G2;
use ark_std::rand::Rng;
use ark_serialize::CanonicalSerialize;
use crate::utils::hash_to_g1;

pub trait IbeClient<I: Ibe> {
    // fn setup(&self, p_pub: G2) -> Self {
    //     Self {
    //         Ibe::setup(G2::generator(), p_pub)
    //     }
    // }
    fn encrypt<R: Rng + Sized>(
        &self, 
        ibe: &I,
        data: Vec<([u8;32], Vec<u8>)>,
        rng: &mut R,
    ) -> Vec<Vec<u8>>; 
}

pub struct DefaultIbeClient;

/// a clent to setup and perform IBE functions
/// uses known generator of G2 and other ranomd generator point
impl<I: Ibe> IbeClient<I> for DefaultIbeClient {
    // fn setup(&self, p_pub: G2) -> Self {
    //     Self {
    //         Ibe::setup(G2::generator(), p_pub)
    //     }
    // }
    /// * `data`: A map of data to be encrpted to id to encrypt it for
    fn encrypt<R: Rng + Sized>(
        &self, 
        bfibe: &I,
        data: Vec<([u8;32], Vec<u8>)>,
        rng: &mut R,
    ) -> Vec<Vec<u8>> {
        let mut out: Vec<Vec<u8>> = Vec::new();
        for (m, id) in data.iter() {
            // gen new ciphertext
            let ct = bfibe.encrypt(m, id, &mut *rng);
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