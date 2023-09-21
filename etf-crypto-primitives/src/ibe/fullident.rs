use ark_bls12_381::{
    Bls12_381, G1Projective as G1, G2Projective as G2, 
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_ec::pairing::Pairing;
use ark_std::{
    ops::Mul,
    rand::Rng,
    borrow::ToOwned,
};
use ark_std::vec::Vec;
use crate::utils::{hash_to_g1, h2, h3, h4};

/// a ciphertext (U, V, W)
/// Q: can I find a best way to aggregate the ciphertexts? 
/// that would be ideal, then we don't need a giant 
/// vec of these
#[derive(CanonicalDeserialize, CanonicalSerialize)]
pub struct IbeCiphertext {
    pub u: G2,
    pub v: Vec<u8>,
    pub w: Vec<u8>,
}

pub trait Ibe {

    fn encrypt<R: Rng + Sized>(
        ibe_pp: G2, p_pub: G2,
        message: &[u8;32], identity: &[u8], rng: R
    ) -> IbeCiphertext;

    fn decrypt(ibe_pp: G2, ciphertext: IbeCiphertext, sk: G1) -> Vec<u8>;
}

/// a struct to hold IBE public params
#[derive(
    Debug, Clone, 
    CanonicalDeserialize, CanonicalSerialize,
)]
pub struct BfIbe;

/// the IBE implementation
/// based on the BF-IBE except using bilinear map from G1 * G2 -> G2
///
impl Ibe for BfIbe {

    /// encrypt the message for the given identity
    ///
    /// * `message`: The message to encrypt
    /// * `identity`: The identity for which the message will be encrypted
    /// * `rng`: A random number generator
    ///
    fn encrypt<R: Rng + Sized>(
        ibe_pp: G2,
        p_pub: G2,
        message: &[u8;32],
        identity: &[u8],
        mut rng: R,
    ) -> IbeCiphertext {
        // random sigma in {0, 1}^32
        let t: Vec<u8> = (0..32).map(|_| rng.next_u32() as u8).collect();
        let sigma = h4(&t);
        // r= H3(sigma, message)
        let r = h3(&sigma, message);
        // U = rP
        let u: G2 = ibe_pp.mul(r); // U = rP
    
        // calc identity point
        let q = hash_to_g1(identity);
        // e(Q_id, P_pub)
        let g_id = Bls12_381::pairing(q, p_pub).mul(r);
        // sigma (+) H2(e(Q_id, P_pub))
        let v_rhs = h2(g_id);
        let v_out = cross_product_32(&sigma, &v_rhs);
        // message (+) H4(sigma)
        let w_rhs = h4(&sigma);
        let w_out = cross_product_32(message, &w_rhs);
        // (rP, sigma (+) H2(e(Q_id, P_pub)), message (+) H4(sigma))
        IbeCiphertext {
            u,
            v: v_out.to_vec(), 
            w: w_out.to_vec(),
        }
    }

    /// decrypts a message using the provided key
    /// * `ciphertext`: The ciphertext to decrypt
    /// * `sk`: The appropriate identity's secret key
    ///
    fn decrypt(
        ibe_pp: G2,
        ciphertext: IbeCiphertext,
        sk: G1,
    ) -> Vec<u8> {
        // sigma = V (+) H2(e(d_id, U))
        let sigma_rhs = h2(Bls12_381::pairing(sk, ciphertext.u));
        let sigma = cross_product_32(&ciphertext.v, &sigma_rhs);

        // m = W (+) H4(sigma)
        let m_rhs = h4(&sigma);
        let m = cross_product_32(&ciphertext.w, &m_rhs);

        // check: U =? rP
        let r = h3(&sigma, &m);
        let u_check = ibe_pp.mul(r);
        assert!(u_check.eq(&ciphertext.u));

        m
    }

}

// TODO: can do this in place instead
fn cross_product_32(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut o = a.to_owned();
    for (i, ri) in o.iter_mut().enumerate().take(32) {
        *ri ^= b[i];
    }
    o.to_vec()
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_std::{test_rng, UniformRand, rand::RngCore};

    #[test]
    pub fn can_encrypt_and_decrypt() {
        // setup
        let id_string = b"example@test.com";
        // a dummy message
        let message: [u8;32] = [2;32];
        // every participant knows the msk...
        // could be replaced by an MPC protocol
        let msk = Fr::from(test_rng().next_u64());
        // a random element of G1, the IBE public parameter
        let ibe_pp = G2::rand(&mut test_rng());
        let p_pub = ibe_pp.mul(msk);

        let ct = BfIbe::encrypt(ibe_pp, p_pub, &message, id_string, &mut test_rng());
        // then calculate our own secret
        let d = hash_to_g1(id_string).mul(msk);

        let recovered_message = BfIbe::decrypt(ibe_pp, ct, d);
        let message_vec = message.to_vec();
        assert_eq!(message_vec, recovered_message);
    }

}