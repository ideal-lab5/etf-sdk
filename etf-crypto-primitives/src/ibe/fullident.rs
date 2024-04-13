use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_ec::Group;
use ark_std::{
    ops::Mul,
    rand::Rng,
};
use ark_std::vec::Vec;
use crate::utils::{h2, h3_new, h4, cross_product_32};

use w3f_bls::{EngineBLS, Message};

// keep in mind SignautreGroup = G2, pubkeygroup = G1

/// a ciphertext (U, V, W)
/// Q: can I find a best way to aggregate the ciphertexts? 
/// that would be ideal, then we don't need a giant 
/// vec of these
#[derive(Debug, Clone, PartialEq, CanonicalDeserialize, CanonicalSerialize)]
pub struct IBECiphertext<E: EngineBLS> {
    pub u: E::PublicKeyGroup,
    pub v: Vec<u8>,
    pub w: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum IbeError {
    DecryptionFailed,
}


/// A type to represent an IBE identity (for which we will encrypt message)
#[derive(Debug, Clone)]
pub struct Identity(pub Message);

impl Identity {

    pub fn new(identity: &[u8]) -> Self {
        Self(Message::new(b"", identity))
    }

    pub fn extract<E: EngineBLS>(&self, sk: E::Scalar) -> IBESecret<E> {
        IBESecret(self.public::<E>() * sk)
    }

    pub fn public<E: EngineBLS>(&self) -> E::SignatureGroup {
        self.0.hash_to_signature_curve::<E>()
    }

    pub fn encrypt<E, R>(
        &self,
        message: &[u8;32],
        p_pub: E::PublicKeyGroup,
        mut rng: R
    ) -> IBECiphertext<E> where E: EngineBLS, R: Rng + Sized {
        let t = E::Scalar::rand(&mut rng);
        let mut t_bytes = Vec::new();
        t.serialize_compressed(&mut t_bytes).expect("field elements have 32 bytes; qed");
        assert!(t_bytes.len() == 32);
        let sigma = h4(&t_bytes);
        // r= H3(sigma, message)
        let r: E::Scalar = h3_new::<E>(&sigma, message);
        let p = <<E as EngineBLS>::PublicKeyGroup as Group>::generator();
        // U = rP \in \mathbb{G}_1
        let u = p * r; 
        // e(P_pub, Q_id)
        let g_id = E::pairing(p_pub.mul(r), self.public::<E>());
        // sigma (+) H2(e(Q_id, P_pub))
        let v_rhs = h2(g_id);
        let v_out = cross_product_32(&sigma, &v_rhs);
        // message (+) H4(sigma)
        let w_rhs = h4(&sigma);
        let w_out = cross_product_32(message, &w_rhs);
        // (rP, sigma (+) H2(e(Q_id, P_pub)), message (+) H4(sigma))
        IBECiphertext::<E> {
            u,
            v: v_out.to_vec(), 
            w: w_out.to_vec(),
        }
    }

}

/// The output of the IBE extract algorithm is a BLS signature
pub struct IBESecret<E: EngineBLS>(pub E::SignatureGroup);

impl<E: EngineBLS> IBESecret<E> {
    pub fn decrypt(
        &self, 
        ciphertext: &IBECiphertext<E>,
    ) -> Result<Vec<u8>, IbeError> {
        // sigma = V (+) H2(e(d_id, U))
        let sigma_rhs = h2(E::pairing(ciphertext.u, self.0));
        let sigma = cross_product_32(&ciphertext.v, &sigma_rhs);

        // m = W (+) H4(sigma)
        let m_rhs = h4(&sigma);
        let m = cross_product_32(&ciphertext.w, &m_rhs);

        // check: U == rP
        let p = <<E as EngineBLS>::PublicKeyGroup as Group>::generator();
        let r = h3_new::<E>(&sigma, &m);
        let u_check = p * r;
        if !u_check.eq(&ciphertext.u) {
            return Err(IbeError::DecryptionFailed);
        }

        Ok(m)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_377::Bls12_377;
    use ark_bls12_381::Bls12_381;
    use ark_ec::bls12::Bls12Config;
    use ark_ec::hashing::curve_maps::wb::{WBConfig, WBMap};
    use ark_ec::hashing::map_to_curve_hasher::MapToCurve;
    use ark_ec::pairing::Pairing as PairingEngine;

    use w3f_bls::{CurveExtraConfig, TinyBLS, UsualBLS};

    use ark_std::{test_rng, UniformRand, rand::RngCore};

    fn run_test<
        EB: EngineBLS<Engine = E>,
        E: PairingEngine, 
        P: Bls12Config + CurveExtraConfig>()
    where
        <P as Bls12Config>::G2Config: WBConfig,
        WBMap<<P as Bls12Config>::G2Config>: MapToCurve<<E as PairingEngine>::G2>,
    {
        let id_string = b"example@test.com";
        let identity = Identity::new(id_string);
        let message: [u8;32] = [2;32];
        let msk = <EB as EngineBLS>::Scalar::rand(&mut test_rng());
        // // then we need out p_pub = msk * P \in G_1
        let p_pub = <<EB as EngineBLS>::PublicKeyGroup as Group>::generator() * msk;
        let ct: IBECiphertext<EB> = identity.encrypt(&message, p_pub, &mut test_rng());
        // we then calculate the IBE secret by calculating a BLS signature d = sQ_{ID} where Q_{ID} = H1(ID)
        let sk = identity.extract::<EB>(msk);
        match sk.decrypt(&ct) {
            Ok(data) => {
                assert_eq!(data, message.to_vec())
            },
            Err(_) => {
                panic!("The test should pass.");
            }
        }
    }

    #[test]
    pub fn can_encrypt_and_decrypt() {
        run_test::<TinyBLS<Bls12_377, ark_bls12_377::Config>, Bls12_377, ark_bls12_377::Config>();
    }

}