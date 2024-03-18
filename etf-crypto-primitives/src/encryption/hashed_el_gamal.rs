//! Hashed El Gamal Publicly Verifiable Encryption Scheme
//!
//! This is a Sigma protocol with a Fiat-Shamir Transform over a Hashed El Gamal encryption scheme
//! The scheme allows a prover to convince a verifier that:
//!    1) For a commitment c and (hashed-) El Gamal ciphertext ct that the preimage of the ciphertext was commited to by c
//!    2) An El Gamal ciphertext was encrypted for a specific recipient (do we want this? would be better if only the recipient could verify this aspect... let's consider that later0)
//!
//!

use ark_ec::{CurveGroup};
use ark_ff::UniformRand;
use ark_std::rand::Rng;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use core::marker::PhantomData;
use crate::utils::cross_product_32;

/// the ciphertext type
#[derive(Clone, PartialEq, Debug)]
pub struct Ciphertext<C: CurveGroup> {
    pub c1: C,
    pub c2: [u8; 32], 
}

impl<C: CurveGroup> Ciphertext<C> {
    pub fn add(self, ct: Ciphertext<C>) -> Self {
        Ciphertext {
            c1: self.c1 + ct.c1,
            c2: cross_product_32(
                &self.c2, 
                &ct.c2,
            ).try_into().unwrap(),
        }
    }
}

/// the hashed el gamal cryptosystem
pub struct HashedElGamal<C: CurveGroup> {
    _phantom_data: PhantomData<C>,
}

impl<C: CurveGroup> HashedElGamal<C> {

    pub fn encrypt<R: Rng + Sized>(
        secret: C::ScalarField, 
        pk: C, 
        generator: C,
        mut rng: R,
    ) -> Ciphertext<C> {
        let r = C::ScalarField::rand(&mut rng);
        let c1 = generator.mul(r);
        let inner = pk.mul(r);
        
        let mut secret_bytes = Vec::new();
        secret.serialize_compressed(&mut secret_bytes).unwrap();

        let c2: [u8;32] = crate::utils::cross_product_32(
            &crate::utils::h2(inner), 
            &secret_bytes
        ).try_into().unwrap();

        Ciphertext{ c1, c2 }

    }

    /// decrypt a ciphertext using a secret key, recovered a scalar field element
    /// TODO: error handling
    pub fn decrypt(
        sk: C::ScalarField, 
        ciphertext: Ciphertext<C>
    ) -> C::ScalarField {
        let s = ciphertext.c1.mul(sk);
        let c2: [u8;32] = crate::utils::cross_product_32(
            &crate::utils::h2(s), 
            &ciphertext.c2,
        ).try_into().unwrap();
        C::ScalarField::deserialize_compressed(&c2[..]).unwrap()
    }

}


#[cfg(test)]
 mod test {

    use super::*;
    use ark_std::{
        test_rng,
        ops::Mul,
    };
    use ark_ec::Group;
    use ark_ff::UniformRand;
    use ark_bls12_381::{Fr, G1Projective as G1};

    #[test]
    fn test_basic_encrypt_decrypt_works() {

        let sk = Fr::rand(&mut test_rng());
        let pk = G1::generator().mul(sk);

        let secret = Fr::rand(&mut test_rng());
        
        let ct = HashedElGamal::encrypt(secret, pk, G1::generator(), &mut test_rng());
        let recovered = HashedElGamal::decrypt(sk, ct);
        assert_eq!(recovered, secret);
    }
}