
/*
 * Copyright 2024 by Ideal Labs, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
use ark_std::{rand::Rng, vec::Vec};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use core::marker::PhantomData;
use serde::{Deserialize, Serialize};
use crate::{
    ser::{ark_se, ark_de},
    utils::cross_product_32
};

/// the message type required for the hashed el gamal variant
pub type Message = [u8;32];

/// the ciphertext type
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, CanonicalDeserialize, CanonicalSerialize)]
pub struct Ciphertext<C: CurveGroup> {
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub c1: C,
    pub c2: [u8; 32], 
}

impl<C: CurveGroup> Ciphertext<C> {
    /// aggregate two ciphertexts C = <u, v> and C' = <u', v'> by 
    /// calculating C'' = (u + u', v (+) v')
    ///
    /// This is useful in the hashed el gamal sigma protocol
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

/// the hashed el gamal encryption scheme
pub struct HashedElGamal<C: CurveGroup> {
    _phantom_data: PhantomData<C>,
}

// I want to revisit this implementation later on and potentially modify it
// so that the decrypt function works on the secret key, rather than given by the HashedElGAmal type
// but this is fine for now

impl<C: CurveGroup> HashedElGamal<C> {

    /// Encrypt the hash of a message
    /// r <- Zp
    /// <c1, c2> = <rP, pk (+) H(message)>
    /// note that there is no MAC here, we produce that in the hashed el gamal sigma protocl impl
    pub fn encrypt<R: Rng + Sized>(
        message: Message,
        pk: C, 
        generator: C,
        mut rng: R,
    ) -> Ciphertext<C> {
        let r = C::ScalarField::rand(&mut rng);
        let c1 = generator.mul(r);
        let inner = pk.mul(r);

        let c2: [u8;32] = crate::utils::cross_product::<32>(
            &crate::utils::h2(inner).try_into().expect("the element should have 32 bytes"), 
            &message
        );

        Ciphertext{ c1, c2 }

    }

    /// decrypt a ciphertext using a secret key, recovered a scalar field element
    /// TODO: error handling
    pub fn decrypt(
        sk: C::ScalarField, 
        ciphertext: Ciphertext<C>
    ) -> Message {
        // s = sk * c1
        let s = ciphertext.c1.mul(sk);
        // m = s (+) c2
        crate::utils::cross_product::<32>(
            &crate::utils::h2(s).try_into().expect("Sha256 hashes have 32 bytes;qed"), 
            &ciphertext.c2,
        )
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
    use ark_ff::{One, UniformRand};
    use ark_bls12_381::{Fr, G1Projective as G1};

    #[test]
    fn basic_encrypt_decrypt_works() {
        let sk = Fr::rand(&mut test_rng());
        let pk = G1::generator().mul(sk);

        let secret = Fr::rand(&mut test_rng());
        let mut secret_bytes = Vec::new();
        secret.serialize_compressed(&mut secret_bytes).unwrap();
        
        let ct = HashedElGamal::encrypt(secret_bytes.clone().try_into().unwrap(), pk, G1::generator(), &mut test_rng());
        let recovered_bytes = HashedElGamal::decrypt(sk, ct);
        assert_eq!(recovered_bytes.to_vec(), secret_bytes);
    }

    #[test]
    fn can_add_ciphertexts() {
        let sk = Fr::rand(&mut test_rng());
        let pk = G1::generator().mul(sk);

        let secret = Fr::rand(&mut test_rng());
        let mut secret_bytes = Vec::new();
        secret.serialize_compressed(&mut secret_bytes).unwrap();

        
        let other_secret = Fr::one();
        let mut other_secret_bytes = Vec::new();
        other_secret.serialize_compressed(&mut other_secret_bytes).unwrap();

        let combined = secret + other_secret;
        let mut combined_bytes = Vec::new();
        combined.serialize_compressed(&mut combined_bytes).unwrap();
        
        let ct = HashedElGamal::encrypt(
            secret_bytes.clone().try_into().unwrap(), pk, G1::generator(), &mut test_rng());
        let other_ct = HashedElGamal::encrypt(
            other_secret_bytes.clone().try_into().unwrap(), pk, G1::generator(), &mut test_rng());

        let expected = Ciphertext {
            c1: ct.c1 + other_ct.c1,
            c2: crate::utils::cross_product::<32>(
                &ct.c2,
                &other_ct.c2,
            ).try_into().unwrap()
        };
        assert_eq!(ct.add(other_ct), expected);
    }

    #[test]
    fn decryption_fails_with_bad_key() {
        let sk = Fr::rand(&mut test_rng());
        let bad_sk = Fr::one();
        let pk = G1::generator().mul(sk);

        let secret = Fr::rand(&mut test_rng());
        let mut secret_bytes = Vec::new();
        secret.serialize_compressed(&mut secret_bytes).unwrap();
        
        let ct = HashedElGamal::encrypt(
            secret_bytes.clone().try_into().unwrap(), 
            pk, 
            G1::generator(), 
            &mut test_rng()
        );
        let recovered_bytes = HashedElGamal::decrypt(bad_sk, ct);
        assert!(recovered_bytes.to_vec() != secret_bytes);
    }
}