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

use ark_ec::CurveGroup;
use ark_ff::{fields::PrimeField, UniformRand, Zero};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_std::{rand::Rng, vec::Vec};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};
use serde::{Deserialize, Serialize};
use crate::{
    encryption::hashed_el_gamal::{Ciphertext, HashedElGamal},
    types::ProtocolParams as Params,
    ser::{ark_de, ark_se},
};

// a public commitment for a point in the curve group's scalar field
pub type Commitment<C> = C;

/// Error types for the protocol
#[derive(Debug)]
pub enum Error {
    SerializationError,
}

/// the NIZK PoK
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct PoK<C: CurveGroup> {
    /// the commitment to the random value (e.g. rG)
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub s: C,
    /// the 'blinding' commitment to the random value (e.g. rH)
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub t: C,
    /// the challenge (e.g. z = k + es)
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub z: C::ScalarField,
    /// the commitment to the secret input
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub commitment: C,
    /// the (hashed el gamal) ciphertext
    pub ciphertext: Ciphertext<C>,
}

/// the NIZK PoK with support for batched ciphertexts
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, CanonicalSerialize, CanonicalDeserialize)]
pub struct BatchPoK<C: CurveGroup> {
    /// the commitment to the random value (e.g. rG)
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub s: C,
    /// the 'blinding' commitment to the random value (e.g. rH)
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub t: C,
    /// the challenge (e.g. z = k + es)
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub z: C::ScalarField,
    /// the commitment to the secret input
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub commitment: C,
    /// the (hashed el gamal) ciphertexts
    pub ciphertexts: Vec<Ciphertext<C>>,
}


impl<C: CurveGroup> PoK<C> {

    /// Prove that a commitment is of the preimage of a Hashed-El Gamal ciphertext
    /// without revealing the message. Also produces valid Hashed El Gamal Ciphertexts
    ///
    /// * `s`: The scalar field element to prove knowledge of
    /// * `params`: The parameters required to run the protocol (two group generators)
    /// * `rng`: A CSPRNG
    ///
    pub fn prove<R: Rng + Sized>(
        message: C::ScalarField,
        params: Params<C>,
        mut rng: R,
    ) -> Self {
        let mut message_bytes = Vec::new();
        message.serialize_compressed(&mut message_bytes)
            .expect("The message must be a scalar field element;qed");
        let ciphertext = HashedElGamal::encrypt(
            message_bytes
                .try_into()
                .expect("The message byte length should be correct"), 
                params.h, 
                params.g, 
                &mut rng
            ).unwrap();
            // TODO handle errors properly
        let commitment: Commitment<C> = params.g * message + params.h * message;

        let k = C::ScalarField::rand(&mut rng);
        let s = params.g * k;
        let t = params.h * k;

        let mut s_bytes = Vec::new();
        let mut t_bytes = Vec::new();
        s.serialize_compressed(&mut s_bytes)
            .expect("group element should exist");
        t.serialize_compressed(&mut t_bytes)
            .expect("group element should exist");

        // prepare input for shake128
        let mut inputs = Vec::new();
        inputs.push(s_bytes);
        inputs.push(t_bytes);
        let mut c1_bytes = Vec::new();
        ciphertext.c1
            .serialize_compressed(&mut c1_bytes)
            .unwrap();
        inputs.push(c1_bytes);
        inputs.push(ciphertext.c2.to_vec());

        let challenge: C::ScalarField =
            C::ScalarField::from_be_bytes_mod_order(&shake128(inputs.as_ref()));
        let z = k + challenge * message;
        PoK { s, t, z, commitment, ciphertext }
    }

    /// verify a proof that a commitment is of the preimage of an el gamal ciphertext
    /// outputs true if the proof is valid, false otherwise
    /// 
    /// * `params`: The parameters required to verify the proof (two group generators required)
    ///
    pub fn verify(
        &self,
        params: Params<C>,
    ) -> bool {
        let mut s_bytes = Vec::new();
        let mut t_bytes = Vec::new();
        self.s.serialize_compressed(&mut s_bytes)
            .expect("group elements are serializable");
        self.t.serialize_compressed(&mut t_bytes)
            .expect("group elements are serializable");

        let mut inputs = Vec::new();
        inputs.push(s_bytes);
        inputs.push(t_bytes);
        let mut c1_bytes = Vec::new();
        self.ciphertext.c1.serialize_compressed(&mut c1_bytes)
            .expect("the group element must be serializable");
        inputs.push(c1_bytes);
        inputs.push(self.ciphertext.c2.to_vec());


        let challenge: C::ScalarField =
            C::ScalarField::from_be_bytes_mod_order(&shake128(inputs.as_ref()));

        let zg = params.g * self.z;
        let zh = params.h * self.z;

        zg + zh == self.s + self.t + self.commitment * challenge
    }
}

impl<C: CurveGroup> BatchPoK<C> {
    
    /// batch prove
    /// works by aggregating the messages and then calling the prove function on the result
    /// returns a vec of ciphertexts for decryption later on but they are not needed for verification
    ///
    /// `messages`:
    /// `params`:
    /// `rng`: 
    ///
    pub fn prove<R: Rng + Sized>(
        messages: &[C::ScalarField],
        pk: C,
        mut rng: R,
    ) -> BatchPoK<C> {
        let g = C::generator();
        
        let aggregated_messages = (0..messages.len())
            .fold(C::ScalarField::zero(), |acc, val| acc + messages[val]);

        let batch_data: Vec<(Ciphertext<C>, Commitment<C>)> = messages.into_iter().map(|m| {
            let mut message_bytes = Vec::new();
            m.serialize_compressed(&mut message_bytes).expect("The messager should be serializable");
            // TODO: error handling
            let ciphertext: Ciphertext<C> = HashedElGamal::encrypt(
                message_bytes
                    .try_into()
                    .expect("The message was a scalar field element and so has the right size"), 
                pk, 
                g, 
                &mut rng).unwrap(); // TODO: ERROR HANDLING
            let commitment: Commitment<C> = g * m + pk * m;
            (ciphertext, commitment)
        }).collect::<Vec<_>>();


        let ciphertexts = batch_data.iter().map(|b| b.0.clone()).collect::<Vec<_>>();

        let mut batch_ciphertext: Ciphertext<C> = ciphertexts[0].clone();
        for ct in ciphertexts.iter().skip(1) {
            batch_ciphertext = batch_ciphertext.add(ct.clone());
        }

        let batch_commitment = batch_data.iter().map(|c| c.1).fold(C::zero(), |acc, val| acc + val);

        let k = C::ScalarField::rand(&mut rng); 
        let s = g * k;
        let t = pk * k;

        let mut s_bytes = Vec::new();
        let mut t_bytes = Vec::new();
        s.serialize_compressed(&mut s_bytes)
            .expect("group element should exist");
        t.serialize_compressed(&mut t_bytes)
            .expect("group element should exist");

        // prepare input for shake128
        let mut inputs = Vec::new();
        inputs.push(s_bytes);
        inputs.push(t_bytes);
        let mut c1_bytes = Vec::new();
        batch_ciphertext.c1.serialize_compressed(&mut c1_bytes).expect("group elements are serializable");
        inputs.push(c1_bytes);
        inputs.push(batch_ciphertext.c2.to_vec());

        let challenge: C::ScalarField =
            C::ScalarField::from_be_bytes_mod_order(&shake128(inputs.as_ref()));
        let z = k + challenge * aggregated_messages;
        BatchPoK { 
            s, t, z, 
            commitment: batch_commitment,
            ciphertexts,
        }
    }

    /// verify a proof that a commitment is of the preimage of an el gamal ciphertext
    /// outputs true if the proof is valid, false otherwise
    /// 
    /// * `params`: The parameters required to verify the proof (two group generators required)
    ///
    pub fn verify(
        &self,
        pk: C,
    ) -> bool {

        // first we need to combine the ciphertexts
        let mut ciphertext: Ciphertext<C> = self.ciphertexts[0].clone();
        for ct in self.ciphertexts.iter().skip(1) {
            ciphertext = ciphertext.add(ct.clone());
        }

        let mut s_bytes = Vec::new();
        let mut t_bytes = Vec::new();
        self
            .s
            .serialize_compressed(&mut s_bytes)
            .expect("group element should exist");
        self
            .t
            .serialize_compressed(&mut t_bytes)
            .expect("group element should exist");

        let mut inputs = Vec::new();
        inputs.push(s_bytes);
        inputs.push(t_bytes);
        let mut c1_bytes = Vec::new();
        ciphertext.c1.serialize_compressed(&mut c1_bytes).expect("group elements should be serializable");
        inputs.push(c1_bytes);
        inputs.push(ciphertext.c2.to_vec());


        let challenge: C::ScalarField =
            C::ScalarField::from_be_bytes_mod_order(&shake128(inputs.as_ref()));

        let zg = C::generator() * self.z;
        let zh = pk * self.z;

        zg + zh == self.s + self.t + self.commitment * challenge
    }

}

/// shake128 hash some input
fn shake128(input: &[Vec<u8>]) -> [u8; 32] {
    let mut h = Shake128::default();

    for item in input.iter() {
        h.update(item);
    }

    let mut o = [0u8; 32];
    // get challenge from hasher
    h.finalize_xof().read(&mut o);
    o
}

#[cfg(test)]
mod test {

    use super::*;
    use ark_ec::Group;
    use ark_ed_on_bls12_381::EdwardsProjective as JubJub;
    use ark_std::{ops::Mul, test_rng};

    #[test]
    pub fn prove_and_verify() {
        let mut rng = test_rng();
        // the secret key
        let x = <JubJub as Group>::ScalarField::rand(&mut rng);
        let g: JubJub = JubJub::generator().into();
        let h: JubJub = g.mul(x).into();
        let params = Params { g, h };

        let message = <JubJub as Group>::ScalarField::rand(&mut rng);

        let proof = PoK::prove(message, params.clone(), test_rng());
        let result = proof.verify(params);

        assert_eq!(result, true);

        // and we can decrypt the ciphertext
        let recovered = HashedElGamal::decrypt(x, proof.ciphertext).unwrap();

        let mut message_bytes = Vec::new();
        message.serialize_compressed(&mut message_bytes).unwrap();
        assert_eq!(recovered.to_vec(), message_bytes);
    }

    #[test]
    pub fn batch_prove_and_verify() {
        let mut rng = test_rng();
        // the secret key
        let x = <JubJub as Group>::ScalarField::rand(&mut rng);
        let m1 = <JubJub as Group>::ScalarField::rand(&mut rng);
        let m2 = <JubJub as Group>::ScalarField::rand(&mut rng);

        let mut m1_bytes = Vec::new();
        m1.serialize_compressed(&mut m1_bytes).unwrap();

        let mut m2_bytes = Vec::new();
        m2.serialize_compressed(&mut m2_bytes).unwrap();
        
        let g: JubJub = JubJub::generator().into();
        // the public key
        let h: JubJub = g.mul(x).into();

        let proof = BatchPoK::prove(&vec![m1, m2], h, test_rng());
        let result = proof.verify(h);
        assert_eq!(result, true);

        assert_eq!(2, proof.ciphertexts.clone().len());
        let n1 = HashedElGamal::decrypt(x, proof.ciphertexts[0].clone()).unwrap();
        assert_eq!(m1_bytes, n1);
        let n2 = HashedElGamal::decrypt(x, proof.ciphertexts[1].clone()).unwrap();
        assert_eq!(m2_bytes, n2);
    }

    #[test]
    pub fn verify_fails_with_invalid_challenge() {
        let mut rng = test_rng();
        // the secret key
        let x = <JubJub as Group>::ScalarField::rand(&mut rng);
        let g: JubJub = JubJub::generator().into();
        // the public key
        let h: JubJub = g.mul(x).into();

        let j = <JubJub as Group>::ScalarField::rand(&mut rng);
        let bad_proof = PoK {
            s: g.mul(j).into(),
            t: g.mul(j).into(),
            z: j,
            commitment: g.mul(j).into(),
            ciphertext: Ciphertext {
                c1: g.mul(j).into(),
                c2: [1;32],
            }
        };

        let params = Params { g, h };
        let result = bad_proof.verify(params);
        assert_eq!(result, false);
    }

    #[test]
    pub fn verify_fails_with_invalid_commitment() {
        let mut rng = test_rng();
        // the secret key
        let x = <JubJub as Group>::ScalarField::rand(&mut rng);
        let g: JubJub = JubJub::generator().into();
        // the public key
        let h: JubJub = g.mul(x).into();

        let j = <JubJub as Group>::ScalarField::rand(&mut rng);
        let bad_commitment = g.mul(j).into();

        let params = Params { g, h };

        let mut proof = PoK::prove(x, params.clone(), test_rng());
        proof.commitment = bad_commitment;
        let result = proof.verify(params);
        assert_eq!(result, false);
    }

    #[test]
    pub fn verify_fails_with_invalid_ciphertext() {
        let mut rng = test_rng();
        // the secret key
        let x = <JubJub as Group>::ScalarField::rand(&mut rng);
        let g: JubJub = JubJub::generator().into();
        // the public key
        let h: JubJub = g.mul(x).into();

        let j = <JubJub as Group>::ScalarField::rand(&mut rng);
        let bad_ciphertext = Ciphertext {
            c1: g.mul(j).into(),
            c2: [1;32],
        };

        let params = Params { g, h };

        let mut proof = PoK::prove(x, params.clone(), test_rng());
        proof.ciphertext = bad_ciphertext;
        let result = proof.verify(params);
        assert_eq!(result, false);
    }
}