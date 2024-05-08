
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
use ark_serialize::{CanonicalSerialize, SerializationError};
use ark_std::{rand::Rng, vec::Vec};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};
use crate::types::ProtocolParams as Params;

// a public commitment for a point in the curbe group's scalar field
pub type Commitment<C> = C;

// represents an el gamal ciphertext
#[derive(Debug, Clone, PartialEq)]
pub struct Ciphertext<C: CurveGroup> {
    c1: C::Affine,
    c2: C::Affine,
}

#[derive(Debug)]
pub enum Error {
    SerializationError,
}

impl<C: CurveGroup> Ciphertext<C> {
    fn serialize_compressed(&self) -> Result<(Vec<u8>, Vec<u8>), SerializationError> {
        let mut c1_bytes = Vec::new();
        let mut c2_bytes = Vec::new();

        self.c1.serialize_compressed(&mut c1_bytes)?;
        self.c2.serialize_compressed(&mut c2_bytes)?;

        Ok((c1_bytes, c2_bytes))
    }
}

/// the NIZK PoK
#[derive(Clone, PartialEq, Debug)]
pub struct PoK<C: CurveGroup> {
    /// the commitment to the random value (e.g. rG)
    pub t: C,
    /// the 'blinding' commitment to the random value (e.g. rH)
    pub a: C,
    /// the challenge (e.g. z = k + es)
    pub z: C::ScalarField,
    /// the commitment to the secret input
    pub commitment: C,
    /// the (el gamal) ciphertext
    pub ciphertext: Ciphertext<C>,
}

impl<C: CurveGroup> PoK<C> {
    /// Prove that a commitment is of the preimage of an El Gamal ciphertext
    /// without revealing the message
    ///
    /// * `s`: The scalar field element to prove knowledge of
    /// * `params`: The parameters required to run the protocol (two group generators)
    /// * `rng`: A CSPRNG
    ///
    pub fn prove<R: Rng + Sized>(
        s: C::ScalarField,
        params: Params<C>,
        mut rng: R,
    ) -> Self {
        // el gamal encryption
        let r = C::ScalarField::rand(&mut rng);
        let c1 = params.g * r;
        let c2 = params.h * (s * r);

        let ct: Ciphertext<C> = Ciphertext {
            c1: c1.into(),
            c2: c2.into(),
        };

        // the commitment
        let c: Commitment<C> = params.g * s + params.h * s;

        let k = C::ScalarField::rand(&mut rng);
        let t = params.g * k;
        let a = params.h * k;

        let mut t_bytes = Vec::new();
        let mut a_bytes = Vec::new();
        t.serialize_compressed(&mut t_bytes)
            .expect("group element should exist");
        a.serialize_compressed(&mut a_bytes)
            .expect("group element should exist");

        let mut inputs = Vec::new();
        inputs.push(t_bytes);
        inputs.push(a_bytes);
        let (c1_bytes, c2_bytes) = ct
            .serialize_compressed()
            .expect("group elements should exist");
        inputs.push(c1_bytes);
        inputs.push(c2_bytes);

        let challenge: C::ScalarField =
            C::ScalarField::from_be_bytes_mod_order(&shake128(inputs.as_ref()));
        let z = k + challenge * s;
        PoK { t, a, z, commitment: c, ciphertext: ct }
    }

    /// batch prove a many messages
    /// works by aggregating the messages and then calling the prove function on the result
    ///
    /// `messages`:
    /// `params`:
    /// `rng`: 
    ///
    pub fn batch_prove<R: Rng + Sized>(
        messages: &[C::ScalarField],
        params: Params<C>,
        mut rng: R,
    ) -> PoK<C> {
        let m = (0..messages.len()).fold(C::ScalarField::zero(), |acc, val| acc + messages[val]);
        PoK::prove(m, params, &mut rng)
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
        let mut t_bytes = Vec::new();
        let mut a_bytes = Vec::new();
        self
            .t
            .serialize_compressed(&mut t_bytes)
            .expect("group element should exist");
        self
            .a
            .serialize_compressed(&mut a_bytes)
            .expect("group element should exist");

        let mut inputs = Vec::new();
        inputs.push(t_bytes);
        inputs.push(a_bytes);
        let (c1_bytes, c2_bytes) = self.ciphertext
            .serialize_compressed()
            .expect("group element should exist");
        inputs.push(c1_bytes);
        inputs.push(c2_bytes);

        let challenge: C::ScalarField =
            C::ScalarField::from_be_bytes_mod_order(&shake128(inputs.as_ref()));

        let zg = params.g * self.z;
        let zh = params.h * self.z;

        zg + zh == self.t + self.a + self.commitment * challenge
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
        // the public key
        let h: JubJub = g.mul(x).into();

        let params = Params { g, h };

        let proof = PoK::prove(x, params.clone(), test_rng());
        let result = proof.verify(params);
        assert_eq!(result, true);
    }

    #[test]
    pub fn batch_prove_and_verify() {
        let mut rng = test_rng();
        // the secret key
        let x = <JubJub as Group>::ScalarField::rand(&mut rng);
        let y = <JubJub as Group>::ScalarField::rand(&mut rng);
        
        let g: JubJub = JubJub::generator().into();
        // the public key
        let h: JubJub = g.mul(x).into();

        let params = Params { g, h };

        let proof = PoK::batch_prove(&vec![x, y], params.clone(), test_rng());
        let result = proof.verify(params);
        assert_eq!(result, true);
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
            t: g.mul(j).into(),
            a: g.mul(j).into(),
            z: j,
            commitment: g.mul(j).into(),
            ciphertext: Ciphertext {
                c1: g.mul(j).into(),
                c2: g.mul(j).into(),
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
            c2: g.mul(j).into(),
        };

        let params = Params { g, h };

        let mut proof = PoK::prove(x, params.clone(), test_rng());
        proof.ciphertext = bad_ciphertext;
        let result = proof.verify(params);
        assert_eq!(result, false);
    }
}