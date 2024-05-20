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
/// functions useful for testing
use ark_serialize::CanonicalDeserialize;
use ark_std::{vec::Vec, test_rng, UniformRand, ops::Mul};
use ark_bls12_381::{Fr, G1Affine as G1, G2Affine as G2};
use ark_ec::AffineRepr;
use crate::utils::*;

/// generate pseudorandom ibe params to seed the IBE
/// returns (P, P_{pub}, s) where P_{pub} = sP
pub fn test_ibe_params() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let g = test_ibe_params_typed();
    (
        convert_to_bytes::<G2, 96>(g.0).to_vec(),
        convert_to_bytes::<G2, 96>(g.1).to_vec(),
        convert_to_bytes::<Fr, 32>(g.2).to_vec()
    )
    
}

/// generate pseudorandom ibe params to seed the IBE
/// returns (P, P_{pub}, s) where P_{pub} = sP
pub fn test_ibe_params_typed() -> (G2, G2, Fr) {
    let ibe_pp: G2 = G2::generator();
    let s = Fr::rand(&mut test_rng());
    let p_pub: G2 = ibe_pp.mul(s).into();
    (ibe_pp, p_pub, s)
}

/// perform the IBE EXTRACT phase of the BF IBE
/// this can be used to simulate the ETF network
///
/// returns a list of (sk, pk)
///
/// * `x`: The secret key as bytes
/// * `ids`: the slot ids
///
pub fn ibe_extract(x: Vec<u8>, ids: Vec<Vec<u8>>) -> Vec<(Vec<u8>, Vec<u8>)> {
    let s = Fr::deserialize_compressed(&x[..]).unwrap();
    ibe_extract_typed(s, ids).iter().map(|x| {
        let pk_bytes = convert_to_bytes::<G1, 48>(x.1);
        let sk_bytes = convert_to_bytes::<G1, 48>(x.0);
        (sk_bytes.to_vec(), pk_bytes.to_vec())
    }).collect::<Vec<_>>()
}

/// perform the IBE EXTRACT phase of the BF IBE
/// this can be used to simulate the ETF network
///
/// returns a list of (sk, pk)
///
/// * `s`: The secret key
/// * `ids`: the slot ids
///
pub fn ibe_extract_typed(s: Fr, ids: Vec<Vec<u8>>) -> Vec<(G1, G1)> {
    ids.iter().map(|id| {
        let pk = hash_to_g1(id);
        let sk = pk.mul(s).into();
        (sk, pk)
    }).collect::<Vec<_>>()
}