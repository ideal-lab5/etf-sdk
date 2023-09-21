/// functions useful for testing
use ark_serialize::CanonicalDeserialize;
use ark_std::{vec::Vec, test_rng, UniformRand, ops::Mul};
use ark_bls12_381::{Fr, G1Affine as G1, G2Affine as G2};
use ark_ec::AffineRepr;
use crate::utils::*;

/// generate pseudorandom ibe params to seed the IBE
/// returns (P, P_{pub}, s) where P_{pub} = sP
pub fn test_ibe_params() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let ibe_pp: G2 = G2::generator();
    let s = Fr::rand(&mut test_rng());
    let p_pub: G2 = ibe_pp.mul(s).into();
    (
        convert_to_bytes::<G2, 96>(ibe_pp).to_vec(),
        convert_to_bytes::<G2, 96>(p_pub).to_vec(),
        convert_to_bytes::<Fr, 32>(s).to_vec()
    )
    
}

/// perform the IBE EXTRACT phase of the BF IBE
/// this can be used to simulate the ETF network
///
/// * `x`: The secret key as bytes
/// * `ids`: the slot ids
///
pub fn ibe_extract(x: Vec<u8>, ids: Vec<Vec<u8>>) -> Vec<(Vec<u8>, Vec<u8>)> {
    let s = Fr::deserialize_compressed(&x[..]).unwrap();
    ids.iter().map(|id| {
        let pk = hash_to_g1(id);
        let sk = pk.mul(s);
        let pk_bytes = convert_to_bytes::<G1, 48>(pk);
        let sk_bytes = convert_to_bytes::<G1, 48>(sk.into());
        (sk_bytes.to_vec(), pk_bytes.to_vec())
    }).collect::<Vec<_>>()
}