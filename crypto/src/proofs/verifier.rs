use crate::proofs::dleq::DLEQProof;
use crate::utils::{hash_to_g1};
use ark_ec::AffineRepr;

// #![cfg(not(feature = "std"))]
use ark_std::vec::Vec;

// #![cfg(feature = "std")]
// use std::vec::Vec;

/// verify a DLEQ proof
/// TODO: do I really need this?
pub trait DleqVerifier {
    fn verify(id: Vec<u8>, proof: DLEQProof, extras: Vec<u8>) -> bool;
}
/// A struct to verify a dleq proof given inputs to an ibe id
pub struct IbeDleqVerifier;

impl DleqVerifier for IbeDleqVerifier {

    /// a default verifier, using the G1 generator and derived IBE pubkey
    /// return true if the proof is valid, false otherwise
    ///
    /// * `id`: An identity in the identity based cryptosystem
    /// * `proof`: A dleq proof
    /// * `extras`: Extras used to generate the proof
    ///
    fn verify(id: Vec<u8>, proof: DLEQProof, extras: Vec<u8>) -> bool {
        let g = ark_bls12_381::G1Affine::generator();
        let pk = hash_to_g1(&id);
        proof.verify(g, pk, extras)
    }

}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::{Fr, G1Affine};
    use ark_std::test_rng;
    use ark_ff::UniformRand;
    use ark_ec::AffineRepr;

    #[test]
    pub fn can_verify_proof_is_valid() {
        let x = Fr::rand(&mut test_rng());
        let g = G1Affine::generator();
        let pk = hash_to_g1(b"test");
        let p = DLEQProof::new(x, g, pk, vec![], test_rng());
        assert!(IbeDleqVerifier::verify(b"test".to_vec(), p, vec![]).eq(&true));
    }

    #[test]
    pub fn can_verify_proof_is_not_valid() {
        let x = Fr::rand(&mut test_rng());
        let g = G1Affine::generator();
        let pk = G1Affine::generator();
        let p = DLEQProof::new(x, g, pk, vec![], test_rng());
        assert!(IbeDleqVerifier::verify(b"test".to_vec(), p, vec![]).eq(&false));
    }
}