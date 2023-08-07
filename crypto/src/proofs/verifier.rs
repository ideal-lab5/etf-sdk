use crate::proofs::dleq::DLEQProof;
use crate::utils::{hash_to_g1};
use ark_ec::AffineRepr;

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