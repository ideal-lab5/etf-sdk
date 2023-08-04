use crate::proofs::dleq::DLEQProof;
use crate::utils::{hash_to_g1};
use ark_ec::{AffineRepr, Group};

pub struct IbeDleqVerifier;

impl IbeDleqVerifier {

    /// a default verifier, using the G1 generator and derived IBE pubkey
    pub fn verify(id: Vec<u8>, proof: DLEQProof, extras: Vec<u8>) -> bool {
        let g = ark_bls12_381::G1Affine::generator();
        let pk = hash_to_g1(&id);
        proof.verify(g, pk, extras)
    }

}