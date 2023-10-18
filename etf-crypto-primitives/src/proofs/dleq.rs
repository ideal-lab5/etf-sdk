/// DLEQ Proofs
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{UniformRand, ops::Mul};
use ark_ff::PrimeField;
use sha3::digest::{Update, ExtendableOutput, XofReader};
use ark_bls12_381::Fr;
use ark_std::rand::Rng;

// use alloc::vec::Vec;

// #![cfg(not(feature = "std"))]
use ark_std::vec::Vec;

// #![cfg(feature = "std")]
// use std::vec::Vec;

/// the type of the G1 group
type K = ark_bls12_381::G1Affine;

/// a struct to hold a DLEQ proof
#[derive(
    CanonicalDeserialize, CanonicalSerialize, 
    Clone, Debug, Default, PartialEq
)]
pub struct DLEQProof {
	/// the first commitment point rG
    pub rand_commitment_g: K,
	///  the second commitment point rH
    pub rand_commitment_h: K,
    /// a commitment to xG where x is the secret
    pub secret_commitment_g: K,
    /// a commitment to xH where x is the secret
    pub secret_commitment_h: K,
	/// the witness s = r + c*x
    pub witness: Fr,
}

/// implementation of dleq proof
impl DLEQProof {

    /// construct a new DLEQ Proof for the given id and secret
    ///
    /// * `seed`: The identity from which we will derive a public key
    /// * `x`: The secret in the scalar field S (over which K is defined).
    /// * `g`: A group generator of K
    /// * `h`: A group generator of K
    ///
    pub fn new<R: Rng + Sized>(x: Fr, g: K, h: K, extras: Vec<u8>, rng: R) -> Self {
        prepare_proof(x, g, h, extras, rng)
    }

    /// verify a DLEQ Proof with a given public parameters
    ///
    /// * `g`: a generator in G1
    /// * `h`: A generator in G1
    /// * `extras`: extra bytes used to generator the proof
    ///
    pub fn verify(&self, g: K, h: K, extras: Vec<u8>) -> bool {
        verify_proof(g, h, self.clone(), extras)
    }
}

/// Prepare a DLEQ proof of knowledge of the value 'x'
/// 
/// * `x`: The secret (scalar)
/// * `g`: A generator point in G1
/// * `h`:  A generator point in G1
/// * `extras`: extra bytes to append to the hasher
/// * `rng`: A random number generator
///
fn prepare_proof<R: Rng + Sized>(
    x: Fr, g: K, h: K, 
    extras: Vec<u8>, 
    mut rng: R,
) -> DLEQProof {
    let r: Fr = Fr::rand(&mut rng);
    let rand_commitment_g: K = g.mul(r).into();
    let rand_commitment_h: K = h.mul(r).into();
    let secret_commitment_g: K = g.mul(x).into();
    let secret_commitment_h: K = h.mul(x).into();

    let c: Fr = prepare_witness(vec![
        rand_commitment_g, rand_commitment_h, 
        secret_commitment_g, secret_commitment_h,
    ], &extras);
    let s = r + x * c;
    DLEQProof {
        rand_commitment_g, 
        rand_commitment_h, 
        secret_commitment_g,
        secret_commitment_h,
        witness: s,
    }
}

/// verify the proof was generated on the given input
/// 
/// * `g`: A publicly known generator used to generate the proof
/// * `h`: A publicly known generator used to generate the proof
/// * `proof`: The DLEQ proof to verify 
/// * `extras`: Extra bytes to add to the hasher
/// 
fn verify_proof(g: K, h: K, proof: DLEQProof, extras: Vec<u8>) -> bool {
    let c = prepare_witness(vec![
        proof.rand_commitment_g, proof.rand_commitment_h,
        proof.secret_commitment_g, proof.secret_commitment_h,
    ], &extras);

    let check_g: K = (proof.secret_commitment_g.mul(c) - g.mul(proof.witness)).into();
    let check_h: K = (proof.secret_commitment_h.mul(c) - h.mul(proof.witness)).into();

    check_g.x.eq(&proof.rand_commitment_g.x) &&
        check_h.x.eq(&proof.rand_commitment_h.x)
}

/// Prepare a witness for the proof using Shake128
/// 
/// `points`: A vec of points in the group G1
/// `extras`: Extra bytes to add to the hasher
/// 
fn prepare_witness(points: Vec<K>, extras: &[u8]) -> Fr {
    let mut h = sha3::Shake128::default();

    for p in points.iter() {
        let mut bytes = Vec::with_capacity(p.compressed_size());
        p.serialize_compressed(&mut bytes).unwrap();
        h.update(bytes.as_slice());
    }

    h.update(extras);
    
    let mut o = [0u8; 32];
    // get challenge from hasher
    h.finalize_xof().read(&mut o);
    Fr::from_be_bytes_mod_order(&o)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;

    use ark_ec::AffineRepr;

    fn setup(extras: Vec<u8>) -> (K, K, DLEQProof) {
        let x = Fr::rand(&mut test_rng());
        let g = K::generator();
        let h = K::rand(&mut test_rng());
        (g, h, DLEQProof::new(x, g, h, extras, test_rng()))
    }

    #[test]
    fn dleq_prepare_and_verify_works() {
        let extras = b"extra extra".to_vec();
        let (g, h, proof) = setup(extras.clone());
        let validity = proof.verify(g, h, extras);
        assert_eq!(validity, true);
    }

    #[test]
    fn dleq_prepare_and_verify_fails_with_wrong_generator_point() {
        let extras = b"".to_vec();
        let (g, _h, proof) = setup(extras.clone());
        let validity = proof.verify(g, g, extras);
        assert_eq!(validity, false);
    }

    #[test]
    fn dleq_fails_with_wrong_extras() {
        let extras = b"extra extra".to_vec();
        let (g, h, proof) = setup(extras.clone());
        let validity = proof.verify(g, h, Vec::new());
        assert_eq!(validity, false);
    }

    #[test]
    fn dleq_proof_is_serializable() {
        let (_, _, p) = setup(Vec::new());
        let mut p_out = Vec::new();
        p.serialize_compressed(&mut p_out).unwrap();

        assert!(p_out.len().eq(&p.compressed_size()));

        let q = DLEQProof::deserialize_compressed(&p_out[..]).unwrap();
        assert_eq!(p, q);
    }

    // #[test]
    // pub fn ntotatest() {
    //     let ibe_pp: ark_bls12_381::G2Affine = ark_bls12_381::G2Affine::generator().into();
    //     let s = Fr::from_be_bytes_mod_order(&[2;32]);
    //     let p_pub: ark_bls12_381::G2Affine = ibe_pp.mul(s).into();

    //     let p = crate::utils::convert_to_bytes::<ark_bls12_381::G2Affine, 96>(ibe_pp);
    //     let q = crate::utils::convert_to_bytes::<ark_bls12_381::G2Affine, 96>(p_pub);
    //     // let r = crate::utils::convert_to_bytes::<ark_bls12_381::Fr, 32>(s);

    //     panic!("{:?}, {:?}", hex::encode(p), hex::encode(q));
        
    // }
}