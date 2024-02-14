use sha2::Digest;

use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_ec::{AffineRepr, CurveGroup};
use ark_bls12_381::{Fr, G1Affine};
use ark_std::vec::Vec;
#[cfg(feature = "paillier")]
use kzen_paillier::{DecryptionKey, EncryptionKey, KeyGeneration, Keypair, Paillier};
use serde::{Serialize, Deserialize};

#[cfg(feature = "paillier")]
#[derive(Debug, Serialize, Deserialize)]
pub struct KeypairWrapper {
    pub ek: EncryptionKey,
    pub dk: DecryptionKey,
}

#[cfg(feature = "paillier")]
/// create a new keypair for the paillier cryptosystem
pub fn paillier_create_keypair() -> Result<Vec<u8>, serde_json::Error> {
    let bytes = serde_json::to_vec(&Paillier::keypair())?;
    Ok(bytes)
}

#[cfg(feature = "paillier")]
/// create a new (ek, dk) from a keypair
pub fn paillier_create_keys(keypair_bytes: Vec<u8>) -> Result<Vec<u8>, serde_json::Error> {
    let kp: Keypair = serde_json::from_slice(&keypair_bytes)?;
    let keys = kp.keys();
    let output = serde_json::to_vec(&KeypairWrapper {
        ek: keys.0,
        dk: keys.1,
    })?;
    Ok(output)
}

/// sha256 hasher
pub fn sha256(b: &[u8]) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b);
    hasher.finalize().to_vec()
}

/// {0, 1}^* -> G1
pub fn hash_to_g1(b: &[u8]) -> G1Affine {
    let mut nonce = 0u32;
    loop {
        let c = [b, &nonce.to_be_bytes()].concat();
        match G1Affine::from_random_bytes(&sha256(&c)) {
            Some(v) => {
                return v.mul_by_cofactor_to_group().into_affine();
            }
            None => nonce += 1,
        }
    }
}

// TODO: change to expect Pairing output?
pub fn h2<G: CanonicalSerialize>(g: G) -> Vec<u8> {
    // let mut out = Vec::with_capacity(g.compressed_size());
    let mut out = Vec::new();
    g.serialize_compressed(&mut out).unwrap();
    sha256(&out)
}

// Q: Should add add a const to the signature so I can enforce sized inputs?
// right now this works with any size slices
/// H_3: {0,1}^n x {0, 1}^m -> Z_p
pub fn h3(a: & [u8], b: &[u8]) -> Fr {
    let mut input = Vec::new();
    input.extend_from_slice(a);
    input.extend_from_slice(b);
    let hash = sha256(&input);
    Fr::from_be_bytes_mod_order(&hash)
}

/// H_4: {0, 1}^n -> {0, 1}^n
pub fn h4(a: &[u8]) -> Vec<u8> {
    let o = sha256(a);
    o[..a.len()].to_vec()
}

// TODO: proper error handling
/// a helper function to deserialize arkworks elements from bytes
pub fn convert_from_bytes<E: CanonicalDeserialize, const N: usize>(
    bytes: &[u8; N],
) -> Option<E> {
	E::deserialize_compressed(&bytes[..]).ok()
}

// should it be an error instead?
/// a helper function to serialize arkworks elements to bytes
pub fn convert_to_bytes<E: CanonicalSerialize, const N: usize>(k: E) -> [u8;N] {
	let mut out = Vec::with_capacity(k.compressed_size());
	k.serialize_compressed(&mut out).unwrap_or(());
	let o: [u8; N] = out.try_into().unwrap_or([0;N]);
	o
}

#[cfg(test)]
mod test {
    
    #[test]
    fn utils_can_calc_sha256() {
        let actual = crate::utils::sha256(b"test");
        let expected = vec![159, 134, 208, 129, 136, 76, 125, 101, 154, 47, 234, 160, 197, 90, 208, 21, 163, 191, 79, 27, 43, 11, 130, 44, 209, 93, 108, 21, 176, 240, 10, 8];
        assert_eq!(actual, expected);
    }
}

// cargo test --features paillier
#[cfg(test)]
#[cfg(feature = "paillier")]
mod pailler_test {
    #[test]
    fn paillier_can_create_and_inspect_keys() {
        let kp = crate::utils::paillier_create_keypair().unwrap();
        let ek = crate::utils::paillier_create_keys(kp).ok();
    }
}