use ark_bls12_381::{
    Bls12_381, Fr,
    G1Projective as G1, G1Affine,
    G2Projective as G2, G2Affine, 
};
use ark_ec::{
    AffineRepr, CurveGroup, Group,
    pairing::Pairing,
};
use ark_serialize::CanonicalSerialize;
use ark_std::{
    ops::Mul,
    rand::Rng,
    Zero,
};
use sha2::Digest;

use rand_chacha::{
    ChaCha20Rng,
    rand_core::{RngCore, SeedableRng},
};

#[derive(PartialEq, Clone)]
pub struct IbSignature {
    pub s: G1,
    pub t: G2,
}

// BF IBE Scheme
// fn main() {
//     // assume n participants
//     let n = 10;
//     // each one should have its own BLS keys e.g. (x, xP)
//     let mut keys = Vec::new();
//     let mut rng = ChaCha20Rng::seed_from_u64(23u64);
//     for i in 0..n {
//         let x = Fr::from(rng.next_u64());
//         let y = G2::generator().mul(x);
//         keys.push((x, y));
//     }
//     // every participant knows the msk...
//     // could be replaced by an MPC protocol
//     let msk = Fr::from(rng.next_u64());
//     let mpk = G2::generator().mul(msk);

//     // each participant needs an identity in G2
//     let mut ids = Vec::new();
//     // let mut pubkeys = Vec::new();
//     for (x, y) in keys.iter() {
//         let mut id = Vec::new();
//         y.serialize_compressed(&mut id).unwrap();
//         ids.push(id.clone());
//     }
//     // sign a message
//     let message = b"yip yip!";
//     let pk = hash_to_g1(&ids[0]);
//     // in a real world example, this would happen some time later...
//     let sk = pk.clone().mul(msk);
//     let signature = sign(sk, message, rng.clone());

//     let is_valid = verify(signature.clone(), &ids[0], hash_to_g1(message).into(), mpk);
//     assert!(is_valid);

//     let is_not_valid = verify(signature, &ids[1], hash_to_g1(message).into(), mpk);
//     assert!(is_not_valid == false);

//     // test encryption  and decryption
//     // TODO: need MapToPoint impl
//     let message = b"test_test_test_test_test_test_00";
//     let ct = encrypt(&ids[1], mpk, message, rng.clone());
//     let sk1 = hash_to_g1(&ids[1]).mul(msk);
//     let recovered_message = decrypt(sk1, ct);
//     assert!(recovered_message == message);
// }

/// sign a message given a secret key
/// 
fn sign<R: Rng + Sized>(sk: G1, m: &[u8], mut rng: R) -> IbSignature {
    let r = Fr::from(rng.next_u64());
    let s: G1 = sk + hash_to_g1(m).mul(r.clone());
    let t = G2::generator().mul(r);
    IbSignature { s, t }
}

/// verify an identity based signature, given an identity, message, and system params
fn verify(
    signature: IbSignature, 
    id: &[u8], 
    m: G1, 
    mpk: G2,
) -> bool {
    let lhs = Bls12_381::pairing(signature.s, G2::generator());
    let rhs = Bls12_381::pairing(hash_to_g1(id), mpk) + Bls12_381::pairing(m, signature.t);
    lhs == rhs
}

fn encrypt<R: Rng + Sized>(
    mpk: G2,
    m: &[u8;32],
    id: &[u8],
    mut rng: R,
) -> (G2, Vec<u8>) {
    let r = Fr::from(rng.next_u64());
    let u = G2::generator().mul(r);
    let g_id = Bls12_381::pairing(hash_to_g1(&id), mpk);
    let mut v = Vec::new();
    g_id.mul(r).serialize_compressed(&mut v).unwrap();
    v = sha256(&v);
    for i in 0..32 {
        v[i] ^= m[i];
    }
    (u, v.to_vec())
}

/// decrypts a message using the provided key
pub fn decrypt(
    ciphertext: (G2, Vec<u8>),
    sk: G1,
) -> Vec<u8> {
    let r = Bls12_381::pairing(sk, ciphertext.0);
    let mut ret = Vec::new();
    r.serialize_compressed(&mut ret).unwrap();
    ret = sha256(&ret);
    // decode the message
    for (i, ri) in ret.iter_mut().enumerate().take(32) {
        *ri ^= ciphertext.1[i];
    }
    ret
}

fn sha256(b: &[u8]) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b);
    hasher.finalize().to_vec()
}

/// {0, 1}^* -> G1
fn hash_to_g1(b: &[u8]) -> G1Affine {
    let mut nonce = 0u32;
    loop {
        let c = [b, &nonce.to_be_bytes()].concat();
        match G1Affine::from_random_bytes(&sha256(&c)) {
            Some(v) => {
                // if v.is_in_correct_subgroup_assuming_on_curve() { return v.into(); }
                return v.mul_by_cofactor_to_group().into_affine();
            }
            None => nonce += 1,
        }
    }
}

///{0, 1}^* -> G2
fn hash_to_g2(b: &[u8]) -> G2Affine {
    let mut nonce = 0u32;
    loop {
        let c = [b, &nonce.to_be_bytes()].concat();
        match G2Affine::from_random_bytes(&sha256(&c)) {
            Some(v) => {
                // if v.is_in_correct_subgroup_assuming_on_curve() { return v.into(); }
                return v.mul_by_cofactor_to_group().into_affine();
            }
            None => nonce += 1,
        }
    }
}