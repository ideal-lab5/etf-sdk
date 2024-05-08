// #[cfg_attr(tarpaulin, skip)]
// use etf_crypto_primitives::{
//     proofs::{dleq::DLEQProof, verifier::DleqVerifier},
//     ibe::fullident::Ibe,
//     encryption::tlock::{AesIbeCt, Tlock, DecryptionResult},
// };

// use rand_chacha::ChaCha20Rng;
// use ark_std::rand::SeedableRng;
// use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

// #[derive(Debug)]
// pub enum Error {
//     EncryptionError,
//     DecryptionError,
// }

// #[cfg_attr(tarpaulin, skip)]
// // these are the funcs that I want to compile to wasm
// pub trait EtfApi<D: DleqVerifier, I: Ibe, E: Tlock<I>> {

//     /// verify the DLEQ proof
//     fn verify(
//         id: Vec<u8>, 
//         dleq_proof: DLEQProof,
//         extras: Vec<u8>,
//     ) -> bool;

//     /// encrypt the message for the given slot ids
//     fn encrypt(
//         ibe_pp_bytes: Vec<u8>, 
//         p_pub: Vec<u8>, 
//         message: &[u8], 
//         slot_ids: Vec<Vec<u8>>, 
//         t: u8,
//         seed: &[u8],
//     ) -> Result<AesIbeCt, Error>;

//     // decrypt the message with the given sk
//     fn decrypt(
//         ibe_pp_bytes: Vec<u8>,
//         ciphertext: Vec<u8>,
//         nonce: Vec<u8>,
//         capsule: Vec<Vec<u8>>, 
//         sks: Vec<Vec<u8>>,
//     ) -> Result<DecryptionResult, Error>;
// }

// ///  the default implementation of the etf api
// /// https://stackoverflow.com/questions/50200197/how-do-i-share-a-struct-containing-a-phantom-pointer-among-threads
// #[derive(Debug, CanonicalSerialize, CanonicalDeserialize)]
// // pub struct DefaultApi<D: DleqVerifier, I: Ibe, E: Tlock<I>> {
// pub struct DefaultApi<D: DleqVerifier, I: Ibe, E: Tlock<I>> {
//     // ibe: BfIbe,
//     _d: ark_std::marker::PhantomData<fn() -> D>,
//     _i: ark_std::marker::PhantomData<fn() -> I>,
//     _e: ark_std::marker::PhantomData<fn() -> E>,
// }

// #[cfg_attr(tarpaulin, skip)]
// impl<D: DleqVerifier, I: Ibe, E: Tlock<I>> EtfApi<D, I, E> for DefaultApi<D, I, E>  {

//     /// verify a dleq proof using the IbeDleqVerifier
//     /// The verifier expects a specific G1 generator and a specific hash to g1 function
//     /// which the dleq proof must have used, otherwise it will fail
//     ///
//     /// * `id`:
//     /// * `proof`:
//     /// * `extras`: 
//     ///
//     #[cfg_attr(tarpaulin, skip)]
//     fn verify(
//         id: Vec<u8>,
//         proof: DLEQProof,
//         extras: Vec<u8>,
//     ) -> bool {
//         D::verify(id, proof, extras)
//     }

//     /// encrypt a message using AES-GCM
//     /// with the ephemeral secret split into shares and encrypted for the future slot ids
//     /// TODO: more intelligent error mapping...
//     ///
//     fn encrypt(
//         ibe_pp_bytes: Vec<u8>,
//         p_pub_bytes: Vec<u8>,
//         message: &[u8], 
//         slot_ids: Vec<Vec<u8>>,
//         t: u8,
//         seed: &[u8],
//     ) -> Result<AesIbeCt, Error> {
//         let seed_hash = etf_crypto_primitives::utils::sha256
//             (&etf_crypto_primitives::utils::sha256(seed));
//         let rng = ChaCha20Rng::from_seed(seed_hash.try_into().expect("should be 32 bytes; qed"));
//         let res = E::encrypt(ibe_pp_bytes, p_pub_bytes, message, slot_ids, t, rng)
//             .map_err(|_| Error::EncryptionError)?;
//         Ok(res)
//     }

//     fn decrypt(
//         ibe_pp_bytes: Vec<u8>,
//         ciphertext: Vec<u8>,
//         nonce: Vec<u8>,
//         capsule: Vec<Vec<u8>>, 
//         sks: Vec<Vec<u8>>,
//     ) -> Result<DecryptionResult, Error> {
//         let res = E::decrypt(ibe_pp_bytes, ciphertext, nonce, capsule, sks)
//             .map_err(|_| Error::DecryptionError)?;
//         Ok(res)
//     }
// }

// #[cfg(test)]
// pub mod tests {
//     use super::*;
//     use ark_std::{test_rng, UniformRand, ops::Mul, rand::{CryptoRng, Rng}};
//     use ark_bls12_381::{G1Affine as G1, G2Affine as G2, G1Projective, G2Projective, Fr};
//     use ark_ec::AffineRepr;
//     use ark_serialize::CanonicalSerialize;
//     use etf_crypto_primitives::{
//         utils::hash_to_g1,
//         encryption::tlock::{AesIbeCt, ClientError},
//         ibe::fullident::{IbeCiphertext, Ibe, IbeError},
//         encryption::aes::AESOutput,
//         utils::convert_to_bytes,
//     };


//     // A mock implementation of DleqVerifier trait for testing
//     struct MockDleqVerifier;

//     impl DleqVerifier for MockDleqVerifier {
//         // Implement the required methods for the trait
//         fn verify(_id: Vec<u8>, _proof: DLEQProof, _extras: Vec<u8>) -> bool {
//             true
//         }
//     }
 
//     // A mock implementation of Tlock trait for testing
//     struct MockTlock;

//     impl<I: Ibe> Tlock<I> for MockTlock {
//         // Implement the required methods for the trait
 
//         fn encrypt<R: Rng + CryptoRng + Sized>(
//             _p: Vec<u8>, _q: Vec<u8>, _m: &[u8], _ids: Vec<Vec<u8>>, _t: u8, _rng: R,
//         ) -> Result<AesIbeCt, ClientError> {
//             Ok(AesIbeCt {
//                 aes_ct: AESOutput {
//                     ciphertext: vec![1, 2, 3],
//                     nonce: vec![2, 3, 4],
//                     key: vec![3, 4, 5],
//                 },
//                 etf_ct:  vec![vec![4], vec![5], vec![6]].into(),
//             })
//         }
//         fn decrypt(
//             _p: Vec<u8>, 
//             _ct: Vec<u8>, 
//             _nonce: Vec<u8>, 
//             _capsule: Vec<Vec<u8>>, 
//             _secrets: Vec<Vec<u8>>
//         ) -> Result<DecryptionResult, ClientError> {
//             Ok(DecryptionResult{ message: vec![5, 6, 7], secret: vec![7, 8, 9] })
//         }
//     }

//     struct MockIbe;

//     impl Ibe for MockIbe {
//         fn encrypt<R: Rng + Sized>(
//             ibe_pp: G2Projective, 
//             _p_pub: G2Projective,
//             _message: &[u8;32], 
//             _identity: G1Projective, 
//             _rng: R
//         ) -> IbeCiphertext {
//             IbeCiphertext{ u: ibe_pp, v: Vec::new(), w: Vec::new() }
//         }
    
//         fn decrypt(_ibe_pp: G2Projective, _ciphertext: IbeCiphertext, _sk: G1Projective) -> Result<Vec<u8>, IbeError> {
//             Ok(Vec::new())
//         }
//     }
 
//     #[test]
//     fn default_api_can_verify() {
//         let x = Fr::rand(&mut test_rng());
//         let id = b"test";
//         let g = G1::generator();
//         let h = hash_to_g1(id);


//         // create IBE public parameters
//         let ibe_pp: G2 = G2::generator().into();
//         let s = Fr::rand(&mut test_rng());
//         let p_pub: G2 = ibe_pp.mul(s).into();

//         let mut ibe_pp_bytes = Vec::new();
//         ibe_pp.serialize_compressed(&mut ibe_pp_bytes).unwrap();

//         let mut p_pub_bytes = Vec::new();
//         p_pub.serialize_compressed(&mut p_pub_bytes).unwrap();

//         let proof = DLEQProof::new(x, g, h, vec![], test_rng());
//         assert!(
//             DefaultApi::<MockDleqVerifier, MockIbe, MockTlock>::verify(
//                 id.to_vec(), proof, vec![]) == true);
//     }

//     #[test]
//     fn api_encryption_works() {
//         let message = b"this is a test";
//         let slot_ids = vec![b"sl1".to_vec(), b"sl2".to_vec(), b"sl3".to_vec()];
//         let t = 2;
//         let ibe_pp: G2 = G2::generator().into();
//         let s = Fr::rand(&mut test_rng());
//         let p_pub: G2 = ibe_pp.mul(s).into();

//         let ibe_pp_bytes = convert_to_bytes::<G2, 96>(ibe_pp);
//         let p_pub_bytes = convert_to_bytes::<G2, 96>(p_pub);

//         match DefaultApi::<MockDleqVerifier, MockIbe, MockTlock>::
//             encrypt(ibe_pp_bytes.to_vec(), p_pub_bytes.to_vec(), message, slot_ids, t, b"seed") {
//                 Ok(_) => { },
//                 Err(_) => { panic!("the encrypt call should work") },
//         }
//     }

//     #[test]
//     fn api_decryption_works() {
//         match DefaultApi::<MockDleqVerifier, MockIbe, MockTlock>::
//             decrypt(vec![], vec![], vec![], vec![vec![1]], vec![]) {
//                 Ok(_) => { },
//                 Err(_) => { panic!("the decrypt call should work") },
//         }
//     }
// }