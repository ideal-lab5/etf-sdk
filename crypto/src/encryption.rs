use aes_gcm::{
    aead::{AeadCore, AeadInPlace, KeyInit, OsRng},
    Aes256Gcm, Nonce, // Or `Aes128Gcm`
};
use generic_array::ArrayLength;
use ark_std::rand::Rng;
use ark_bls12_381::Fr;
use ark_ff::{PrimeField, UniformRand};
use ark_poly::{
    polynomial::univariate::DensePolynomial,
    DenseUVPolynomial, Polynomial,
};

pub struct AESOutput {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub key: Vec<u8>,
}

pub enum Error {
    EncryptionError,
}

pub fn aes_encrypt(message: &[u8]) -> Result<AESOutput, Error> {
    let key = Aes256Gcm::generate_key(&mut OsRng);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message

    let mut buffer: Vec<u8> = Vec::new(); // Note: buffer needs 16-bytes overhead for auth tag
    buffer.extend_from_slice(message);
    // Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
    cipher.encrypt_in_place(&nonce, b"", &mut buffer)
        .map_err(|e| Error::EncryptionError)?;
    Ok(AESOutput{ ciphertext: buffer, nonce: nonce.to_vec(), key: key.to_vec() })
}

pub fn aes_decrypt() {
    todo!();
}

pub fn shamir<R: Rng + Sized>(k: [u8;32], n: u8, t: u8, mut rng: R) -> Vec<Fr> {
    // 1. generate t random values
    let s = Fr::from_be_bytes_mod_order(&k);
    let mut coeffs = vec![s];
    let mut rand_coeffs = (1..t+1).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
    coeffs.append(&mut rand_coeffs);
    let f = DensePolynomial::<Fr>::from_coefficients_vec(coeffs);
    let shares = (1..n+1).map(|i| f.evaluate(&Fr::from(i))).collect();
    shares
}

// pub fn decrypt() {
//         // // `buffer` now contains the message ciphertext
//     // assert_ne!(&buffer, b"plaintext message");
//     // // Decrypt `buffer` in-place, replacing its ciphertext context with the original plaintext
//     // cipher.decrypt_in_place(&nonce, b"", &mut buffer)?;
//     // assert_eq!(&buffer, b"plaintext message");
// }


#[cfg(test)]
mod test {
    use super::*;

    fn aes_encrypt_works() {
        assert!(true);
    }
}