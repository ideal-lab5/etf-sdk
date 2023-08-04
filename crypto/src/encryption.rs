use aes_gcm::{
    aead::{AeadCore, AeadInPlace, KeyInit, OsRng},
    Aes256Gcm, Nonce, // Or `Aes128Gcm`
};
use generic_array::ArrayLength;

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