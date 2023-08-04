use aes_gcm::{
    aead::{AeadCore, AeadInPlace, KeyInit, OsRng, heapless::Vec},
    Aes256Gcm, Nonce, // Or `Aes128Gcm`
};

pub fn encrypt(message: &[u8], pubkey: Vec<u8>) -> Vec<u8> {
    
    let key = Aes256Gcm::generate_key(&mut OsRng);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message

    let mut buffer: Vec<u8, 128> = Vec::new(); // Note: buffer needs 16-bytes overhead for auth tag
    buffer.extend_from_slice(message);
    // Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
    cipher.encrypt_in_place(&nonce, b"", &mut buffer)?;
    // `buffer` now contains the message ciphertext
    assert_ne!(&buffer, b"plaintext message");
    // Decrypt `buffer` in-place, replacing its ciphertext context with the original plaintext
    cipher.decrypt_in_place(&nonce, b"", &mut buffer)?;
    assert_eq!(&buffer, b"plaintext message");

    Vec::new();
}
