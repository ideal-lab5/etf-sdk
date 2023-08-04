use ark_bls12_381::{
    Bls12_381, Fr,
    G1Projective as G1, G1Affine,
    G2Projective as G2, 
};
use ark_ec::{
    AffineRepr, CurveGroup,
    pairing::Pairing,
};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_std::{
    ops::Mul,
    rand::Rng,
};
use sha2::Digest;

/// a ciphertext (U, V, W)
pub struct Ciphertext {
    pub u: G2,
    pub v: Vec<u8>,
    pub w: Vec<u8>,
}

/// a struct to hold IBE public params
pub struct Ibe {
    pub ibe_pp: G2,
    pub p_pub: G2,
}

/// the IBE implementation
/// based on the BF-IBE except using bilinear map from G1 * G2 -> G2
///
impl Ibe {

    /// setup the IBE, providing public parameters
    ///could include a proof that P_pub was calculated from sP ?
    pub fn setup(ibe_pp: G2, p_pub: G2) -> Self {
        Self { ibe_pp, p_pub }
    }

    /// encrypt the message for the given identity
    ///
    /// * `message`: The message to encrypt
    /// * `identity`: The identity for which the message will be encrypted
    /// * `rng`: A random number generator
    ///
    pub fn encrypt<R: Rng + Sized>(
        &self,
        message: &[u8;32],
        identity: &[u8],
        mut rng: R,
    ) -> Ciphertext {
        // random sigma in {0, 1}^32
        let t: Vec<u8> = (0..32).map(|_| rng.next_u32() as u8).collect();
        let sigma = h4(&t);
        // r= H3(sigma, message)
        let r = h3(&sigma, message);
        // U = rP
        let u: G2 = self.ibe_pp.mul(r); // U = rP
    
        // calc identity point
        let q = hash_to_g1(&identity);
        // e(Q_id, P_pub)
        let g_id = Bls12_381::pairing(q, self.p_pub).mul(r);
        // sigma (+) H2(e(Q_id, P_pub))
        let v_rhs = h2(g_id);
        let v_out = cross_product_32(&sigma, &v_rhs);
        // message (+) H4(sigma)
        let w_rhs = h4(&sigma);
        let w_out = cross_product_32(message, &w_rhs);
        // (rP, sigma (+) H2(e(Q_id, P_pub)), message (+) H4(sigma))
        Ciphertext { u: u, v: v_out.to_vec(), w: w_out.to_vec() }
    }

    /// decrypts a message using the provided key
    /// * `ciphertext`: The ciphertext to decrypt
    /// * `sk`: The appropriate identity's secret key
    ///
    pub fn decrypt(
        &self,
        ciphertext: Ciphertext,
        sk: G1,
    ) -> Vec<u8> {
        // sigma = V (+) H2(e(d_id, U))
        let sigma_rhs = h2(Bls12_381::pairing(sk, ciphertext.u));
        let sigma = cross_product_32(&ciphertext.v, &sigma_rhs);

        // m = W (+) H4(sigma)
        let m_rhs = h4(&sigma);
        let m = cross_product_32(&ciphertext.w, &m_rhs);

        // check: U =? rP
        let r = h3(&sigma, &m);
        let u_check = self.ibe_pp.mul(r);
        assert!(u_check.eq(&ciphertext.u));

        m
    }

}

fn cross_product_32(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut o = a.clone().to_owned();
    for (i, ri) in o.iter_mut().enumerate().take(32) {
        *ri ^= b[i];
    }
    o.to_vec()
}

/// sha256 hasher
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

// TODO: change to expect Pairing output?
fn h2<G: CanonicalSerialize>(g: G) -> Vec<u8> {
    // let mut out = Vec::with_capacity(g.compressed_size());
    let mut out = Vec::new();
    g.serialize_compressed(&mut out).unwrap();
    sha256(&out)
}

// Q: Should add add a const to the signature so I can enforce sized inputs?
// right now this works with any size slices
/// H_3: {0,1}^n x {0, 1}^m -> Z_p
fn h3(a: & [u8], b: &[u8]) -> Fr {
    let mut input = Vec::new();
    input.extend_from_slice(a);
    input.extend_from_slice(b);
    let hash = sha256(&input);
    Fr::from_be_bytes_mod_order(&hash)
}

/// H_4: {0, 1}^n -> {0, 1}^n
fn h4(a: &[u8]) -> Vec<u8> {
    let o = sha256(a);
    o[..a.len()].to_vec()
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_chacha::{
        ChaCha20Rng,
        rand_core::SeedableRng,
    };
    use ark_std::UniformRand;
    use ark_ec::Group;

    #[test]
    pub fn can_encrypt() {
        // setup
        let id_string = b"example@test.com";
        // a dummy message
        let message: [u8;32] = [2;32];
        let mut rng = ChaCha20Rng::seed_from_u64(23u64);
        // every participant knows the msk...
        // could be replaced by an MPC protocol
        let msk = Fr::from(rng.next_u64());
        // a random element of G1, the IBE public parameter
        let ibe_pp = G2::rand(&mut rng);
        let p_pub = ibe_pp.mul(msk);

        let ibe = Ibe::setup(ibe_pp, p_pub);
        let ct = ibe.encrypt(&message, id_string, &mut rng);
        // then calculate our own secret
        let d = hash_to_g1(id_string).mul(msk);

        let recovered_message = ibe.decrypt(ibe_pp, ct, d);
        let message_vec = message.to_vec();
        assert_eq!(message_vec, recovered_message);
    }

}