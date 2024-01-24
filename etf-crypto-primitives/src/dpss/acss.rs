use ark_bls12_381::{Fr, G1Projective as G};
use ark_ec::CurveGroup;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_ff::{UniformRand, Zero};
use ark_crypto_primitives::encryption::{
    AsymmetricEncryptionScheme, 
    elgamal::{
        Ciphertext, 
        ElGamal, 
        Parameters, 
        Randomness,
    },
};
use ark_poly::{
    polynomial::univariate::DensePolynomial,
    DenseUVPolynomial, Polynomial,
};
use ark_std::{
    cmp::Ordering,
    marker::PhantomData,
    ops::Mul,
    vec::Vec, 
    rand::Rng,
    collections::BTreeMap,
};
use paillier::{
    Decrypt,
    DecryptionKey,
    EncodedCiphertext, 
    Encrypt, 
    EncryptionKey, 
    Paillier,
};
use crate::utils::hash_to_g1;
use crate::encryption::aes::{interpolate};

/// errors for the DPSS reshare algorithm
#[derive(Debug)]
pub enum ACSSError {
    /// the ciphertext could not be decrypted
    InvalidCiphertext,
    /// the commitment could not be verified
    InvalidCommitment,
}

// A wrapper for EncryptionKey 
#[derive(Clone)]
pub struct WrappedEncryptionKey(pub EncryptionKey);

impl Eq for WrappedEncryptionKey {}

impl PartialEq for WrappedEncryptionKey {
    fn eq(&self, other: &Self) -> bool {
        // Check equality based on both 'n' and 'nn' fields
        self.0.n == other.0.n && self.0.nn == other.0.nn
    }
}

impl Ord for WrappedEncryptionKey {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare based on the ordering of the 'n' field
        match self.0.n.cmp(&other.0.n) {
            Ordering::Equal => {
                // If 'n' is equal, compare based on the 'nn' field
                self.0.nn.cmp(&other.0.nn)
            }
            ordering => ordering,
        }
    }
}

impl PartialOrd for WrappedEncryptionKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl WrappedEncryptionKey {
    pub fn into_inner(self) -> EncryptionKey {
        self.0
    }
}

// no proof yet
#[derive(Clone, PartialEq, Debug)]
pub struct Capsule {
    // field element where evaluation took place
    pub eval: Fr,
    // an encrypted secret
    pub v: EncodedCiphertext<Vec<u64>>,
    // an encrypted secret (blinding)
    pub v_hat: EncodedCiphertext<Vec<u64>>,
    // pedersen committment
    pub commitment: G,
}

#[derive(Clone, PartialEq)]
pub struct ACSSParams {
    g: G,
    h: G,
}

/// the high threshold asynchronous complete secret sharing struct
pub struct HighThresholdACSS<PublicKey> {
    params: ACSSParams,
    _phantom: PhantomData<PublicKey>,
}

impl<PublicKey> HighThresholdACSS<PublicKey> 
    where PublicKey: Ord + Clone {

    /// as a semi-trusted dealer, construct shares for the initial committee
    /// `params`: ACSS Params
    /// `msk`: the master secret key
    /// `msk_hat`: the blinding secret key
    /// `next_committee`: The next committee to generate shares for
    /// `t`: The threshold (t <= n)
    /// `rng`: A random number generator
    ///
    /// TODO:
    /// - Encryption + ZKPoK
    pub fn produce_shares<R: Rng + Sized>(
        params: ACSSParams,
        msk: Fr, 
        msk_hat: Fr,
        next_committee: &[WrappedEncryptionKey],
        t: u8,
        mut rng: R,
    ) -> BTreeMap<WrappedEncryptionKey, Capsule> {
        // f(x) -> [f(0), {(1, f(1)), ..., (n, f(n))}]
        let evals: BTreeMap<Fr, Fr> = generate_shares_checked(
            msk, next_committee.len() as u8, t, &mut rng);
        // f_hat(x) (blinding polynomial)
        let evals_hat: BTreeMap<Fr, Fr> = generate_shares_checked(
            msk_hat, next_committee.len() as u8, t, &mut rng);
        // merge the evaluations
        let mut result: BTreeMap<WrappedEncryptionKey, Capsule> = BTreeMap::new();

        // check that evals.len == evals_hat.len == next_committe.len ?

        for (idx, member) in next_committee.iter().enumerate() {
            let f_elem = Fr::from((idx as u8) + 1);
            // TODO: handle error
            let u = evals.get(&f_elem).unwrap();
            let mut u_bytes: Vec<u8> = Vec::new();
            u.serialize_compressed(&mut u_bytes).unwrap();

            let u_bytes_64 = u_bytes.iter().map(|u| *u as u64).collect::<Vec<_>>();

            let u_hat = evals_hat.get(&f_elem).unwrap();
            let mut u_hat_bytes: Vec<u8> = Vec::new();
            u_hat.serialize_compressed(&mut u_hat_bytes).unwrap();

            let u_hat_bytes_64 = u_bytes.iter().map(|u| *u as u64).collect::<Vec<_>>();

            // encryption
            let v = Paillier::encrypt(&member.clone().into_inner(), u_bytes_64.as_slice());
            let v_hat = Paillier::encrypt(&member.clone().into_inner(), u_hat_bytes_64.as_slice());
            // TODO: Encryption + ZKPoK
            let commitment = params.g.mul(u) + params.h.mul(u_hat);

            result.insert(
                member.clone(),
                Capsule {
                    eval: f_elem,
                    v: v,
                    v_hat: v_hat,
                    commitment: commitment,
                }
            );
        };

        result
    }

    /// decrypt shares + authenticate
    /// outputs (s, s_hat, commitment)
    pub fn authenticate_shares(
        params: ACSSParams, 
        dk: DecryptionKey,
        capsule: Capsule
    ) -> Result<(Fr, Fr), ACSSError>  {
        // TODO: degree check here
        // decrypt v
        // our values are really u8's casted as u64's, so we need to convert back
        let u_bytes: Vec<u64> = Paillier::decrypt(&dk, &capsule.v);
        let u_u8_bytes: Vec<u8> = u_bytes.iter().map(|u| *u as u8).collect::<Vec<_>>();

        if let Ok(u) = Fr::deserialize_compressed(&u_u8_bytes[..]) {
            let blinding_u_bytes: Vec<u64> = Paillier::decrypt(&dk, &capsule.v_hat);
            let blinding_u_u8_bytes: Vec<u8> = blinding_u_bytes.iter().map(|u| *u as u8).collect::<Vec<_>>();
            // panic!("{:?}", blinding_u_u8_bytes);
            if let Ok(u_blind) = Fr::deserialize_compressed(&blinding_u_u8_bytes[..]) {
                // TODO: is this needed?
                // let c = params.g.mul(u.clone()) + params.h.mul(u_blind.clone());
                // if !c.eq(&capsule.commitment.into_affine()) {
                //     return Err(ACSSError::InvalidCommitment);
                // }

                return Ok((u, u_blind));
            }            
        }
        
        Err(ACSSError::InvalidCiphertext)
    }
}


pub fn generate_shares_checked<R: Rng + Sized>(
    s: Fr, n: u8, t: u8, mut rng: R
) -> BTreeMap<Fr, Fr> {
    
    // if n == 1 {
    //     let r = Fr::rand(&mut rng);
    //     return vec![(Fr::zero(), r)];
    // }

    let mut coeffs: Vec<Fr> = (0..t+1).map(|i| Fr::rand(&mut rng)).collect();
    coeffs[0] = s.clone();

    let f = DensePolynomial::<Fr>::from_coefficients_vec(coeffs);
    let mut out: BTreeMap<Fr, Fr> = BTreeMap::new();
    (1..n+1).for_each(|i| {
        let idx = Fr::from(i);
        let eval = f.evaluate(&idx);
        out.insert(idx, eval);
    });
    out
}

pub mod tests {

    use super::*;
    use ark_std::vec::Vec;
    use ark_bls12_381::Fr;
    use crate::encryption::aes::generate_secrets;
    use rand_chacha::ChaCha20Rng;
    use ark_ec::Group;
    use ark_std::{
        rand::SeedableRng,
        test_rng,
    };

    use paillier::{BigInt, KeyGeneration, EncryptionKey};
    use ark_poly::{
        polynomial::univariate::DensePolynomial,
        DenseUVPolynomial, Polynomial,
    };

    // we want to show:
    // Given a committee that holds a secret msk where each member has  secret share,
    // we want to share the msk with a new committee while only providing new shares
    #[test]
    pub fn basic_reshare_works() {
        // generate initial committee keys
        let initial_committee_keys: Vec<(EncryptionKey, DecryptionKey)> 
            = (0..3).map(|_| { Paillier::keypair().keys() }).collect();
        let next_committee_keys: Vec<(EncryptionKey, DecryptionKey)> 
            = (0..5).map(|_| { Paillier::keypair().keys() }).collect();
        // then flatmap to public keys
        let initial_committee: Vec<WrappedEncryptionKey> = initial_committee_keys
            .iter()
            .map(|c| WrappedEncryptionKey(c.0.clone()))
            .collect::<Vec<_>>();
        let next_committee = next_committee_keys
            .iter()
            .map(|c| WrappedEncryptionKey(c.0.clone()))
            .collect::<Vec<_>>();

        let initial_committee_threshold = 2u8;
        let next_committee_threshold = 3u8;
        let g = G::generator();
        // // TODO: we need to find another generator...
        let h = G::generator();
        let params = ACSSParams { g, h };

        let msk = Fr::rand(&mut test_rng());
        let msk_hat = Fr::rand(&mut test_rng());

        let initial_committee_shares: BTreeMap<WrappedEncryptionKey, Capsule> = 
            HighThresholdACSS::<WrappedEncryptionKey>::produce_shares(
                params.clone(), 
                msk, 
                msk_hat, 
                &initial_committee, 
                initial_committee_threshold, 
                test_rng()
            );

        // simulate a public broadcast channel
        let mut simulated_broadcast: 
            BTreeMap<WrappedEncryptionKey, BTreeMap<WrappedEncryptionKey, Capsule>> = BTreeMap::new();
        // each member of the initial committee 'owns' a secret (identified by matching indices)
        initial_committee_keys.iter().for_each(|c| {
            let member_secrets = initial_committee_shares
                .get(&WrappedEncryptionKey(c.0.clone()))
                .unwrap();
            // authenticate + decrypt shares
            let (u, u_hat) = HighThresholdACSS::<WrappedEncryptionKey>::authenticate_shares(
                params.clone(), c.1.clone(), member_secrets.clone(),
            ).unwrap();
            // and they each create a resharing of their secrets
            let next_committee_resharing: BTreeMap<WrappedEncryptionKey, Capsule> = 
                HighThresholdACSS::<WrappedEncryptionKey>::produce_shares(
                    params.clone(),
                    u,
                    u_hat, 
                    &next_committee, 
                    next_committee_threshold, 
                    test_rng(),
            );
            assert!(next_committee_resharing.keys().len().eq(&next_committee.len()));
            simulated_broadcast.insert(
                WrappedEncryptionKey(c.0.clone()), 
                next_committee_resharing,
            );
        });

        let mut new_committee_sks = Vec::new();
        let mut new_committee_blinding_sks = Vec::new();

        // now, next committee members verify + derive
        next_committee_keys.iter().for_each(|(ek, dk)| {
            // collect each new member's shares from the old committee
            // let mut my_shares: Vec<(Fr, Fr)> = Vec::new();

            let mut coeffs: Vec<Fr> = Vec::new();
            let mut blinding_coeffs: Vec<Fr> = Vec::new();

            initial_committee.iter().for_each(|old_member| {
                // get the share they gave us
                let capsule = simulated_broadcast.get(old_member)
                    .unwrap()
                    .get(&WrappedEncryptionKey(ek.clone()))
                    .unwrap();
                // authenticate and decrypt
                let (u, u_hat) = HighThresholdACSS::<WrappedEncryptionKey>::authenticate_shares(
                    params.clone(),
                    dk.clone(),
                    capsule.clone(),
                ).unwrap();
                // store somewhere

                coeffs.push(u);
                blinding_coeffs.push(u_hat);
                // panic!("{:?}", u_hat);
                // my_shares.push((u, u_hat));
            });

            // then each member of the new committee interpolates their new secrets
            let evals = coeffs.iter().enumerate().map(|(i, c)| (Fr::from((i as u8) + 1), *c)).collect::<Vec<_>>();
            let blinding_evals = blinding_coeffs.iter().enumerate().map(|(i, c)| (Fr::from((i as u8) + 1), *c)).collect::<Vec<_>>();
            
            let sk = crate::encryption::aes::interpolate(evals);
            new_committee_sks.push(sk);
            
            let blinding_sk = crate::encryption::aes::interpolate(blinding_evals.clone());
            new_committee_blinding_sks.push(blinding_sk);

            // panic!("{:?}", blinding_evals);
        });

        // panic!("{:?}", new_committee_sks);

        // // then we can interpolate these sks and blinding_sks to recover the original msk, msk_hat
        let new_committee_evals = new_committee_sks.iter().enumerate().map(|(idx, item)| {
            (Fr::from((idx as u8) + 1), *item)
        }).collect::<Vec<_>>();

        let recovered_sk = crate::encryption::aes::interpolate(new_committee_evals);
        assert_eq!(msk, recovered_sk);

        let new_committee_blinding_evals = new_committee_blinding_sks.iter().enumerate().map(|(idx, item)| {
            (Fr::from((idx as u8) + 1), *item)
        }).collect::<Vec<_>>();

        let recovered_blinding_sk = crate::encryption::aes::interpolate(new_committee_blinding_evals);
        assert_eq!(msk_hat, recovered_blinding_sk);
    }
}
