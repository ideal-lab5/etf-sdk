use ark_bls12_381::{Fr, G1Projective as G};
use ark_ec::CurveGroup;
use ark_serialize::CanonicalSerialize;
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
use paillier::{EncryptionKey, Paillier};
use crate::utils::hash_to_g1;
use crate::encryption::aes::{interpolate};

type AuxData = Vec<u8>;

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

// no proof yet
#[derive(Clone, PartialEq, Copy, Debug)]
pub struct Capsule {
    // field element where evaluation took place
    pub eval: Fr,
    // an encrypted secret
    pub v: Fr,
    // an encrypted secret (blinding)
    pub v_hat: Fr,
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
        next_committee: &[PublicKey],
        t: u8,
        mut rng: R,
    ) -> BTreeMap<PublicKey, Capsule> {
        // f(x) -> [f(0), {(1, f(1)), ..., (n, f(n))}]
        let evals: BTreeMap<Fr, Fr> = generate_shares_checked(
            msk, next_committee.len() as u8, t, &mut rng);
        // f_hat(x) (blinding polynomial)
        let evals_hat: BTreeMap<Fr, Fr> = generate_shares_checked(
            msk_hat, next_committee.len() as u8, t, &mut rng);
        // merge the evaluations
        let mut result: BTreeMap<PublicKey, Capsule> = BTreeMap::new();

        // check that evals.len == evals_hat.len == next_committe.len ?

        for (idx, member) in next_committee.iter().enumerate() {
            let f_elem = Fr::from((idx as u8) + 1);
            // TODO: handle error
            let u = evals.get(&f_elem).unwrap();
            let u_hat = evals_hat.get(&f_elem).unwrap();

            // TODO: Encryption + ZKPoK
            // research alternatives to Paillier.. FHE?

            let commitment = params.g.mul(u) + params.h.mul(u_hat);

            result.insert(
                member.clone(),
                Capsule {
                    eval: f_elem,
                    v: *u,
                    v_hat: *u_hat,
                    commitment: commitment,
                }
            );
        };

        result
    }

    /// decrypt shares + authenticate
    /// outputs (s, s_hat, commitment)
    fn authenticate_shares(
        params: ACSSParams, 
        sk: Fr, 
        capsule: Capsule
    ) -> (Fr, Fr, G)  {
        // TODO: degree check here
        // // decrypt v
        // let s = ElGamal::<G>::decrypt(
        //     &self.params, sk.clone(), capsule.v).unwrap();
        // // decrypt v_hat
        // let s_hat= ElGamal::<G>::decrypt(
        //     &self.params, sk, capsule.v_hat).unwrap();
        // compute g^s h^s
        let c = params.g.mul(capsule.v.clone()) + params.h.mul(capsule.v_hat.clone());
        assert!(capsule.commitment.eq(&c));
        (capsule.v.into(), capsule.v_hat.into(), capsule.commitment)
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

    // // NOTE: This assumes that all participants agree on the ORDER of the committee
    // #[test]
    // pub fn basic_share_generation_and_recovery_works() {
    //     // generate all keys
    //     let next_committee_keys = (0..3).map(|_| { Paillier::keypair().keys() });
    //     // 
    //     let next_committee = next_committee_keys.iter().map(|m| m.p);
    //     let t = 3u8;
    //     let g = G::generator();
    //     // // TODO: we need to find another generator...
    //     let h = G::generator();
    //     let params = ACSSParams { g, h };

    //     let msk = Fr::rand(&mut test_rng());
    //     let msk_hat = Fr::rand(&mut test_rng());

    //     // let acss = HighThresholdACSS::new(params);
    //     let shares: BTreeMap<u8, Capsule> = 
    //         HighThresholdACSS::produce_shares(
    //             params, msk, msk_hat, &next_committee, t, test_rng());

    //     // then we should be able to recover msk and msk_hat via lagrange
    //     let mut first_poly_evals: Vec<(Fr, Fr)> = Vec::new();
    //     for (idx, member) in next_committee.iter().enumerate() {
    //         let cap = shares.get(member).unwrap();
    //         first_poly_evals.push((Fr::from(cap.eval), cap.v));
    //     };

    //     let mut blinding_poly_evals: Vec<(Fr, Fr)> = Vec::new();
    //     for (idx, member) in next_committee.iter().enumerate() {
    //         let cap = shares.get(member).unwrap();
    //         blinding_poly_evals.push((Fr::from(cap.eval), cap.v_hat));
    //     };

    //     let first_recovered_secret = crate::encryption::aes::interpolate(first_poly_evals);
    //     assert_eq!(msk, first_recovered_secret);

    //     let blinding_poly_secret = crate::encryption::aes::interpolate(blinding_poly_evals);
    //     assert_eq!(msk_hat, blinding_poly_secret);
    // }

    // we want to show:
    // Given a committee that holds a secret msk where each member has  secret share,
    // we want to share the msk with a new committee while only providing new shares
    #[test]
    pub fn basic_reshare_works() {
        // generate initial committee keys
        let initial_committee_keys = (0..3).map(|_| { Paillier::keypair().keys() });
        let next_committee_keys = (0..5).map(|_| { Paillier::keypair().keys() });
        // then flatmap to public keys

        let initial_committee: Vec<WrappedEncryptionKey> = initial_committee_keys
            .map(|c| WrappedEncryptionKey(c.0))
            .collect::<Vec<_>>();
        let next_committee = next_committee_keys
            .map(|c| WrappedEncryptionKey(c.0))
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
        initial_committee.iter().for_each(|c| {
            let member_secret = initial_committee_shares.get(c).unwrap();
            // and they each create a resharing of their secrets
            let next_committee_resharing: BTreeMap<WrappedEncryptionKey, Capsule> = 
                HighThresholdACSS::<WrappedEncryptionKey>::produce_shares(
                    params.clone(),
                    member_secret.v, 
                    member_secret.v_hat, 
                    &next_committee, 
                    next_committee_threshold, 
                    test_rng(),
            );
            assert!(next_committee_resharing.keys().len().eq(&next_committee.len()));
            simulated_broadcast.insert(c.clone(), next_committee_resharing);
        });

        let mut new_committee_sks = Vec::new();
        let mut new_committee_blinding_sks = Vec::new();

        // now, next committee members verify + derive
        next_committee.iter().for_each(|new_member| {
            // collect each new member's shares from the old committee
            let mut my_shares: Vec<Capsule> = Vec::new();
            initial_committee.iter().for_each(|old_member| {
                // get the share they gave us
                my_shares.push(*simulated_broadcast.get(old_member)
                    .unwrap()
                    .get(new_member)
                    .unwrap());
            });

            // then each member of the new committee interpolates their new secrets
            let coeffs: Vec<Fr> = my_shares.iter().map(|c| c.v).collect::<Vec<_>>();
            let blinding_coeffs: Vec<Fr> = my_shares.iter().map(|c| c.v_hat).collect::<Vec<_>>();

            let evals = coeffs.iter().enumerate().map(|(i, c)| (Fr::from((i as u8) + 1), *c)).collect::<Vec<_>>();
            let blinding_evals = blinding_coeffs.iter().enumerate().map(|(i, c)| (Fr::from((i as u8) + 1), *c)).collect::<Vec<_>>();

            let sk = crate::encryption::aes::interpolate(evals);
            // panic!("{:?}", sk);
            new_committee_sks.push(sk);
            let blinding_sk = crate::encryption::aes::interpolate(blinding_evals);
            new_committee_blinding_sks.push(blinding_sk);
        });

        // then we can interpolate these sks and blinding_sks to recover the original msk, msk_hat
        let new_committee_evals = new_committee_sks.iter().enumerate().map(|(idx, item)| {
            (Fr::from((idx as u8) + 1), *item)
        }).collect::<Vec<_>>();

        // panic!("{:?}", new_committee_evals);
        let recovered_sk = crate::encryption::aes::interpolate(new_committee_evals);
        assert_eq!(msk, recovered_sk);

        let new_committee_blinding_evals = new_committee_blinding_sks.iter().enumerate().map(|(idx, item)| {
            (Fr::from((idx as u8) + 1), *item)
        }).collect::<Vec<_>>();

        let recovered_blinding_sk = crate::encryption::aes::interpolate(new_committee_blinding_evals);
        assert_eq!(msk_hat, recovered_blinding_sk);
    }
}
