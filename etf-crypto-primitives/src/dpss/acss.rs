
/*
 * Copyright 2024 by Ideal Labs, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use ark_serialize::CanonicalDeserialize;
use ark_ff::UniformRand;
use ark_poly::{
    polynomial::univariate::DensePolynomial,
    DenseUVPolynomial, Polynomial,
};
use ark_ec::Group;
use ark_std::{
    marker::PhantomData,
    vec::Vec, 
    rand::{CryptoRng, Rng},
    collections::BTreeMap,
};
use crate::{
    encryption::hashed_el_gamal::HashedElGamal,
    proofs::hashed_el_gamal_sigma::BatchPoK,
};
use w3f_bls::{DoublePublicKey, DoublePublicKeyScheme, EngineBLS, KeypairVT, PublicKey, SecretKeyVT};

/// errors for the ACSS algorithm
#[derive(Debug, PartialEq)]
pub enum ACSSError {
    /// the committee was invalid (either empty or buffer overflow)
    InvalidCommittee,
    /// the ciphertext could not be decrypted
    InvalidCiphertext,
    /// the commitment could not be verified
    InvalidCommitment,
    /// the proof could not be verified
    InvalidProof,
    /// insufficiently many valid proofs of knowledge were provided
    InsufficientValidPoK,
    /// a proof of knowledge could not be generated
    InvalidMessage,
}

/// a double secret holds two elements of the scalar field
pub struct DoubleSecret<E: EngineBLS>(pub E::Scalar, pub E::Scalar);

impl <E: EngineBLS> DoubleSecret<E> {
    /// create a resharing of a double secret with a committee
    ///
    /// * `committee`: The committee to reshare to
    /// * `t`: the threshold (1 < t < committee_size)
    /// * `rng`: a CSPRNG
    ///
    pub fn reshare<R: Rng + CryptoRng>(
        &self, 
        committee: &[PublicKey<E>], 
        t: u8, 
        mut rng: R
    ) -> Result<Vec<(DoublePublicKey<E>, BatchPoK<E::PublicKeyGroup>)>, ACSSError> {
            HighThresholdACSS::<E>::reshare(
                self.0, self.1,
                committee, t, &mut rng
            )
    }
}

/// a wrapper around a keypair vartime...
/// could get confusing with w3f-bls keypair, maybe add conversion?
pub struct Keypair<E: EngineBLS>(pub KeypairVT<E>);

impl<E: EngineBLS> Keypair<E> {
    /// try to recover a double secret key from a resharing
    /// returns none if ACSS recovery fails
    ///
    /// * `pok`: A batch pok
    /// * `threshold`: A minimum number of valid proofs of knowledge requires
    /// note to self: 'pok' is difficult to pluralize, poks doesn't really work since it's proofs of knowledge,
    /// but psok seems even stranger. What if I said 'knowlegde proofs'? pluralized as 'kps'
    pub fn recover(
        &self, 
        pok: BatchPoK<E::PublicKeyGroup>, 
        threshold: u8
    ) -> Result<DoubleSecret<E>, ACSSError> {
        let secret = self.0.secret.0;
        HighThresholdACSS::<E>::recover(secret, vec![pok], threshold)
    }
}
/// the high threshold asynchronous complete secret sharing struct
pub struct HighThresholdACSS<E: EngineBLS> {
    _curve_group: PhantomData<E>,
}

impl<E: EngineBLS> HighThresholdACSS<E> {

    /// Construct a resharing for a committee identified by their public keys
    ///
    /// `msk`: the master secret key
    /// `msk_hat`: the blinding secret key
    /// `committee`: The next committee to generate shares for
    /// `t`: The threshold (1 <= t <= n) (note: if t = 0, this function returns an empty vec)
    /// `rng`: A CSPRNG
    ///
    pub fn reshare<R: CryptoRng + Rng>(
        msk: E::Scalar, 
        msk_hat: E::Scalar,
        committee: &[PublicKey<E>],
        t: u8,
        mut rng: R,
    ) -> Result<Vec<(DoublePublicKey<E>, BatchPoK<E::PublicKeyGroup>)>, ACSSError> {

        if committee.is_empty() {
            return Err(ACSSError::InvalidCommittee);
        }

        // f(x) -> [f(0), {(1, f(1)), ..., (n, f(n))}]
        let evals: BTreeMap<E::Scalar, E::Scalar> = generate_shares_checked::<E, R>(
            msk, committee.len() as u8, t, &mut rng);
        // f_hat(x) (blinding polynomial) -> [f'(0), {(1, f'(1)), ...(n, f'(n))}]
        let evals_hat: BTreeMap<E::Scalar, E::Scalar> = generate_shares_checked::<E, R>(
            msk_hat, committee.len() as u8, t, &mut rng);

        let mut poks: Vec<(DoublePublicKey<E>, BatchPoK<E::PublicKeyGroup>)> = Vec::new();
        for (pk, (u, u_hat)) in committee.iter()
            .zip(evals.iter()
            .zip(evals_hat.iter())) {
            if let Ok(pok) = BatchPoK::prove(&[*u.1, *u_hat.1], pk.0, &mut rng) {
                // lets get a public key while we're at it...
                let etf_pk = SecretKeyVT::<E>(*u.1).into_double_public_key();
                poks.push((etf_pk, pok));
            } else {
                return Err(ACSSError::InvalidMessage)
            }
        }

        Ok(poks)
    }

    /// decrypt shares + authenticate from a collection of batched PoKs
    /// outputs the new share and its blinding share
    /// assumes default generator is used
    //
    pub fn recover(
        sk: E::Scalar,
        poks: Vec<BatchPoK<E::PublicKeyGroup>>,
        threshold: u8,
    ) -> Result<DoubleSecret<E>, ACSSError>  {
        let q = E::PublicKeyGroup::generator() * sk;

        let mut secrets = Vec::new();
        let mut blinding_secrets = Vec::new();

        let mut invalid_poks = Vec::new();

        for (idx, pok) in poks.iter().enumerate() {
              if !pok.verify(q) {
                invalid_poks.push(pok);
                if poks.len() - invalid_poks.len() > threshold as usize {
                    return Err(ACSSError::InsufficientValidPoK);
                };
            }

            let f = E::Scalar::from(idx as u8 + 1);

            let r_bytes = HashedElGamal::decrypt(sk, pok.ciphertexts[0].clone()).unwrap();
            let r = E::Scalar::deserialize_compressed(&r_bytes[..])
                .map_err(|_| ACSSError::InvalidCiphertext)?;
            secrets.push((f, r));

            let r_prime_bytes = HashedElGamal::decrypt(sk, pok.ciphertexts[1].clone()).unwrap();
            let r_prime = E::Scalar::deserialize_compressed(&r_prime_bytes[..])
                .map_err(|_| ACSSError::InvalidCiphertext)?;
            blinding_secrets.push((f, r_prime));
        }

        let s = crate::utils::interpolate::<E::SignatureGroup>(secrets);
        let s_prime = crate::utils::interpolate::<E::SignatureGroup>(blinding_secrets);
        Ok(DoubleSecret::<E>(s, s_prime))
    }
}

/// randomly sample coefficients for a degree t polynomial `f(x)` such that `f(0) = s`
/// then output points {(1, f(1), ..., (n, f(n)))}
/// 
/// `s`: The secret (value of poly at 0)
/// `n`: The number of shares to generate
/// `t`: The threshold (degree of the polynomial)
/// `rng`: A cryptographically secure rng
///
pub fn generate_shares_checked<E: EngineBLS, R: Rng + Sized>(
    s: E::Scalar, 
    n: u8, 
    t: u8, 
    rng: &mut R,
) -> BTreeMap<E::Scalar, E::Scalar> {
    let mut out: BTreeMap<E::Scalar, E::Scalar> = BTreeMap::new();

    // we must have that 0 < t < n, but we don't want an explicit error here
    // so instead, we 'soft fail' by returning an empty map
    // we could reframe this a little bit
    // instead of worrying about the threshold t
    // we could instead consider using the number of allowable invalid shares (i.e. n - t)
    if n == 0 || t == 0 || t > n {
        return out;        
    }
    let mut coeffs: Vec<E::Scalar> = 
        (0..t).map(|_| E::Scalar::rand(rng)).collect();
    coeffs[0] = s;
//
    let f = DensePolynomial::<E::Scalar>::from_coefficients_vec(coeffs);

    (1..n+1).for_each(|i| {
        let idx = E::Scalar::from(i);
        let eval = f.evaluate(&idx);
        out.insert(idx, eval);
    });
    out
}

#[cfg(test)]
pub mod tests {

    use super::*;
    use ark_std::vec::Vec;
    use ark_ec::Group;
    use ark_std::{test_rng, rand::SeedableRng};

    use ark_ff::One;
    use rand_chacha::ChaCha20Rng;

    use crate::utils::convert_to_bytes;

    use w3f_bls::{Keypair, PublicKey, TinyBLS377};

    #[derive(Debug, PartialEq)]
    enum TestStatusReport {
        ReshareSoftFail{ size: u8 },
        ReshareError{ error: ACSSError },
        RecoverError{ error: ACSSError },
        Completed{
            // recovered secret
            a: Vec<u8>, 
            // recovered blinding secret
            b: Vec<u8>,
            // msk
            c: Vec<u8>, 
            // blinding msk
            d: Vec<u8>,
        },
    }

    fn acss_with_engine_bls<E: EngineBLS>(
        m: u8,
        t: u8,
        num_actual_signers: u8,
        num_valid_pok: u8,
        do_fail_bad_recover: bool,
        handler: &dyn Fn(TestStatusReport) -> ()
    ) -> () {
        let mut rng = ChaCha20Rng::seed_from_u64(0);

        let msk = E::Scalar::rand(&mut rng);
        let msk_prime = E::Scalar::rand(&mut rng);

        let double_secret = DoubleSecret::<E>(msk, msk_prime);

        let mut keys: Vec<Keypair<E>> = (0..m).map(|_| {
            Keypair::<E>::generate(test_rng())
        }).collect();

        let initial_committee_public_keys = keys.iter().map(|kp| kp.public).collect::<Vec<_>>();

        let mock_bad_resharing =
            BatchPoK::prove(
                &vec![E::Scalar::one(), E::Scalar::one()], 
                E::PublicKeyGroup::generator(), 
                test_rng()
            ).unwrap();
        // );

        match double_secret.reshare(initial_committee_public_keys.as_slice(), t, &mut rng) {
            Ok(mut resharing) => {
                let mut poks: Vec<BatchPoK<E::PublicKeyGroup>> = resharing
                    .iter()
                    .map(|r| r.1.clone())
                    .collect();
                if resharing.is_empty() {
                    handler(TestStatusReport::ReshareSoftFail{ size: resharing.len() as u8 });

                    if !do_fail_bad_recover {
                        return ();
                    }
                } else {
                    // only the first `num_valid_pok` are valid, the rest are invalid 
                    poks = poks[0..num_valid_pok as usize].to_vec();
                    (num_valid_pok..num_actual_signers)
                        .for_each(|_| poks.push(mock_bad_resharing.clone()));
                }

                let mut recovered_shares: Vec<DoubleSecret<E>> = Vec::new();
                // we only need to take 'num_actual_signers' elements from keys
                keys = keys[0..num_actual_signers as usize].to_vec();
                // then each member of the committee recovers a share
                keys.iter().enumerate().for_each(|(idx, kp)| {

                    let w = Keypair(kp.into_vartime());
                    let r = poks[idx].clone();

                    match w.recover(r, t) {
                        Ok(recovered_share) => {
                            recovered_shares.push(recovered_share);
                        },
                        Err(e) => {
                            handler(TestStatusReport::RecoverError{ error : e });
                            return ();
                        }
                    }                  
                });

                let msk_shares: Vec<(E::Scalar, E::Scalar)> = recovered_shares
                    .iter()
                    .enumerate()
                    .map(|(idx, share)| (E::Scalar::from(idx as u8 + 1), share.0))
                    .collect();
                let recovered_msk = crate::utils::interpolate::<E::SignatureGroup>(msk_shares);
        
                let msk_hat_shares: Vec<(E::Scalar, E::Scalar)> = recovered_shares
                    .iter()
                    .enumerate()
                    .map(|(idx, share)| (E::Scalar::from(idx as u8 + 1), share.1))
                    .collect();
                let recovered_msk_hat = crate::utils::interpolate::<E::SignatureGroup>(msk_hat_shares);

                let a = convert_to_bytes::<E::Scalar, 32>(recovered_msk).to_vec();
                let b = convert_to_bytes::<E::Scalar, 32>(recovered_msk_hat).to_vec();
                let c = convert_to_bytes::<E::Scalar, 32>(msk).to_vec();
                let d = convert_to_bytes::<E::Scalar, 32>(msk_prime).to_vec();
                handler(TestStatusReport::Completed{ a, b, c, d });
            }, 
            Err(e) => {
                handler(TestStatusReport::ReshareError{ error : e })
            }
        }

        ()
    }

    #[test]
    pub fn acss_works_with_single_member_committee() {
        // committe size: 1
        // threshold: 1
        // num actual signers: 1
        // num valid poks: 1
        acss_with_engine_bls::<TinyBLS377>(1, 1, 1, 1, false, &|status: TestStatusReport| {
            match status {
                TestStatusReport::Completed{ a, b, c, d } => {
                    assert_eq!(a, c);
                    assert_eq!(b, d);
                }
                _ => {
                    panic!("The test should report `completed`");
                }
            }
        });
    }

    #[test]
    pub fn acss_works_with_many_member_committee_full_sigs() {
        // committe size: 3
        // threshold: 3
        // num actual signers: 3
        // num valid poks: 3
        acss_with_engine_bls::<TinyBLS377>(3, 3, 3, 3, false, &|status: TestStatusReport| {
            match status {
                TestStatusReport::Completed{ a, b, c, d } => {
                    assert_eq!(a, c);
                    assert_eq!(b, d);
                }
                _ => {
                    panic!("The test should report `completed`");
                }
            }
        });
    }

    #[test]
    pub fn acss_works_with_many_member_committee_threshold_sigs() {
        // committe size: 3
        // threshold: 2
        // num actual signers: 2
        // num valid poks: 2
        acss_with_engine_bls::<TinyBLS377>(3, 2, 2, 2, false, &|status: TestStatusReport| {
            match status {
                TestStatusReport::Completed{ a, b, c, d } => {
                    assert_eq!(a, c);
                    assert_eq!(b, d);
                }
                _ => {
                    panic!("The test should report `completed`");
                }
            }
        });
    }

    
    #[test]
    pub fn acss_fails_with_many_member_committee_less_than_threshold_sigs() {
        // committe size: 3
        // threshold: 3
        // num actual signers: 1
        // num valid poks: 1
        acss_with_engine_bls::<TinyBLS377>(3, 3, 1, 1, false, 
            &|status: TestStatusReport| {
                match status {
                    TestStatusReport::Completed{ a, b, c, d } => {
                        assert!(a != c);
                        assert!(b != d);
                    }
                    _ => {
                        panic!("The test should report `completed`");
                    }
                }
            }
        );
    }

    #[test]
    pub fn acss_empty_committee_error() {
        // committe size: 0
        // threshold: 0
        // num actual signers: 0
        // num valid poks: 0
        acss_with_engine_bls::<TinyBLS377>(0, 0, 0, 0, false, &|status: TestStatusReport| {
            match status {
                TestStatusReport::ReshareError{ error } => {
                    assert_eq!(error, ACSSError::InvalidCommittee);
                },
                _ => {
                    panic!("The resharing should fail");
                }
            }
        });
    }
    
    #[test]
    pub fn acss_reshare_fails_with_zero_threshold() {
        // committe size: 3
        // threshold: 0
        // num actual signers: 3 <-- irrelevant in this test
        // num valid poks: 3 <-- irrelevant in this test
        acss_with_engine_bls::<TinyBLS377>(3, 0, 3, 3, false, 
            &|status: TestStatusReport| {
                match status {
                    TestStatusReport::ReshareSoftFail{ size } => {
                        assert_eq!(size, 0)
                    },
                    _ => {
                        panic!("All other conditions are invalid");
                    }
                }
            }
        );
    }

    #[test]
    pub fn acss_recover_fails_when_less_than_size_minus_threshold_pok_are_invalid() {
        // committe size: 3
        // threshold: 2
        // num actual signers: 2
        // num valid poks: 1
        acss_with_engine_bls::<TinyBLS377>(3, 2, 2, 1, false, 
            &|status: TestStatusReport| {
                match status {
                    TestStatusReport::RecoverError{ error } => {
                        assert_eq!(error, ACSSError::InvalidCiphertext);
                    },
                    TestStatusReport::Completed{ a, b, c, d } => {
                        assert!(a != c);
                        assert!(b != d);
                    },
                    _ => {
                        panic!("All other conditions are invalid");
                    }
                }
            }
        );
    }

    pub fn test_generate_shares_checked<E: EngineBLS>(
        n: u8, 
        t: u8,
        expected_output_buffer_size: usize,
    ) {
        let mut rng = ChaCha20Rng::seed_from_u64(0);
        let msk = E::Scalar::rand(&mut rng);

        let evals: BTreeMap<E::Scalar, E::Scalar> = 
            generate_shares_checked::<E, ChaCha20Rng>(msk, n, t, &mut rng);
        
        assert_eq!(evals.len(), expected_output_buffer_size);
    }

    #[test]
    pub fn can_generate_shares_checked() {
        test_generate_shares_checked::<TinyBLS377>(5, 3, 5);
        test_generate_shares_checked::<TinyBLS377>(3, 3, 3);
        test_generate_shares_checked::<TinyBLS377>(3, 0, 0);
        test_generate_shares_checked::<TinyBLS377>(0, 0, 0);
        test_generate_shares_checked::<TinyBLS377>(21, 100, 0);
    }
}
