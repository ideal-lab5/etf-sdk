use ark_bls12_381::{Fr, G1Projective as G};
use ark_ec::CurveGroup;
use ark_serialize::CanonicalSerialize;
use ark_ff::UniformRand;
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
    ops::Mul,
    vec::Vec, 
    rand::Rng,
    collections::BTreeMap,
};
use crate::utils::hash_to_g1;
use crate::encryption::aes::{generate_shares_checked, interpolate};

type AuxData = Vec<u8>;

// no proof yet
#[derive(Clone, PartialEq, Copy, Debug)]
pub struct Capsule {
    // pub v: Ciphertext<G>,
    // pub v_hat: Ciphertext<G>,
    pub v: Fr,
    pub v_hat: Fr,
    pub commitment: G,
    // pub proof: DLEQProof<G>,
}

#[derive(Clone, PartialEq)]
pub struct ACSSParams {
    g: G,
    h: G,
    // elgamal_params: Parameters<G>,
}


/// the high threshold asynchronous secret sharing struct
pub struct HighThresholdACSS;
impl HighThresholdACSS {

    /// as a semi-trusted dealer, construct shares for the initial committee
    /// `params`: ACSS Params
    /// `n`: The number of shares to generate
    /// `t`: The threshold (t <= n)
    /// `aux`: Any aux data (pass through)
    /// `rng`: A random number generator
    fn build_shares<R: Rng + Sized>(
        params: ACSSParams, 
        msk: Fr, 
        msk_hat: Fr, 
        n: u8, t: u8, 
        aux: AuxData, mut rng: R,
    ) -> (Vec<(Fr, Capsule)>, AuxData) {
        // f(x) -> [f(0), {(1, f(1)), ..., (n, f(n))}]
        let evals = generate_shares_checked(msk, n, t, &mut rng);
        // f_hat(x) (blinding polynomial)
        let evals_hat = generate_shares_checked(msk_hat, n, t, &mut rng);
        // merge the evaluations
        let mut result: Vec<(Fr, Capsule)> = Vec::new();
        let mut test = Vec::new();
        for (key_a, value_a) in &evals {
            if let Some((_, value_b)) = evals_hat.iter().find(|(key_b, _)| key_a.eq(key_b)) {
                let commitment = params.g.mul(value_a) + params.h.mul(value_b);
                test.push((key_a.clone(), value_a.clone()));
                result.push((
                    key_a.clone(), 
                    Capsule {
                        v: value_a.clone(), 
                        v_hat: value_b.clone(),
                        commitment,
                    }));
            };
        }

        (result, aux) 

        // // choose random polys
        // let p = DensePolynomial::<Fr>::rand(d, &mut rng);
        // // TODO: must have: p(0) = s ... so we could just have this function output s along with the BTreeMap 
        // let s = p.evaluate(&Fr::from(0));
        // let p_hat = DensePolynomial::<Fr>::rand(d, &mut rng);
        // // encrypt + gen proofs
        // let mut shares: BTreeMap<G, Capsule> = BTreeMap::new();
        // let out: BTreeMap<usize, Capsule> = pks.iter().enumerate().map(|(idx, pk)| {
        //     // let r = Randomness::rand(&mut rng);
        //     // evaluate polys (calc shares)
        //     // idx + 1 since we do not want to eval at 0
        //     let p_eval = p.evaluate(&Fr::from((idx + 1) as u8));
        //     // the blinding polynomial
        //     let p_hat_eval = p_hat.evaluate(&Fr::from((idx + 1) as u8));
        //     // calculate a commitment to the evals
        //     let commitment = params.g.mul(p_eval) + params.h.mul(p_hat_eval);

        //     // // encrypt + serialize p(i)
        //     // let mut p_bytes = Vec::new();
        //     // p_eval.serialize_compressed(&mut p_bytes).expect("ok");
        //     // let p_pt = hash_to_g1(&p_bytes);

        //     // // encrypt and serialize p_hat(i)
        //     // let mut p_hat_bytes = Vec::new();
        //     // p_hat_eval.serialize_compressed(&mut p_hat_bytes).expect("ok");
        //     // let p_hat_pt = hash_to_g1(&p_hat_bytes);

        //     // let p_cipher = ElGamal::<G>::encrypt(
        //     //     &self.params, &pk.into_affine(), &p_hat_pt, &r).unwrap();
        //     // let p_hat_cipher = ElGamal::<G>::encrypt(
        //     //     &self.params, &pk.into_affine(), &p_hat_pt, &r).unwrap();
        //     // // TODO: generate proofs
        //     // let p_proof = DLEQProof::prove(s, p_cipher.0, p_chi)

        //     // TODO: unencrypted for now...
        //     (idx, Capsule {
        //         // v: p_cipher, 
        //         // v_hat: p_hat_cipher, 
        //         v: p_eval, 
        //         v_hat: p_hat_eval, 
        //         commitment
        //     })
        // }).collect();
        // (out, s, aux.clone())
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

    use ark_poly::{
        polynomial::univariate::DensePolynomial,
        DenseUVPolynomial, Polynomial,
    };

    /// a helper struct to simulate a network for testing
    #[derive(Clone)]
    pub struct TestNetwork {
        pub participants: Vec<Participant>,
        pub msk: Option<Fr>,
    }

    impl TestNetwork {
        pub fn rand(size: usize) -> Self {
            let participants = (0..size).map(|i| { Participant::rand() }).collect();
            TestNetwork { participants, msk: None }
        }

        // /// update the network participants additively based on their intermediate shares
        // /// this is kind of bad...
        // pub fn merge_intermediate(&self, mut participants: Vec<Participant>) -> TestNetwork {
        //      // Ensure that both input vectors have the same length
        //     assert_eq!(
        //         self.participants.len(),
        //         participants.len(),
        //         "Input vectors must have the same length"
        //     );

        //     // Iterate over both vectors simultaneously
        //     for (network_participant, input_participant) in
        //         self.participants.iter_mut().zip(participants.into_iter()) {
        //         // Merge the intermediate shares of the input participant into the network participant
        //         network_participant.append_intermediate(input_participant.intermediate_shares);
        //     }
        //     self.clone()
        // }

        pub fn pubkeys(&self) -> Vec<G> {
            self.participants
                .clone()
                .iter()
                .map(|p| p.public_key)
                .collect::<Vec<_>>()
        }
    }

    /// a helper 'participant' struct to simulate network partcipants
    #[derive(Clone, PartialEq, Debug)]
    pub struct Participant {
        secret_key: Fr,
        public_key: G,
        /// shares received by other participants in the current round
        received_shares: Option<(Fr, Fr, G)>,
        /// shares received when a new committee is participating in a reshare
        intermediate_shares: Vec<(Fr, Fr, G)>,
    }

    impl Participant {
        pub fn rand() -> Self {
            let secret_key = Fr::rand(&mut test_rng());
            let public_key = G::generator().mul(secret_key.clone());
            Participant { 
                secret_key, public_key,
                received_shares: None,
                intermediate_shares: vec![],
            }
        }

        pub fn append_intermediate(&mut self, mut i: Vec<(Fr, Fr, G)>) -> &mut Self {
            self.intermediate_shares.append(&mut i);
            self
        }
    }

    /// should probably be out of test scope
    /// a helper function to setup a default test network
    /// with randomly generated participants
    pub fn acss(
        mut net: TestNetwork,
        msk: Fr, msk_hat: Fr,
        n: u8, t: u8,
        params: ACSSParams
    ) -> TestNetwork {
        // we simulate a network of participants
        // as a semi-trusted dealer generate shares and the 'master secret key', sk
        // shares is a 'd' sharing of sk
        let (shares_map, _aux) = HighThresholdACSS::build_shares(
            params.clone(), // ACSS params
            msk,
            msk_hat,
            n, t,  // the threshold
            Vec::new(),  // aux data
            test_rng(), // rng
        );

        // simulate distribution and authentication of shares
        // all shares should be valid
        let participants_with_shares = 
            net.participants.into_iter().enumerate().map(|(idx, mut p)| {
                let authenticated_shares: (Fr, Fr, G) = 
                    HighThresholdACSS::authenticate_shares(
                        params.clone(), 
                        p.secret_key, 
                        shares_map[idx].1,
                    );
                p.received_shares = Some(authenticated_shares);
                p
            }).collect::<Vec<_>>();
        net.participants = participants_with_shares;
        net.msk = Some(msk);
        net
    }

    // NOTE: This assumes that all participants agree on the ORDER of the committee
    #[test]
    pub fn acss_keygen_and_recovery_works() {
        let n = 10u8;
        let t = 7u8;
        let g = G::generator();
        // // TODO: we need to find another generator...
        let h = G::generator();
        let params = ACSSParams { g, h };
        let msk = Fr::rand(&mut test_rng());
        let msk_hat = Fr::rand(&mut test_rng());
        let mut net = TestNetwork::rand(n as usize);
        net = acss(net, msk, msk_hat, n, t, params);
        // now we should be able to recover the sk from the shares via lagrange interpolation
        let first_poly_evals: Vec<(Fr, Fr)> = net.participants.clone().iter()
            .enumerate()
            .map(|(idx, p)| {
            (Fr::from((idx + 1) as u8), p.received_shares.unwrap().0)
        }).collect::<Vec<_>>();
        let recovered_secret = crate::encryption::aes::interpolate(first_poly_evals);
        assert_eq!(net.msk.unwrap(), recovered_secret);
    }

    #[test]
    pub fn acss_reshare_works() {
        // the current committee size and threshold
        let n = 10u8;
        let t = 7u8;
        // the upcoming committee size and threshold
        let m = 7u8;
        let s = 5u8;

        let g = G::generator();
        // TODO: we need to find another generator...
        let h = G::generator();
        let params = ACSSParams { g, h };
        // first setup the network and initial shares + distribution
        let msk = Fr::rand(&mut test_rng());
        let msk_hat = Fr::rand(&mut test_rng());
        let mut net = TestNetwork::rand(n as usize);
        net = acss(net, msk, msk_hat, n, t, params.clone());
        // the network with the upcoming committee participating 
        // this isn't a realist/ideal representation, just for testing purposes,
        let mut next_net = TestNetwork::rand(m as usize);
        // the participants in net will perform a key handoff to participants of next_net

        // now we need to define a new committee and prepare shares
        // each participant generates new polynomials (acting as a dealer)
        // let mut shared_secret_networks: Vec<TestNetwork> = Vec::new();
        net.participants.iter().for_each(|p| {
            // create a sharing a the participant's shares of s 
            // with each member of the upcoming committee 
            let participants = acss(
                next_net.clone(),
                p.received_shares.unwrap().0,
                p.received_shares.unwrap().1,
                m, s, 
                params.clone(),
            ).participants;
            // let all_received_shares = participants.iter().map(|p| p.received_shares.unwrap()).collect::<Vec<_>>();
            // next_net = next_net.merge_intermediate(participants);
            next_net.participants.iter_mut()
                .enumerate()
                .for_each(|(idx, np)| np.intermediate_shares.push(participants[idx].received_shares.unwrap()));
        });
        // panic!("{:?}", next_net.participants);
        // panic!("{:?}", net.participants.intermediate_shares);
        // now we can "merge" the networks 
        // I suppose this would be the MBVA process
        // for now we will forgo that complexity in place of just reformatting the data

        // each participant loops over the shared_secret_network_participants and builds a map of intermediate shares
        // then uses these to interpolate polys and get secret shares

        let mut next_committee_first_poly_shares: Vec<(Fr, Fr)> = Vec::new();
        let mut next_committee_second_poly_shares: Vec<(Fr, Fr)> = Vec::new();

        for i in 0..next_net.participants.len() {
            let participant = next_net.participants[i].clone();
            // then interpolate the secret shares from shares
            // again this is assuming a globally agreed on order of everything and wouldn't
            // work this way in practice
            let first_share_poly_evals: Vec<(Fr, Fr)> = participant.intermediate_shares.clone().iter()
                .enumerate()
                .map(|(idx, share)| {
                (Fr::from((idx + 1) as u8), share.0)
            }).collect::<Vec<_>>();

            let second_share_poly_evals: Vec<(Fr, Fr)> = participant.intermediate_shares.clone().iter()
                .enumerate()
                .map(|(idx, share)| {
                (Fr::from((idx + 1) as u8), share.1)
            }).collect::<Vec<_>>();

            let first_recovered_share = crate::encryption::aes::interpolate(first_share_poly_evals);
            let second_recovered_share = crate::encryption::aes::interpolate(second_share_poly_evals);
            next_committee_first_poly_shares.push((Fr::from((i + 1) as u8), first_recovered_share));
            next_committee_second_poly_shares.push((Fr::from((i + 1) as u8), second_recovered_share));
        }
        // then interpolate polys from the interpolated shares
        let recovered_msk = crate::encryption::aes::interpolate(next_committee_first_poly_shares);
        let recovered_msk_hat = crate::encryption::aes::interpolate(next_committee_second_poly_shares);

        assert_eq!(msk, recovered_msk);

    }

    // #[test]
    // fn ok() {
    //     let left: Vec<(u8, u8)> = vec![(1, 1), (2, 1), (3, 1)];
    //     let right: Vec<(u8, u8)> = vec![(1, 2), (2, 3), (3, 4)];

    //     let combined: Vec<(u8, u8)> = left
    //         .iter()
    //         .zip(right.iter())
    //         .map(|((a, b), (_, b_prime))| (a.clone(), b + b_prime))
    //         .collect();

    //     assert_eq!(combined, vec![(1, 3), (2, 4), (3, 5)])
    // }
}
