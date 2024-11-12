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

use alloc::vec::Vec;

use ark_ec::hashing::curve_maps::wb::{WBConfig, WBMap};
use ark_ec::hashing::{
    map_to_curve_hasher::{MapToCurve, MapToCurveBasedHasher},
    HashToCurve,
};
use ark_ec::{
    pairing::{MillerLoopOutput, Pairing},
    AffineRepr, CurveGroup,
};
use ark_ff::field_hashers::DefaultFieldHasher;

use sha2::Sha256; //IETF standard asks for SHA256

use ark_ec::bls12::Bls12Config;
use core::marker::PhantomData;
use w3f_bls::EngineBLS;

pub const QUICKNET_CTX: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
pub const MAIN_CTX: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

/// Usual aggregate BLS signature scheme on ZCash's BLS12-381 curve.
pub type UsualBLSDrandMainnet = UsualBLS<ark_bls12_381::Bls12_381, ark_bls12_381::Config>;
pub type TinyBLS381DrandQuicknet = TinyBLSDrandQuicknet<ark_bls12_381::Bls12_381, ark_bls12_381::Config>;

/// Aggregate BLS signature scheme with Signature in G1 for BLS12-381 curve.
impl CurveExtraConfig for ark_bls12_381::Config {
    const CURVE_NAME: &'static [u8] = b"BLS12381";
}

/// Usual aggregate BLS signature scheme on ZCash's BLS12-381 curve.
// pub const Z_BLS : ZBLS = UsualBLS(::zexe_algebra::bls12_381::Bls12_381{});

/// Usual BLS variant with tiny 48 byte public keys and 96 byte signatures.
///
/// We favor this variant because verifiers always perform
/// `O(signers)` additions on the `PublicKeyGroup`, or worse 128 bit
/// scalar multiplications with delinearization.
/// We also orient this variant to match zcash's traits.
#[derive(Default)]
pub struct UsualBLS<E: Pairing, P: Bls12Config + CurveExtraConfig>(pub E, PhantomData<fn() -> P>)
where
    <P as Bls12Config>::G2Config: WBConfig,
    WBMap<<P as Bls12Config>::G2Config>: MapToCurve<<E as Pairing>::G2>;

impl<E: Pairing, P: Bls12Config + CurveExtraConfig> EngineBLS for UsualBLS<E, P>
where
    <P as Bls12Config>::G2Config: WBConfig,
    WBMap<<P as Bls12Config>::G2Config>: MapToCurve<<E as Pairing>::G2>,
{
    type Engine = E;
    type Scalar = <Self::Engine as Pairing>::ScalarField;

    type PublicKeyGroup = E::G1;
    type PublicKeyGroupAffine = E::G1Affine;
    type PublicKeyPrepared = E::G1Prepared;
    type PublicKeyGroupBaseField = <<E as Pairing>::G1 as CurveGroup>::BaseField;

    const PUBLICKEY_SERIALIZED_SIZE: usize = 48;
    const SECRET_KEY_SIZE: usize = 32;

    const CURVE_NAME: &'static [u8] = P::CURVE_NAME;
    const SIG_GROUP_NAME: &'static [u8] = b"G2";
    const CIPHER_SUIT_DOMAIN_SEPARATION: &'static [u8] = b"_XMD:SHA-256_SSWU_RO_";

    type SignatureGroup = E::G2;
    type SignatureGroupAffine = E::G2Affine;
    type SignaturePrepared = E::G2Prepared;
    type SignatureGroupBaseField = <<E as Pairing>::G2 as CurveGroup>::BaseField;

    const SIGNATURE_SERIALIZED_SIZE: usize = 96;

    type HashToSignatureField = DefaultFieldHasher<Sha256, 128>;
    type MapToSignatureCurve = WBMap<P::G2Config>;

    fn miller_loop<'a, I>(i: I) -> MillerLoopOutput<E>
    where
        // Self::PublicKeyPrepared: 'a,
        // Self::SignaturePrepared: 'a,
        I: IntoIterator<Item = &'a (Self::PublicKeyPrepared, Self::SignaturePrepared)>,
    {
        let (i_a, i_b): (Vec<Self::PublicKeyPrepared>, Vec<Self::SignaturePrepared>) =
            i.into_iter().cloned().unzip();

        E::multi_miller_loop(i_a, i_b)
    }

    fn pairing<G1, G2>(p: G1, q: G2) -> E::TargetField
    where
        G1: Into<E::G1Affine>,
        G2: Into<E::G2Affine>,
    {
        E::pairing(p.into(), q.into()).0
    }

    /// Prepared negative of the generator of the public key curve.
    fn minus_generator_of_public_key_group_prepared() -> Self::PublicKeyPrepared {
        let g1_minus_generator = <Self::PublicKeyGroup as CurveGroup>::Affine::generator();
        <Self::PublicKeyGroup as Into<Self::PublicKeyPrepared>>::into(
            -g1_minus_generator.into_group(),
        )
    }

    fn hash_to_curve_map() -> MapToCurveBasedHasher<
        Self::SignatureGroup,
        Self::HashToSignatureField,
        Self::MapToSignatureCurve,
    > {
        MapToCurveBasedHasher::<
            Self::SignatureGroup,
            DefaultFieldHasher<Sha256, 128>,
            WBMap<P::G2Config>,
        >::new(MAIN_CTX)
        .unwrap()
    }
}



/// A BLS variant with tiny 48 byte signatures and 96 byte public keys,
/// 
/// Specifically, this configuration is used by Drand's QuickNet.
/// 
/// Note on performance: verifiers  always perform `O(signers)` additions on the `PublicKeyGroup`,
/// or worse 128 bit scalar multiplications with delinearization.
/// Yet, there are specific use cases where this variant performs
/// better.  We swapy two group roles relative to zcash here.
#[derive(Default)]
pub struct TinyBLSDrandQuicknet<E: Pairing, P: Bls12Config + CurveExtraConfig>(pub E, PhantomData<fn() -> P>)
where
    <P as Bls12Config>::G1Config: WBConfig,
    WBMap<<P as Bls12Config>::G1Config>: MapToCurve<<E as Pairing>::G1>;

/// Trait to add extra config for a curve which is not in ArkWorks library
pub trait CurveExtraConfig {
    const CURVE_NAME: &'static [u8];
}

impl<E: Pairing, P: Bls12Config + CurveExtraConfig> EngineBLS for TinyBLSDrandQuicknet<E, P>
where
    <P as Bls12Config>::G1Config: WBConfig,
    WBMap<<P as Bls12Config>::G1Config>: MapToCurve<<E as Pairing>::G1>,
{
    type Engine = E;
    type Scalar = <Self::Engine as Pairing>::ScalarField;

    type SignatureGroup = E::G1;
    type SignatureGroupAffine = E::G1Affine;
    type SignaturePrepared = E::G1Prepared;
    type SignatureGroupBaseField = <<E as Pairing>::G1 as CurveGroup>::BaseField;

    const SIGNATURE_SERIALIZED_SIZE: usize = 48;

    type PublicKeyGroup = E::G2;
    type PublicKeyGroupAffine = E::G2Affine;
    type PublicKeyPrepared = E::G2Prepared;
    type PublicKeyGroupBaseField = <<E as Pairing>::G2 as CurveGroup>::BaseField;

    const PUBLICKEY_SERIALIZED_SIZE: usize = 96;
    const SECRET_KEY_SIZE: usize = 32;

    const CURVE_NAME: &'static [u8] = P::CURVE_NAME;
    const SIG_GROUP_NAME: &'static [u8] = b"G1";
    const CIPHER_SUIT_DOMAIN_SEPARATION: &'static [u8] = b"_XMD:SHA-256_SSWU_RO_";

    type HashToSignatureField = DefaultFieldHasher<Sha256, 128>;
    type MapToSignatureCurve = WBMap<P::G1Config>;

    fn miller_loop<'a, I>(i: I) -> MillerLoopOutput<E>
    where
        I: IntoIterator<Item = &'a (Self::PublicKeyPrepared, Self::SignaturePrepared)>,
    {
        // We require an ugly unecessary allocation here because
        // zcash's pairing library cnsumes an iterator of references
        // to tuples of references, which always requires
        let (i_a, i_b): (Vec<Self::PublicKeyPrepared>, Vec<Self::SignaturePrepared>) =
            i.into_iter().cloned().unzip();

        E::multi_miller_loop(i_b, i_a) //in Tiny BLS signature is in G1
    }

    fn pairing<G2, G1>(p: G2, q: G1) -> E::TargetField
    where
        G1: Into<E::G1Affine>,
        G2: Into<E::G2Affine>,
    {
        E::pairing(q.into(), p.into()).0
    }

    /// Prepared negative of the generator of the public key curve.
    fn minus_generator_of_public_key_group_prepared() -> Self::PublicKeyPrepared {
        let g2_minus_generator = <Self::PublicKeyGroup as CurveGroup>::Affine::generator();
        <Self::PublicKeyGroup as Into<Self::PublicKeyPrepared>>::into(
            -g2_minus_generator.into_group(),
        )
    }

    fn hash_to_curve_map() -> MapToCurveBasedHasher<
        Self::SignatureGroup,
        Self::HashToSignatureField,
        Self::MapToSignatureCurve,
    > {
        MapToCurveBasedHasher::<
            Self::SignatureGroup,
            DefaultFieldHasher<Sha256, 128>,
            WBMap<P::G1Config>,
        >::new(QUICKNET_CTX)
        .unwrap()
    }
}

