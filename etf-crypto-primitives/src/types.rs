// //! Common types used in etf-crypto-primitives

use scale_info::TypeInfo;
use serde::{Deserialize, Serialize};
use codec::{Decode, Encode, MaxEncodedLen};
use core::cmp::Ordering;
use alloc::vec::Vec;
use ark_ec::CurveGroup;
use ark_std::rand::Rng;


#[cfg(feature = "std")]
use curv::arithmetic::Converter;
#[cfg(feature = "std")]
use kzen_paillier::{BigInt, EncryptionKey};

// // A wrapper for EncryptionKey 
// #[derive(Clone, Serialize, Deserialize, Encode, Decode, TypeInfo, Default, Debug)]
// pub struct WrappedEncryptionKey(pub Vec<u8>);

// impl Eq for WrappedEncryptionKey {}

// impl PartialEq for WrappedEncryptionKey {
//     fn eq(&self, other: &Self) -> bool {
        
//         // Check equality based on both 'n' and 'nn' fields
//         self.0 == other.0
//     }
// }

// impl Ord for WrappedEncryptionKey {
//     fn cmp(&self, other: &Self) -> Ordering {
//         // Compare based on the ordering of the 'n' field
//         self.0.cmp(&other.0)
//     }
// }

// impl PartialOrd for WrappedEncryptionKey {
//     fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
//         Some(self.cmp(other))
//     }
// }

// #[cfg(feature = "std")]
// impl WrappedEncryptionKey {
//     pub fn into_inner(self) -> EncryptionKey {
//         EncryptionKey::from(&BigInt::from_bytes(&self.0))
//     }
// }

// impl AsRef<[u8]> for WrappedEncryptionKey {
//     fn as_ref(&self) -> &[u8] {
//         &self.0
//     }
// }

/// public parameters for El Gamal encryption
#[derive(Clone, Debug)]
pub struct ProtocolParams<C: CurveGroup> {
    pub g: C,
    pub h: C,
}

impl<C: CurveGroup> ProtocolParams<C> {
    pub fn rand<R: Rng + Sized>(mut rng: R) -> Self {
        Self {
            g: C::generator(),
            h: C::rand(&mut rng)
        }
    }
}
