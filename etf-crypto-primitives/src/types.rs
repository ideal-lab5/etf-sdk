// //! Common types used in etf-crypto-primitives

use ark_ec::CurveGroup;
use ark_std::rand::Rng;

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
