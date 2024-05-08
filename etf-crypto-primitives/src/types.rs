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
//! Common types used in etf-crypto-primitives

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
