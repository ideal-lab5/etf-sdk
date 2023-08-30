#![cfg_attr(not(feature = "std"), no_std)]
#![warn(
    unused,
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    rust_2021_compatibility
)]
#![allow(clippy::op_ref, clippy::suspicious_op_assign_impl)]
#![deny(unsafe_code)]

#[macro_use]
extern crate alloc;

pub mod utils;
pub mod encryption;
pub mod ibe;
pub mod proofs;
pub mod client;

fn main() { }