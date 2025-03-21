//! This module serves as a wrapper for Frost protocol.
use frost_secp256k1::Secp256K1Sha256;
use serde::{Deserialize, Serialize};

use crate::compat::CSCurve;

pub type KeygenOutput = crate::generic_dkg::KeygenOutput<Secp256K1Sha256>;


// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct KeygenOutput<C: CSCurve> {
//     pub private_share: C::Scalar,
//     pub public_key: C::AffinePoint,
// }

pub mod math;
pub mod presign;
pub mod triples;
pub mod dkg_ecdsa;
pub mod sign;
#[cfg(test)]
mod test;