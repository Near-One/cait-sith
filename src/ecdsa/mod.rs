//! This module serves as a wrapper for Frost protocol.

use crate::generic_dkg::{BytesOrder, Ciphersuite, ScalarSerializationFormat};
use frost_secp256k1::Secp256K1Sha256;

pub type KeygenOutput = crate::generic_dkg::KeygenOutput<Secp256K1Sha256>;

impl ScalarSerializationFormat for Secp256K1Sha256 {
    fn bytes_order() -> BytesOrder {
        BytesOrder::BigEndian
    }
}

impl Ciphersuite for Secp256K1Sha256 {}

pub mod dkg_ecdsa;
pub mod math;
pub mod presign;
pub mod sign;
#[cfg(test)]
mod test;
pub mod triples;
