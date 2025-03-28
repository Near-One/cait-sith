//! This module serves as a wrapper for Frost protocol.

use frost_secp256k1::keys::{PublicKeyPackage, SigningShare};
use frost_secp256k1::Secp256K1Sha256;
use crate::generic_dkg::{BytesOrder, Ciphersuite, ScalarSerializationFormat};

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct KeygenOutput {
    pub private_share: SigningShare,
    pub public_key_package: PublicKeyPackage,
}

impl From<crate::generic_dkg::KeygenOutput<Secp256K1Sha256>> for KeygenOutput {
    fn from(value: crate::generic_dkg::KeygenOutput<Secp256K1Sha256>) -> Self {
        Self {
            private_share: value.private_share,
            public_key_package: value.public_key_package,
        }
    }
}

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
