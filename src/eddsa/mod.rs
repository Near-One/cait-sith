//! This module serves as a wrapper for Frost protocol.
use crate::generic_dkg::{BytesOrder, Ciphersuite, ScalarSerializationFormat};
use frost_ed25519::Ed25519Sha512;
use frost_ed25519::keys::{PublicKeyPackage, SigningShare};

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct KeygenOutput {
    pub private_share: SigningShare,
    pub public_key_package: PublicKeyPackage,
}

impl From<crate::generic_dkg::KeygenOutput<Ed25519Sha512>> for KeygenOutput {
    fn from(value: crate::generic_dkg::KeygenOutput<Ed25519Sha512>) -> Self {
        Self {
            private_share: value.private_share,
            public_key_package: value.public_key_package,
        }
    }
}

impl ScalarSerializationFormat for Ed25519Sha512 {
    fn bytes_order() -> BytesOrder {
        BytesOrder::LittleEndian
    }
}

impl Ciphersuite for Ed25519Sha512 {}

pub mod dkg_ed25519;
pub mod sign;
#[cfg(test)]
mod test;
