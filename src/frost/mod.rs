//! This module serves as a wrapper for Frost protocol.
use frost_ed25519::Ed25519Sha512;
pub type KeygenOutput = crate::generic_dkg::KeygenOutput<Ed25519Sha512>;


mod dkg_ed25519;
mod sign_ed25519;
#[cfg(test)]
mod test;
