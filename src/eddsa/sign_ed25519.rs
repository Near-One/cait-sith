//! This module wraps a signature generation functionality from `Frost` library
//!  into `cait-sith::Protocol` representation.
use crate::eddsa::KeygenOutput;
use crate::participants::{ParticipantCounter, ParticipantList};
use crate::protocol::internal::{make_protocol, Context, SharedChannel};
use crate::protocol::{InitializationError, Participant, Protocol, ProtocolError};

use rand_core::OsRng;
use std::collections::BTreeMap;
use frost_ed25519::*;
use frost_ed25519::keys::{SigningShare, PublicKeyPackage, KeyPackage};


/// Coordinator sends this message to other participants to:
///     (a) indicate the start of the protocol
///     (b) claim `Coordinator` role
#[derive(serde::Serialize, serde::Deserialize)]
struct InitMessage();

/// A function that takes a signing share and a keygenOutput
/// and construct a public key package used for frost signing
fn construct_key_package(
    threshold: usize,
    me: &Participant,
    signing_share: &SigningShare,
    verification_package: &PublicKeyPackage,
) -> KeyPackage{
    let identifier = me.to_identifier();
    let signing_share = signing_share.clone();
    let verifying_share = signing_share.into();
    let verifying_key = verification_package.verifying_key().clone();

    KeyPackage::new(identifier, signing_share, verifying_share, verifying_key, threshold as u16)
}

/// Returns a future that executes signature protocol for *the Coordinator*.
///
/// WARNING: Extracted from FROST documentation:
/// In all of the main FROST ciphersuites, the entire message must be sent
/// to participants. In some cases, where the message is too big, it may be
/// necessary to send a hash of the message instead. We strongly suggest
/// creating a specific ciphersuite for this, and not just sending the hash
/// as if it were the message.
/// For reference, see how RFC 8032 handles "pre-hashing".
pub(crate) async fn do_sign_coordinator(
    mut chan: SharedChannel,
    participants: ParticipantList,
    threshold: usize,
    me: Participant,
    keygen_output: KeygenOutput,
    message: Vec<u8>,
) -> Result<Signature, ProtocolError> {
    let mut seen = ParticipantCounter::new(&participants);
    let mut rng = OsRng;

    // --- Round 1.
    // * Send acknowledgment to other participants.
    // * Wait for their commitments.

    let mut commitments_map: BTreeMap<frost_ed25519::Identifier, round1::SigningCommitments> =
        BTreeMap::new();

    let r1_wait_point = chan.next_waitpoint();
    chan.send_many(r1_wait_point, &InitMessage()).await;

    let signing_share = SigningShare::new(keygen_output.private_share.to_scalar());

    let (nonces, commitments) = round1::commit(&signing_share, &mut rng);
    commitments_map.insert(me.to_identifier(), commitments);
    seen.put(me);

    while !seen.full() {
        let (from, commitment): (_, round1::SigningCommitments) = chan.recv(r1_wait_point).await?;

        if !seen.put(from) {
            continue;
        }
        commitments_map.insert(from.to_identifier(), commitment);
    }

    let signing_package = frost_ed25519::SigningPackage::new(commitments_map, message.as_slice());

    // --- Round 2.
    // * Convert collected commitments into the signing package.
    // * Send it to all participants.
    // * Wait for each other's signature share

    let mut signature_shares: BTreeMap<frost_ed25519::Identifier, round2::SignatureShare> =
        BTreeMap::new();

    let r2_wait_point = chan.next_waitpoint();
    chan.send_many(r2_wait_point, &signing_package).await;

    let vk_package = keygen_output.public_key_package;
    let key_package = construct_key_package(threshold, &me, &signing_share, &vk_package);

    let signature_share = round2::sign(&signing_package, &nonces, &key_package)
        .map_err(|e| ProtocolError::AssertionFailed(e.to_string()))?;
    signature_shares.insert(me.to_identifier(), signature_share);
    seen.clear();
    seen.put(me);

    while !seen.full() {
        let (from, signature_share): (_, round2::SignatureShare) = chan.recv(r2_wait_point).await?;
        if !seen.put(from) {
            continue;
        }
        signature_shares.insert(from.to_identifier(), signature_share);
    }

    // --- Signature aggregation.
    // * Converted collected signature shares into the signature.
    // * Signature is verified internally during `aggregate()` call.

    let signature = frost_ed25519::aggregate(
        &signing_package,
        &signature_shares,
        &vk_package,
    )
    .map_err(|e| ProtocolError::AssertionFailed(e.to_string()))?;

    Ok(signature)
}

/// Returns a future that executes signature protocol for *a Participant*.
///
/// WARNING: Extracted from FROST documentation:
/// In all of the main FROST ciphersuites, the entire message must be sent
/// to participants. In some cases, where the message is too big, it may be
/// necessary to send a hash of the message instead. We strongly suggest
/// creating a specific ciphersuite for this, and not just sending the hash
/// as if it were the message.
/// For reference, see how RFC 8032 handles "pre-hashing".
pub(crate) async fn do_sign_participant(
    mut chan: SharedChannel,
    threshold: usize,
    me: Participant,
    keygen_output: KeygenOutput,
    message: Vec<u8>,
) -> Result<(), ProtocolError> {
    let mut rng = OsRng;
    // create signing share out of private_share
    let signing_share = SigningShare::new(keygen_output.private_share.to_scalar());

    let (nonces, commitments) = round1::commit(&signing_share, &mut rng);

    // --- Round 1.
    // * Wait for an initial message from a coordinator.
    // * Send coordinator our commitment.

    let r1_wait_point = chan.next_waitpoint();
    let (coordinator, _): (_, InitMessage) = chan.recv(r1_wait_point).await?;
    chan.send_private(r1_wait_point, coordinator, &commitments)
        .await;

    // --- Round 2.
    // * Wait for a signing package.
    // * Send our signature share.

    let r2_wait_point = chan.next_waitpoint();
    let signing_package = loop {
        let (from, signing_package): (_, frost_ed25519::SigningPackage) =
            chan.recv(r2_wait_point).await?;
        if from != coordinator {
            continue;
        }
        break signing_package;
    };

    if signing_package.message() != message.as_slice() {
        return Err(ProtocolError::AssertionFailed(
            "Expected message doesn't match with the actual message received in a signing package"
                .to_string(),
        ));
    }

    let vk_package = keygen_output.public_key_package;
    let key_package = construct_key_package(threshold, &me, &signing_share, &vk_package);

    let signature_share = round2::sign(&signing_package, &nonces, &key_package)
        .map_err(|e| ProtocolError::AssertionFailed(e.to_string()))?;

    chan.send_private(r2_wait_point, coordinator, &signature_share)
        .await;

    Ok(())
}

/// Runs signature protocol on the coordinator side.
///
/// WARNING: Extracted from FROST documentation:
/// In all of the main FROST ciphersuites, the entire message must be sent
/// to participants. In some cases, where the message is too big, it may be
/// necessary to send a hash of the message instead. We strongly suggest
/// creating a specific ciphersuite for this, and not just sending the hash
/// as if it were the message.
/// For reference, see how RFC 8032 handles "pre-hashing".
pub fn sign_coordinator(
    participants: &[Participant],
    threshold: usize,
    me: Participant,
    keygen_output: KeygenOutput,
    message: Vec<u8>,
) -> Result<impl Protocol<Output = Signature>, InitializationError> {
    if participants.len() < 2 {
        return Err(InitializationError::BadParameters(format!(
            "participant count cannot be < 2, found: {}",
            participants.len()
        )));
    };
    let Some(participants) = ParticipantList::new(&participants) else {
        return Err(InitializationError::BadParameters(format!(
            "Participants list contains duplicates",
        )));
    };

    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::BadParameters(
            "participant list must contain this participant".to_string(),
        ));
    };

    let ctx = Context::new();
    let fut = do_sign_coordinator(
        ctx.shared_channel(),
        participants,
        threshold,
        me,
        keygen_output,
        message,
    );
    Ok(make_protocol(ctx, fut))
}

/// Runs signature protocol on the participant side.
///
/// WARNING: Extracted from FROST documentation:
/// In all of the main FROST ciphersuites, the entire message must be sent
/// to participants. In some cases, where the message is too big, it may be
/// necessary to send a hash of the message instead. We strongly suggest
/// creating a specific ciphersuite for this, and not just sending the hash
/// as if it were the message.
/// For reference, see how RFC 8032 handles "pre-hashing".
pub fn sign_participant(
    participants: &[Participant],
    threshold: usize,
    me: Participant,
    keygen_output: KeygenOutput,
    message: Vec<u8>,
) -> Result<impl Protocol<Output = ()>, InitializationError> {

    if participants.len() < 2 {
        return Err(InitializationError::BadParameters(format!(
            "participant count cannot be < 2, found: {}",
            participants.len()
        )));
    };
    let Some(participants) = ParticipantList::new(&participants) else {
        return Err(InitializationError::BadParameters(format!(
            "Participants list contains duplicates",
        )));
    };

    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::BadParameters(
            "participant list must contain this participant".to_string(),
        ));
    };

    let ctx = Context::new();
    let fut = do_sign_participant(
        ctx.shared_channel(),
        threshold,
        me,
        keygen_output,
        message,
    );
    Ok(make_protocol(ctx, fut))
}

#[cfg(test)]
mod tests {
    use frost_ed25519::Signature;
    use crate::crypto::hash;

    use crate::eddsa::test::{
        run_signature_protocols, build_key_packages_with_dealer, IsSignature,
        run_keygen
    };
    use crate::protocol::Participant;
    use std::error::Error;

    fn assert_single_coordinator_result(data: Vec<(Participant, IsSignature)>) -> Signature {
        let mut signature = None;
        let count = data
            .iter()
            .filter(|(_, output)| match output {
                Some(s) => {
                    signature = Some(*s);
                    true
                },
                None => false,
            })
            .count();
        assert_eq!(count, 1);
        signature.unwrap()
    }

    #[test]
    fn basic_two_participants() {
        let max_signers = 2;
        let threshold = 2;
        let actual_signers = 2;
        let coordinators = 1;
        let msg = "hello_near";
        let msg_hash = hash(&msg);

        let key_packages = build_key_packages_with_dealer(max_signers, threshold);
        let data =
        run_signature_protocols(&key_packages, actual_signers, coordinators, threshold, msg_hash).unwrap();
        assert_single_coordinator_result(data);
    }

    #[test]
    #[should_panic]
    fn multiple_coordinators() {
        let max_signers = 3;
        let threshold = 2;
        let actual_signers = 2;
        let coordinators = 2;
        let msg = "hello_near";
        let msg_hash = hash(&msg);

        let key_packages = build_key_packages_with_dealer(max_signers, threshold);
        let data =
        run_signature_protocols(&key_packages, actual_signers, coordinators, threshold, msg_hash).unwrap();
        assert_single_coordinator_result(data);
    }

    #[test]
    fn stress() {
        let max_signers = 7;
        let coordinators = 1;
        let msg = "hello_near";
        let msg_hash = hash(&msg);

        for min_signers in 2..max_signers {
            for actual_signers in min_signers..=max_signers {
                let key_packages = build_key_packages_with_dealer(max_signers, min_signers);
                let data =
                run_signature_protocols(&key_packages, actual_signers, coordinators, min_signers, msg_hash)
                        .unwrap();
                assert_single_coordinator_result(data);
            }
        }
    }

    #[test]
    fn dkg_sign_test()
    -> Result<(), Box<dyn Error>>{
        let participants = vec![
            Participant::from(3u32),
            Participant::from(1u32),
            Participant::from(2u32),
        ];
        let actual_signers = participants.len();
        let coordinators = 1;
        let threshold = 2;
        let msg = "hello_near";
        let msg_hash = hash(&msg);

        let key_packages = run_keygen(&participants, threshold)?;
        let data =
            run_signature_protocols(&key_packages, actual_signers, coordinators, threshold, msg_hash)
            .unwrap();
        let signature = assert_single_coordinator_result(data);

        assert!(key_packages[0].1.public_key_package
            .verifying_key()
            .verify(msg_hash.as_ref(), &signature)
            .is_ok());
        Ok(())
    }
}
