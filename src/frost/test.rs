use crate::frost::KeygenOutput;
use crate::participants::ParticipantList;
use crate::protocol::{run_protocol, Participant, Protocol};
use frost_ed25519::{Identifier, Signature, SigningKey};
use rand_core::{OsRng, RngCore};
use std::error::Error;

use crate::frost::sign_ed25519::{sign_coordinator, sign_participant};
use rand::prelude::StdRng;
use rand::SeedableRng;

use crate::crypto::hash;



#[allow(dead_code)]
pub(crate) enum SignatureOutput {
    Coordinator(Signature),
    Participant,
}

pub(crate) fn build_key_packages_with_dealer(
    max_signers: usize,
    min_signers: usize,
) -> Vec<(Participant, KeygenOutput)> {
    use std::collections::BTreeMap;

    let mut identifiers = Vec::with_capacity(max_signers);
    for _ in 0..max_signers {
        // from 1 to avoid assigning 0 to a ParticipantId
        identifiers.push(Participant::from(OsRng.next_u32()))
    }

    let from_frost_identifiers = identifiers
        .iter()
        .map(|&x| (x.to_identifier(), x))
        .collect::<BTreeMap<_, _>>();

    let identifiers_list = from_frost_identifiers.keys().cloned().collect::<Vec<_>>();

    let (shares, pubkey_package) = frost_ed25519::keys::generate_with_dealer(
        max_signers as u16,
        min_signers as u16,
        frost_ed25519::keys::IdentifierList::Custom(identifiers_list.as_slice()),
        OsRng,
    )
    .unwrap();

    shares
        .into_iter()
        .map(|(id, share)| {
            (
                from_frost_identifiers[&id],
                KeygenOutput {
                    private_share: SigningKey::from_scalar(share.signing_share().to_scalar()).unwrap(),
                    public_key_package: pubkey_package.clone(),
                },
            )
        })
        .collect::<Vec<_>>()
}

enum SignProtType {
    Coordinator(Signature),
    Participant(()),
}

pub(crate) fn run_signature_protocols(
    participants: &[(Participant, KeygenOutput)],
    actual_signers: usize,
    coordinators_count: usize,
    threshold: usize
) -> Result<Vec<(Participant, SignatureOutput)>, Box<dyn Error>> {

    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = SignatureOutput>>)> =
        Vec::with_capacity(participants.len());

    let participants_list = participants
        .iter()
        .take(actual_signers)
        .map(|(id, _)| *id)
        .collect::<Vec<_>>();

    let msg = "hello_near";
    let msg_hash = hash(&msg);


    for (idx, (participant, key_pair)) in participants.iter().take(actual_signers).enumerate() {
        let protocol = if idx < coordinators_count{
            sign_coordinator(
                &participants_list.clone(),
                threshold,
                *participant,
                key_pair.clone(),
                msg_hash.as_ref().to_vec()
            )
        } else {
           sign_participant(
                &participants_list.clone(),
                threshold,
                *participant,
                key_pair.clone(),
                msg_hash.as_bytes().to_vec(),
            )
        };

        protocols.push((*participant, protocol))
    }

    Ok(run_protocol(protocols)?)
}

/// Assert that:
///     1. Each participant has the same view of `PublicKeyPackage`
///     2. Each participant is present in `PublicKeyPackage::verifying_shares()`
///     3. No "other" participant is present in `PublicKeyPackage::verifying_shares()`
///     4. For each participant their `verifying_share = secret_share * G`
///     5. For each participant their `verifying_share` is the same across `KeyPackage` and `PublicKeyPackage`
pub(crate) fn assert_public_key_invariant(
    participants: &[(Participant, KeygenOutput)],
) -> Result<(), Box<dyn Error>> {
    use anyhow::Context;
    use frost_ed25519::keys::VerifyingShare;
    use frost_ed25519::Group;

    let public_key_package = participants.first().unwrap().1.public_key_package.clone();

    if participants
        .iter()
        .any(|(_, key_pair)| key_pair.public_key_package != public_key_package)
    {
        anyhow::bail!("public key package is not the same for all participants");
    }

    if public_key_package.verifying_shares().len() != participants.len() {
        anyhow::bail!(
            "public key package has different number of verifying shares than participants"
        );
    }

    for (participant, key_pair) in participants {
        let scalar = key_pair.key_package.signing_share().to_scalar();
        let actual_verifying_share = {
            let point = frost_ed25519::Ed25519Group::generator() * scalar;
            VerifyingShare::new(point)
        };

        if actual_verifying_share != *key_pair.key_package.verifying_share() {
            anyhow::bail!("verifying share in `KeyPackage` is not equal to secret share * G");
        }

        {
            let expected_verifying_share = key_pair
                .public_key_package
                .verifying_shares()
                .get(&(*participant).to_identifier())
                .context("participant not found in `PublicKeyPackage` verifying shares")?;
            if actual_verifying_share != *expected_verifying_share {
                anyhow::bail!(
                    "verifying share in `PublicKeyPackage` is not equal to secret share * G"
                );
            }
        }
    }

    Ok(())
}

/// Extract group signin key from participants.
/// The caller is responsible for providing at least `min_signers` shares:
///  if less than that is provided, a different key will be returned.
pub(crate) fn reconstruct_signing_key(
    participants: &[(Participant, KeygenOutput)],
) -> Result<frost_ed25519::SigningKey, Box<dyn Error>> {
    let key_packages = participants
        .iter()
        .map(|(_, key_pair)| key_pair.key_package.clone())
        .collect::<Vec<_>>();

    let signing_key = frost_ed25519::keys::reconstruct(&key_packages)?;

    Ok(signing_key)
}

/// Assert that:
///     1. For each subset of size `< threshold` incorrect signing key is reconstructed.
///     2. For each subset of size `>= threshold` correct signing key is constructed.
pub(crate) fn assert_signing_schema_threshold_holds(
    expected_signing_key: frost_ed25519::SigningKey,
    threshold: usize,
    participants: &[(Participant, KeygenOutput)],
) -> anyhow::Result<()> {
    use itertools::Itertools;
    for actual_signers_count in 1..=participants.len() {
        participants
            .iter()
            .cloned()
            .combinations(actual_signers_count)
            .try_for_each(|signers| {
                if actual_signers_count < threshold {
                    if reconstruct_signing_key(signers.as_slice()).is_ok() {
                        anyhow::bail!(
                            "signing key should not be reconstructed \
                        for subset of size {}",
                            actual_signers_count
                        );
                    }
                } else {
                    let actual_signing_key = reconstruct_signing_key(signers.as_slice())?;
                    if actual_signing_key != expected_signing_key {
                        anyhow::bail!(
                            "signing key should be reconstructed for subset of size {},\
                     which is greater or equal to threshold: {}",
                            actual_signers_count,
                            threshold
                        );
                    }
                }
                Ok(())
            })?;
    }
    Ok(())
}

#[test]
fn verify_stability_of_identifier_derivation() {
    let participant = Participant::from(1e9 as u32);
    let identifier = Identifier::derive(participant.bytes().as_slice()).unwrap();
    assert_eq!(
        identifier.serialize(),
        vec![
            96, 203, 29, 92, 230, 35, 120, 169, 19, 185, 45, 28, 48, 68, 84, 190, 12, 186, 169,
            192, 196, 21, 238, 181, 134, 181, 203, 236, 162, 68, 212, 4
        ]
    );
}
