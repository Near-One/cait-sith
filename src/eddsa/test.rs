use crate::eddsa::KeygenOutput;
use crate::participants::ParticipantList;
use crate::protocol::{run_protocol, Participant, Protocol, ProtocolError};
use crate::protocol::internal::{make_protocol, Context, SharedChannel};
use crate::eddsa::sign_ed25519::{do_sign_participant, do_sign_coordinator};
use crate::eddsa::dkg_ed25519::{keygen, reshare, refresh};

use frost_ed25519::keys::{PublicKeyPackage, VerifyingShare};
use frost_ed25519::{Ed25519Sha512, Group, Field, Signature, SigningKey};
use rand_core::{OsRng, RngCore};
use std::error::Error;
use itertools::Itertools;

use crate::crypto::Digest;
pub(crate) type IsSignature = Option<Signature>;

/// this is a centralized key generation
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

/// runs distributed keygen
pub(crate) fn run_keygen(
    participants: &[Participant],
    threshold: usize,
) -> Result<Vec<(Participant, KeygenOutput)>, Box<dyn Error>> {
    let mut protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = KeygenOutput>>,
    )> = Vec::with_capacity(participants.len());

    for p in participants.iter() {
        let protocol = keygen(participants, *p, threshold)?;
        protocols.push((*p, Box::new(protocol)));
    }

    let result = run_protocol(protocols)?;
    Ok(result)
}

/// runs distributed refresh
pub(crate) fn run_refresh(
    participants: &[Participant],
    keys: Vec<(Participant, KeygenOutput)>,
    threshold: usize,
) -> Result<Vec<(Participant, KeygenOutput)>, Box<dyn Error>> {
    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = KeygenOutput>>)> =
        Vec::with_capacity(participants.len());

    for (p, out) in keys.iter() {
        let protocol = refresh(
            Some(out.private_share),
            out.public_key_package.clone(),
            &participants,
            threshold,
            *p,
        )?;
        protocols.push((*p, Box::new(protocol)));
    }

    let result = run_protocol(protocols)?;
    Ok (result)
}

/// runs distributed reshare
pub(crate) fn run_reshare(
    participants: &[Participant],
    pub_key: &PublicKeyPackage,
    keys: Vec<(Participant, KeygenOutput)>,
    old_threshold: usize,
    new_threshold: usize,
) -> Result<Vec<(Participant, KeygenOutput)>, Box<dyn Error>> {
    let mut setup: Vec<_> = keys
            .into_iter()
            .map(|(p, out)| (p, (Some(out.private_share), out.public_key_package)))
            .collect();
        setup.push((Participant::from(3u32), (None, pub_key.clone())));


    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = KeygenOutput>>)> =
    Vec::with_capacity(participants.len());

    for (p, out) in setup.iter() {
        let protocol = reshare(
            &participants[..3],
            old_threshold,
            out.0,
            out.1.clone(),
            &participants,
            new_threshold,
            *p,
        )?;
        protocols.push((*p, Box::new(protocol)));
    }

    let result = run_protocol(protocols)?;
    Ok(result)
}



/// similar to do_sign_participant except
/// it outputs the same type as do_sign_coordinator_test
async fn do_sign_participant_test(
    chan: SharedChannel,
    threshold: usize,
    me: Participant,
    keygen_output: KeygenOutput,
    message: Vec<u8>,
) -> Result<IsSignature, ProtocolError> {
    do_sign_participant(chan, threshold, me, keygen_output, message).await?;
    Ok(None)
}

/// similar to do_sign_coordinator except
/// it outputs the same type as do_sign_participant_test
async fn do_sign_coordinator_test(
    chan: SharedChannel,
    participants: ParticipantList,
    threshold: usize,
    me: Participant,
    keygen_output: KeygenOutput,
    message: Vec<u8>,
) -> Result<IsSignature, ProtocolError> {
    let sig = do_sign_coordinator(chan, participants, threshold, me, keygen_output, message).await?;
    Ok(Some(sig))
}


fn sign_test(
    participants: Vec<Participant>,
    threshold: usize,
    me: Participant,
    keygen_output: KeygenOutput,
    message: Vec<u8>,
    is_coordinator: bool,
) -> Result<Box<dyn Protocol<Output = IsSignature>>, ProtocolError> {
    if participants.len() < 2 {
        return Err(ProtocolError::AssertionFailed(format!(
            "participant count cannot be < 2, found: {}",
            participants.len()
        )));
    };
    let Some(participants) = ParticipantList::new(&participants) else {
        return Err(ProtocolError::AssertionFailed(format!(
            "Participants list contains duplicates",
        )));
    };

    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(ProtocolError::AssertionFailed(
            "participant list must contain this participant".to_string(),
        ));
    };

    let ctx = Context::new();
    if is_coordinator {
        let fut = do_sign_coordinator_test(
            ctx.shared_channel(),
            participants,
            threshold,
            me,
            keygen_output,
            message,
        );
        Ok(Box::new(make_protocol(ctx, fut)))
    } else {
        let fut = do_sign_participant_test(
            ctx.shared_channel(),
            threshold,
            me,
            keygen_output,
            message,
        );
        Ok(Box::new(make_protocol(ctx, fut)))
    }
}

pub(crate) fn run_signature_protocols(
    participants: &[(Participant, KeygenOutput)],
    actual_signers: usize,
    coordinators_count: usize,
    threshold: usize,
    msg_hash: Digest,
) -> Result<Vec<(Participant, IsSignature)>, Box<dyn Error>> {
    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = IsSignature>>)> =
        Vec::with_capacity(participants.len());

    let participants_list = participants
        .iter()
        .take(actual_signers)
        .map(|(id, _)| *id)
        .collect::<Vec<_>>();

    for (idx, (participant, key_pair)) in participants.iter().take(actual_signers).enumerate() {
        let protocol: Box<dyn Protocol<Output = IsSignature>> =
            sign_test(
                participants_list.clone(),
                threshold,
                *participant,
                key_pair.clone(),
                msg_hash.as_ref().to_vec(),
                idx < coordinators_count,
            )?;

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
    let public_key_package = participants.first().unwrap().1.public_key_package.clone();

    if participants
        .iter()
        .any(|(_, key_pair)| key_pair.public_key_package != public_key_package)
    {
        assert!(false , "public key package is not the same for all participants");
    }

    if public_key_package.verifying_shares().len() != participants.len() {
        assert!(false ,
            "public key package has different number of verifying shares than participants"
        );
    }

    for (participant, key_pair) in participants {
        let scalar = key_pair.private_share.to_scalar();
        let actual_verifying_share = {
            let point = frost_ed25519::Ed25519Group::generator() * scalar;
            VerifyingShare::new(point)
        };

        let verifying_share = key_pair.public_key_package
                                .verifying_shares()
                                .get(&participant.to_identifier())
                                .unwrap()
                                .clone();
        if actual_verifying_share != verifying_share {
            assert!(false ,"verifying share in `KeyPackage` is not equal to secret share * G");
        }

        {
            let expected_verifying_share = key_pair
                .public_key_package
                .verifying_shares()
                .get(&participant.to_identifier())
                .unwrap();
            if actual_verifying_share != *expected_verifying_share {
                assert!(false ,
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
    participants_keys: &[(Participant, KeygenOutput)],
) -> frost_ed25519::SigningKey {
    let mut secret = frost_ed25519::Ed25519ScalarField::zero();
    let participants: Vec<Participant> = participants_keys
        .iter()
        .map(|(participant, _)| participant.clone())
        .collect();

    let participants = ParticipantList::new(&participants).unwrap();

    for (p, keys) in participants_keys {
        let lagrange_coefficient = participants.generic_lagrange::<Ed25519Sha512>(*p);
        secret = secret + (lagrange_coefficient * keys.private_share.to_scalar());
    }
    SigningKey::from_scalar(secret).unwrap()
}

/// Assert that:
///     1. For each subset of size `< threshold` incorrect signing key is reconstructed.
///     2. For each subset of size `>= threshold` correct signing key is constructed.
pub(crate) fn assert_signing_schema_threshold_holds(
    expected_signing_key: frost_ed25519::SigningKey,
    threshold: usize,
    participants: &[(Participant, KeygenOutput)],
) -> Result<(), Box<dyn Error>> {

    for actual_signers_count in 1..=participants.len() {
        participants
            .iter()
            .cloned()
            .combinations(actual_signers_count)
            .for_each(|signers| {
            let signing_key= reconstruct_signing_key(signers.as_slice());
            if actual_signers_count < threshold {
                if signing_key == expected_signing_key {
                    assert!(false ,
                        "signing key should not be reconstructed \
                        for subset of size {actual_signers_count:?}")
                    };
            } else {
                if signing_key != expected_signing_key {
                    assert!(false ,
                        "signing key should be reconstructed for subset of size {actual_signers_count:?},\
                    which is greater or equal to threshold: {threshold:?}");
                }
            };
        });
    };
    Ok(())
}