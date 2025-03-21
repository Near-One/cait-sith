use k256::{AffinePoint, Secp256k1};

use crate::{
    compat::scalar_hash,
    presign,
    sign,
    ecdsa::triples::{self, TriplePub, TripleShare},
    FullSignature, PresignArguments, PresignOutput,
};







use crate::ecdsa::KeygenOutput;
use crate::participants::ParticipantList;
use crate::protocol::{run_protocol, Participant, Protocol, ProtocolError};
use crate::protocol::internal::{make_protocol, Context, SharedChannel};
use crate::ecdsa::dkg_ecdsa::{keygen, reshare, refresh};

use frost_secp256k1::keys::{PublicKeyPackage, VerifyingShare};
use frost_secp256k1::{Secp256K1Sha256, Group, Field, Signature, SigningKey};
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

    let (shares, pubkey_package) = frost_secp256k1::keys::generate_with_dealer(
        max_signers as u16,
        min_signers as u16,
        frost_secp256k1::keys::IdentifierList::Custom(identifiers_list.as_slice()),
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
    new_participants: Vec<Participant>,
) -> Result<Vec<(Participant, KeygenOutput)>, Box<dyn Error>> {
    assert!(new_participants.len() > 0);
    let mut setup: Vec<_> = vec![];

    for new_participant in &new_participants{
        let mut is_break = false;
        for (p,k) in &keys {
            if p.clone() == new_participant.clone() {
                setup.push((p.clone(), (Some(k.private_share.clone()), k.public_key_package.clone())));
                is_break = true;
                break;
            }
        }
        if !is_break{
            setup.push((new_participant.clone(), (None, pub_key.clone())));
        }
    }

    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = KeygenOutput>>)> =
    Vec::with_capacity(participants.len());

    for (p, out) in setup.iter() {
        let protocol = reshare(
            &participants,
            old_threshold,
            out.0,
            out.1.clone(),
            &new_participants,
            new_threshold,
            *p,
        )?;
        protocols.push((*p, Box::new(protocol)));
    }

    let result = run_protocol(protocols)?;
    Ok(result)
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
            let point = frost_secp256k1::Secp256K1Group::generator() * scalar;
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




























// fn run_keygen(
//     participants: Vec<Participant>,
//     threshold: usize,
// ) -> Vec<(Participant, KeygenOutput<Secp256k1>)> {
//     #[allow(clippy::type_complexity)]
//     let mut protocols: Vec<(
//         Participant,
//         Box<dyn Protocol<Output = KeygenOutput<Secp256k1>>>,
//     )> = Vec::with_capacity(participants.len());

//     for p in participants.iter() {
//         let protocol = keygen(&participants, *p, threshold);
//         assert!(protocol.is_ok());
//         let protocol = protocol.unwrap();
//         protocols.push((*p, Box::new(protocol)));
//     }

//     run_protocol(protocols).unwrap()
// }

// fn run_presign(
//     participants: Vec<(Participant, KeygenOutput<Secp256k1>)>,
//     shares0: Vec<TripleShare<Secp256k1>>,
//     shares1: Vec<TripleShare<Secp256k1>>,
//     pub0: &TriplePub<Secp256k1>,
//     pub1: &TriplePub<Secp256k1>,
//     threshold: usize,
// ) -> Vec<(Participant, PresignOutput<Secp256k1>)> {
//     assert!(participants.len() == shares0.len());
//     assert!(participants.len() == shares1.len());

//     #[allow(clippy::type_complexity)]
//     let mut protocols: Vec<(
//         Participant,
//         Box<dyn Protocol<Output = PresignOutput<Secp256k1>>>,
//     )> = Vec::with_capacity(participants.len());

//     let participant_list: Vec<Participant> = participants.iter().map(|(p, _)| *p).collect();

//     for (((p, keygen_out), share0), share1) in participants
//         .into_iter()
//         .zip(shares0.into_iter())
//         .zip(shares1.into_iter())
//     {
//         let protocol = presign(
//             &participant_list,
//             p,
//             &participant_list,
//             p,
//             PresignArguments {
//                 triple0: (share0, pub0.clone()),
//                 triple1: (share1, pub1.clone()),
//                 keygen_out,
//                 threshold,
//             },
//         );
//         assert!(protocol.is_ok());
//         let protocol = protocol.unwrap();
//         protocols.push((p, Box::new(protocol)));
//     }

//     run_protocol(protocols).unwrap()
// }

// #[allow(clippy::type_complexity)]
// fn run_sign(
//     participants: Vec<(Participant, PresignOutput<Secp256k1>)>,
//     public_key: AffinePoint,
//     msg: &[u8],
// ) -> Vec<(Participant, FullSignature<Secp256k1>)> {
//     let mut protocols: Vec<(
//         Participant,
//         Box<dyn Protocol<Output = FullSignature<Secp256k1>>>,
//     )> = Vec::with_capacity(participants.len());

//     let participant_list: Vec<Participant> = participants.iter().map(|(p, _)| *p).collect();

//     for (p, presign_out) in participants.into_iter() {
//         let protocol = sign(
//             &participant_list,
//             p,
//             public_key,
//             presign_out,
//             scalar_hash(msg),
//         );
//         assert!(protocol.is_ok());
//         let protocol = protocol.unwrap();
//         protocols.push((p, Box::new(protocol)));
//     }

//     run_protocol(protocols).unwrap()
// }

// #[test]
// fn test_e2e() {
//     let participants = vec![
//         Participant::from(0u32),
//         Participant::from(1u32),
//         Participant::from(2u32),
//     ];
//     let t = 3;

//     let mut keygen_result = run_keygen(participants.clone(), t);
//     keygen_result.sort_by_key(|(p, _)| *p);

//     let public_key = keygen_result[0].1.public_key;
//     assert_eq!(keygen_result[0].1.public_key, keygen_result[1].1.public_key);
//     assert_eq!(keygen_result[1].1.public_key, keygen_result[2].1.public_key);

//     let (pub0, shares0) = triples::deal(&mut OsRng, &participants, t);
//     let (pub1, shares1) = triples::deal(&mut OsRng, &participants, t);

//     let mut presign_result = run_presign(keygen_result, shares0, shares1, &pub0, &pub1, t);
//     presign_result.sort_by_key(|(p, _)| *p);

//     let msg = b"hello world";

//     run_sign(presign_result, public_key, msg);
// }
