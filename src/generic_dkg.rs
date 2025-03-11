use rand_core::OsRng;
use std::ops::Index;
use crate::serde::encode;
use crate::crypto::{Digest, hash};

use frost_core::{
    Challenge, Ciphersuite, Element, Field, Group, Scalar, Signature, SigningKey, VerifyingKey, Identifier, Error
};
use frost_core::keys::{
    SecretShare, SigningShare,
    CoefficientCommitment, VerifiableSecretSharingCommitment};

use crate::echo_broadcast::do_broadcast;
use crate::participants::{ParticipantCounter, ParticipantList, ParticipantMap};
use crate::protocol::{Participant, ProtocolError};
use crate::protocol::internal::{make_protocol, Context, SharedChannel};


const LABEL: &[u8] = b"Generic DKG";


/// This function prevents calling keyshare function with inproper inputs
fn assert_keyshare_inputs<C: Ciphersuite>(
    me: Participant,
    secret: &Scalar<C>,
    old_reshare_package: Option<(VerifyingKey<C>, ParticipantList)>,
) -> Result<(Option<VerifyingKey<C>>, Option<ParticipantList>), ProtocolError> {
    let is_zero_secret = *secret == <C::Group as Group>::Field::zero();
    if old_reshare_package.is_some(){
        let (old_key, old_participants) = old_reshare_package.unwrap();
        if is_zero_secret{
            //  return error if me is not a purely new joiner to the participants set
            if old_participants.contains(me){
                return Err(ProtocolError::AssertionFailed(
                    format!("{me:?} is running DKG with a zero share but does belong to the old participant set")))
            }
        } else {
            //  return error if me is part of the old participants set
            if !old_participants.contains(me){
                return Err(ProtocolError::AssertionFailed(
                    format!("{me:?} is running Resharing with a zero share but does belong to the old participant set")))
            }
        }
        Ok((Some(old_key), Some(old_participants)))
    }else{
        if is_zero_secret{
            return Err(ProtocolError::AssertionFailed(
                format!("{me:?} is running DKG with a zero share")))
        }
        Ok((None, None))
    }
}

/// Creates a polynomial p of degree threshold - 1
/// and sets p(0) = secret
fn generate_secret_polynomial<C: Ciphersuite>(
    secret: Scalar<C>,
    threshold: usize,
    rng: &mut OsRng,
) -> Vec<Scalar<C>> {
    let mut coefficients = Vec::with_capacity(threshold);

    coefficients.push(secret);
    for _ in 1..threshold {
        coefficients.push(<C::Group as Group>::Field::random(rng));
    }

    coefficients
}


/// Generates the challenge for the proof of knowledge
/// H(id, context_string, g^{secret} , R)
fn challenge<C: Ciphersuite>(
    id: Scalar<C>,
    vk_share: &CoefficientCommitment<C>,
    big_r: &Element<C>,
) -> Result<Challenge<C>, ProtocolError> {
    let mut preimage = vec![];
    let serialized_id = <C::Group as Group>::Field::serialize(&id);

    // Should not return Error
    // The function should not be called when the first coefficient is zero
    let serialized_vk_share = vk_share.serialize()
        .map_err(|_| ProtocolError::AssertionFailed(
        format!("The verification share could not be serialized as it is null")))?;

    let serialized_big_r = <C::Group>::serialize(big_r)
        .map_err(|_| ProtocolError::AssertionFailed(
        format!("The group element R could not be serialized as it is the identity")))?;

    preimage.extend_from_slice(serialized_id.as_ref());
    preimage.extend_from_slice(serialized_vk_share.as_ref());
    preimage.extend_from_slice(serialized_big_r.as_ref());

    let hash = C::HDKG(&preimage[..]).ok_or(ProtocolError::DKGNotSupported)?;
    Ok(Challenge::from_scalar(hash))
}


/// Computes the proof of knowledge of the secret coefficient a_0
/// used to generate the public polynomial.
/// generate a random k and compute R = g^k
/// Compute mu = k + a_0 * H(id, context_string, g^{a_0} , R)
/// Output (R, mu)
fn proof_of_knowledge<C: Ciphersuite>(
    me: Participant,
    coefficients: &[Scalar<C>],
    coefficient_commitment: &Vec<CoefficientCommitment<C>>,
    rng: &mut OsRng,
) -> Result<Signature<C>, ProtocolError> {
    // creates an identifier for the participant
    let id = me.scalar::<C>()?;
    let vk_share = coefficient_commitment[0];

    // pick a random k_i and compute R_id = g^{k_id},
    let (k, big_r) = <C>::generate_nonce(rng);

    // compute H(id, context_string, g^{a_0} , R_id) as a scalar
    let hash = challenge::<C>(id, &vk_share, &big_r)?;
    let a_0 = coefficients[0];
    let mu = k + a_0 * hash.to_scalar();
    Ok(Signature::new(big_r, mu))
}

/// Generates a proof of knowledge.
/// The proof of knowledge could be set to None in case the participant is new
/// and thus its secret share is known (set to zero)
fn compute_proof_of_knowledge<C: Ciphersuite>(
    me: Participant,
    old_participants: Option<ParticipantList>,
    coefficients: &[Scalar<C>],
    coefficient_commitment: &Vec<CoefficientCommitment<C>>,
    rng: &mut OsRng,
) -> Result<Option<Signature<C>>, ProtocolError> {

    // I am allowed to send none only if I am a new participant
    if old_participants.is_some() && !old_participants.unwrap().contains(me){
        return Ok(None)
    };
    // generate a proof of knowledge if the participant me is not holding a secret that is zero
    let proof = proof_of_knowledge(me, coefficients, coefficient_commitment, rng)?;
    Ok(Some(proof))
}

/// Verifies the proof of knowledge of the secret coefficients used to generate the
/// public secret sharing commitment.
/// if the proof of knowledge is none then make sure that the participant is
/// performing reshare and does not exist in the set of old participants
fn verify_proof_of_knowledge<C: Ciphersuite>(
    participant: Participant,
    old_participants: Option<ParticipantList>,
    commitment: &VerifiableSecretSharingCommitment<C>,
    proof_of_knowledge: &Option<Signature<C>>,
) -> Result<(), ProtocolError> {

    // check that only the parties that are new can send none and the others do not!
    if proof_of_knowledge.is_none(){
        if old_participants.is_none() || old_participants.unwrap().contains(participant){
            return Err(ProtocolError::MaliciousParticipant(participant))
        }
    };

    // now we know the proof is not none
    let proof_of_knowledge = proof_of_knowledge.unwrap();
    let id = participant.scalar::<C>()?;
    // creating an identifier as required by the syntax of verify_proof_of_knowledge of frost_core
    // cannot panic as the previous line ensures id is neq zero
    let id = Identifier::new(id).unwrap();
    frost_core::keys::dkg::verify_proof_of_knowledge(id, commitment, &proof_of_knowledge)
                        .map_err(|_| ProtocolError::InvalidProofOfKnowledge(participant))
}

// evaluates a polynomial on the identifier of the participant
fn evaluate_polynomial<C:Ciphersuite>
    (coefficients: &[Scalar<C>], participant: Participant) -> Result<SigningShare<C>, ProtocolError> {
    let id = participant.scalar::<C>()?;
    // cannot panic as the previous line ensures id is neq zero
    let id = Identifier::new(id).unwrap();
    Ok(SigningShare::from_coefficients(coefficients, id))
}

// creates a signing share structure using my identifier, the received
// signing share and the received commitment
fn validate_received_share<C:Ciphersuite>(
    me: &Participant,
    from: &Participant,
    signing_share_from: &SigningShare<C>,
    commitment: &VerifiableSecretSharingCommitment<C>,
) -> Result<(), ProtocolError>{

    let id = me.scalar::<C>()?;
    // cannot panic as the previous line ensures id is neq zero
    let id = Identifier::new(id).unwrap();

    // The verification is exactly the same as the regular SecretShare verification;
    // however the required components are in different places.
    // Build a temporary SecretShare so what we can call verify().
    let secret_share = SecretShare::new(
        id,
        signing_share_from.clone(),
        commitment.clone());


    // Verify the share. We don't need the result.
    // Identify the culprit if an InvalidSecretShare error is returned.
    secret_share.verify().map_err(|e| {
        if let Error::InvalidSecretShare { .. } = e {
            ProtocolError::InvalidSecretShare(*from)
        } else {
            ProtocolError::AssertionFailed(format!("could not
            extract the verification key matching the secret
            share sent by {from:?}"))
        }
    })?;
    Ok(())
}

/// computes a transcript hash out of the public data
fn compute_transcript_hash<C:Ciphersuite>(
    participants: &ParticipantList,
    threshold: usize,
    all_commitments: &ParticipantMap<'_, VerifiableSecretSharingCommitment<C>>,
    all_proofs: &ParticipantMap<'_, Option<Signature<C>>>,
    ) -> Digest{
    // transcript contains:
    //      groupname
    //      participants
    //      threshold
    //      commitments
    //      zk proofs
    // we do not need to include the master verification key mvk as it is directly extracted from commitments
    let mut transcript = Vec::new();
    transcript.extend_from_slice(LABEL);
    transcript.extend_from_slice(b"group");
    transcript.extend_from_slice(C::ID.as_bytes());
    transcript.extend_from_slice(b"participants");
    transcript.extend_from_slice(&encode(participants));
    transcript.extend_from_slice(b"threshold");
    transcript.extend_from_slice(&u64::try_from(threshold).unwrap().to_be_bytes());
    transcript.extend_from_slice(b"all commitments");
    transcript.extend_from_slice(b"commitment opening: big_f");
    transcript.extend_from_slice(hash(all_commitments).as_ref());
    transcript.extend_from_slice(b"proofs");
    transcript.extend_from_slice(hash(all_proofs).as_ref());
    hash(&transcript)
}

/// generates a verification key out of a public commited polynomial
fn verifying_key_from_commitments<C:Ciphersuite>(
    commitments: Vec<&VerifiableSecretSharingCommitment<C>>
) -> Result<VerifyingKey<C>, ProtocolError>{
    let group_commitment = frost_core::keys::sum_commitments(&commitments)
        .map_err(|_| ProtocolError::IncorrectNumberOfCommitments)?;
    let vk = VerifyingKey::from_commitment(&group_commitment)
        .map_err(|_| ProtocolError::ErrorExtractVerificationKey)?;
    Ok(vk)
}


async fn broadcast_success_failure(
    chan: &mut SharedChannel,
    participants: &ParticipantList,
    me: &Participant,
    err: Option<ProtocolError>,
) -> Result<(), ProtocolError>{
    match err {
        // Need for consistent Broadcast to prevent adversary from sending
        // that it failed to some honest parties but not the others implying
        // that only some parties will drop out of the protocol but not others
        Some(err) => {
            // broadcast node me failed
            do_broadcast(chan, participants, me, false).await?;
            return Err(err);
        }

        None => {
            // broadcast node me succeded
            let vote_list = do_broadcast(chan, participants, me, true).await?;
            // unwrap here would never fail as the broadcast protocol ends only when the map is full
            let vote_list = vote_list.into_vec_or_none().unwrap();
            // go through all the list of votes and check if any is fail
            if vote_list.contains(&false) {
                return Err(ProtocolError::AssertionFailed(format!(
                    "A participant seems to have failed its checks. Aborting DKG!"
                )));
            };
            // Wait for all the tasks to complete
            return Ok(());
        }
    }
}

async fn do_keyshare<C: Ciphersuite>(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    threshold: usize,
    secret: Scalar<C>,
    old_reshare_package: Option<(VerifyingKey<C>, ParticipantList)>,
    mut rng: OsRng,
// ) -> Result<(C::Scalar, C::AffinePoint), ProtocolError> {
 ) -> Result<(SigningKey<C>, VerifyingKey<C>), ProtocolError>{

    let mut all_commitments = ParticipantMap::new(&participants);
    let mut all_proofs = ParticipantMap::new(&participants);

    // Make sure you do not call do_keyshare with zero as secret on an old participant
    let (old_verification_key, old_participants) = assert_keyshare_inputs(me, &secret, old_reshare_package)?;

    // Start Round 1
    // generate your secret polynomial p with the constant term set to the secret
    // and the rest of the coefficients are picked at random
    let secret_coefficients = generate_secret_polynomial::<C>(secret, threshold, &mut rng);

    // Compute the multiplication of every coefficient of p with the generator G
    let coefficient_commitment: Vec<CoefficientCommitment<C>> = secret_coefficients
        .iter()
        .map(|c| CoefficientCommitment::new(<C::Group as Group>::generator() * *c))
        .collect();
    // generate a proof of knowledge if the participant me is not holding a secret that is zero
    let proof_of_knowledge = compute_proof_of_knowledge(me, old_participants.clone(), &secret_coefficients, &coefficient_commitment, &mut rng)?;

    // Create the public polynomial = secret coefficients times G
    let commitment = VerifiableSecretSharingCommitment::new(coefficient_commitment);

    // add my commitment and proof to the map
    all_commitments.put(me, commitment.clone());
    all_proofs.put(me, proof_of_knowledge.clone());

    // Broadcast to all the commitment and the proof of knowledge
    let commitments_and_proofs_map = do_broadcast(&mut chan, &participants, &me, (commitment, proof_of_knowledge)).await?;

    // Start Round 2
    let wait_round2 = chan.next_waitpoint();
    for p in participants.others(me) {
        let (commitment_i, proof_i) = commitments_and_proofs_map.index(p);
        if commitment_i.coefficients().len() != threshold {
            return Err(ProtocolError::IncorrectNumberOfCommitments);
        };

        // verify the proof of knowledge
        // if proof is none then make sure the participant is new
        // and performing a resharing not a DKG
        verify_proof_of_knowledge(p, old_participants.clone(), commitment_i, proof_i)?;

        // add received commitment and proof to the map
        all_commitments.put(p, commitment_i.clone());
        all_proofs.put(p, proof_i.clone());

        // Securely send to each other participant a secret share
        // using the evaluation secret polynomial on the identifier of the recipient
        let signing_share_to_p = evaluate_polynomial::<C>(&secret_coefficients, p)?;
        // send the evaluation privately to participant p
        chan.send_private(wait_round2, p, &signing_share_to_p).await;
    }

    // compute the my secret evaluation of my private polynomial
    let mut my_signing_share = evaluate_polynomial::<C>(&secret_coefficients, me)?.to_scalar();
    // receive evaluations from all
    let mut seen = ParticipantCounter::new(&participants);
    seen.put(me);
    while !seen.full() {
        let (from, signing_share_from): (Participant, SigningShare<C>) = chan.recv(wait_round2).await?;
        if !seen.put(from) {
            continue
        }

        let commitment_from = all_commitments.index(from);

        // Verify the share
        validate_received_share::<C>(&me, &from, &signing_share_from, commitment_from)?;

        // Compute the sum of all the owned secret shares
        // At the end of this loop, I will be owning a valid secret signing share
        my_signing_share = my_signing_share + signing_share_from.to_scalar();

    };

    // Start Round 3
    // compute transcript hash
    let my_transcript = compute_transcript_hash(&participants, threshold, &all_commitments, &all_proofs);
    // receive all transcript hashes
    let transcript_list = do_broadcast(&mut chan, &participants, &me, my_transcript).await?;
    let transcript_list = transcript_list.into_vec_or_none().unwrap();
    // verify that all the transcripts are the same
    let mut err = None;
    // check transcript hashes
    for their_transcript in transcript_list {
        if my_transcript != their_transcript {
            err = Some(ProtocolError::AssertionFailed(format!("transcript hash did not match expectation")));
            break;
        }
    }

    // Construct the keypairs
    // Construct the signing share
    let signing_share = SigningKey::<C>::from_scalar(my_signing_share)
    .map_err(|_| ProtocolError::MalformedSigningKey)?;
    // cannot fail as all_commitments at least contains my commitment
    let all_commitments_vec = all_commitments.into_vec_or_none().unwrap();
    let all_commitments_refs = all_commitments_vec.iter().collect();

        // Calculate the public verification key.
    let verifying_key = match verifying_key_from_commitments(all_commitments_refs){
        Ok(vk) => Some(vk),
        Err(e) => {err = Some(e); None},
    };

    // In the case of Resharing, check if the old public key is the same as the new one
    if let Some(vk) = old_verification_key {
        if verifying_key.is_some(){
            // check the equality between the old key and the new key without failing the unwrap
            if vk != verifying_key.unwrap(){
                err = Some(ProtocolError::AssertionFailed(format!("new public key does not match old public key")));
            }
        };
    };

    // Start Round 4
    broadcast_success_failure(&mut chan, &participants, &me, err).await?;

    // unwrap cannot fail as round 4 ensures failing if verification_key is None
    return Ok((signing_share, verifying_key.unwrap()));
}


fn do_keygen<C: Ciphersuite>(){
    // pick share at random
    let mut rng = OsRng;
    let secret: SigningKey<C> = SigningKey::new(&mut rng);

    // TODO

    // run keyshare
    // output OK(output)
}

pub fn keygen(){
    // // validate_num_of_signers::<C>(min_signers, max_signers)?;
    // if participants.len() < 2 {
    //     return Err(InitializationError::BadParameters(format!(
    //         "participant count cannot be < 2, found: {}",
    //         participants.len()
    //     )));
    // };

    // // validate threshold
    // if threshold > participants.len() {
    //     return Err(InitializationError::BadParameters(
    //         "threshold must be <= participant count".to_string(),
    //     ));
    // }

    // // ensure uniqueness of participants in the participant list
    // let participants = ParticipantList::new(participants).ok_or_else(|| {
    //     InitializationError::BadParameters("participant list cannot contain duplicates".to_string())
    // })?;

    // // ensure my presence in the participant list
    // if !participants.contains(me) {
    //     return Err(InitializationError::BadParameters(
    //         "participant list must contain this participant".to_string(),
    //     ));
    // }


    // let ctx = Context::new();
    // let fut = do_keygen(ctx.shared_channel(), participants, me, threshold);
    // Ok(make_protocol(ctx, fut))
}


fn do_reshare<C: Ciphersuite>
    (old_signing_key: Option<SigningKey<C>>){
    let mut rng = OsRng;

    // make sure that me is in the new participant set but not in the old one
    // if that is the case but old_signing_key is set to something that is not None
    // then return Error... this means that somebody has plugged an extremely
    // old key in the function

    let secret: Scalar<C> = match old_signing_key {
        // set share to 0 if there was no old signing key
        None => <C::Group as Group>::Field::zero(),
        Some(secret) => secret.to_scalar(),
    };
    // if is none, set share to zero

}

pub fn reshare(){
    // validate_num_of_signers::<C>(min_signers, max_signers)?;
    // validate thresholds
    // validate old set/new set
    // etc
}


/// The refresh protocol.
/// This is like resharing, but having the old participants set be the same as the new one.
pub fn refresh(){

}