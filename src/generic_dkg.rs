use rand_core::OsRng;
use std::ops::Index;
use crate::serde::encode;

use frost_core::{
    Challenge, Ciphersuite, Element, Field, Group, Scalar, Signature, SigningKey, Identifier
};
use frost_core::keys::{
    KeyPackage, PublicKeyPackage, CoefficientCommitment, VerifiableSecretSharingCommitment, SigningShare};

use crate::echo_broadcast::do_broadcast;
use crate::participants::{ParticipantCounter, ParticipantList, ParticipantMap};
use crate::protocol::{Participant, ProtocolError};
use crate::protocol::internal::{make_protocol, Context, SharedChannel};


const LABEL: &[u8] = b"Generic DKG";

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
fn compute_proof_of_knowledge<C: Ciphersuite>(
    me: &Participant,
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


/// Verifies the proof of knowledge of the secret coefficients used to generate the
/// public secret sharing commitment.
/// if the proof of knowledge is none then make sure that the participant is
/// performing reshare and does not exist in the set of old participants
fn verify_proof_of_knowledge<C: Ciphersuite>(
    participant: Participant,
    commitment: &VerifiableSecretSharingCommitment<C>,
    proof_of_knowledge: &Option<Signature<C>>,
) -> Result<(), ProtocolError> {

    if proof_of_knowledge.is_none(){
        // TODO
        todo!("need to check that only the parties that are new can send none and the others do not!");
        return Ok(());
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
    // creating an identifier as required by the syntax of verify_proof_of_knowledge of frost_core
    // cannot panic as the previous line ensures id is neq zero
    let id = Identifier::new(id).unwrap();
    Ok(SigningShare::from_coefficients(coefficients, id))
}


async fn do_keyshare<C: Ciphersuite>(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    threshold: usize,
    secret: Scalar<C>,
    old_pk: Option<PublicKeyPackage<C>>,
    mut rng: OsRng,
// ) -> Result<(C::Scalar, C::AffinePoint), ProtocolError> {
 ) -> Result<(KeyPackage<C>, PublicKeyPackage<C>), ProtocolError>{
    // determines whether this is a resharing for a new participant
    // this boolean is important as it is impossible to serialize the
    // identity element 0*G and thus impossible to compute a proof of knowledge
    let is_resharing = secret == <C::Group as Group>::Field::zero();

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
    let proof_of_knowledge = if !is_resharing{
        Some(compute_proof_of_knowledge(&me, &secret_coefficients, &coefficient_commitment, &mut rng)?)
    }else{
        None
    };

    let commitment = VerifiableSecretSharingCommitment::new(coefficient_commitment);

    // Broadcast to all the commitment and the proof of knowledge
    let commitments_and_proofs_map = do_broadcast(&mut chan, &participants, &me, (commitment, proof_of_knowledge)).await?;


    // Start Round 2
    let wait_round2 = chan.next_waitpoint();
    for p in participants.others(me) {
        let (commitment_i, proof_i) = commitments_and_proofs_map.index(p);
        let com_i_len = commitment_i.coefficients().len();
        if com_i_len != threshold {
            return Err(ProtocolError::IncorrectNumberOfCommitments(com_i_len, threshold));
        };

        // verify the proof of knowledge
        // if proof is none then make sure the participant is new
        // and we are performing a resharing
        verify_proof_of_knowledge(p, commitment_i, proof_i)?;

        // Securely send to each other participant a secret share
        // using the evaluation secret polynomial on the identifier of the recipient
        let their_signing_share = evaluate_polynomial::<C>(&secret_coefficients, p)?;
        // send the evaluation privately to participant p
        chan.send_private(wait_round2, p, &their_signing_share).await;
    }

    // compute the my secret evaluation of my private polynomial
    let my_secret_eval = evaluate_polynomial::<C>(&secret_coefficients, me)?.to_scalar();
    // receive evaluations from all
    let mut seen = ParticipantCounter::new(&participants);
    seen.put(me);
    while !seen.full() {
        let (from, signing_share): (Participant, SigningShare<C>) = chan.recv(wait_round2).await?;
        if !seen.put(from) {
            continue
        }
        // TODO
        // add these shares
    }




    // all_commitments.put(me, commitment);
    // // while !all_commitments.full() {
    // //     let (from, commitment) = chan.recv(wait0).await?;
    // //     all_commitments.put(from, commitment);
    // // }




    // transcript data
    let mut transcript = Vec::new();
    transcript.extend_from_slice(LABEL);
    transcript.extend_from_slice(b"group");
    transcript.extend_from_slice(C::ID.as_bytes());
    transcript.extend_from_slice(b"participants");
    transcript.extend_from_slice(&encode(&participants));
    transcript.extend_from_slice(b"threshold");
    transcript.extend_from_slice(&u64::try_from(threshold).unwrap().to_be_bytes());
    transcript.extend_from_slice(b"all commitments");



    todo!("return");

    // match old_pk {
    //     Some(big_s) if big_s != big_x => {
    //         err = "new public key does not match old public key".to_string()
    //     }
    //     _ => {}
    // };

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
/// This is like resharing, but with extra constraints to ensure that the set
/// of participants and threshold do not change.
pub fn refresh(){

}