use frost_secp256k1::*;
use keys::PublicKeyPackage;

use crate::generic_dkg::*;
use crate::protocol::internal::{make_protocol, Context};
use crate::protocol::{InitializationError, Protocol, Participant};
use crate::ecdsa::KeygenOutput;

type E = Secp256K1Sha256;

/// Performs the Ed25519 DKG protocol
pub fn keygen(
    participants: &[Participant],
    me: Participant,
    threshold: usize,
) -> Result<impl Protocol<Output = KeygenOutput>, InitializationError> {
    let ctx = Context::new();
    let participants = assert_keygen_invariants::<E>(participants, me, threshold)?;
    let fut = do_keygen(ctx.shared_channel(), participants, me, threshold);
    Ok(make_protocol(ctx, fut))
}

/// Performs the Ed25519 Reshare protocol
pub fn reshare(
    old_participants: &[Participant],
    old_threshold: usize,
    old_signing_key: Option<SigningKey>,
    old_public_key: PublicKeyPackage,
    new_participants: &[Participant],
    new_threshold: usize,
    me: Participant,
) -> Result<impl Protocol<Output = KeygenOutput>, InitializationError> {
    let ctx = Context::new();
    let threshold = new_threshold;
    let old_public_key = *old_public_key.verifying_key();
    let (participants,old_participants) = reshare_assertions::<E>(new_participants, me, threshold, old_signing_key, old_threshold, old_participants)?;
    let fut = do_reshare(ctx.shared_channel(), participants, me, threshold, old_signing_key, old_public_key, old_participants);
    Ok(make_protocol(ctx, fut))
}

/// Performs the Ed25519 Refresh protocol
pub fn refresh(
    old_signing_key: Option<SigningKey>,
    old_public_key: PublicKeyPackage,
    new_participants: &[Participant],
    new_threshold: usize,
    me: Participant,
) -> Result<impl Protocol<Output = KeygenOutput>, InitializationError> {
    if old_signing_key.is_none(){
        return Err(InitializationError::BadParameters(format!(
            "The participant {me:?} is running refresh without an old share",
        )));
    }
    let ctx = Context::new();
    let threshold = new_threshold;
    let old_public_key = *old_public_key.verifying_key();
    let (participants,old_participants) = reshare_assertions::<E>(new_participants, me, threshold, old_signing_key, threshold, new_participants)?;
    let fut = do_reshare(ctx.shared_channel(), participants, me, threshold, old_signing_key, old_public_key, old_participants);
    Ok(make_protocol(ctx, fut))
}



#[cfg(test)]
mod test {
    use super::*;

    use std::error::Error;
    use crate::protocol::Participant;
    use crate::ecdsa::test::{
        run_keygen,
        run_refresh,
        run_reshare,
        assert_public_key_invariant
    };
    use crate::participants::ParticipantList;


    #[test]
    fn test_keygen() -> Result<(), Box<dyn Error>> {
        let participants = vec![
            Participant::from(31u32),
            Participant::from(1u32),
            Participant::from(2u32),
        ];
        let threshold = 3;

        let result = run_keygen(&participants, threshold)?;
        assert_public_key_invariant(&result)?;

        assert!(result.len() == participants.len());
        assert_eq!(result[0].1.public_key_package, result[1].1.public_key_package);
        assert_eq!(result[1].1.public_key_package, result[2].1.public_key_package);

        let pub_key = result[2].1.public_key_package.verifying_key().to_element();

        let participants = vec![result[0].0, result[1].0, result[2].0];
        let shares = vec![
            result[0].1.private_share.to_scalar(),
            result[1].1.private_share.to_scalar(),
            result[2].1.private_share.to_scalar(),
        ];
        let p_list = ParticipantList::new(&participants).unwrap();
        let x = p_list.generic_lagrange::<E>(participants[0]) * shares[0]
            + p_list.generic_lagrange::<E>(participants[1]) * shares[1]
            + p_list.generic_lagrange::<E>(participants[2]) * shares[2];
        assert_eq!(<Secp256K1Group>::generator() * x, pub_key);
        Ok(())
    }

    #[test]
    fn test_refresh() -> Result<(), Box<dyn Error>> {
        let participants = vec![
            Participant::from(0u32),
            Participant::from(31u32),
            Participant::from(2u32),
        ];
        let threshold = 3;

        let result0 = run_keygen(&participants, threshold)?;
        assert_public_key_invariant(&result0)?;

        let pub_key = result0[2].1.public_key_package.verifying_key().to_element();

        let result1 = run_refresh(&participants, result0, threshold)?;
        assert_public_key_invariant(&result1)?;

        let participants = vec![
            result1[0].0,
            result1[1].0,
            result1[2].0
        ];
        let shares = vec![
            result1[0].1.private_share.to_scalar(),
            result1[1].1.private_share.to_scalar(),
            result1[2].1.private_share.to_scalar()
        ];
        let p_list = ParticipantList::new(&participants).unwrap();
        let x = p_list.generic_lagrange::<E>(participants[0]) * shares[0]
            + p_list.generic_lagrange::<E>(participants[1]) * shares[1]
            + p_list.generic_lagrange::<E>(participants[2]) * shares[2];
        assert_eq!(<Secp256K1Group>::generator() * x, pub_key);
        Ok(())
    }

    #[test]
    fn test_reshare() -> Result<(), Box<dyn Error>> {
        let participants = vec![
            Participant::from(0u32),
            Participant::from(1u32),
            Participant::from(2u32),
        ];
        let threshold0 = 2;
        let threshold1 = 3;

        let result0 = run_keygen(&participants, threshold0)?;
        assert_public_key_invariant(&result0)?;

        let pub_key = result0[2].1.public_key_package.clone();

        let mut new_participant = participants.clone();
        new_participant.push(Participant::from(31u32));
        let result1 = run_reshare(&participants, &pub_key, result0, threshold0, threshold1, new_participant)?;
        assert_public_key_invariant(&result1)?;

        let participants = vec![
            result1[0].0,
            result1[1].0,
            result1[2].0,
            result1[3].0
        ];
        let shares = vec![
            result1[0].1.private_share.to_scalar(),
            result1[1].1.private_share.to_scalar(),
            result1[2].1.private_share.to_scalar(),
            result1[3].1.private_share.to_scalar()
        ];
        let p_list = ParticipantList::new(&participants).unwrap();
        let x = p_list.generic_lagrange::<E>(participants[0]) * shares[0]
            + p_list.generic_lagrange::<E>(participants[1]) * shares[1]
            + p_list.generic_lagrange::<E>(participants[2]) * shares[2]
            + p_list.generic_lagrange::<E>(participants[3]) * shares[3];
        assert_eq!(<Secp256K1Group>::generator() * x, pub_key.verifying_key().to_element());

        Ok(())
    }
}