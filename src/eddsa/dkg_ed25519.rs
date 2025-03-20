use frost_ed25519::*;
use keys::PublicKeyPackage;

use crate::generic_dkg::*;
use crate::protocol::internal::{make_protocol, Context};
use crate::protocol::{InitializationError, Protocol, Participant};
use crate::eddsa::KeygenOutput;

type E = Ed25519Sha512;

/// Performs the Ed25519 DKG protocol
pub fn keygen(
    participants: &[Participant],
    me: Participant,
    threshold: usize,
) -> Result<impl Protocol<Output = KeygenOutput>, InitializationError> {
    let ctx = Context::new();
    let participants = keygen_assertions::<E>(participants, me, threshold)?;
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
    let old_public_key = old_public_key.verifying_key().clone();
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
    let old_public_key = old_public_key.verifying_key().clone();
    let (participants,old_participants) = reshare_assertions::<E>(new_participants, me, threshold, old_signing_key, threshold, new_participants)?;
    let fut = do_reshare(ctx.shared_channel(), participants, me, threshold, old_signing_key, old_public_key, old_participants);
    Ok(make_protocol(ctx, fut))
}


#[cfg(test)]
mod test {
    use super::*;

    use std::error::Error;
    use crate::protocol::{run_protocol, Participant};
    use crate::participants::ParticipantList;

    #[allow(clippy::type_complexity)]
    fn run_keygen(
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

    #[test]
    fn test_keygen() -> Result<(), Box<dyn Error>> {
        let participants = vec![
            Participant::from(3u32),
            Participant::from(1u32),
            Participant::from(2u32),
        ];
        let threshold = 3;

        let result = run_keygen(&participants, threshold)?;
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
        assert_eq!(<Ed25519Group>::generator() * x, pub_key);
        Ok(())
    }

    #[test]
    fn test_refresh() -> Result<(), Box<dyn Error>> {
        let participants = vec![
            Participant::from(0u32),
            Participant::from(1u32),
            Participant::from(2u32),
        ];
        let threshold = 3;

        let result0 = run_keygen(&participants, threshold)?;

        let pub_key = result0[2].1.public_key_package.verifying_key().to_element();

        // Refresh
        let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = KeygenOutput>>)> =
            Vec::with_capacity(participants.len());

        for (p, out) in result0.iter() {
            let protocol = refresh(
                Some(out.private_share),
                out.public_key_package.clone(),
                &participants,
                threshold,
                *p,
            )?;
            protocols.push((*p, Box::new(protocol)));
        }

        let result1 = run_protocol(protocols)?;

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
        assert_eq!(<Ed25519Group>::generator() * x, pub_key);
        Ok(())
    }

    #[test]
    fn test_reshare() -> Result<(), Box<dyn Error>> {
        let participants = vec![
            Participant::from(0u32),
            Participant::from(1u32),
            Participant::from(2u32),
            Participant::from(3u32),
        ];
        let threshold0 = 3;
        let threshold1 = 4;

        let result0 = run_keygen(&participants[..3], threshold0)?;

        let pub_key = result0[2].1.public_key_package.clone();

        // Reshare
        let mut setup: Vec<_> = result0
            .into_iter()
            .map(|(p, out)| (p, (Some(out.private_share), out.public_key_package)))
            .collect();
        setup.push((Participant::from(3u32), (None, pub_key.clone())));

        let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = KeygenOutput>>)> =
            Vec::with_capacity(participants.len());

        for (p, out) in setup.iter() {
            let protocol = reshare(
                &participants[..3],
                threshold0,
                out.0,
                out.1.clone(),
                &participants,
                threshold1,
                *p,
            )?;
            protocols.push((*p, Box::new(protocol)));
        }

        let result1 = run_protocol(protocols)?;

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
        assert_eq!(<Ed25519Group>::generator() * x, pub_key.verifying_key().to_element());

        Ok(())
    }
}