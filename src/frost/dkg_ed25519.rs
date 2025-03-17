use frost_ed25519::*;

use crate::generic_dkg::*;
use crate::protocol::internal::{make_protocol, Context};
use crate::protocol::{InitializationError, Protocol, Participant};

type E = Ed25519Sha512;

/// Performs the first part of the distributed key generation protocol
/// for the given participant.
///
/// It returns the [`round1::SecretPackage`] that must be kept in memory
/// by the participant for the other steps, and the [`round1::Package`] that
/// must be sent to each other participant in the DKG run.
pub fn keygen(
    participants: &[Participant],
    me: Participant,
    threshold: usize,
) -> Result<impl Protocol<Output = KeygenOutput<E>>, InitializationError> {
    let ctx = Context::new();
    let participants = keygen_assertions::<E>(participants, me, threshold)?;
    let fut = do_keygen(ctx.shared_channel(), participants, me, threshold);
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
    ) -> Result<Vec<(Participant, KeygenOutput<E>)>, Box<dyn Error>> {
        let mut protocols: Vec<(
            Participant,
            Box<dyn Protocol<Output = KeygenOutput<E>>>,
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
        assert_eq!(result[0].1.public_key, result[1].1.public_key);
        assert_eq!(result[1].1.public_key, result[2].1.public_key);

        let pub_key = result[2].1.public_key.to_element();

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

    // #[test]
    // fn test_refresh() -> Result<(), Box<dyn Error>> {
    //     let participants = vec![
    //         Participant::from(0u32),
    //         Participant::from(1u32),
    //         Participant::from(2u32),
    //     ];
    //     let threshold = 3;

    //     let result0 = do_keygen(&participants, threshold)?;

    //     let pub_key = result0[2].1.public_key;

    //     // Refresh
    //     let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = Scalar>>)> =
    //         Vec::with_capacity(participants.len());

    //     for (p, out) in result0.iter() {
    //         let protocol = refresh::<Secp256k1>(
    //             &participants,
    //             threshold,
    //             *p,
    //             out.private_share,
    //             out.public_key,
    //         )?;
    //         protocols.push((*p, Box::new(protocol)));
    //     }

    //     let result1 = run_protocol(protocols)?;

    //     let participants = vec![result1[0].0, result1[1].0, result1[2].0];
    //     let shares = vec![result1[0].1, result1[1].1, result1[2].1];
    //     let p_list = ParticipantList::new(&participants).unwrap();
    //     let x = p_list.lagrange::<Secp256k1>(participants[0]) * shares[0]
    //         + p_list.lagrange::<Secp256k1>(participants[1]) * shares[1]
    //         + p_list.lagrange::<Secp256k1>(participants[2]) * shares[2];
    //     assert_eq!(ProjectivePoint::GENERATOR * x, pub_key);

    //     Ok(())
    // }

    // #[test]
    // fn test_reshare() -> Result<(), Box<dyn Error>> {
    //     let participants = vec![
    //         Participant::from(0u32),
    //         Participant::from(1u32),
    //         Participant::from(2u32),
    //         Participant::from(3u32),
    //     ];
    //     let threshold0 = 3;
    //     let threshold1 = 4;

    //     let result0 = do_keygen(&participants[..3], threshold0)?;

    //     let pub_key = result0[2].1.public_key;

    //     // Reshare
    //     let mut setup: Vec<_> = result0
    //         .into_iter()
    //         .map(|(p, out)| (p, (Some(out.private_share), out.public_key)))
    //         .collect();
    //     setup.push((Participant::from(3u32), (None, pub_key)));

    //     let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = Scalar>>)> =
    //         Vec::with_capacity(participants.len());

    //     for (p, out) in setup.iter() {
    //         let protocol = reshare::<Secp256k1>(
    //             &participants[..3],
    //             threshold0,
    //             &participants,
    //             threshold1,
    //             *p,
    //             out.0,
    //             out.1,
    //         )?;
    //         protocols.push((*p, Box::new(protocol)));
    //     }

    //     let result1 = run_protocol(protocols)?;

    //     let participants = vec![result1[0].0, result1[1].0, result1[2].0, result1[3].0];
    //     let shares = vec![result1[0].1, result1[1].1, result1[2].1, result1[3].1];
    //     let p_list = ParticipantList::new(&participants).unwrap();
    //     let x = p_list.lagrange::<Secp256k1>(participants[0]) * shares[0]
    //         + p_list.lagrange::<Secp256k1>(participants[1]) * shares[1]
    //         + p_list.lagrange::<Secp256k1>(participants[2]) * shares[2]
    //         + p_list.lagrange::<Secp256k1>(participants[3]) * shares[3];
    //     assert_eq!(ProjectivePoint::GENERATOR * x, pub_key);

    //     Ok(())
    // }
}