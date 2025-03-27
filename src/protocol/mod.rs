//! This module provides abstractions for working with protocols.
//!
//! This library tries to abstract away as much of the internal machinery
//! of protocols as much as possible. To use a protocol, you just need to be able
//! to deliver messages to and from that protocol, and eventually it will produce
//! a result, without you having to worry about how many rounds it has, or how
//! to serialize the emssages it produces.
use std::{collections::HashMap, error, fmt};

use crate::compat::CSCurve;
use ::serde::{Deserialize, Serialize};

use frost_core::serialization::SerializableScalar;
use frost_core::{Ciphersuite, Identifier, Scalar};

/// Represents an error which can happen when running a protocol.
#[derive(Debug)]
pub enum ProtocolError {
    /// Some assertion in the protocol failed.
    AssertionFailed(String),
    /// The ciphersuite does not support DKG.
    DKGNotSupported,
    /// Could not extract the verification Key from a commitment.
    ErrorExtractVerificationKey,
    /// The sent commitment hash does not equal the hash of the sent commitment
    InvalidCommitmentHash,
    /// Incorrect number of commitments.
    IncorrectNumberOfCommitments,
    /// The identifier of the signer whose share validation failed.
    InvalidProofOfKnowledge(Participant),
    /// The validation of the secret share sent has failed
    InvalidSecretShare(Participant),
    /// The signing key is zero
    MalformedElement,
    /// Detected malicious participant
    MaliciousParticipant(Participant),
    /// The signing key is zero
    MalformedSigningKey,
    /// Error in serializing point
    PointSerialization,
    /// Some generic error happened.
    Other(Box<dyn error::Error + Send + Sync>),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolError::Other(e) => write!(f, "{}", e),
            ProtocolError::AssertionFailed(e) => write!(f, "assertion failed {}", e),
            ProtocolError::DKGNotSupported => write!(f, "the ciphersuite does not support DKG"),
            ProtocolError::ErrorExtractVerificationKey => write!(
                f,
                "could not extract the verification Key from the commitment."
            ),
            ProtocolError::InvalidCommitmentHash => {
                write!(f, "the sent commitment_hash does not equals the hash of the commitment")
            }
            ProtocolError::IncorrectNumberOfCommitments => {
                write!(f, "incorrect number of commitments")
            }
            ProtocolError::InvalidProofOfKnowledge(p) => write!(
                f,
                "the proof of knowledge of participant {p:?} is not valid."
            ),
            ProtocolError::InvalidSecretShare(p) => {
                write!(f, "participant {p:?} sent an invalid secret share.")
            }
            ProtocolError::MalformedElement => {
                write!(f, "the element you are trying to construct is malformed.")
            }
            ProtocolError::MaliciousParticipant(p) => {
                write!(f, "detected a malicious participant {p:?}.")
            }
            ProtocolError::MalformedSigningKey => write!(f, "the constructed signing key is null."),
            ProtocolError::PointSerialization => {
                write!(f, "The group element could not be serialized.")
            }
        }
    }
}

impl error::Error for ProtocolError {}

impl From<Box<dyn error::Error + Send + Sync>> for ProtocolError {
    fn from(e: Box<dyn error::Error + Send + Sync>) -> Self {
        Self::Other(e)
    }
}

/// Represents an error which can happen when *initializing* a protocol.
///
/// These are related to bad parameters for the protocol, and things like that.
///
/// These are usually more recoverable than other protocol errors.
#[derive(Debug)]
pub enum InitializationError {
    BadParameters(String),
}

impl fmt::Display for InitializationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InitializationError::BadParameters(s) => write!(f, "bad parameters: {}", s),
        }
    }
}

impl error::Error for InitializationError {}

/// Represents a participant in the protocol.
///
/// Each participant should be uniquely identified by some number, which this
/// struct holds. In our case, we use a `u32`, which is enough for billions of
/// participants. That said, you won't actually be able to make the protocols
/// work with billions of users.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub struct Participant(u32);

impl Participant {
    /// Return this participant as little endian bytes.
    pub fn bytes(&self) -> [u8; 4] {
        self.0.to_le_bytes()
    }

    /// Return the scalar associated with this participant.
    /// The implementation follows the original cait-sith library
    pub fn scalar<C: CSCurve>(&self) -> C::Scalar {
        C::Scalar::from(self.0 as u64 + 1)
    }

    /// Return the scalar associated with this participant.
    /// The implementation follows the original frost library
    pub fn generic_scalar<C: Ciphersuite>(&self) -> Scalar<C> {
        let mut bytes = vec![0u8; 32];
        let id = (self.0 as u64) + 1;
        bytes[..8].copy_from_slice(&id.to_le_bytes());

        // transform the bytes into a scalar and fails if Scalar
        // is not in the range [0, order - 1]
        let scalar = SerializableScalar::<C>::deserialize(&bytes).expect("Cannot be zero");
        scalar.0
    }

    /// Returns a Frost identifier used in the frost library
    pub fn to_identifier<C: Ciphersuite>(&self) -> Identifier<C> {
        let id = self.generic_scalar::<C>();
        // creating an identifier as required by the syntax of frost_core
        // cannot panic as the previous line ensures id is neq zero
        Identifier::new(id).unwrap()
    }
}

impl From<Participant> for u32 {
    fn from(p: Participant) -> Self {
        p.0
    }
}

impl From<u32> for Participant {
    fn from(x: u32) -> Self {
        Participant(x)
    }
}

/// Represents the data making up a message.
///
/// We choose to just represent messages as opaque vectors of bytes, with all
/// the serialization logic handled internally.
pub type MessageData = Vec<u8>;

/// Represents an action by a participant in the protocol.
///
/// The basic flow is that each participant receives messages from other participants,
/// and then reacts with some kind of action.
///
/// This action can consist of sending a message, doing nothing, etc.
///
/// Eventually, the participant returns a value, ending the protocol.
#[derive(Debug, Clone)]
pub enum Action<T> {
    /// Don't do anything.
    Wait,
    /// Send a message to all other participants.
    ///
    /// Participants *never* sends messages to themselves.
    SendMany(MessageData),
    /// Send a private message to another participant.
    ///
    /// It's imperactive that only this participant can read this message,
    /// so you might want to use some form of encryption.
    SendPrivate(Participant, MessageData),
    /// End the protocol by returning a value.
    Return(T),
}

/// A trait for protocols.
///
/// Basically, this represents a struct for the behavior of a single participant
/// in a protocol. The idea is that the computation of that participant is driven
/// mainly by receiving messages from other participants.
pub trait Protocol {
    type Output;

    /// Poke the protocol, receiving a new action.
    ///
    /// The idea is that the protocol should be poked until it returns an error,
    /// or it returns an action with a return value, or it returns a wait action.
    ///
    /// Upon returning a wait action, that protocol will not advance any further
    /// until a new message arrives.
    fn poke(&mut self) -> Result<Action<Self::Output>, ProtocolError>;

    /// Inform the protocol of a new message.
    fn message(&mut self, from: Participant, data: MessageData);
}

/// Run a protocol to completion, synchronously.
///
/// This works by executing each participant in order.
///
/// The reason this function exists is as a convenient testing utility.
/// In practice each protocol participant is likely running on a different machine,
/// and so orchestrating the protocol would happen differently.
pub fn run_protocol<T>(
    mut ps: Vec<(Participant, Box<dyn Protocol<Output = T>>)>,
) -> Result<Vec<(Participant, T)>, ProtocolError> {
    let indices: HashMap<Participant, usize> =
        ps.iter().enumerate().map(|(i, (p, _))| (*p, i)).collect();

    let size = ps.len();
    let mut out = Vec::with_capacity(size);
    while out.len() < size {
        for i in 0..size {
            while {
                let action = ps[i].1.poke()?;
                match action {
                    Action::Wait => false,
                    Action::SendMany(m) => {
                        for j in 0..size {
                            if i == j {
                                continue;
                            }
                            let from = ps[i].0;
                            ps[j].1.message(from, m.clone());
                        }
                        true
                    }
                    Action::SendPrivate(to, m) => {
                        let from = ps[i].0;
                        ps[indices[&to]].1.message(from, m);
                        true
                    }
                    Action::Return(r) => {
                        out.push((ps[i].0, r));
                        false
                    }
                }
            } {}
        }
    }

    Ok(out)
}

/// Like [run_protocol()], except for just two parties.
///
/// This is more useful for testing two party protocols with assymetric results,
/// since the return types for the two protocols can be different.
pub(crate) fn run_two_party_protocol<T0: fmt::Debug, T1: fmt::Debug>(
    p0: Participant,
    p1: Participant,
    prot0: &mut dyn Protocol<Output = T0>,
    prot1: &mut dyn Protocol<Output = T1>,
) -> Result<(T0, T1), ProtocolError> {
    let mut active0 = true;

    let mut out0 = None;
    let mut out1 = None;

    while out0.is_none() || out1.is_none() {
        if active0 {
            let action = prot0.poke()?;
            match action {
                Action::Wait => active0 = false,
                Action::SendMany(m) => prot1.message(p0, m),
                Action::SendPrivate(to, m) if to == p1 => {
                    prot1.message(p0, m);
                }
                Action::Return(out) => out0 = Some(out),
                // Ignore other actions, which means sending private messages to other people.
                _ => {}
            }
        } else {
            let action = prot1.poke()?;
            match action {
                Action::Wait => active0 = true,
                Action::SendMany(m) => prot0.message(p1, m),
                Action::SendPrivate(to, m) if to == p0 => {
                    prot0.message(p1, m);
                }
                Action::Return(out) => out1 = Some(out),
                // Ignore other actions, which means sending private messages to other people.
                _ => {}
            }
        }
    }

    Ok((out0.unwrap(), out1.unwrap()))
}

pub(crate) mod internal;
