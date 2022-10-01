use std::{
    cell::RefCell,
    future::Future,
    mem,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
};

use super::{MessageData, Participant};

/// Represents a queue of messages.
///
/// This is used to receive incoming messages as they arrive, and automatically
/// sort them into bins based on
#[derive(Debug, Clone)]
pub struct MessageQueue {
    /// We have one stack of messages for each round / wait point.
    stacks: Vec<Vec<(Participant, MessageData)>>,
}

impl MessageQueue {
    /// Create a new message queue, given a number of wait points.
    ///
    /// Each wait point is a distinct point in the protocol where we'll wait
    /// for a message.
    ///
    /// We also take in a hint for the number of parties participating in the protocol.
    /// This just allows us to pre-allocate buffers of the right size, and is just
    /// a performance optimization.
    pub fn new(waitpoints: usize, parties_hint: usize) -> Self {
        Self {
            stacks: vec![Vec::with_capacity(parties_hint.saturating_sub(1)); waitpoints],
        }
    }

    /// The number of waitpoints in this queue.
    pub fn waitpoints(&self) -> usize {
        self.stacks.len()
    }

    /// Push a new message into the queue.
    ///
    /// This will read the first byte of the message to determine what round it
    /// belongs to.
    pub fn push(&mut self, from: Participant, message: MessageData) {
        if message.is_empty() {
            return;
        }

        let round = usize::from(message[0]);
        if round >= self.stacks.len() {
            return;
        }

        self.stacks[round].push((from, message));
    }

    /// Pop a message from a specific round.
    ///
    /// This round **must** be less than the number of waitpoints of this queue.
    pub fn pop(&mut self, round: usize) -> Option<(Participant, MessageData)> {
        assert!(round < self.stacks.len());

        self.stacks[round].pop()
    }
}

/// A future which tries to read a message from a specific round.
struct MessageQueueWait {
    queue: Rc<RefCell<MessageQueue>>,
    round: usize,
}

impl MessageQueueWait {
    fn new(queue: Rc<RefCell<MessageQueue>>, round: usize) -> Self {
        Self { queue, round }
    }
}

impl Future for MessageQueueWait {
    type Output = (Participant, MessageData);

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.queue.borrow_mut().pop(self.round) {
            Some(out) => Poll::Ready(out),
            None => Poll::Pending,
        }
    }
}

/// Used to represent the different kinds of messages a participant can send.
///
/// This is basically used to communicate between the future and the executor.
#[derive(Debug, Clone)]
pub enum Message {
    Many(MessageData),
    Private(Participant, MessageData),
}

/// A mailbox is a single item queue, used to handle message outputs.
///
/// The idea is that the future can write a message here, and then the executor
/// can pull it out.
pub struct Mailbox(Option<Message>);

impl Mailbox {
    /// Receive any message queued in here.
    fn recv(&mut self) -> Option<Message> {
        self.0.take()
    }
}

/// A future used to wait until a mailbox is emptied.
struct MailboxWait {
    mailbox: Rc<RefCell<Mailbox>>,
    /// This will always be some, but we need to be able to take it
    message: Option<Message>,
}

impl MailboxWait {
    fn new(mailbox: Rc<RefCell<Mailbox>>, message: Message) -> Self {
        Self {
            mailbox,
            message: Some(message),
        }
    }
}

impl Future for MailboxWait {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.mailbox.borrow().0.is_some() {
            return Poll::Pending;
        }
        let message = self.message.take();
        self.mailbox.borrow_mut().0 = message;
        Poll::Ready(())
    }
}
