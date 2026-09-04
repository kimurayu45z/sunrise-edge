//! A deterministic, injectable fake [`Transport`], analogous to
//! `runtime`'s `Memory*` test adapters, used by every test in this crate and
//! reusable by `apps/cli`'s own tests.

use std::fmt;

use crate::apdu::{ApduCommand, ApduResponse, Transport};

/// [`FakeTransport`]'s own transport-layer failure: it ran out of scripted
/// responses, standing in for a real disconnect, timeout, or malformed
/// physical frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FakeTransportError;

impl fmt::Display for FakeTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("fake transport ran out of scripted responses (simulated disconnect)")
    }
}

impl std::error::Error for FakeTransportError {}

/// A deterministic fake [`Transport`] that returns pre-scripted responses in
/// order and records every command it observed.
///
/// Once every scripted response has been consumed, every further call
/// returns [`FakeTransportError`], deterministically simulating a mid-session
/// disconnect.
pub struct FakeTransport {
    responses: std::collections::VecDeque<ApduResponse>,
    commands: Vec<ApduCommand>,
}

impl FakeTransport {
    /// Creates a fake transport that returns `responses` in order.
    #[must_use]
    pub fn new(responses: Vec<ApduResponse>) -> Self {
        Self {
            responses: responses.into(),
            commands: Vec::new(),
        }
    }

    /// Returns every command this transport observed, in order.
    #[must_use]
    pub fn commands(&self) -> &[ApduCommand] {
        &self.commands
    }
}

impl Transport for FakeTransport {
    type Error = FakeTransportError;

    fn exchange(&mut self, command: &ApduCommand) -> Result<ApduResponse, Self::Error> {
        self.commands.push(command.clone());
        self.responses.pop_front().ok_or(FakeTransportError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apdu::STATUS_SUCCESS;

    #[test]
    fn returns_scripted_responses_in_order_and_records_commands() {
        let mut transport = FakeTransport::new(vec![
            ApduResponse {
                data: vec![1],
                status_word: STATUS_SUCCESS,
            },
            ApduResponse {
                data: vec![2],
                status_word: STATUS_SUCCESS,
            },
        ]);
        let command = ApduCommand {
            cla: 0xE0,
            ins: 0x00,
            p1: 0,
            p2: 0,
            data: Vec::new(),
        };

        assert_eq!(transport.exchange(&command).unwrap().data, vec![1]);
        assert_eq!(transport.exchange(&command).unwrap().data, vec![2]);
        assert_eq!(transport.commands().len(), 2);
    }

    #[test]
    fn fails_closed_once_scripted_responses_are_exhausted() {
        let mut transport = FakeTransport::new(vec![]);
        let command = ApduCommand {
            cla: 0xE0,
            ins: 0x00,
            p1: 0,
            p2: 0,
            data: Vec::new(),
        };
        assert_eq!(
            transport.exchange(&command).unwrap_err(),
            FakeTransportError
        );
    }
}
