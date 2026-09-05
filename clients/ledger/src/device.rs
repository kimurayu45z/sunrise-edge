//! The host side of the frozen Sunrise Ledger device contract (see
//! `docs/signing/hardware-signing.md`, "Device APDU contract").
//!
//! [`LedgerDevice`] is generic over [`Transport`] so every test in this
//! crate exercises this exact protocol logic — APDU chunking, exact
//! response lengths, and exact status-word handling — against
//! [`crate::fake::FakeTransport`] instead of real hardware.

use sunrise_edge_client::DeviceSigningProfile;

use crate::apdu::{
    ApduCommand, ApduResponse, CLA, INS_GET_CONFIGURATION, INS_RESET_SIGNING, INS_SIGN_TRANSACTION,
    INS_VERIFY_PUBLIC_KEY, P1_DEFAULT, P1_SIGN_CONTINUE, P1_SIGN_FIRST, P1_SIGN_LAST,
    P1_VERIFY_PUBLIC_KEY, P2_DEFAULT, STATUS_SUCCESS, Transport,
};
use crate::configuration::Configuration;
use crate::error::{DeviceError, status_to_error};
use crate::path::DerivationPath;

/// Each frame chunk carries at most this many bytes of signed-frame payload
/// (`docs/signing/hardware-signing.md`, "Device APDU contract").
pub const MAX_CHUNK_BYTES: usize = 230;

/// `verify public key`'s exact success-data length.
const PUBLIC_KEY_LEN: usize = 32;
/// `sign transaction` LAST's exact success-data length.
const SIGNATURE_LEN: usize = 64;

/// The host side of one Ledger device speaking the frozen `E0`-CLA Sunrise
/// signing contract, generic over an injectable [`Transport`].
pub struct LedgerDevice<T> {
    transport: T,
}

impl<T: Transport> LedgerDevice<T> {
    /// Wraps an already-connected transport.
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    /// `get configuration`: returns the device's exact six-byte
    /// profile/version/flags response, decoded but not yet validated.
    ///
    /// Callers must call [`Configuration::require_supported`] on the result
    /// before proceeding to [`Self::verify_public_key`] or
    /// [`Self::sign_transaction`]; this method itself does not enforce that
    /// order so a caller can also inspect/log an unsupported configuration.
    pub fn get_configuration(&mut self) -> Result<Configuration, DeviceError<T::Error>> {
        let response = self.exchange(INS_GET_CONFIGURATION, P1_DEFAULT, P2_DEFAULT, Vec::new())?;
        Configuration::decode(&response.data).map_err(DeviceError::UnsupportedConfiguration)
    }

    /// `verify public key`: always requires on-device confirmation and
    /// returns the exact 32-byte RFC 8032 compressed Ed25519 public key
    /// derived at `path`.
    pub fn verify_public_key(
        &mut self,
        path: DerivationPath,
    ) -> Result<[u8; PUBLIC_KEY_LEN], DeviceError<T::Error>> {
        let response = self.exchange(
            INS_VERIFY_PUBLIC_KEY,
            P1_VERIFY_PUBLIC_KEY,
            P2_DEFAULT,
            path.encode().to_vec(),
        )?;
        require_exact_len(&response.data, PUBLIC_KEY_LEN)?;
        let mut key = [0_u8; PUBLIC_KEY_LEN];
        key.copy_from_slice(&response.data);
        Ok(key)
    }

    /// `reset signing`: idempotently wipes any buffered signing session.
    pub fn reset_signing(&mut self) -> Result<(), DeviceError<T::Error>> {
        let response = self.exchange(INS_RESET_SIGNING, P1_DEFAULT, P2_DEFAULT, Vec::new())?;
        require_exact_len(&response.data, 0)?;
        Ok(())
    }

    /// `sign transaction`: sends `framed_message` (the complete output of
    /// [`sunrise_edge_client::PreparedTransaction::signable_frame`]) as one
    /// FIRST APDU followed by zero or more CONTINUE APDUs and exactly one
    /// LAST APDU, returning the final 64-byte signature.
    ///
    /// # Host-side chunking
    ///
    /// `docs/signing/hardware-signing.md` bounds each chunk at [`MAX_CHUNK_BYTES`] and states that
    /// LAST — never FIRST — is the call that triggers review and carries the
    /// signature ("only LAST's success response carries the 64-byte
    /// signature"), and that LAST is "valid only while collecting", i.e.
    /// never as the very first APDU. Read together, this requires *every*
    /// signing session to send at least one FIRST and a separate, later
    /// LAST — even when the complete frame would otherwise fit inside a
    /// single FIRST chunk. This method therefore never lets FIRST alone
    /// carry the entire frame: when `framed_message` is no longer than
    /// [`MAX_CHUNK_BYTES`], it reserves the frame's final byte for a
    /// dedicated LAST call instead. A one-byte frame cannot be split into
    /// two non-empty chunks this way and is rejected with a typed
    /// [`DeviceError::FrameTooSmall`] (distinct from [`DeviceError::EmptyFrame`],
    /// which only ever applies to a zero-byte frame); this is unreachable
    /// for any real Transaction v1 signature frame, which is always far
    /// larger than one byte.
    pub fn sign_transaction(
        &mut self,
        path: DerivationPath,
        framed_message: &[u8],
    ) -> Result<[u8; SIGNATURE_LEN], DeviceError<T::Error>> {
        if framed_message.is_empty() {
            return Err(DeviceError::EmptyFrame);
        }
        let maximum = DeviceSigningProfile::V1.max_framed_message_bytes();
        if framed_message.len() > maximum {
            return Err(DeviceError::FrameTooLarge {
                actual: framed_message.len(),
                maximum,
            });
        }
        let total_length =
            u32::try_from(framed_message.len()).map_err(|_| DeviceError::FrameTooLarge {
                actual: framed_message.len(),
                maximum,
            })?;

        let chunks = plan_chunks(framed_message)?;
        let mut iter = chunks.into_iter().peekable();
        let mut is_first = true;
        // Tracks whether the device has already accepted a FIRST chunk
        // (status `9000`), regardless of whether this host then judged that
        // response's own length invalid. Once true, any later host-side
        // error (a bad response length, a non-success status, or a
        // transport failure) triggers a best-effort `reset signing` before
        // this function returns that primary error — defense in depth
        // against leaving the device mid-session when this host has already
        // decided to abandon it, on top of the device's own documented
        // wipe-on-failure behavior (`docs/signing/hardware-signing.md`, "Device APDU contract").
        // The reset's own outcome is deliberately discarded: it must never
        // replace or mask the primary error, and a transport that is
        // already unusable is expected to make the reset attempt fail too.
        let mut first_accepted = false;
        let mut last_response: Option<ApduResponse> = None;

        while let Some(chunk) = iter.next() {
            let is_last = iter.peek().is_none();
            let p1 = if is_first {
                P1_SIGN_FIRST
            } else if is_last {
                P1_SIGN_LAST
            } else {
                P1_SIGN_CONTINUE
            };

            let mut data = Vec::with_capacity(if is_first {
                4 + crate::path::ENCODED_LEN + chunk.len()
            } else {
                chunk.len()
            });
            if is_first {
                data.extend_from_slice(&total_length.to_be_bytes());
                data.extend_from_slice(&path.encode());
            }
            data.extend_from_slice(chunk);

            let this_response = match self.exchange(INS_SIGN_TRANSACTION, p1, P2_DEFAULT, data) {
                Ok(response) => response,
                Err(error) => {
                    if first_accepted {
                        let _ = self.reset_signing();
                    }
                    return Err(error);
                }
            };
            if is_first {
                first_accepted = true;
            }

            let length_check = if is_last {
                require_exact_len(&this_response.data, SIGNATURE_LEN)
            } else {
                require_exact_len(&this_response.data, 0)
            };
            if let Err(error) = length_check {
                let _ = self.reset_signing();
                return Err(error);
            }

            is_first = false;
            last_response = Some(this_response);
        }

        let response = last_response.ok_or(DeviceError::NoChunksPlanned)?;
        let mut signature = [0_u8; SIGNATURE_LEN];
        signature.copy_from_slice(&response.data);
        Ok(signature)
    }

    fn exchange(
        &mut self,
        ins: u8,
        p1: u8,
        p2: u8,
        data: Vec<u8>,
    ) -> Result<ApduResponse, DeviceError<T::Error>> {
        let command = ApduCommand {
            cla: CLA,
            ins,
            p1,
            p2,
            data,
        };
        let response = self
            .transport
            .exchange(&command)
            .map_err(DeviceError::Transport)?;
        if response.status_word == STATUS_SUCCESS {
            Ok(response)
        } else {
            Err(status_to_error(response.status_word))
        }
    }
}

fn require_exact_len<E>(data: &[u8], expected: usize) -> Result<(), DeviceError<E>> {
    if data.len() == expected {
        Ok(())
    } else {
        Err(DeviceError::UnexpectedResponseLength {
            expected,
            actual: data.len(),
        })
    }
}

/// Splits `framed_message` into non-empty, at-most-[`MAX_CHUNK_BYTES`]
/// pieces such that at least two pieces always exist (see
/// [`LedgerDevice::sign_transaction`]'s doc comment).
fn plan_chunks<E>(framed_message: &[u8]) -> Result<Vec<&[u8]>, DeviceError<E>> {
    const MINIMUM_CHUNKABLE_LEN: usize = 2;
    if framed_message.len() <= MAX_CHUNK_BYTES {
        if framed_message.len() < MINIMUM_CHUNKABLE_LEN {
            return Err(DeviceError::FrameTooSmall {
                actual: framed_message.len(),
                minimum: MINIMUM_CHUNKABLE_LEN,
            });
        }
        let split = framed_message.len() - 1;
        return Ok(vec![&framed_message[..split], &framed_message[split..]]);
    }
    Ok(framed_message.chunks(MAX_CHUNK_BYTES).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apdu::{STATUS_INVALID_DATA, STATUS_USER_REJECTED};
    use crate::fake::FakeTransport;

    fn device(responses: Vec<ApduResponse>) -> LedgerDevice<FakeTransport> {
        LedgerDevice::new(FakeTransport::new(responses))
    }

    fn ok(data: Vec<u8>) -> ApduResponse {
        ApduResponse {
            data,
            status_word: STATUS_SUCCESS,
        }
    }

    #[test]
    fn get_configuration_decodes_the_exact_six_bytes() {
        let mut device = device(vec![ok(vec![0x00, 0x01, 1, 2, 3, 0])]);
        let configuration = device.get_configuration().unwrap();
        assert_eq!(configuration.profile, 1);
        assert_eq!(
            (
                configuration.major,
                configuration.minor,
                configuration.patch
            ),
            (1, 2, 3)
        );
    }

    #[test]
    fn verify_public_key_sends_p1_01_and_the_encoded_path() {
        let key = [0x42_u8; 32];
        let mut device = device(vec![ok(key.to_vec())]);
        let path = DerivationPath::provisional(0).unwrap();
        let returned = device.verify_public_key(path).unwrap();
        assert_eq!(returned, key);

        let sent = device.transport.commands();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].ins, INS_VERIFY_PUBLIC_KEY);
        assert_eq!(sent[0].p1, P1_VERIFY_PUBLIC_KEY);
        assert_eq!(sent[0].data, path.encode().to_vec());
    }

    #[test]
    fn verify_public_key_rejects_a_wrong_length_response() {
        let mut device = device(vec![ok(vec![0x00; 31])]);
        let error = device
            .verify_public_key(DerivationPath::provisional(0).unwrap())
            .unwrap_err();
        assert!(matches!(
            error,
            DeviceError::UnexpectedResponseLength {
                expected: 32,
                actual: 31
            }
        ));
    }

    #[test]
    fn reset_signing_requires_an_empty_response() {
        let mut device = device(vec![ok(Vec::new())]);
        device.reset_signing().unwrap();
    }

    #[test]
    fn reset_signing_rejects_a_non_empty_response() {
        let mut device = device(vec![ok(vec![1])]);
        let error = device.reset_signing().unwrap_err();
        assert!(matches!(
            error,
            DeviceError::UnexpectedResponseLength {
                expected: 0,
                actual: 1
            }
        ));
    }

    #[test]
    fn sign_transaction_chunks_a_large_frame_into_first_continue_last() {
        let frame = vec![0xAB_u8; 500];
        let signature = [0x55_u8; 64];
        let mut device = device(vec![ok(Vec::new()), ok(Vec::new()), ok(signature.to_vec())]);
        let path = DerivationPath::provisional(3).unwrap();

        let returned = device.sign_transaction(path, &frame).unwrap();
        assert_eq!(returned, signature);

        let sent = device.transport.commands();
        assert_eq!(sent.len(), 3);
        assert_eq!(sent[0].p1, P1_SIGN_FIRST);
        assert_eq!(sent[1].p1, P1_SIGN_CONTINUE);
        assert_eq!(sent[2].p1, P1_SIGN_LAST);

        // FIRST: 4-byte total_length + 21-byte path + first 230-byte chunk.
        assert_eq!(sent[0].data.len(), 4 + 21 + 230);
        assert_eq!(&sent[0].data[0..4], &500_u32.to_be_bytes());
        assert_eq!(&sent[0].data[4..25], &path.encode());
        assert_eq!(&sent[0].data[25..], &frame[0..230]);

        // CONTINUE: next 230 bytes.
        assert_eq!(sent[1].data, frame[230..460]);
        // LAST: final 40 bytes.
        assert_eq!(sent[2].data, frame[460..500]);
    }

    #[test]
    fn sign_transaction_uses_exactly_first_and_last_for_a_two_chunk_frame() {
        let frame = vec![0xCD_u8; 231];
        let signature = [0x77_u8; 64];
        let mut device = device(vec![ok(Vec::new()), ok(signature.to_vec())]);
        let path = DerivationPath::provisional(0).unwrap();

        device.sign_transaction(path, &frame).unwrap();

        let sent = device.transport.commands();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0].p1, P1_SIGN_FIRST);
        assert_eq!(sent[1].p1, P1_SIGN_LAST);
        assert_eq!(sent[0].data.len(), 4 + 21 + 230);
        assert_eq!(sent[1].data.len(), 1);
    }

    #[test]
    fn sign_transaction_still_sends_first_then_last_for_a_frame_at_the_chunk_boundary() {
        // Exactly MAX_CHUNK_BYTES total: FIRST cannot consume the whole
        // frame (see the doc comment), so one byte is reserved for LAST.
        let frame = vec![0xEF_u8; MAX_CHUNK_BYTES];
        let signature = [0x11_u8; 64];
        let mut device = device(vec![ok(Vec::new()), ok(signature.to_vec())]);

        device
            .sign_transaction(DerivationPath::provisional(0).unwrap(), &frame)
            .unwrap();

        let sent = device.transport.commands();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0].p1, P1_SIGN_FIRST);
        assert_eq!(sent[0].data.len(), 4 + 21 + (MAX_CHUNK_BYTES - 1));
        assert_eq!(sent[1].p1, P1_SIGN_LAST);
        assert_eq!(sent[1].data, vec![0xEF_u8; 1]);
    }

    #[test]
    fn sign_transaction_rejects_an_empty_frame() {
        let mut device = device(vec![]);
        let error = device
            .sign_transaction(DerivationPath::provisional(0).unwrap(), &[])
            .unwrap_err();
        assert!(matches!(error, DeviceError::EmptyFrame));
        assert!(device.transport.commands().is_empty());
    }

    #[test]
    fn sign_transaction_rejects_a_one_byte_frame_as_too_small_not_too_large() {
        let mut device = device(vec![]);
        let error = device
            .sign_transaction(DerivationPath::provisional(0).unwrap(), &[0xAB])
            .unwrap_err();
        assert!(matches!(
            error,
            DeviceError::FrameTooSmall {
                actual: 1,
                minimum: 2
            }
        ));
        assert!(device.transport.commands().is_empty());
    }

    #[test]
    fn sign_transaction_rejects_a_frame_over_the_profile_maximum() {
        let frame = vec![0u8; DeviceSigningProfile::V1.max_framed_message_bytes() + 1];
        let mut device = device(vec![]);
        let error = device
            .sign_transaction(DerivationPath::provisional(0).unwrap(), &frame)
            .unwrap_err();
        assert!(matches!(error, DeviceError::FrameTooLarge { .. }));
        assert!(device.transport.commands().is_empty());
    }

    #[test]
    fn sign_transaction_rejects_a_non_empty_intermediate_response() {
        let frame = vec![0xAB_u8; 500];
        let mut device = device(vec![ok(vec![0x01])]);
        let error = device
            .sign_transaction(DerivationPath::provisional(0).unwrap(), &frame)
            .unwrap_err();
        assert!(matches!(
            error,
            DeviceError::UnexpectedResponseLength {
                expected: 0,
                actual: 1
            }
        ));
    }

    #[test]
    fn sign_transaction_rejects_a_wrong_length_final_signature() {
        let frame = vec![0xCD_u8; 231];
        let mut device = device(vec![ok(Vec::new()), ok(vec![0u8; 63])]);
        let error = device
            .sign_transaction(DerivationPath::provisional(0).unwrap(), &frame)
            .unwrap_err();
        assert!(matches!(
            error,
            DeviceError::UnexpectedResponseLength {
                expected: 64,
                actual: 63
            }
        ));
    }

    #[test]
    fn every_documented_status_word_maps_to_its_typed_error() {
        use crate::apdu::*;
        type StatusMatcher = fn(&DeviceError<crate::fake::FakeTransportError>) -> bool;
        let cases: [(u16, StatusMatcher); 8] = [
            (STATUS_USER_REJECTED, |e| {
                matches!(e, DeviceError::UserRejected)
            }),
            (STATUS_INVALID_SIGNING_STATE, |e| {
                matches!(e, DeviceError::InvalidSigningState)
            }),
            (STATUS_INVALID_DATA, |e| {
                matches!(e, DeviceError::InvalidOrUnrecognizedData)
            }),
            (STATUS_PROFILE_BOUND_EXCEEDED, |e| {
                matches!(e, DeviceError::ProfileBoundExceeded)
            }),
            (STATUS_INVALID_P1P2, |e| {
                matches!(e, DeviceError::InvalidP1P2)
            }),
            (STATUS_UNSUPPORTED_INS, |e| {
                matches!(e, DeviceError::UnsupportedIns)
            }),
            (STATUS_UNSUPPORTED_CLA, |e| {
                matches!(e, DeviceError::UnsupportedCla)
            }),
            (STATUS_INTERNAL_FAILURE, |e| {
                matches!(e, DeviceError::InternalFailure)
            }),
        ];
        for (status, matcher) in cases {
            let mut device = device(vec![ApduResponse {
                data: Vec::new(),
                status_word: status,
            }]);
            let error = device.reset_signing().unwrap_err();
            assert!(matcher(&error), "status {status:#06x} mapped to {error:?}");
        }
    }

    #[test]
    fn an_unrecognized_status_word_is_a_typed_unknown_status_never_success() {
        let mut device = device(vec![ApduResponse {
            data: Vec::new(),
            status_word: 0x1234,
        }]);
        let error = device.reset_signing().unwrap_err();
        assert!(matches!(error, DeviceError::UnknownStatus(0x1234)));
    }

    #[test]
    fn a_disconnected_transport_fails_closed_mid_signing_sequence_and_attempts_reset() {
        let frame = vec![0xAB_u8; 500];
        // Only one scripted response: the second APDU (CONTINUE) hits a
        // disconnected fake transport, and the best-effort reset attempt
        // that follows finds the transport still disconnected too.
        let mut device = device(vec![ok(Vec::new())]);
        let error = device
            .sign_transaction(DerivationPath::provisional(0).unwrap(), &frame)
            .unwrap_err();
        assert!(matches!(error, DeviceError::Transport(_)));
        // FIRST, the failed CONTINUE, and a best-effort RESET attempt were
        // all observed; no signature was ever produced, and the reset
        // attempt's own failure never replaces the primary `Transport`
        // error above.
        let sent = device.transport.commands();
        assert_eq!(sent.len(), 3);
        assert_eq!(sent[2].ins, INS_RESET_SIGNING);
    }

    #[test]
    fn sign_transaction_attempts_a_best_effort_reset_after_first_accepted_and_a_later_status_error()
    {
        let frame = vec![0xAB_u8; 500];
        let mut device = device(vec![
            ok(Vec::new()),
            ApduResponse {
                data: Vec::new(),
                status_word: STATUS_INVALID_DATA,
            },
            ok(Vec::new()),
        ]);

        let error = device
            .sign_transaction(DerivationPath::provisional(0).unwrap(), &frame)
            .unwrap_err();

        assert!(matches!(error, DeviceError::InvalidOrUnrecognizedData));
        let sent = device.transport.commands();
        assert_eq!(sent.len(), 3);
        assert_eq!(sent[0].p1, P1_SIGN_FIRST);
        assert_eq!(sent[1].p1, P1_SIGN_CONTINUE);
        assert_eq!(
            sent[2].ins, INS_RESET_SIGNING,
            "a best-effort reset must be attempted once FIRST was accepted"
        );
    }

    #[test]
    fn sign_transaction_attempts_a_best_effort_reset_after_a_bad_first_response_length() {
        let frame = vec![0xAB_u8; 500];
        // FIRST itself returns success but with a non-empty response,
        // which is a host-side length violation, not a device status
        // error; the reset attempt must still be made since the device
        // did accept FIRST.
        let mut device = device(vec![ok(vec![0x01]), ok(Vec::new())]);

        let error = device
            .sign_transaction(DerivationPath::provisional(0).unwrap(), &frame)
            .unwrap_err();

        assert!(matches!(
            error,
            DeviceError::UnexpectedResponseLength {
                expected: 0,
                actual: 1
            }
        ));
        let sent = device.transport.commands();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[1].ins, INS_RESET_SIGNING);
    }

    #[test]
    fn sign_transaction_never_attempts_a_reset_when_first_itself_is_rejected() {
        let frame = vec![0xAB_u8; 500];
        let mut device = device(vec![ApduResponse {
            data: Vec::new(),
            status_word: STATUS_USER_REJECTED,
        }]);

        let error = device
            .sign_transaction(DerivationPath::provisional(0).unwrap(), &frame)
            .unwrap_err();

        assert!(matches!(error, DeviceError::UserRejected));
        // No reset was attempted: the device never accepted FIRST in the
        // first place, so there is no session to defensively wipe.
        assert_eq!(device.transport.commands().len(), 1);
    }
}
