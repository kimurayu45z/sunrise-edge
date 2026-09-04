//! [`LedgerExternalSigner`]: a `sunrise_edge_client::ExternalSigner`
//! implementation backed by [`LedgerDevice`].

use std::cell::RefCell;
use std::fmt;

use sunrise_edge_client::{Address, ExternalSigner, SignatureSchemeId};

use crate::apdu::Transport;
use crate::device::LedgerDevice;
use crate::error::DeviceError;
use crate::path::DerivationPath;

/// A Ledger hardware signer for one connected device and one fixed
/// derivation path.
///
/// [`Self::connect`] performs the device-reported configuration check and
/// the on-device-confirmed public key/address check *before* returning, so a
/// caller always has a verified [`Address`] before it builds a
/// [`sunrise_edge_client::TransactionRequest`]. [`ExternalSigner::sign_frame`]
/// independently repeats both checks immediately before every signing
/// request, rather than trusting the connect-time result: a stale cached
/// configuration or public key is not proof the same device/session is still
/// present, and this is the literal "device-reported configuration/public
/// key/address checks before signing" boundary the CLI signer selection
/// relies on.
pub struct LedgerExternalSigner<T> {
    device: RefCell<LedgerDevice<T>>,
    path: DerivationPath,
    address: Address,
}

impl<T> fmt::Debug for LedgerExternalSigner<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LedgerExternalSigner")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

impl<T: Transport> LedgerExternalSigner<T> {
    /// Connects to `transport`: checks `get configuration` reports a
    /// supported profile/flags, then fetches (with on-device confirmation)
    /// and caches the exact public key/address at `path`.
    pub fn connect(transport: T, path: DerivationPath) -> Result<Self, DeviceError<T::Error>> {
        let mut device = LedgerDevice::new(transport);
        device.get_configuration()?.require_supported()?;
        let public_key = device.verify_public_key(path)?;
        Ok(Self {
            device: RefCell::new(device),
            path,
            address: Address::new(public_key),
        })
    }
}

impl<T: Transport> ExternalSigner for LedgerExternalSigner<T> {
    type Error = DeviceError<T::Error>;

    fn signature_scheme_id(&self) -> SignatureSchemeId {
        SignatureSchemeId::Ed25519
    }

    fn address(&self) -> Address {
        self.address
    }

    fn sign_frame(&self, framed_message: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let mut device = self
            .device
            .try_borrow_mut()
            .map_err(|_| DeviceError::DeviceBusy)?;
        device.get_configuration()?.require_supported()?;
        let public_key = device.verify_public_key(self.path)?;
        if public_key != *self.address.as_bytes() {
            return Err(DeviceError::PublicKeyMismatch);
        }
        let signature = device.sign_transaction(self.path, framed_message)?;
        Ok(signature.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apdu::{ApduResponse, STATUS_SUCCESS, STATUS_USER_REJECTED};
    use crate::fake::FakeTransport;

    fn ok(data: Vec<u8>) -> ApduResponse {
        ApduResponse {
            data,
            status_word: STATUS_SUCCESS,
        }
    }

    fn valid_configuration() -> ApduResponse {
        ok(vec![0x00, 0x01, 1, 0, 0, 0x00])
    }

    #[test]
    fn connect_checks_configuration_then_verifies_the_public_key() {
        let key = [0x22_u8; 32];
        let transport = FakeTransport::new(vec![valid_configuration(), ok(key.to_vec())]);
        let signer =
            LedgerExternalSigner::connect(transport, DerivationPath::provisional(0).unwrap())
                .unwrap();
        assert_eq!(signer.address(), Address::new(key));
    }

    #[test]
    fn connect_rejects_an_unsupported_profile_before_verifying_a_public_key() {
        let transport = FakeTransport::new(vec![ok(vec![0x00, 0x02, 1, 0, 0, 0x00])]);
        let error =
            LedgerExternalSigner::connect(transport, DerivationPath::provisional(0).unwrap())
                .unwrap_err();
        assert!(matches!(error, DeviceError::UnsupportedConfiguration(_)));
    }

    #[test]
    fn connect_rejects_an_unknown_configuration_flag() {
        let transport = FakeTransport::new(vec![ok(vec![0x00, 0x01, 1, 0, 0, 0x01])]);
        let error =
            LedgerExternalSigner::connect(transport, DerivationPath::provisional(0).unwrap())
                .unwrap_err();
        assert!(matches!(error, DeviceError::UnsupportedConfiguration(_)));
    }

    #[test]
    fn concurrent_or_reentrant_use_is_a_typed_error_not_a_refcell_panic() {
        let key = [0x24_u8; 32];
        let transport = FakeTransport::new(vec![valid_configuration(), ok(key.to_vec())]);
        let signer =
            LedgerExternalSigner::connect(transport, DerivationPath::provisional(0).unwrap())
                .unwrap();
        let _active_call = signer.device.borrow_mut();

        let error = signer.sign_frame(&[0xAB, 0xCD]).unwrap_err();

        assert!(matches!(error, DeviceError::DeviceBusy));
    }

    #[test]
    fn connect_propagates_an_on_device_rejection_of_the_public_key_request() {
        let transport = FakeTransport::new(vec![
            valid_configuration(),
            ApduResponse {
                data: Vec::new(),
                status_word: STATUS_USER_REJECTED,
            },
        ]);
        let error =
            LedgerExternalSigner::connect(transport, DerivationPath::provisional(0).unwrap())
                .unwrap_err();
        assert!(matches!(error, DeviceError::UserRejected));
    }

    #[test]
    fn sign_frame_re_checks_configuration_and_public_key_before_signing() {
        let key = [0x33_u8; 32];
        let frame = vec![0xAB_u8; 500];
        let signature = [0x99_u8; 64];
        let transport = FakeTransport::new(vec![
            valid_configuration(),
            ok(key.to_vec()),
            valid_configuration(),
            ok(key.to_vec()),
            ok(Vec::new()),
            ok(Vec::new()),
            ok(signature.to_vec()),
        ]);
        let signer =
            LedgerExternalSigner::connect(transport, DerivationPath::provisional(0).unwrap())
                .unwrap();

        let returned = signer.sign_frame(&frame).unwrap();
        assert_eq!(returned, signature.to_vec());
    }

    #[test]
    fn sign_frame_fails_closed_when_the_public_key_changed_since_connect() {
        let original_key = [0x33_u8; 32];
        let different_key = [0x44_u8; 32];
        let frame = vec![0xAB_u8; 500];
        let transport = FakeTransport::new(vec![
            valid_configuration(),
            ok(original_key.to_vec()),
            valid_configuration(),
            ok(different_key.to_vec()),
        ]);
        let signer =
            LedgerExternalSigner::connect(transport, DerivationPath::provisional(0).unwrap())
                .unwrap();

        let error = signer.sign_frame(&frame).unwrap_err();
        assert!(matches!(error, DeviceError::PublicKeyMismatch));
    }

    #[test]
    fn sign_frame_propagates_an_on_device_rejection_of_the_signing_request() {
        let key = [0x33_u8; 32];
        let frame = vec![0xAB_u8; 500];
        let transport = FakeTransport::new(vec![
            valid_configuration(),
            ok(key.to_vec()),
            valid_configuration(),
            ok(key.to_vec()),
            ApduResponse {
                data: Vec::new(),
                status_word: STATUS_USER_REJECTED,
            },
        ]);
        let signer =
            LedgerExternalSigner::connect(transport, DerivationPath::provisional(0).unwrap())
                .unwrap();

        let error = signer.sign_frame(&frame).unwrap_err();
        assert!(matches!(error, DeviceError::UserRejected));
    }

    #[test]
    fn sign_frame_fails_closed_on_a_mid_sequence_disconnect() {
        let key = [0x33_u8; 32];
        let frame = vec![0xAB_u8; 500];
        // Only one FIRST-chunk response is scripted after the checks: the
        // CONTINUE call finds no more scripted responses (simulated
        // disconnect).
        let transport = FakeTransport::new(vec![
            valid_configuration(),
            ok(key.to_vec()),
            valid_configuration(),
            ok(key.to_vec()),
            ok(Vec::new()),
        ]);
        let signer =
            LedgerExternalSigner::connect(transport, DerivationPath::provisional(0).unwrap())
                .unwrap();

        let error = signer.sign_frame(&frame).unwrap_err();
        assert!(matches!(error, DeviceError::Transport(_)));
    }
}
