//! Explicit, all-or-none CLI signer selection between the development-only
//! local seed signer and a Ledger hardware signer (S4c; see `SIGNING.md`
//! and `ARCHITECTURE.md`'s Hardware Signing Profile v1 decision records).
//!
//! Exactly one signer must be selected: `--seed-file` alone (development-
//! only, in-memory, never a keystore), or `--ledger-hid-path`,
//! `--ledger-account`, and `--ledger-expected-firmware-version` together (a
//! real Ledger device, verified by its dashboard/firmware identity, its
//! reported application identity, its device-reported configuration, and
//! its on-device-confirmed public key/address before any signing — see
//! [`connect_ledger_staged`] and `sunrise_edge_ledger::LedgerExternalSigner`).
//! Any other combination — neither, both groups at once, or exactly one or
//! two of the three Ledger flags — is a typed rejection before any network
//! dispatch or device connection. `--ledger-expected-firmware-version` is
//! itself validated ([`sunrise_edge_ledger::ExpectedFirmwareVersion::new`])
//! during selection parsing, strictly before any device dispatch.

use sunrise_edge_client::{
    DEVNET_ASSET_TRANSFER_POLICY, DeviceSigningProfile, PreparedTransaction,
};
use sunrise_edge_ledger::{
    DerivationPath, ExpectedFirmwareVersion, IdentityError, LedgerExternalSigner, Transport,
    verify_active_app, verify_dashboard_and_open,
};

use crate::args::{FlagSpec, ParsedArgs, scalar};
use crate::error::CliError;
use crate::parse::parse_u32;

/// Development-only local seed file flag.
pub const SEED_FILE: &str = "--seed-file";
/// Ledger device HID path flag.
pub const LEDGER_HID_PATH: &str = "--ledger-hid-path";
/// Ledger provisional derivation account flag.
pub const LEDGER_ACCOUNT: &str = "--ledger-account";
/// Ledger expected dashboard-reported firmware (Secure Element) version
/// flag.
pub const LEDGER_EXPECTED_FIRMWARE_VERSION: &str = "--ledger-expected-firmware-version";

/// The signer-selection flags every signer-capable subcommand accepts, in
/// addition to its own flags.
#[must_use]
pub fn signer_flag_specs() -> Vec<FlagSpec> {
    vec![
        scalar(SEED_FILE),
        scalar(LEDGER_HID_PATH),
        scalar(LEDGER_ACCOUNT),
        scalar(LEDGER_EXPECTED_FIRMWARE_VERSION),
    ]
}

/// One fully validated, mutually exclusive signer choice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerSelection {
    /// The development-only local in-memory seed signer.
    Local {
        /// Path to the development seed file (see `crate::seed`).
        seed_file: String,
    },
    /// A Ledger hardware signer, addressed by an explicit HID device path
    /// and provisional derivation account.
    Ledger {
        /// Explicit platform HID device path.
        hid_path: String,
        /// Non-hardened `account` component of the provisional derivation
        /// path `m/44'/21333'/account'/0'/0'`.
        account: u32,
        /// The exact dashboard-reported firmware (Secure Element) version
        /// this host requires before opening the Sunrise application.
        expected_firmware_version: ExpectedFirmwareVersion,
    },
}

/// Parses the required, explicit, all-or-none signer selection.
pub fn parse_signer_selection(parsed: &ParsedArgs) -> Result<SignerSelection, CliError> {
    let local = parsed.is_present(SEED_FILE);
    let ledger_hid = parsed.is_present(LEDGER_HID_PATH);
    let ledger_account = parsed.is_present(LEDGER_ACCOUNT);
    let ledger_firmware = parsed.is_present(LEDGER_EXPECTED_FIRMWARE_VERSION);

    match (local, ledger_hid, ledger_account, ledger_firmware) {
        (true, false, false, false) => Ok(SignerSelection::Local {
            seed_file: parsed.require(SEED_FILE)?.to_string(),
        }),
        (false, true, true, true) => {
            let expected_firmware_version =
                ExpectedFirmwareVersion::new(parsed.require(LEDGER_EXPECTED_FIRMWARE_VERSION)?)
                    .map_err(CliError::LedgerExpectedFirmwareVersion)?;
            let account = parse_u32(LEDGER_ACCOUNT, parsed.require(LEDGER_ACCOUNT)?)?;
            DerivationPath::provisional(account)
                .map_err(|error| CliError::LedgerConnect(Box::new(error)))?;
            Ok(SignerSelection::Ledger {
                hid_path: parsed.require(LEDGER_HID_PATH)?.to_string(),
                account,
                expected_firmware_version,
            })
        }
        (false, false, false, false) => Err(CliError::MissingSignerSelection),
        (true, _, _, _) => Err(CliError::ConflictingSignerSelection),
        (false, hid, account, _firmware) => {
            let missing = if !hid {
                LEDGER_HID_PATH
            } else if !account {
                LEDGER_ACCOUNT
            } else {
                LEDGER_EXPECTED_FIRMWARE_VERSION
            };
            Err(CliError::PartialLedgerSignerConfiguration { missing })
        }
    }
}

/// Connects a [`LedgerExternalSigner`] over an already-constructed
/// `transport`: checks the device-reported configuration, then fetches and
/// confirms its public key/address at `account`'s provisional derivation
/// path — both *before* returning — matching this crate's "device-reported
/// configuration/public key/address checks before signing" requirement.
///
/// Generic over [`Transport`] so this exact connect-then-verify sequence is
/// unit-testable with `sunrise_edge_ledger::FakeTransport`, independent of
/// the `usb-hid` feature and any real USB/HID hardware. [`connect_ledger_staged`]
/// inlines this same connect-then-verify sequence for its own final step
/// rather than calling this function, so this function currently has no
/// non-test caller; it is kept so the sequence remains independently
/// unit-testable in isolation from the staged dashboard/firmware/open-app
/// flow.
#[allow(dead_code, reason = "kept for isolated unit testing; see doc comment")]
pub fn connect_ledger_with<T: Transport>(
    transport: T,
    account: u32,
) -> Result<LedgerExternalSigner<T>, CliError> {
    let path = DerivationPath::provisional(account)
        .map_err(|error| CliError::LedgerConnect(Box::new(error)))?;
    LedgerExternalSigner::connect(transport, path)
        .map_err(|error| CliError::LedgerConnect(Box::new(error)))
}

#[allow(dead_code, reason = "used by usb-hid-gated callers and by tests")]
fn identity_error<E>(error: IdentityError<E>) -> CliError
where
    E: std::error::Error + Send + Sync + 'static,
{
    CliError::LedgerIdentity(Box::new(error))
}

/// Runs `SIGNING.md`'s complete staged device-identity sequence before ever
/// connecting a [`LedgerExternalSigner`]:
///
/// 1. Over `dashboard_transport` (the device at the dashboard, no
///    application open): verifies the dashboard's own reported identity is
///    exactly `BOLOS`, that its firmware has a supported target id, no
///    OS-Upgrade (OSU) marker, and exactly matches `expected_firmware_version`
///    ([`verify_dashboard_and_open`]), then opens the Sunrise application.
/// 2. Drops `dashboard_transport` and calls `reconnect` to obtain a fresh
///    transport to the now-open Sunrise application (a real caller
///    reconnects at the same USB/HID path; see
///    `crate::signer::reconnect_same_hid_path` under the `usb-hid` feature).
/// 3. Over the reconnected transport: verifies the active application is
///    exactly [`sunrise_edge_ledger::EXPECTED_APP_NAME`] at exactly
///    [`sunrise_edge_ledger::EXPECTED_APP_VERSION`]
///    ([`verify_active_app`]).
/// 4. Only then connects the [`LedgerExternalSigner`], which itself checks
///    the device-reported configuration and then fetches and confirms the
///    on-device-confirmed public key/address at `account`'s provisional
///    derivation path — the same connect-then-verify sequence
///    [`connect_ledger_with`] performs, inlined here rather than called.
///
/// Generic over [`Transport`] (the same transport type for both stages) so
/// this exact sequence is unit-testable end to end with
/// `sunrise_edge_ledger::FakeTransport`, independent of the `usb-hid`
/// feature and any real USB/HID hardware.
#[allow(dead_code, reason = "used by usb-hid-gated callers and by tests")]
pub fn connect_ledger_staged<T, F>(
    dashboard_transport: T,
    expected_firmware_version: &ExpectedFirmwareVersion,
    account: u32,
    reconnect: F,
) -> Result<LedgerExternalSigner<T>, CliError>
where
    T: Transport,
    F: FnOnce() -> Result<T, CliError>,
{
    let path = DerivationPath::provisional(account)
        .map_err(|error| CliError::LedgerConnect(Box::new(error)))?;
    let mut dashboard_transport = dashboard_transport;
    verify_dashboard_and_open(&mut dashboard_transport, expected_firmware_version)
        .map_err(identity_error)?;
    drop(dashboard_transport);

    let mut app_transport = reconnect()?;
    verify_active_app(&mut app_transport).map_err(identity_error)?;

    LedgerExternalSigner::connect(app_transport, path)
        .map_err(|error| CliError::LedgerConnect(Box::new(error)))
}

/// Retries `attempt` until it succeeds or `deadline` (measured against a
/// monotonic clock, never wall-clock time) has passed, sleeping
/// `retry_interval` between attempts. Never retries forever: once the
/// deadline has passed, `attempt`'s most recent failure is returned instead
/// of retrying again.
#[allow(dead_code, reason = "used by usb-hid-gated callers and by tests")]
fn retry_until_deadline<T, E>(
    deadline: std::time::Instant,
    retry_interval: std::time::Duration,
    mut attempt: impl FnMut() -> Result<T, E>,
) -> Result<T, E> {
    loop {
        match attempt() {
            Ok(value) => return Ok(value),
            Err(error) => {
                if std::time::Instant::now() >= deadline {
                    return Err(error);
                }
                std::thread::sleep(retry_interval);
            }
        }
    }
}

/// Bounded deadline this host waits, in total, for the device to reappear
/// at the same HID path after `open app` (see
/// [`reconnect_same_hid_path`]).
#[cfg(feature = "usb-hid")]
const LEDGER_RECONNECT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);
/// Sleep between reconnect attempts within [`LEDGER_RECONNECT_DEADLINE`].
#[cfg(feature = "usb-hid")]
const LEDGER_RECONNECT_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// Reopens `path` after `open app`, retrying with a bounded monotonic
/// deadline and a fixed retry sleep: the device visibly re-enumerates its
/// USB/HID interface when it switches from the dashboard to an opened
/// application, so the very next `HidTransport::open` attempt commonly
/// fails transiently. Never blocks indefinitely — once
/// [`LEDGER_RECONNECT_DEADLINE`] elapses, this fails closed with a typed
/// [`CliError::LedgerReconnectTimedOut`] carrying the most recent attempt's
/// failure, rather than retrying forever or silently giving up early.
#[cfg(feature = "usb-hid")]
pub fn reconnect_same_hid_path(path: &str) -> Result<sunrise_edge_ledger::HidTransport, CliError> {
    let deadline = std::time::Instant::now() + LEDGER_RECONNECT_DEADLINE;
    retry_until_deadline(deadline, LEDGER_RECONNECT_RETRY_INTERVAL, || {
        sunrise_edge_ledger::HidTransport::open(path)
    })
    .map_err(|error| CliError::LedgerReconnectTimedOut {
        path: path.to_string(),
        deadline_ms: u64::try_from(LEDGER_RECONNECT_DEADLINE.as_millis()).unwrap_or(u64::MAX),
        last_error: error.to_string(),
    })
}

/// Applies the CLI's one approved Ledger clear-signing profile and policy,
/// then independently verifies the returned signature before producing
/// canonical signed transaction bytes.
#[allow(
    dead_code,
    reason = "used by usb-hid-gated production code and feature-independent tests"
)]
pub fn finalize_with_ledger<T: Transport>(
    prepared: PreparedTransaction,
    signer: &LedgerExternalSigner<T>,
) -> Result<Vec<u8>, CliError> {
    prepared
        .sign_and_finalize_external(
            signer,
            &DeviceSigningProfile::V1,
            &DEVNET_ASSET_TRANSFER_POLICY,
        )
        .map_err(CliError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::parse_flags;
    use std::ffi::OsString;

    use sunrise_edge_client::{
        AccessEntry, AccessManifest, AccessMode, Amount, AssetId, CanonicalStruct, ChainId,
        ClearSigningPolicyError, ClientError, Digest32, Epoch, ExternalSigner, FeePayment,
        HashAlgorithmId, LocalSigner, ObjectId, ObjectRef, ProtocolVersion, SignatureSchemeId,
        SigningViewError, TransactionRequest,
    };
    use sunrise_edge_ledger::apdu::STATUS_SUCCESS;
    use sunrise_edge_ledger::device::MAX_CHUNK_BYTES;
    use sunrise_edge_ledger::{ApduResponse, FakeTransport};

    fn parsed(pairs: &[(&'static str, &str)]) -> ParsedArgs {
        let specs = signer_flag_specs();
        let args: Vec<OsString> = pairs
            .iter()
            .flat_map(|(name, value)| [OsString::from(*name), OsString::from(*value)])
            .collect();
        parse_flags(args, &specs).unwrap()
    }

    fn recognized_transfer_request(module_version_delta: u64) -> TransactionRequest {
        let source_ref = ObjectRef {
            id: ObjectId::new([0x11; 32]),
            version: 1,
            digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x12; 32]),
        };
        let destination_ref = ObjectRef {
            id: ObjectId::new([0x21; 32]),
            version: 2,
            digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x22; 32]),
        };
        let treasury_ref = ObjectRef {
            id: ObjectId::new([0x31; 32]),
            version: 3,
            digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x32; 32]),
        };
        let mut access_manifest = AccessManifest::new();
        for object_ref in [source_ref.clone(), destination_ref, treasury_ref] {
            access_manifest.push(AccessEntry {
                object_ref,
                mode: AccessMode::Write,
            });
        }
        let mut arguments = CanonicalStruct::new(
            DEVNET_ASSET_TRANSFER_POLICY.args_type_id(),
            DEVNET_ASSET_TRANSFER_POLICY.args_version(),
        );
        arguments
            .field_u64(DEVNET_ASSET_TRANSFER_POLICY.args_field_id(), 250)
            .unwrap();

        TransactionRequest {
            chain_id: ChainId::new("sunrise-local-devnet").unwrap(),
            protocol_version: ProtocolVersion::new(3),
            epoch: Epoch::new(0),
            nonce: 7,
            access_manifest,
            module_ref: ObjectRef {
                id: ObjectId::new(DEVNET_ASSET_TRANSFER_POLICY.module_id()),
                version: DEVNET_ASSET_TRANSFER_POLICY.module_version() + module_version_delta,
                digest: Digest32::new(
                    DEVNET_ASSET_TRANSFER_POLICY.code_digest_algorithm(),
                    DEVNET_ASSET_TRANSFER_POLICY.code_digest_bytes(),
                ),
            },
            entrypoint: DEVNET_ASSET_TRANSFER_POLICY.entrypoint().to_string(),
            args: arguments.finish().unwrap(),
            gas_limit: 1_000,
            fee_payment: Some(FeePayment {
                asset_id: AssetId::new(DEVNET_ASSET_TRANSFER_POLICY.fee_asset_id()),
                max_fee: Amount::new(1_001),
                fee_object: source_ref,
            }),
        }
    }

    fn ledger_for_prepared(
        local_signer: &LocalSigner,
        prepared: &PreparedTransaction,
    ) -> LedgerExternalSigner<FakeTransport> {
        let frame: Vec<u8> = prepared.signable_frame().unwrap();
        let signature: Vec<u8> = local_signer.sign_frame(&frame).unwrap();
        let chunk_count: usize = if frame.len() <= MAX_CHUNK_BYTES {
            2
        } else {
            frame.len().div_ceil(MAX_CHUNK_BYTES)
        };
        let mut responses: Vec<ApduResponse> = vec![
            ApduResponse {
                data: vec![0x00, 0x01, 0, 1, 0, 0x00],
                status_word: STATUS_SUCCESS,
            },
            ApduResponse {
                data: local_signer.address().as_bytes().to_vec(),
                status_word: STATUS_SUCCESS,
            },
            ApduResponse {
                data: vec![0x00, 0x01, 0, 1, 0, 0x00],
                status_word: STATUS_SUCCESS,
            },
            ApduResponse {
                data: local_signer.address().as_bytes().to_vec(),
                status_word: STATUS_SUCCESS,
            },
        ];
        for _ in 0..chunk_count - 1 {
            responses.push(ApduResponse {
                data: Vec::new(),
                status_word: STATUS_SUCCESS,
            });
        }
        responses.push(ApduResponse {
            data: signature,
            status_word: STATUS_SUCCESS,
        });
        LedgerExternalSigner::connect(
            FakeTransport::new(responses),
            DerivationPath::provisional(0).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn selects_local_when_only_seed_file_is_present() {
        let selection = parse_signer_selection(&parsed(&[(SEED_FILE, "seed.hex")])).unwrap();
        assert_eq!(
            selection,
            SignerSelection::Local {
                seed_file: "seed.hex".to_string()
            }
        );
    }

    #[test]
    fn selects_ledger_when_all_three_ledger_flags_are_present() {
        let selection = parse_signer_selection(&parsed(&[
            (LEDGER_HID_PATH, "/dev/hidraw0"),
            (LEDGER_ACCOUNT, "3"),
            (LEDGER_EXPECTED_FIRMWARE_VERSION, "1.6.0"),
        ]))
        .unwrap();
        assert_eq!(
            selection,
            SignerSelection::Ledger {
                hid_path: "/dev/hidraw0".to_string(),
                account: 3,
                expected_firmware_version: ExpectedFirmwareVersion::new("1.6.0").unwrap(),
            }
        );
    }

    #[test]
    fn rejects_no_signer_selected() {
        assert!(matches!(
            parse_signer_selection(&parsed(&[])),
            Err(CliError::MissingSignerSelection)
        ));
    }

    #[test]
    fn rejects_local_combined_with_any_ledger_flag() {
        assert!(matches!(
            parse_signer_selection(&parsed(&[
                (SEED_FILE, "seed.hex"),
                (LEDGER_HID_PATH, "/dev/hidraw0"),
            ])),
            Err(CliError::ConflictingSignerSelection)
        ));
        assert!(matches!(
            parse_signer_selection(&parsed(&[(SEED_FILE, "seed.hex"), (LEDGER_ACCOUNT, "0"),])),
            Err(CliError::ConflictingSignerSelection)
        ));
        assert!(matches!(
            parse_signer_selection(&parsed(&[
                (SEED_FILE, "seed.hex"),
                (LEDGER_EXPECTED_FIRMWARE_VERSION, "1.6.0"),
            ])),
            Err(CliError::ConflictingSignerSelection)
        ));
        assert!(matches!(
            parse_signer_selection(&parsed(&[
                (SEED_FILE, "seed.hex"),
                (LEDGER_HID_PATH, "/dev/hidraw0"),
                (LEDGER_ACCOUNT, "0"),
                (LEDGER_EXPECTED_FIRMWARE_VERSION, "1.6.0"),
            ])),
            Err(CliError::ConflictingSignerSelection)
        ));
    }

    #[test]
    fn rejects_exactly_one_or_two_of_the_three_ledger_flags() {
        assert!(matches!(
            parse_signer_selection(&parsed(&[(LEDGER_HID_PATH, "/dev/hidraw0")])),
            Err(CliError::PartialLedgerSignerConfiguration {
                missing: LEDGER_ACCOUNT
            })
        ));
        assert!(matches!(
            parse_signer_selection(&parsed(&[(LEDGER_ACCOUNT, "0")])),
            Err(CliError::PartialLedgerSignerConfiguration {
                missing: LEDGER_HID_PATH
            })
        ));
        assert!(matches!(
            parse_signer_selection(&parsed(&[(LEDGER_EXPECTED_FIRMWARE_VERSION, "1.6.0")])),
            Err(CliError::PartialLedgerSignerConfiguration {
                missing: LEDGER_HID_PATH
            })
        ));
        assert!(matches!(
            parse_signer_selection(&parsed(&[
                (LEDGER_HID_PATH, "/dev/hidraw0"),
                (LEDGER_ACCOUNT, "0"),
            ])),
            Err(CliError::PartialLedgerSignerConfiguration {
                missing: LEDGER_EXPECTED_FIRMWARE_VERSION
            })
        ));
    }

    #[test]
    fn rejects_a_malformed_ledger_account() {
        assert!(matches!(
            parse_signer_selection(&parsed(&[
                (LEDGER_HID_PATH, "/dev/hidraw0"),
                (LEDGER_ACCOUNT, "not-a-number"),
                (LEDGER_EXPECTED_FIRMWARE_VERSION, "1.6.0"),
            ])),
            Err(CliError::InvalidInteger {
                flag: LEDGER_ACCOUNT,
                ..
            })
        ));
    }

    #[test]
    fn rejects_a_hardened_ledger_account_during_selection_before_device_dispatch() {
        let error = parse_signer_selection(&parsed(&[
            (LEDGER_HID_PATH, "/dev/hidraw0"),
            (LEDGER_ACCOUNT, "2147483648"),
            (LEDGER_EXPECTED_FIRMWARE_VERSION, "1.6.0"),
        ]))
        .unwrap_err();
        assert!(matches!(error, CliError::LedgerConnect(_)));
    }

    #[test]
    fn rejects_an_empty_expected_firmware_version_before_any_device_dispatch() {
        let error = parse_signer_selection(&parsed(&[
            (LEDGER_HID_PATH, "/dev/hidraw0"),
            (LEDGER_ACCOUNT, "0"),
            (LEDGER_EXPECTED_FIRMWARE_VERSION, ""),
        ]))
        .unwrap_err();
        assert!(matches!(
            error,
            CliError::LedgerExpectedFirmwareVersion(
                sunrise_edge_ledger::ExpectedFirmwareVersionError::Empty
            )
        ));
    }

    #[test]
    fn connect_ledger_with_checks_configuration_before_the_public_key() {
        use sunrise_edge_client::ExternalSigner;
        use sunrise_edge_ledger::{ApduResponse, FakeTransport};

        let key = [0x11_u8; 32];
        let transport = FakeTransport::new(vec![
            ApduResponse {
                data: vec![0x00, 0x01, 0, 1, 0, 0x00],
                status_word: 0x9000,
            },
            ApduResponse {
                data: key.to_vec(),
                status_word: 0x9000,
            },
        ]);

        let signer = connect_ledger_with(transport, 0).unwrap();
        assert_eq!(signer.address(), sunrise_edge_client::Address::new(key));
    }

    #[test]
    fn connect_ledger_with_rejects_an_account_that_already_has_the_hardened_bit_set() {
        use sunrise_edge_ledger::FakeTransport;

        let error = connect_ledger_with(FakeTransport::new(vec![]), 0x8000_0000).unwrap_err();
        assert!(matches!(error, CliError::LedgerConnect(_)));
    }

    // ---- connect_ledger_staged ----

    fn ok(data: Vec<u8>) -> sunrise_edge_ledger::ApduResponse {
        sunrise_edge_ledger::ApduResponse {
            data,
            status_word: sunrise_edge_ledger::apdu::STATUS_SUCCESS,
        }
    }

    fn lv(bytes: &[u8]) -> Vec<u8> {
        let mut out = vec![u8::try_from(bytes.len()).unwrap()];
        out.extend_from_slice(bytes);
        out
    }

    fn app_and_version_response(name: &str, version: &str) -> Vec<u8> {
        let mut data = vec![1_u8];
        data.extend(lv(name.as_bytes()));
        data.extend(lv(version.as_bytes()));
        data
    }

    const VALID_TARGET_ID: u32 = 0x3310_0004;

    fn firmware_response(target_id: u32, se_version: &str) -> Vec<u8> {
        let mut data = target_id.to_be_bytes().to_vec();
        data.extend(lv(se_version.as_bytes()));
        data.extend(lv(&[0x00]));
        data
    }

    fn valid_expected_firmware() -> ExpectedFirmwareVersion {
        ExpectedFirmwareVersion::new("1.6.0").unwrap()
    }

    fn valid_dashboard_transport() -> sunrise_edge_ledger::FakeTransport {
        sunrise_edge_ledger::FakeTransport::new(vec![
            ok(app_and_version_response("BOLOS", "1.6.0")),
            ok(firmware_response(VALID_TARGET_ID, "1.6.0")),
            ok(Vec::new()),
        ])
    }

    fn valid_app_transport(key: [u8; 32]) -> sunrise_edge_ledger::FakeTransport {
        sunrise_edge_ledger::FakeTransport::new(vec![
            ok(app_and_version_response(
                sunrise_edge_ledger::identity::EXPECTED_APP_NAME,
                sunrise_edge_ledger::identity::EXPECTED_APP_VERSION,
            )),
            ok(vec![0x00, 0x01, 0, 1, 0, 0x00]),
            ok(key.to_vec()),
        ])
    }

    #[test]
    fn connect_ledger_staged_runs_the_complete_sequence_in_order_and_succeeds() {
        let key = [0x55_u8; 32];
        let app_transport = valid_app_transport(key);
        let mut reconnect_calls = 0_u32;

        let signer = connect_ledger_staged(
            valid_dashboard_transport(),
            &valid_expected_firmware(),
            0,
            || {
                reconnect_calls += 1;
                Ok(app_transport)
            },
        )
        .unwrap();

        assert_eq!(signer.address(), sunrise_edge_client::Address::new(key));
        assert_eq!(reconnect_calls, 1);
    }

    #[test]
    fn connect_ledger_staged_never_reconnects_when_the_dashboard_identity_check_fails() {
        let dashboard_transport = sunrise_edge_ledger::FakeTransport::new(vec![ok(
            app_and_version_response("SomeOtherApp", "1.6.0"),
        )]);

        let error = connect_ledger_staged(
            dashboard_transport,
            &valid_expected_firmware(),
            0,
            || -> Result<sunrise_edge_ledger::FakeTransport, CliError> {
                panic!("reconnect must never be called once the dashboard identity check fails")
            },
        )
        .unwrap_err();

        assert!(matches!(error, CliError::LedgerIdentity(_)));
    }

    #[test]
    fn connect_ledger_staged_rejects_an_invalid_path_before_dashboard_dispatch() {
        let error = connect_ledger_staged(
            sunrise_edge_ledger::FakeTransport::new(Vec::new()),
            &valid_expected_firmware(),
            0x8000_0000,
            || -> Result<sunrise_edge_ledger::FakeTransport, CliError> {
                panic!("reconnect must not run for an invalid derivation path")
            },
        )
        .unwrap_err();

        assert!(matches!(error, CliError::LedgerConnect(_)));
    }

    #[test]
    fn connect_ledger_staged_never_reconnects_when_the_firmware_version_mismatches() {
        let dashboard_transport = sunrise_edge_ledger::FakeTransport::new(vec![
            ok(app_and_version_response("BOLOS", "1.6.0")),
            ok(firmware_response(VALID_TARGET_ID, "1.5.9")),
        ]);

        let error = connect_ledger_staged(
            dashboard_transport,
            &valid_expected_firmware(),
            0,
            || -> Result<sunrise_edge_ledger::FakeTransport, CliError> {
                panic!("reconnect must never be called once the firmware version mismatches")
            },
        )
        .unwrap_err();

        assert!(matches!(error, CliError::LedgerIdentity(_)));
    }

    #[test]
    fn connect_ledger_staged_reconnects_but_never_checks_configuration_when_the_active_app_check_fails()
     {
        let dashboard_transport = valid_dashboard_transport();
        let app_transport = sunrise_edge_ledger::FakeTransport::new(vec![ok(
            app_and_version_response("SomeOtherApp", "0.1.0"),
        )]);
        let mut reconnect_calls = 0_u32;

        let error =
            connect_ledger_staged(dashboard_transport, &valid_expected_firmware(), 0, || {
                reconnect_calls += 1;
                Ok(app_transport)
            })
            .unwrap_err();

        assert!(matches!(error, CliError::LedgerIdentity(_)));
        assert_eq!(
            reconnect_calls, 1,
            "reconnect must be attempted exactly once, after the dashboard stage succeeded"
        );
    }

    #[test]
    fn connect_ledger_staged_propagates_a_reconnect_failure() {
        let dashboard_transport = valid_dashboard_transport();

        let error = connect_ledger_staged(
            dashboard_transport,
            &valid_expected_firmware(),
            0,
            || -> Result<sunrise_edge_ledger::FakeTransport, CliError> {
                Err(CliError::LedgerReconnectTimedOut {
                    path: "/dev/hidraw0".to_string(),
                    deadline_ms: 30_000,
                    last_error: "no device found".to_string(),
                })
            },
        )
        .unwrap_err();

        assert!(matches!(error, CliError::LedgerReconnectTimedOut { .. }));
    }

    // ---- retry_until_deadline ----

    #[test]
    fn retry_until_deadline_returns_the_first_success() {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(200);
        let mut attempts = 0_u32;
        let result: Result<u32, &str> =
            retry_until_deadline(deadline, std::time::Duration::from_millis(1), || {
                attempts += 1;
                Ok(42)
            });
        assert_eq!(result, Ok(42));
        assert_eq!(attempts, 1);
    }

    #[test]
    fn retry_until_deadline_retries_until_a_later_success() {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
        let mut attempts = 0_u32;
        let result: Result<u32, &str> =
            retry_until_deadline(deadline, std::time::Duration::from_millis(5), || {
                attempts += 1;
                if attempts < 3 { Err("not yet") } else { Ok(7) }
            });
        assert_eq!(result, Ok(7));
        assert_eq!(attempts, 3);
    }

    #[test]
    fn retry_until_deadline_gives_up_once_the_monotonic_deadline_passes() {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(20);
        let mut attempts = 0_u32;
        let result: Result<u32, &str> =
            retry_until_deadline(deadline, std::time::Duration::from_millis(5), || {
                attempts += 1;
                Err("still failing")
            });
        assert_eq!(result, Err("still failing"));
        assert!(attempts >= 2, "expected at least one retry, got {attempts}");
    }

    #[test]
    fn ledger_finalization_uses_the_exact_cli_profile_and_policy_and_verifies_the_signature() {
        let local_signer = LocalSigner::from_seed([0xC1; 32]);
        let expected = PreparedTransaction::prepare(
            local_signer.address(),
            SignatureSchemeId::Ed25519,
            recognized_transfer_request(0),
        )
        .unwrap()
        .sign_and_finalize_with(&local_signer)
        .unwrap();
        let prepared_for_device = PreparedTransaction::prepare(
            local_signer.address(),
            SignatureSchemeId::Ed25519,
            recognized_transfer_request(0),
        )
        .unwrap();
        let signer = ledger_for_prepared(&local_signer, &prepared_for_device);

        let actual = finalize_with_ledger(prepared_for_device, &signer).unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn ledger_finalization_rejects_a_policy_mismatch_before_device_signing() {
        let local_signer = LocalSigner::from_seed([0xC2; 32]);
        let prepared = PreparedTransaction::prepare(
            local_signer.address(),
            SignatureSchemeId::Ed25519,
            recognized_transfer_request(1),
        )
        .unwrap();
        let signer = ledger_for_prepared(&local_signer, &prepared);

        let error = finalize_with_ledger(prepared, &signer).unwrap_err();

        assert!(matches!(
            error,
            CliError::Client(source)
                if matches!(
                    *source,
                    ClientError::SigningView(SigningViewError::Policy(
                        ClearSigningPolicyError::ModuleVersion
                    ))
                )
        ));
    }
}
