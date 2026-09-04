//! Explicit, all-or-none CLI signer selection between the development-only
//! local seed signer and a Ledger hardware signer (S4c; see `SIGNING.md`
//! and `ARCHITECTURE.md`'s Hardware Signing Profile v1 decision records).
//!
//! Exactly one signer must be selected: `--seed-file` alone (development-
//! only, in-memory, never a keystore), or both `--ledger-hid-path` and
//! `--ledger-account` together (a real Ledger device, verified by its
//! device-reported configuration and on-device-confirmed public key/address
//! before any signing — see [`connect_ledger_with`] and
//! `sunrise_edge_ledger::LedgerExternalSigner`). Any other combination —
//! neither, both groups at once, or exactly one of the two Ledger flags — is
//! a typed rejection before any network dispatch or device connection.

use sunrise_edge_client::{
    DEVNET_ASSET_TRANSFER_POLICY, DeviceSigningProfile, PreparedTransaction,
};
use sunrise_edge_ledger::{DerivationPath, LedgerExternalSigner, Transport};

use crate::args::{FlagSpec, ParsedArgs, scalar};
use crate::error::CliError;
use crate::parse::parse_u32;

/// Development-only local seed file flag.
pub const SEED_FILE: &str = "--seed-file";
/// Ledger device HID path flag.
pub const LEDGER_HID_PATH: &str = "--ledger-hid-path";
/// Ledger provisional derivation account flag.
pub const LEDGER_ACCOUNT: &str = "--ledger-account";

/// The signer-selection flags every signer-capable subcommand accepts, in
/// addition to its own flags.
#[must_use]
pub fn signer_flag_specs() -> Vec<FlagSpec> {
    vec![
        scalar(SEED_FILE),
        scalar(LEDGER_HID_PATH),
        scalar(LEDGER_ACCOUNT),
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
    },
}

/// Parses the required, explicit, all-or-none signer selection.
pub fn parse_signer_selection(parsed: &ParsedArgs) -> Result<SignerSelection, CliError> {
    let local = parsed.is_present(SEED_FILE);
    let ledger_hid = parsed.is_present(LEDGER_HID_PATH);
    let ledger_account = parsed.is_present(LEDGER_ACCOUNT);

    match (local, ledger_hid, ledger_account) {
        (true, false, false) => Ok(SignerSelection::Local {
            seed_file: parsed.require(SEED_FILE)?.to_string(),
        }),
        (false, true, true) => Ok(SignerSelection::Ledger {
            hid_path: parsed.require(LEDGER_HID_PATH)?.to_string(),
            account: parse_u32(LEDGER_ACCOUNT, parsed.require(LEDGER_ACCOUNT)?)?,
        }),
        (false, false, false) => Err(CliError::MissingSignerSelection),
        (true, _, _) => Err(CliError::ConflictingSignerSelection),
        (false, true, false) => Err(CliError::PartialLedgerSignerConfiguration {
            missing: LEDGER_ACCOUNT,
        }),
        (false, false, true) => Err(CliError::PartialLedgerSignerConfiguration {
            missing: LEDGER_HID_PATH,
        }),
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
/// the `usb-hid` feature and any real USB/HID hardware. Its only non-test
/// caller is behind `#[cfg(feature = "usb-hid")]`
/// (`commands::transfer::run_with_ledger`, `commands::address::run_with_ledger`),
/// so a default (non-test, non-`usb-hid`) build sees no call site at all.
#[allow(dead_code, reason = "used by usb-hid-gated callers and by tests")]
pub fn connect_ledger_with<T: Transport>(
    transport: T,
    account: u32,
) -> Result<LedgerExternalSigner<T>, CliError> {
    let path = DerivationPath::provisional(account)
        .map_err(|error| CliError::LedgerConnect(Box::new(error)))?;
    LedgerExternalSigner::connect(transport, path)
        .map_err(|error| CliError::LedgerConnect(Box::new(error)))
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
                data: vec![0x00, 0x01, 1, 0, 0, 0x00],
                status_word: STATUS_SUCCESS,
            },
            ApduResponse {
                data: local_signer.address().as_bytes().to_vec(),
                status_word: STATUS_SUCCESS,
            },
            ApduResponse {
                data: vec![0x00, 0x01, 1, 0, 0, 0x00],
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
    fn selects_ledger_when_both_ledger_flags_are_present() {
        let selection = parse_signer_selection(&parsed(&[
            (LEDGER_HID_PATH, "/dev/hidraw0"),
            (LEDGER_ACCOUNT, "3"),
        ]))
        .unwrap();
        assert_eq!(
            selection,
            SignerSelection::Ledger {
                hid_path: "/dev/hidraw0".to_string(),
                account: 3,
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
    fn rejects_local_combined_with_either_ledger_flag() {
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
                (LEDGER_HID_PATH, "/dev/hidraw0"),
                (LEDGER_ACCOUNT, "0"),
            ])),
            Err(CliError::ConflictingSignerSelection)
        ));
    }

    #[test]
    fn rejects_exactly_one_of_the_two_ledger_flags() {
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
    }

    #[test]
    fn rejects_a_malformed_ledger_account() {
        assert!(matches!(
            parse_signer_selection(&parsed(&[
                (LEDGER_HID_PATH, "/dev/hidraw0"),
                (LEDGER_ACCOUNT, "not-a-number"),
            ])),
            Err(CliError::InvalidInteger {
                flag: LEDGER_ACCOUNT,
                ..
            })
        ));
    }

    #[test]
    fn connect_ledger_with_checks_configuration_before_the_public_key() {
        use sunrise_edge_client::ExternalSigner;
        use sunrise_edge_ledger::{ApduResponse, FakeTransport};

        let key = [0x11_u8; 32];
        let transport = FakeTransport::new(vec![
            ApduResponse {
                data: vec![0x00, 0x01, 1, 0, 0, 0x00],
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
