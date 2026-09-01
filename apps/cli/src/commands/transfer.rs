//! `transfer`: the one same-owner devnet asset transfer command.
//!
//! This command is the only place in `apps/cli` that knows anything about
//! the `sunrise.devnet.asset_account.v1` module: its fixed `transfer`
//! entrypoint name and its exact `CanonicalStruct(0xF002, v1){1: u64
//! amount}` argument frame. `clients/rust` stays application-agnostic (see
//! `ARCHITECTURE.md` §44 / DR-0083); this file only uses the small, generic
//! canonical-struct and access-manifest surface `clients/rust` re-exports
//! (DR-0084).
//!
//! It queries authoritative context first and validates, before any
//! nonce/object query or signing, that the committed transaction-auth
//! profile id, signature scheme, and address binding are all the ones this
//! client implements (the single committed profile id, `Ed25519`, and
//! `AddressIsPublicKey`); an unknown profile id is rejected there even
//! though it happens to pair a known scheme/binding. It then queries the
//! signer's next nonce (checking its epoch agrees with the context's before
//! proceeding) and both current-inline object references, decoding each
//! object's canonical body and requiring its owner to be the local signer's
//! own address (defense in depth alongside the server's own fail-closed
//! owner check — see `ARCHITECTURE.md` §44 / DR-0083). It then builds the
//! exact two-`Write` access manifest in source/destination order, builds and
//! signs the transaction through `clients/rust`, and submits it with an
//! explicit non-zero request id. Waiting for a receipt is optional and, when
//! requested, bounded by caller-supplied, finite poll parameters.

use std::ffi::OsString;
use std::num::NonZeroU32;
use std::time::Duration;

use sunrise_edge_client::{
    AccessEntry, AccessManifest, AccessMode, Address, CanonicalStruct, Client, Digest32,
    ED25519_ADDRESS_IS_PUBLIC_KEY_BINDING_ID, ED25519_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID,
    ExecutionEffects, ExecutionStatus, HashAlgorithmId, LocalSigner, NodeResponseStatus,
    ObjectEffect, ObjectId, ObjectRef, Owner, ReceiptPollBounds, RequestId, SignatureSchemeId,
    SubmitTransactionRequest, TransactionRequest, Transport, build_signed_transaction,
    decode_object,
};

use crate::args::{ParsedArgs, parse_flags, scalar, switch};
use crate::error::CliError;
use crate::hex::decode_hex_32;
use crate::net::connect;
use crate::output::{bounded_hex_field, sanitize_line};
use crate::parse::{parse_u16, parse_u32, parse_u64};
use crate::seed::load_dev_seed;

const ENDPOINT: &str = "--endpoint";
const SEED_FILE: &str = "--seed-file";
const MODULE_ID: &str = "--module-id";
const MODULE_VERSION: &str = "--module-version";
const MODULE_DIGEST_ALGORITHM: &str = "--module-digest-algorithm";
const MODULE_DIGEST: &str = "--module-digest";
const SOURCE_OBJECT: &str = "--source-object";
const DESTINATION_OBJECT: &str = "--destination-object";
const AMOUNT: &str = "--amount";
const GAS_LIMIT: &str = "--gas-limit";
const REQUEST_ID: &str = "--request-id";
const WAIT: &str = "--wait";
const WAIT_MAX_ATTEMPTS: &str = "--wait-max-attempts";
const WAIT_INITIAL_BACKOFF_MS: &str = "--wait-initial-backoff-ms";
const WAIT_MAX_BACKOFF_MS: &str = "--wait-max-backoff-ms";
const WAIT_MAX_ELAPSED_MS: &str = "--wait-max-elapsed-ms";

/// The devnet `sunrise.devnet.asset_account.v1` module's `transfer`
/// entrypoint name (see `ARCHITECTURE.md` §"Local devnet architecture").
const TRANSFER_ENTRYPOINT: &str = "transfer";
/// Canonical type identifier for the devnet module's transfer arguments
/// (`0xF002`, reserved by DR-0081; devnet-local, not a base-protocol id).
const TRANSFER_ARGS_TYPE_ID: u16 = 0xF002;
const TRANSFER_ARGS_ENCODING_VERSION: u16 = 1;

/// Fully parsed, strongly typed `transfer` inputs.
struct TransferInputs {
    module_ref: ObjectRef,
    source_id: ObjectId,
    destination_id: ObjectId,
    amount: u64,
    gas_limit: u64,
    request_id: RequestId,
    wait_bounds: Option<ReceiptPollBounds>,
}

/// Runs the `transfer` subcommand.
pub fn run<I>(args: I) -> Result<(), CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let parsed = parse_flags(
        args,
        &[
            scalar(ENDPOINT),
            scalar(SEED_FILE),
            scalar(MODULE_ID),
            scalar(MODULE_VERSION),
            scalar(MODULE_DIGEST_ALGORITHM),
            scalar(MODULE_DIGEST),
            scalar(SOURCE_OBJECT),
            scalar(DESTINATION_OBJECT),
            scalar(AMOUNT),
            scalar(GAS_LIMIT),
            scalar(REQUEST_ID),
            switch(WAIT),
            scalar(WAIT_MAX_ATTEMPTS),
            scalar(WAIT_INITIAL_BACKOFF_MS),
            scalar(WAIT_MAX_BACKOFF_MS),
            scalar(WAIT_MAX_ELAPSED_MS),
        ],
    )?;

    let endpoint = parsed.require(ENDPOINT)?;
    let seed_file = parsed.require(SEED_FILE)?;
    let inputs = parse_inputs(&parsed)?;

    let seed = load_dev_seed(std::path::Path::new(seed_file))?;
    let signer = LocalSigner::from_seed(seed);

    let client = connect(endpoint)?;
    execute(&client, &signer, inputs)
}

fn parse_inputs(parsed: &ParsedArgs) -> Result<TransferInputs, CliError> {
    let module_ref = parse_module_ref(parsed)?;
    let source_id = ObjectId::new(decode_hex_32(
        SOURCE_OBJECT,
        parsed.require(SOURCE_OBJECT)?,
    )?);
    let destination_id = ObjectId::new(decode_hex_32(
        DESTINATION_OBJECT,
        parsed.require(DESTINATION_OBJECT)?,
    )?);
    if source_id == destination_id {
        return Err(CliError::SameSourceAndDestination);
    }
    let amount = parse_u64(AMOUNT, parsed.require(AMOUNT)?)?;
    if amount == 0 {
        return Err(CliError::ZeroAmount);
    }
    let gas_limit = parse_u64(GAS_LIMIT, parsed.require(GAS_LIMIT)?)?;
    if gas_limit == 0 {
        return Err(CliError::ZeroGasLimit);
    }
    let request_id = RequestId::new(decode_hex_32(REQUEST_ID, parsed.require(REQUEST_ID)?)?)?;
    let wait_bounds = parse_wait_bounds(parsed)?;

    Ok(TransferInputs {
        module_ref,
        source_id,
        destination_id,
        amount,
        gas_limit,
        request_id,
        wait_bounds,
    })
}

fn execute<T>(
    client: &Client<T>,
    signer: &LocalSigner,
    inputs: TransferInputs,
) -> Result<(), CliError>
where
    T: Transport,
{
    let sender = signer.address();

    let context = client.query_context()?;
    if context.signature_scheme_id() != SignatureSchemeId::Ed25519.as_u16() {
        return Err(CliError::UnsupportedSignatureScheme(
            context.signature_scheme_id(),
        ));
    }
    if context.address_binding_id() != ED25519_ADDRESS_IS_PUBLIC_KEY_BINDING_ID {
        return Err(CliError::UnsupportedAddressBinding(
            context.address_binding_id(),
        ));
    }
    if context.transaction_auth_profile_id() != ED25519_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID {
        return Err(CliError::UnsupportedAuthProfile(
            context.transaction_auth_profile_id(),
        ));
    }

    let nonce_result = client.query_next_nonce(sender)?;
    if nonce_result.epoch() != context.epoch() {
        return Err(CliError::EpochMismatch {
            context_epoch: context.epoch().get(),
            nonce_epoch: nonce_result.epoch().get(),
        });
    }

    let source_ref = require_owned_current_inline(client, SOURCE_OBJECT, inputs.source_id, sender)?;
    let destination_ref =
        require_owned_current_inline(client, DESTINATION_OBJECT, inputs.destination_id, sender)?;

    let mut access_manifest = AccessManifest::new();
    access_manifest.push(AccessEntry {
        object_ref: source_ref,
        mode: AccessMode::Write,
    });
    access_manifest.push(AccessEntry {
        object_ref: destination_ref,
        mode: AccessMode::Write,
    });

    let mut args_frame =
        CanonicalStruct::new(TRANSFER_ARGS_TYPE_ID, TRANSFER_ARGS_ENCODING_VERSION);
    args_frame.field_u64(1, inputs.amount)?;
    let args = args_frame.finish()?;

    let request = TransactionRequest {
        chain_id: context.chain_id().clone(),
        protocol_version: context.protocol_version(),
        epoch: context.epoch(),
        nonce: nonce_result.next_nonce(),
        access_manifest,
        module_ref: inputs.module_ref,
        entrypoint: TRANSFER_ENTRYPOINT.to_string(),
        args,
        gas_limit: inputs.gas_limit,
        fee_payment: None,
    };
    let signed_bytes = build_signed_transaction(signer, SignatureSchemeId::Ed25519, request)?;

    let submit_result = client.submit_transaction(SubmitTransactionRequest {
        chain_id: context.chain_id().clone(),
        protocol_version: context.protocol_version(),
        epoch: context.epoch(),
        request_id: inputs.request_id,
        signed_transaction_bytes: signed_bytes,
    })?;

    if submit_result.responses().is_empty() {
        return Err(CliError::EmptySubmitResponse);
    }

    println!("request_id={}", submit_result.request_id());
    println!("responses={}", submit_result.responses().len());
    // Print every response's diagnostics before failing, but never let a
    // later `Ok` path (including `--wait`) run once any response was
    // rejected or its decoded execution failed: the first such outcome wins.
    let mut outcome: Result<(), CliError> = Ok(());
    for (index, response) in submit_result.responses().iter().enumerate() {
        let status = match response.status() {
            NodeResponseStatus::Accepted => "accepted",
            NodeResponseStatus::Rejected => "rejected",
        };
        println!("response[{index}].status={status}");
        if outcome.is_ok() && response.status() == NodeResponseStatus::Rejected {
            outcome = Err(CliError::TransactionRejected { index });
        }
        let failure_reason = response
            .payload()
            .and_then(|payload| print_payload(index, payload));
        if let Some(reason) = failure_reason
            && outcome.is_ok()
        {
            outcome = Err(CliError::TransactionExecutionFailed { index, reason });
        }
    }
    outcome?;

    if let Some(bounds) = inputs.wait_bounds {
        let receipt = client.wait_for_receipt(inputs.request_id, &bounds)?;
        print_receipt(&receipt);
    }

    Ok(())
}

fn parse_module_ref(parsed: &ParsedArgs) -> Result<ObjectRef, CliError> {
    let id = ObjectId::new(decode_hex_32(MODULE_ID, parsed.require(MODULE_ID)?)?);
    let version = parse_u64(MODULE_VERSION, parsed.require(MODULE_VERSION)?)?;
    let algorithm_id = parse_u16(
        MODULE_DIGEST_ALGORITHM,
        parsed.require(MODULE_DIGEST_ALGORITHM)?,
    )?;
    let algorithm = HashAlgorithmId::try_from(algorithm_id)
        .map_err(|_| CliError::InvalidHashAlgorithm(algorithm_id))?;
    let digest_bytes = decode_hex_32(MODULE_DIGEST, parsed.require(MODULE_DIGEST)?)?;
    Ok(ObjectRef {
        id,
        version,
        digest: Digest32::new(algorithm, digest_bytes),
    })
}

fn parse_wait_bounds(parsed: &ParsedArgs) -> Result<Option<ReceiptPollBounds>, CliError> {
    let wait_flags = [
        WAIT_MAX_ATTEMPTS,
        WAIT_INITIAL_BACKOFF_MS,
        WAIT_MAX_BACKOFF_MS,
        WAIT_MAX_ELAPSED_MS,
    ];
    if !parsed.is_present(WAIT) {
        for flag in wait_flags {
            if parsed.is_present(flag) {
                return Err(CliError::WaitBoundWithoutWait(flag));
            }
        }
        return Ok(None);
    }

    for flag in wait_flags {
        if !parsed.is_present(flag) {
            return Err(CliError::WaitBoundRequired(flag));
        }
    }
    let max_attempts = parse_u32(WAIT_MAX_ATTEMPTS, parsed.require(WAIT_MAX_ATTEMPTS)?)?;
    let max_attempts =
        NonZeroU32::new(max_attempts).ok_or(CliError::WaitBoundRequired(WAIT_MAX_ATTEMPTS))?;
    let initial_backoff = Duration::from_millis(parse_u64(
        WAIT_INITIAL_BACKOFF_MS,
        parsed.require(WAIT_INITIAL_BACKOFF_MS)?,
    )?);
    let max_backoff = Duration::from_millis(parse_u64(
        WAIT_MAX_BACKOFF_MS,
        parsed.require(WAIT_MAX_BACKOFF_MS)?,
    )?);
    let max_elapsed = Duration::from_millis(parse_u64(
        WAIT_MAX_ELAPSED_MS,
        parsed.require(WAIT_MAX_ELAPSED_MS)?,
    )?);
    Ok(Some(ReceiptPollBounds {
        max_attempts,
        initial_backoff,
        max_backoff,
        max_elapsed,
    }))
}

/// Queries `object_id`, requires it to be `CurrentInline`, decodes its exact
/// canonical body through `clients/rust`'s generic public surface
/// (`decode_object`), and requires the decoded `Owner::Address` to equal
/// `expected_owner` before returning its `ObjectRef`.
///
/// This is a client-side, defense-in-depth check: the server's own owned-
/// effects path independently and authoritatively rejects a transaction
/// whose declared sender does not own a referenced object (see
/// `ARCHITECTURE.md` §"Node-core invocation boundary"). Checking here too
/// only saves a round trip and gives an actionable local error; it never
/// weakens or substitutes for that server-side check.
fn require_owned_current_inline<T>(
    client: &Client<T>,
    flag: &'static str,
    object_id: ObjectId,
    expected_owner: Address,
) -> Result<ObjectRef, CliError>
where
    T: Transport,
{
    let result = client.query_object(object_id)?;
    let (object_version, digest, canonical_object_bytes) = match &result {
        sunrise_edge_client::HttpObjectQueryResult::CurrentInline {
            object_version,
            digest,
            canonical_object_bytes,
            ..
        } => (*object_version, *digest, canonical_object_bytes),
        other => {
            return Err(CliError::ObjectNotCurrentlyInline {
                flag,
                object_id: object_id.to_string(),
                status: object_query_status_label(other),
            });
        }
    };

    let object = decode_object(canonical_object_bytes).map_err(|source| {
        CliError::ObjectBodyDecodeFailed {
            flag,
            object_id: object_id.to_string(),
            source,
        }
    })?;

    match &object.owner {
        Owner::Address(owner_address) if *owner_address == expected_owner => Ok(ObjectRef {
            id: object_id,
            version: object_version.get(),
            digest,
        }),
        owner => Err(CliError::ObjectOwnerMismatch {
            flag,
            object_id: object_id.to_string(),
            owner: owner_label(owner),
        }),
    }
}

fn owner_label(owner: &Owner) -> String {
    match owner {
        Owner::Address(address) => format!("address:{address}"),
        Owner::Shared => "shared".to_string(),
        Owner::Immutable => "immutable".to_string(),
        Owner::System => "system".to_string(),
    }
}

fn object_query_status_label(result: &sunrise_edge_client::HttpObjectQueryResult) -> &'static str {
    match result {
        sunrise_edge_client::HttpObjectQueryResult::Absent { .. } => "absent",
        sunrise_edge_client::HttpObjectQueryResult::Tombstoned { .. } => "tombstoned",
        sunrise_edge_client::HttpObjectQueryResult::CurrentInline { .. } => "current_inline",
        sunrise_edge_client::HttpObjectQueryResult::CurrentBlobReference { .. } => {
            "current_blob_reference"
        }
    }
}

/// Prints `payload`'s diagnostics and returns the sanitized execution
/// failure reason, if its decoded effects declared `ExecutionStatus::Failure`.
fn print_payload(index: usize, payload: &[u8]) -> Option<String> {
    match sunrise_edge_client::decode_execution_effects(payload) {
        Ok(effects) => print_effects(index, &effects),
        Err(_) => {
            let (hex, truncated) = bounded_hex_field(payload);
            println!("response[{index}].payload_len={}", payload.len());
            println!("response[{index}].payload_truncated={truncated}");
            println!("response[{index}].payload_hex={hex}");
            None
        }
    }
}

/// Prints `effects`'s diagnostics and returns the sanitized execution
/// failure reason, if any.
fn print_effects(index: usize, effects: &ExecutionEffects) -> Option<String> {
    println!("response[{index}].tx_hash={}", effects.tx_hash);
    println!("response[{index}].gas_used={}", effects.gas_used);
    let failure_reason = match &effects.status {
        ExecutionStatus::Success => {
            println!("response[{index}].execution_status=success");
            None
        }
        ExecutionStatus::Failure { reason } => {
            println!("response[{index}].execution_status=failure");
            let sanitized_reason = sanitize_line(reason);
            println!("response[{index}].execution_failure_reason={sanitized_reason}");
            Some(sanitized_reason)
        }
    };
    println!(
        "response[{index}].object_effects={}",
        effects.object_effects.len()
    );
    for (effect_index, effect) in effects.object_effects.iter().enumerate() {
        print_object_effect(index, effect_index, effect);
    }
    println!("response[{index}].events={}", effects.events.len());
    for (event_index, event) in effects.events.iter().enumerate() {
        let (type_tag_hex, type_tag_truncated) = bounded_hex_field(&event.type_tag);
        let (data_hex, data_truncated) = bounded_hex_field(&event.data);
        println!("response[{index}].event[{event_index}].type_tag_hex={type_tag_hex}");
        println!("response[{index}].event[{event_index}].type_tag_truncated={type_tag_truncated}");
        println!(
            "response[{index}].event[{event_index}].data_len={}",
            event.data.len()
        );
        println!("response[{index}].event[{event_index}].data_truncated={data_truncated}");
        println!("response[{index}].event[{event_index}].data_hex={data_hex}");
    }
    failure_reason
}

fn print_object_effect(response_index: usize, effect_index: usize, effect: &ObjectEffect) {
    let prefix = format!("response[{response_index}].object_effect[{effect_index}]");
    match effect {
        ObjectEffect::Created(object) => {
            println!("{prefix}.kind=created");
            println!("{prefix}.object_id={}", object.id);
            println!("{prefix}.object_version={}", object.version);
            let (hex, truncated) = bounded_hex_field(&object.data);
            println!("{prefix}.data_len={}", object.data.len());
            println!("{prefix}.data_truncated={truncated}");
            println!("{prefix}.data_hex={hex}");
        }
        ObjectEffect::Mutated {
            previous_version,
            new_object,
        } => {
            println!("{prefix}.kind=mutated");
            println!("{prefix}.object_id={}", new_object.id);
            println!("{prefix}.previous_version={previous_version}");
            println!("{prefix}.object_version={}", new_object.version);
            let (hex, truncated) = bounded_hex_field(&new_object.data);
            println!("{prefix}.data_len={}", new_object.data.len());
            println!("{prefix}.data_truncated={truncated}");
            println!("{prefix}.data_hex={hex}");
        }
        ObjectEffect::Deleted { id, version } => {
            println!("{prefix}.kind=deleted");
            println!("{prefix}.object_id={id}");
            println!("{prefix}.object_version={version}");
        }
    }
}

fn print_receipt(receipt: &sunrise_edge_client::HttpReceiptQueryResult) {
    match receipt {
        sunrise_edge_client::HttpReceiptQueryResult::Absent { request_id } => {
            println!("receipt_status=absent");
            println!("receipt_request_id={request_id}");
        }
        sunrise_edge_client::HttpReceiptQueryResult::Present {
            request_id,
            event_digest,
            dedup_record_bytes,
        } => {
            println!("receipt_status=present");
            println!("receipt_request_id={request_id}");
            println!(
                "receipt_event_digest_algorithm={}",
                event_digest.algorithm().as_u16()
            );
            println!("receipt_event_digest={event_digest}");
            let (hex, truncated) = bounded_hex_field(dedup_record_bytes);
            println!(
                "receipt_dedup_record_bytes_len={}",
                dedup_record_bytes.len()
            );
            println!("receipt_dedup_record_bytes_truncated={truncated}");
            println!("receipt_dedup_record_bytes={hex}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{FakeTransport, node_result_ok, query_ok};
    use sunrise_edge_client::{
        AtomicityDomainId, ChainId, Epoch, HashSuiteId, HttpContextQueryResult,
        HttpNextNonceQueryResult, HttpNodeResult, HttpObjectQueryResult, NodeResponse,
        ProtocolVersion,
    };

    fn sample_signer() -> LocalSigner {
        LocalSigner::from_seed([0x77; 32])
    }

    fn sample_inputs() -> TransferInputs {
        TransferInputs {
            module_ref: ObjectRef {
                id: ObjectId::new([0x01; 32]),
                version: 1,
                digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x02; 32]),
            },
            source_id: ObjectId::new([0x10; 32]),
            destination_id: ObjectId::new([0x20; 32]),
            amount: 250,
            gas_limit: 1_000,
            request_id: RequestId::new([0x30; 32]).unwrap(),
            wait_bounds: None,
        }
    }

    fn sample_context() -> HttpContextQueryResult {
        HttpContextQueryResult::new(
            ChainId::new("transfer-test-chain").unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(5),
            HashSuiteId::new(1),
            1,
            SignatureSchemeId::Ed25519.as_u16(),
            ED25519_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
            AtomicityDomainId::new([0x44; 32]).unwrap(),
            vec![0xAA],
        )
        .unwrap()
    }

    fn current_inline_with_owner(
        object_id: ObjectId,
        version: u64,
        owner: Owner,
    ) -> HttpObjectQueryResult {
        let object = objects::Object {
            id: object_id,
            version,
            owner,
            type_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0x09; 32]),
            schema_version: 1,
            data: vec![1, 2, 3],
        };
        let canonical_object_bytes = objects::encode_object(&object).unwrap();
        let digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x0A; 32]);
        HttpObjectQueryResult::CurrentInline {
            object_id,
            head_revision: runtime::ObjectHeadRevision::new(1).unwrap(),
            object_version: runtime::DurableObjectVersion::new(version).unwrap(),
            digest,
            canonical_object_bytes,
        }
    }

    fn current_inline_owned_by(
        object_id: ObjectId,
        version: u64,
        owner: Address,
    ) -> HttpObjectQueryResult {
        current_inline_with_owner(object_id, version, Owner::Address(owner))
    }

    #[test]
    fn execute_succeeds_and_submits_after_the_expected_round_trip() {
        let signer = sample_signer();
        let inputs = sample_inputs();
        let context = sample_context();
        let nonce = HttpNextNonceQueryResult::new(signer.address(), Epoch::new(5), 3);
        let source = current_inline_owned_by(inputs.source_id, 1, signer.address());
        let destination = current_inline_owned_by(inputs.destination_id, 1, signer.address());
        let accepted =
            NodeResponse::new(inputs.request_id, NodeResponseStatus::Accepted, None).unwrap();
        let submit = HttpNodeResult::new(inputs.request_id, vec![accepted]).unwrap();

        let transport = FakeTransport::new(vec![
            query_ok(context.encode().unwrap()),
            query_ok(nonce.encode().unwrap()),
            query_ok(source.encode().unwrap()),
            query_ok(destination.encode().unwrap()),
            node_result_ok(submit.encode().unwrap()),
        ]);
        let client = Client::new(transport);

        execute(&client, &signer, inputs).unwrap();

        let requests = client.transport().requests();
        assert_eq!(requests.len(), 5);
        assert_eq!(requests[0].path, "/v1/context");
        assert_eq!(requests[4].method, sunrise_edge_client::Method::Post);
    }

    #[test]
    fn execute_rejects_a_rejected_submission_response_even_with_wait_requested() {
        let signer = sample_signer();
        let mut inputs = sample_inputs();
        // `--wait` bounds are set to prove a rejected submission can never
        // reach `wait_for_receipt` and be turned into success.
        inputs.wait_bounds = Some(ReceiptPollBounds {
            max_attempts: NonZeroU32::new(3).unwrap(),
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(10),
            max_elapsed: Duration::from_millis(100),
        });
        let context = sample_context();
        let nonce = HttpNextNonceQueryResult::new(signer.address(), Epoch::new(5), 3);
        let source = current_inline_owned_by(inputs.source_id, 1, signer.address());
        let destination = current_inline_owned_by(inputs.destination_id, 1, signer.address());
        let rejected =
            NodeResponse::new(inputs.request_id, NodeResponseStatus::Rejected, None).unwrap();
        let submit = HttpNodeResult::new(inputs.request_id, vec![rejected]).unwrap();

        let transport = FakeTransport::new(vec![
            query_ok(context.encode().unwrap()),
            query_ok(nonce.encode().unwrap()),
            query_ok(source.encode().unwrap()),
            query_ok(destination.encode().unwrap()),
            node_result_ok(submit.encode().unwrap()),
        ]);
        let client = Client::new(transport);

        let error = execute(&client, &signer, inputs).unwrap_err();
        assert!(matches!(error, CliError::TransactionRejected { index: 0 }));
        // Exactly the 5 request/nonce/object/submit calls were made: no 6th
        // (receipt-wait) request was ever issued after the rejection.
        assert_eq!(client.transport().requests().len(), 5);
    }

    #[test]
    fn execute_rejects_an_execution_failure_even_when_the_node_response_is_accepted() {
        let signer = sample_signer();
        let mut inputs = sample_inputs();
        inputs.wait_bounds = Some(ReceiptPollBounds {
            max_attempts: NonZeroU32::new(3).unwrap(),
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(10),
            max_elapsed: Duration::from_millis(100),
        });
        let context = sample_context();
        let nonce = HttpNextNonceQueryResult::new(signer.address(), Epoch::new(5), 3);
        let source = current_inline_owned_by(inputs.source_id, 1, signer.address());
        let destination = current_inline_owned_by(inputs.destination_id, 1, signer.address());
        let effects = execution::ExecutionEffects {
            tx_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0x0B; 32]),
            status: ExecutionStatus::Failure {
                reason: "trap: out of gas".to_string(),
            },
            object_effects: Vec::new(),
            events: Vec::new(),
            gas_used: 1_000,
        };
        let payload = execution::encode_execution_effects(&effects).unwrap();
        let accepted = NodeResponse::new(
            inputs.request_id,
            NodeResponseStatus::Accepted,
            Some(payload),
        )
        .unwrap();
        let submit = HttpNodeResult::new(inputs.request_id, vec![accepted]).unwrap();

        let transport = FakeTransport::new(vec![
            query_ok(context.encode().unwrap()),
            query_ok(nonce.encode().unwrap()),
            query_ok(source.encode().unwrap()),
            query_ok(destination.encode().unwrap()),
            node_result_ok(submit.encode().unwrap()),
        ]);
        let client = Client::new(transport);

        let error = execute(&client, &signer, inputs).unwrap_err();
        assert!(matches!(
            error,
            CliError::TransactionExecutionFailed { index: 0, reason }
                if reason == "trap: out of gas"
        ));
        assert_eq!(client.transport().requests().len(), 5);
    }

    #[test]
    fn execute_rejects_an_empty_submit_response() {
        let signer = sample_signer();
        let inputs = sample_inputs();
        let context = sample_context();
        let nonce = HttpNextNonceQueryResult::new(signer.address(), Epoch::new(5), 3);
        let source = current_inline_owned_by(inputs.source_id, 1, signer.address());
        let destination = current_inline_owned_by(inputs.destination_id, 1, signer.address());
        let submit = HttpNodeResult::new(inputs.request_id, vec![]).unwrap();

        let transport = FakeTransport::new(vec![
            query_ok(context.encode().unwrap()),
            query_ok(nonce.encode().unwrap()),
            query_ok(source.encode().unwrap()),
            query_ok(destination.encode().unwrap()),
            node_result_ok(submit.encode().unwrap()),
        ]);
        let client = Client::new(transport);

        let error = execute(&client, &signer, inputs).unwrap_err();
        assert!(matches!(error, CliError::EmptySubmitResponse));
    }

    #[test]
    fn execute_rejects_an_epoch_mismatch_between_context_and_nonce() {
        let signer = sample_signer();
        let inputs = sample_inputs();
        let context = sample_context();
        let nonce = HttpNextNonceQueryResult::new(signer.address(), Epoch::new(6), 3);

        let transport = FakeTransport::new(vec![
            query_ok(context.encode().unwrap()),
            query_ok(nonce.encode().unwrap()),
        ]);
        let client = Client::new(transport);

        let error = execute(&client, &signer, inputs).unwrap_err();
        assert!(matches!(
            error,
            CliError::EpochMismatch {
                context_epoch: 5,
                nonce_epoch: 6
            }
        ));
    }

    #[test]
    fn execute_rejects_an_unsupported_signature_scheme() {
        let signer = sample_signer();
        let inputs = sample_inputs();
        let context = HttpContextQueryResult::new(
            ChainId::new("transfer-test-chain").unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(5),
            HashSuiteId::new(1),
            1,
            SignatureSchemeId::Secp256k1.as_u16(),
            ED25519_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
            AtomicityDomainId::new([0x44; 32]).unwrap(),
            vec![0xAA],
        )
        .unwrap();

        let transport = FakeTransport::new(vec![query_ok(context.encode().unwrap())]);
        let client = Client::new(transport);

        let error = execute(&client, &signer, inputs).unwrap_err();
        assert!(matches!(
            error,
            CliError::UnsupportedSignatureScheme(id) if id == SignatureSchemeId::Secp256k1.as_u16()
        ));
    }

    #[test]
    fn execute_rejects_an_unsupported_auth_profile_before_any_later_dispatch() {
        let signer = sample_signer();
        let inputs = sample_inputs();
        let context = HttpContextQueryResult::new(
            ChainId::new("transfer-test-chain").unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(5),
            HashSuiteId::new(1),
            // A profile id other than the one implemented
            // `ED25519_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID`, even though the
            // scheme/binding below are otherwise the implemented pair — the
            // profile id itself must still be checked.
            2,
            SignatureSchemeId::Ed25519.as_u16(),
            ED25519_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
            AtomicityDomainId::new([0x44; 32]).unwrap(),
            vec![0xAA],
        )
        .unwrap();

        // Only the context response is scripted: if `execute` dispatched a
        // second request (nonce, object, or submit), the fake transport
        // would return `RequestDeadlineExceeded` for it and the test would
        // observe that error instead of `UnsupportedAuthProfile`, or the
        // request-count assertion below would fail.
        let transport = FakeTransport::new(vec![query_ok(context.encode().unwrap())]);
        let client = Client::new(transport);

        let error = execute(&client, &signer, inputs).unwrap_err();
        assert!(matches!(error, CliError::UnsupportedAuthProfile(2)));
        assert_eq!(client.transport().requests().len(), 1);
    }

    #[test]
    fn execute_rejects_a_source_object_owned_by_a_different_address() {
        let signer = sample_signer();
        let inputs = sample_inputs();
        let context = sample_context();
        let nonce = HttpNextNonceQueryResult::new(signer.address(), Epoch::new(5), 3);
        let other_owner = Address::new([0xB2; 32]);
        let source = current_inline_owned_by(inputs.source_id, 1, other_owner);

        let transport = FakeTransport::new(vec![
            query_ok(context.encode().unwrap()),
            query_ok(nonce.encode().unwrap()),
            query_ok(source.encode().unwrap()),
        ]);
        let client = Client::new(transport);

        let error = execute(&client, &signer, inputs).unwrap_err();
        assert!(matches!(
            error,
            CliError::ObjectOwnerMismatch {
                flag: SOURCE_OBJECT,
                owner,
                ..
            } if owner == format!("address:{other_owner}")
        ));
    }

    #[test]
    fn execute_rejects_shared_system_and_immutable_owned_objects() {
        for (owner, label) in [
            (Owner::Shared, "shared"),
            (Owner::System, "system"),
            (Owner::Immutable, "immutable"),
        ] {
            let signer = sample_signer();
            let inputs = sample_inputs();
            let context = sample_context();
            let nonce = HttpNextNonceQueryResult::new(signer.address(), Epoch::new(5), 3);
            let source = current_inline_with_owner(inputs.source_id, 1, owner);

            let transport = FakeTransport::new(vec![
                query_ok(context.encode().unwrap()),
                query_ok(nonce.encode().unwrap()),
                query_ok(source.encode().unwrap()),
            ]);
            let client = Client::new(transport);

            let error = execute(&client, &signer, inputs).unwrap_err();
            assert!(
                matches!(
                    &error,
                    CliError::ObjectOwnerMismatch { flag: SOURCE_OBJECT, owner, .. }
                        if owner == label
                ),
                "expected an ObjectOwnerMismatch for {label}, got {error:?}"
            );
        }
    }

    #[test]
    fn execute_rejects_a_non_current_inline_source_object() {
        let signer = sample_signer();
        let inputs = sample_inputs();
        let context = sample_context();
        let nonce = HttpNextNonceQueryResult::new(signer.address(), Epoch::new(5), 3);
        let absent_source = HttpObjectQueryResult::Absent {
            object_id: inputs.source_id,
        };

        let transport = FakeTransport::new(vec![
            query_ok(context.encode().unwrap()),
            query_ok(nonce.encode().unwrap()),
            query_ok(absent_source.encode().unwrap()),
        ]);
        let client = Client::new(transport);

        let error = execute(&client, &signer, inputs).unwrap_err();
        assert!(matches!(
            error,
            CliError::ObjectNotCurrentlyInline {
                flag: SOURCE_OBJECT,
                status: "absent",
                ..
            }
        ));
    }

    #[test]
    fn parse_inputs_rejects_matching_source_and_destination() {
        let mut args = base_flag_values();
        args.insert(DESTINATION_OBJECT, "10".repeat(32));
        let parsed = parse_flags(to_os(&args), &transfer_specs()).unwrap();

        assert!(matches!(
            parse_inputs(&parsed),
            Err(CliError::SameSourceAndDestination)
        ));
    }

    #[test]
    fn parse_inputs_rejects_zero_amount() {
        let mut args = base_flag_values();
        args.insert(AMOUNT, "0".to_string());
        let parsed = parse_flags(to_os(&args), &transfer_specs()).unwrap();

        assert!(matches!(parse_inputs(&parsed), Err(CliError::ZeroAmount)));
    }

    #[test]
    fn parse_inputs_rejects_zero_gas_limit() {
        let mut args = base_flag_values();
        args.insert(GAS_LIMIT, "0".to_string());
        let parsed = parse_flags(to_os(&args), &transfer_specs()).unwrap();

        assert!(matches!(parse_inputs(&parsed), Err(CliError::ZeroGasLimit)));
    }

    #[test]
    fn parse_inputs_rejects_zero_request_id() {
        let mut args = base_flag_values();
        args.insert(REQUEST_ID, "00".repeat(32));
        let parsed = parse_flags(to_os(&args), &transfer_specs()).unwrap();

        assert!(matches!(parse_inputs(&parsed), Err(CliError::NodeCore(_))));
    }

    #[test]
    fn wait_bound_flag_without_wait_is_rejected() {
        let mut args = base_flag_values();
        args.insert(WAIT_MAX_ATTEMPTS, "3".to_string());
        let parsed = parse_flags(to_os(&args), &transfer_specs()).unwrap();

        assert!(matches!(
            parse_wait_bounds(&parsed),
            Err(CliError::WaitBoundWithoutWait(WAIT_MAX_ATTEMPTS))
        ));
    }

    #[test]
    fn wait_without_all_bound_flags_is_rejected() {
        let args = to_os_vec(vec![OsString::from(WAIT)]);
        let parsed = parse_flags(args, &[switch(WAIT), scalar(WAIT_MAX_ATTEMPTS)]).unwrap();

        assert!(matches!(
            parse_wait_bounds(&parsed),
            Err(CliError::WaitBoundRequired(WAIT_MAX_ATTEMPTS))
        ));
    }

    #[test]
    fn wait_with_all_bound_flags_parses() {
        let args = to_os_vec(vec![
            OsString::from(WAIT),
            OsString::from(WAIT_MAX_ATTEMPTS),
            OsString::from("5"),
            OsString::from(WAIT_INITIAL_BACKOFF_MS),
            OsString::from("10"),
            OsString::from(WAIT_MAX_BACKOFF_MS),
            OsString::from("100"),
            OsString::from(WAIT_MAX_ELAPSED_MS),
            OsString::from("1000"),
        ]);
        let parsed = parse_flags(
            args,
            &[
                switch(WAIT),
                scalar(WAIT_MAX_ATTEMPTS),
                scalar(WAIT_INITIAL_BACKOFF_MS),
                scalar(WAIT_MAX_BACKOFF_MS),
                scalar(WAIT_MAX_ELAPSED_MS),
            ],
        )
        .unwrap();

        let bounds = parse_wait_bounds(&parsed).unwrap().unwrap();
        assert_eq!(bounds.max_attempts.get(), 5);
        assert_eq!(bounds.initial_backoff, Duration::from_millis(10));
        assert_eq!(bounds.max_backoff, Duration::from_millis(100));
        assert_eq!(bounds.max_elapsed, Duration::from_millis(1_000));
    }

    fn base_flag_values() -> std::collections::BTreeMap<&'static str, String> {
        let mut values = std::collections::BTreeMap::new();
        values.insert(MODULE_ID, "01".repeat(32));
        values.insert(MODULE_VERSION, "1".to_string());
        values.insert(MODULE_DIGEST_ALGORITHM, "1".to_string());
        values.insert(MODULE_DIGEST, "02".repeat(32));
        values.insert(SOURCE_OBJECT, "10".repeat(32));
        values.insert(DESTINATION_OBJECT, "20".repeat(32));
        values.insert(AMOUNT, "250".to_string());
        values.insert(GAS_LIMIT, "1000".to_string());
        values.insert(REQUEST_ID, "30".repeat(32));
        values
    }

    fn transfer_specs() -> Vec<crate::args::FlagSpec> {
        vec![
            scalar(MODULE_ID),
            scalar(MODULE_VERSION),
            scalar(MODULE_DIGEST_ALGORITHM),
            scalar(MODULE_DIGEST),
            scalar(SOURCE_OBJECT),
            scalar(DESTINATION_OBJECT),
            scalar(AMOUNT),
            scalar(GAS_LIMIT),
            scalar(REQUEST_ID),
            switch(WAIT),
            scalar(WAIT_MAX_ATTEMPTS),
            scalar(WAIT_INITIAL_BACKOFF_MS),
            scalar(WAIT_MAX_BACKOFF_MS),
            scalar(WAIT_MAX_ELAPSED_MS),
        ]
    }

    fn to_os(values: &std::collections::BTreeMap<&'static str, String>) -> Vec<OsString> {
        let mut out = Vec::new();
        for (flag, value) in values {
            out.push(OsString::from(*flag));
            out.push(OsString::from(value.clone()));
        }
        out
    }

    fn to_os_vec(values: Vec<OsString>) -> Vec<OsString> {
        values
    }
}
