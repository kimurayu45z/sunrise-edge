//! Shared behavioral conformance for production durable-store implementations.
//!
//! This module is test support. It is available to `runtime` unit tests and to
//! adapter test targets that explicitly enable the `durable-conformance`
//! feature. Passing these cases is contract evidence, not production
//! certification. The shared baseline (`run_durable_store_conformance`,
//! `run_schema_skew_conformance`) exercises complete-read contention,
//! lease/writer fencing, and schema-identity skew against whatever store a
//! fixture wraps; it injects no fault and is not fault or capacity evidence.
//! The optional [`CommitLossFixture`] capability and
//! [`run_commit_loss_conformance`] case are the exception: only a fixture
//! backed by a real, severable network transport may implement them, and
//! doing so is commit-boundary connection-loss fault evidence for that
//! transport (see their doc comments for exact scope and limits).
//! Concurrent cases use only bounded threads that are joined before returning;
//! no background work or process lifetime is part of the store contract.

use super::*;
#[cfg(any(test, feature = "durable-conformance"))]
use hashing::{BuiltinHashFunction, HashFunction};
use std::fmt::Debug;
use std::sync::{Arc, Barrier};

const LIVE_CONTEXT_BUDGET: std::time::Duration = std::time::Duration::from_secs(60);
const OUTBOX_NOW: u64 = 10_000;
const OUTBOX_LEASE_MILLIS: u64 = 1_000;

/// One failed shared conformance expectation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConformanceFailure {
    case: &'static str,
    detail: String,
}

impl ConformanceFailure {
    /// Creates one typed fixture or expectation failure.
    pub fn new(case: &'static str, detail: impl Into<String>) -> Self {
        Self {
            case,
            detail: detail.into(),
        }
    }

    /// Returns the stable conformance case name.
    #[must_use]
    pub const fn case(&self) -> &'static str {
        self.case
    }

    /// Returns the failed expectation detail.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for ConformanceFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.case, self.detail)
    }
}

impl Error for ConformanceFailure {}

/// Result returned by shared durable-store conformance cases.
pub type ConformanceResult<T = ()> = Result<T, ConformanceFailure>;

/// Adapter-owned authority and clock hooks needed by the shared suite.
///
/// The fixture must be fresh for one invocation of
/// [`run_durable_store_conformance`]. Operator actions such as advancing a
/// writer fence are intentionally outside the request-path store traits. A
/// fixture may expose a definite serialization rejection when its bounded
/// unchanged-envelope retry policy cannot revalidate a concurrent conflict.
pub trait DurableStoreFixture {
    /// Durable store implementation exercised by the suite.
    type Store: IndexedOutboxRepository + Send + Sync + 'static;

    /// Returns the same store instance for every call.
    fn store(&self) -> Arc<Self::Store>;

    /// Returns the one logical domain bound to this fixture.
    fn domain(&self) -> AtomicityDomainId;

    /// Returns the fixture's initial authoritative writer generation.
    fn initial_writer_fence(&self) -> WriterFenceGeneration;

    /// Creates an operation context using the fixture's trusted clock.
    ///
    /// A zero budget must set the deadline to the current trusted time so the
    /// shared suite can exercise the exact expired-boundary rule.
    fn live_context(
        &self,
        writer_fence: WriterFenceGeneration,
        correlation_byte: u8,
        budget: std::time::Duration,
    ) -> ConformanceResult<DurableOperationContext>;

    /// Advances the physical writer generation through an operator-only seam.
    fn advance_writer_fence(
        &self,
        expected: WriterFenceGeneration,
        next: WriterFenceGeneration,
    ) -> ConformanceResult<()>;

    /// Returns the exact chain identity every conformance object version
    /// created against this fixture must carry as its
    /// [`DurableObjectProvenance`] `chain_id`.
    ///
    /// A backend that namespaces storage by chain (PostgreSQL's
    /// `object_versions.chain_id_bytes`, checked equal to
    /// `created_chain_id_bytes`) rejects any object created under a
    /// different chain. Deriving every conformance object and blob record
    /// from this single authoritative source — rather than a chain literal
    /// copied into the shared helper — is what keeps memory and PostgreSQL
    /// conformance from drifting apart on this point.
    fn object_provenance_chain_id(&self) -> ConformanceResult<ChainId>;
}

/// Optional persisted-schema skew capability for durable adapter fixtures.
///
/// Ephemeral stores without a real schema identity must not implement this
/// trait or manufacture equivalent evidence.
pub trait SchemaSkewFixture: DurableStoreFixture {
    /// Moves the fixture namespace outside this binary's supported schema window.
    fn install_unsupported_schema(&self) -> ConformanceResult<()>;

    /// Restores the fixture namespace to the binary's exact supported schema.
    fn restore_supported_schema(&self) -> ConformanceResult<()>;
}

/// Point, relative to one dispatched COMMIT, at which a [`CommitLossFixture`]
/// severs its adapter's transport connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitFaultPoint {
    /// Sever the connection before the COMMIT reaches the backend at all.
    BeforeCommitDispatch,
    /// Let the backend return a successful acknowledgement for COMMIT, then
    /// sever the connection before the caller observes it. This proves the
    /// backend accepted the commit and returned it; it is not evidence that
    /// the commit would survive an abrupt process/power loss.
    AfterBackendCommitAccepted,
}

/// Optional commit-boundary connection-loss capability for durable adapter
/// fixtures backed by a real, severable network transport.
///
/// Ephemeral in-process stores have no connection to sever and must not
/// implement this trait or manufacture equivalent evidence. The only current
/// implementation (`runtime-postgres`'s live PostgreSQL test) severs a plain
/// `NoTls` connection; it proves nothing about TLS-path connection loss.
pub trait CommitLossFixture: DurableStoreFixture {
    /// Arms exactly one future COMMIT dispatched through the fixture's store
    /// to be severed at `fault_point`. The fixture must consume the arming
    /// exactly once, on the next COMMIT the store attempts, and must leave
    /// every later, unarmed COMMIT unaffected.
    fn arm_commit_loss(&self, fault_point: CommitFaultPoint) -> ConformanceResult<()>;

    /// Returns whether the most recently armed fault actually severed a
    /// connection at its configured point.
    fn commit_loss_fired(&self) -> ConformanceResult<bool>;

    /// Returns whether the backend sent a successful COMMIT completion before
    /// the fixture severed the connection. Only meaningful after arming
    /// [`CommitFaultPoint::AfterBackendCommitAccepted`].
    fn backend_commit_accepted(&self) -> ConformanceResult<bool>;
}

fn mismatch<T: Debug>(
    case: &'static str,
    expectation: &'static str,
    observed: &T,
) -> ConformanceFailure {
    ConformanceFailure::new(case, format!("{expectation}; observed {observed:?}"))
}

fn build_context<F: DurableStoreFixture>(
    fixture: &F,
    fence: WriterFenceGeneration,
    correlation_byte: u8,
) -> ConformanceResult<DurableOperationContext> {
    fixture.live_context(fence, correlation_byte, LIVE_CONTEXT_BUDGET)
}

fn request_id(case: &'static str, byte: u8) -> ConformanceResult<DurableRequestId> {
    DurableRequestId::new([byte; 32])
        .map_err(|error| ConformanceFailure::new(case, error.to_string()))
}

fn outbox_request_id(case: &'static str, byte: u8) -> ConformanceResult<OutboxRequestId> {
    OutboxRequestId::new([byte; 32])
        .map_err(|error| ConformanceFailure::new(case, error.to_string()))
}

fn lease_id(case: &'static str, byte: u8) -> ConformanceResult<DurableOutboxLeaseId> {
    DurableOutboxLeaseId::new([byte; 32])
        .map_err(|error| ConformanceFailure::new(case, error.to_string()))
}

fn invocation(
    case: &'static str,
    domain: AtomicityDomainId,
    request_byte: u8,
    reads: Vec<(Vec<u8>, StateRevision)>,
    mutations: Vec<(Vec<u8>, StateMutation)>,
    outbox_payloads: Vec<Vec<u8>>,
) -> ConformanceResult<DurableInvocationTransaction> {
    let read_assertions: Vec<StateReadAssertion> = reads
        .into_iter()
        .map(|(key, revision)| StateReadAssertion::new(key, revision))
        .collect::<Result<Vec<StateReadAssertion>, RuntimeError>>()
        .map_err(|error| ConformanceFailure::new(case, error.to_string()))?;
    let mutation_entries: Vec<StateMutationEntry> = mutations
        .into_iter()
        .map(|(key, mutation)| StateMutationEntry::new(key, mutation))
        .collect::<Result<Vec<StateMutationEntry>, RuntimeError>>()
        .map_err(|error| ConformanceFailure::new(case, error.to_string()))?;
    let state: Option<DurableStateTransaction> = if read_assertions.is_empty() {
        None
    } else {
        Some(
            DurableStateTransaction::new(
                domain,
                AtomicStateReadSet::new(read_assertions)
                    .map_err(|error| ConformanceFailure::new(case, error.to_string()))?,
                mutation_entries,
            )
            .map_err(|error| ConformanceFailure::new(case, error.to_string()))?,
        )
    };
    let durable_request_id: DurableRequestId = request_id(case, request_byte)?;
    let event_digest: Digest32 = Digest32::new(
        protocol_types::HashAlgorithmId::Sha2_256,
        [request_byte.wrapping_add(1); 32],
    );
    let receipt: DurableRequestReceipt =
        DurableRequestReceipt::new(durable_request_id, event_digest, vec![request_byte])
            .map_err(|error| ConformanceFailure::new(case, error.to_string()))?;
    let outbox: Option<DurableOutboxBatch> = if outbox_payloads.is_empty() {
        None
    } else {
        let messages: Vec<DurableOutboxMessage> = outbox_payloads
            .into_iter()
            .enumerate()
            .map(|(index, payload)| {
                let index_byte: u8 = u8::try_from(index)
                    .map_err(|_| ConformanceFailure::new(case, "outbox test index exceeds u8"))?;
                DurableOutboxMessage::new(
                    Digest32::new(
                        protocol_types::HashAlgorithmId::Sha3_256,
                        [request_byte.wrapping_add(index_byte).wrapping_add(2); 32],
                    ),
                    payload,
                )
                .map_err(|error| ConformanceFailure::new(case, error.to_string()))
            })
            .collect::<ConformanceResult<Vec<DurableOutboxMessage>>>()?;
        Some(
            DurableOutboxBatch::new(durable_request_id, event_digest, messages)
                .map_err(|error| ConformanceFailure::new(case, error.to_string()))?,
        )
    };
    DurableInvocationTransaction::new(
        domain,
        state,
        DurableObjectChanges::empty(),
        receipt,
        outbox,
    )
    .map_err(|error| ConformanceFailure::new(case, error.to_string()))
}

#[cfg(any(test, feature = "durable-conformance"))]
fn object_version(
    case: &'static str,
    chain_id: &ChainId,
    object_id: ObjectId,
    version: u64,
    byte: u8,
    checkpoint: u64,
) -> ConformanceResult<DurableObjectVersionRecord> {
    object_version_with_protocol_version(
        case,
        chain_id,
        object_id,
        version,
        byte,
        checkpoint,
        ProtocolVersion::new(1),
    )
}

#[cfg(any(test, feature = "durable-conformance"))]
fn object_version_with_protocol_version(
    case: &'static str,
    chain_id: &ChainId,
    object_id: ObjectId,
    version: u64,
    byte: u8,
    checkpoint: u64,
    protocol_version: ProtocolVersion,
) -> ConformanceResult<DurableObjectVersionRecord> {
    let object: Object = Object {
        id: object_id,
        version,
        owner: Owner::Address(objects::Address::new([byte; 32])),
        type_hash: Digest32::new(
            protocol_types::HashAlgorithmId::Sha2_256,
            [byte.wrapping_add(1); 32],
        ),
        schema_version: u32::from(byte),
        data: vec![byte.wrapping_add(2)],
    };
    let canonical_bytes: Vec<u8> =
        encode_object(&object).map_err(|error| ConformanceFailure::new(case, error.to_string()))?;
    let digest: Digest32 = BuiltinHashFunction::new(protocol_types::HashAlgorithmId::Sha2_256)
        .hash(
            protocol_types::HashPurpose::Object,
            protocol_version,
            chain_id,
            &canonical_bytes,
        )
        .map_err(|error| ConformanceFailure::new(case, error.to_string()))?;
    let provenance: DurableObjectProvenance =
        DurableObjectProvenance::new(chain_id.clone(), protocol_version);
    DurableObjectVersionRecord::from_inline_object(object, digest, provenance, checkpoint)
        .map_err(|error| ConformanceFailure::new(case, error.to_string()))
}

#[cfg(any(test, feature = "durable-conformance"))]
fn object_projections(
    case: &'static str,
    byte: u8,
) -> ConformanceResult<(DurableObjectOwnerProjection, DurableObjectRoutingProjection)> {
    let owner: DurableObjectOwnerProjection =
        DurableObjectOwnerProjection::from_owner(Owner::Address(objects::Address::new([byte; 32])))
            .map_err(|error| ConformanceFailure::new(case, error.to_string()))?;
    let routing: DurableObjectRoutingProjection =
        DurableObjectRoutingProjection::new(Some(vec![byte.wrapping_add(1)]))
            .map_err(|error| ConformanceFailure::new(case, error.to_string()))?;
    Ok((owner, routing))
}

#[cfg(any(test, feature = "durable-conformance"))]
fn object_invocation(
    case: &'static str,
    domain: AtomicityDomainId,
    request_byte: u8,
    state: Option<DurableStateTransaction>,
    objects: DurableObjectChanges,
    outbox_payload: Option<Vec<u8>>,
) -> ConformanceResult<DurableInvocationTransaction> {
    let durable_request_id: DurableRequestId = request_id(case, request_byte)?;
    let event_digest: Digest32 = Digest32::new(
        protocol_types::HashAlgorithmId::Sha2_256,
        [request_byte.wrapping_add(1); 32],
    );
    let receipt: DurableRequestReceipt =
        DurableRequestReceipt::new(durable_request_id, event_digest, vec![request_byte])
            .map_err(|error| ConformanceFailure::new(case, error.to_string()))?;
    let outbox: Option<DurableOutboxBatch> = outbox_payload
        .map(|payload: Vec<u8>| {
            let payload_digest: Digest32 = Digest32::new(
                protocol_types::HashAlgorithmId::Sha2_256,
                [request_byte.wrapping_add(2); 32],
            );
            let message: DurableOutboxMessage = DurableOutboxMessage::new(payload_digest, payload)
                .map_err(|error| ConformanceFailure::new(case, error.to_string()))?;
            DurableOutboxBatch::new(durable_request_id, event_digest, vec![message])
                .map_err(|error| ConformanceFailure::new(case, error.to_string()))
        })
        .transpose()?;
    DurableInvocationTransaction::new(domain, state, objects, receipt, outbox)
        .map_err(|error| ConformanceFailure::new(case, error.to_string()))
}

#[cfg(any(test, feature = "durable-conformance"))]
fn object_changes(
    case: &'static str,
    object_id: ObjectId,
    expected: DurableObjectHead,
    mutation: DurableObjectMutation,
) -> ConformanceResult<DurableObjectChanges> {
    DurableObjectChanges::new(
        vec![DurableObjectHeadRead::new(object_id, expected)],
        vec![DurableObjectMutationEntry::new(object_id, mutation)],
    )
    .map_err(|error| ConformanceFailure::new(case, error.to_string()))
}

fn expect_one_commit_one_definite_rejection(
    case: &'static str,
    outcomes: &[DurableCommitOutcome; 2],
) -> ConformanceResult<usize> {
    let committed: Vec<usize> = outcomes
        .iter()
        .enumerate()
        .filter_map(|(index, outcome)| {
            matches!(outcome, DurableCommitOutcome::Committed).then_some(index)
        })
        .collect();
    if committed.len() != 1 {
        return Err(mismatch(
            case,
            "exactly one concurrent invocation must commit",
            outcomes,
        ));
    }
    let rejected_index: usize = 1_usize.saturating_sub(committed[0]);
    if !matches!(
        outcomes[rejected_index],
        DurableCommitOutcome::Rejected(
            DurableCommitRejection::Conflict { .. } | DurableCommitRejection::SerializationFailure
        )
    ) {
        return Err(mismatch(
            case,
            "the losing invocation must report a definite conflict or serialization rejection",
            &outcomes[rejected_index],
        ));
    }
    Ok(committed[0])
}

fn commit_concurrently<S: StructuredDurableDomainStateStore + Send + Sync + 'static>(
    case: &'static str,
    store: Arc<S>,
    contexts: [DurableOperationContext; 2],
    invocations: [DurableInvocationTransaction; 2],
) -> ConformanceResult<[DurableCommitOutcome; 2]> {
    let barrier: Arc<Barrier> = Arc::new(Barrier::new(3));
    let mut handles: Vec<std::thread::JoinHandle<DurableCommitOutcome>> = Vec::with_capacity(2);
    for (context, invocation) in contexts.into_iter().zip(invocations) {
        let store: Arc<S> = Arc::clone(&store);
        let barrier: Arc<Barrier> = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            store.commit_invocation(&context, invocation)
        }));
    }
    barrier.wait();
    let first: DurableCommitOutcome = handles
        .remove(0)
        .join()
        .map_err(|_| ConformanceFailure::new(case, "first commit thread panicked"))?;
    let second: DurableCommitOutcome = handles
        .remove(0)
        .join()
        .map_err(|_| ConformanceFailure::new(case, "second commit thread panicked"))?;
    Ok([first, second])
}

fn deadline_conformance<F: DurableStoreFixture>(fixture: &F) -> ConformanceResult {
    const CASE: &str = "deadline-before-dispatch";
    let store: Arc<F::Store> = fixture.store();
    let domain: AtomicityDomainId = fixture.domain();
    let fence: WriterFenceGeneration = fixture.initial_writer_fence();
    let expired_context: DurableOperationContext =
        fixture.live_context(fence, 0x06, std::time::Duration::ZERO)?;
    let key: Vec<u8> = b"conformance/deadline".to_vec();

    let read: Result<VersionedStateValue, DurableReadError> =
        store.get_versioned_durable(&expired_context, domain, &key);
    if read != Err(DurableReadError::DeadlineExceeded) {
        return Err(mismatch(
            CASE,
            "a context at its exact deadline boundary must reject the state read",
            &read,
        ));
    }
    let receipt_read: Result<Option<DurableRequestReceipt>, DurableReadError> =
        store.get_request_receipt(&expired_context, domain, request_id(CASE, 0x71)?);
    if receipt_read != Err(DurableReadError::DeadlineExceeded) {
        return Err(mismatch(
            CASE,
            "an expired context must reject the receipt read",
            &receipt_read,
        ));
    }

    let atomic: AtomicStateTransaction = AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.clone(), StateRevision::INITIAL)
                .map_err(|error| ConformanceFailure::new(CASE, error.to_string()))?,
        ])
        .map_err(|error| ConformanceFailure::new(CASE, error.to_string()))?,
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(key.clone(), StateMutation::Put(vec![0x71]))
                .map_err(|error| ConformanceFailure::new(CASE, error.to_string()))?,
        ])
        .map_err(|error| ConformanceFailure::new(CASE, error.to_string()))?,
    )
    .map_err(|error| ConformanceFailure::new(CASE, error.to_string()))?;
    let atomic_outcome: DurableCommitOutcome = store.commit_durable(&expired_context, atomic);
    if atomic_outcome
        != DurableCommitOutcome::Rejected(DurableCommitRejection::DeadlineExceededBeforeCommit)
    {
        return Err(mismatch(
            CASE,
            "an expired atomic commit must be a definite pre-dispatch rejection",
            &atomic_outcome,
        ));
    }

    let request_byte: u8 = 0x72;
    let invocation_outcome: DurableCommitOutcome = store.commit_invocation(
        &expired_context,
        invocation(
            CASE,
            domain,
            request_byte,
            vec![(key.clone(), StateRevision::INITIAL)],
            vec![(key.clone(), StateMutation::Put(vec![request_byte]))],
            vec![vec![request_byte]],
        )?,
    );
    if invocation_outcome
        != DurableCommitOutcome::Rejected(DurableCommitRejection::DeadlineExceededBeforeCommit)
    {
        return Err(mismatch(
            CASE,
            "an expired structured commit must be a definite pre-dispatch rejection",
            &invocation_outcome,
        ));
    }

    let outbox_request: OutboxRequestId = outbox_request_id(CASE, request_byte)?;
    let exact_claim: DurableOutboxClaimOutcome = store.claim_request_outbox(
        &expired_context,
        RequestOutboxClaimRequest::new(
            domain,
            outbox_request,
            OUTBOX_NOW,
            lease_id(CASE, 0x73)?,
            OUTBOX_NOW + OUTBOX_LEASE_MILLIS,
        )
        .map_err(|error| ConformanceFailure::new(CASE, error.to_string()))?,
    );
    if exact_claim
        != DurableOutboxClaimOutcome::Rejected(
            DurableOutboxClaimRejection::DeadlineExceededBeforeCommit,
        )
    {
        return Err(mismatch(
            CASE,
            "an expired exact claim must be a definite pre-dispatch rejection",
            &exact_claim,
        ));
    }
    let due_claim: DurableOutboxClaimOutcome = store.claim_due_outbox(
        &expired_context,
        DueOutboxClaimRequest::new(
            domain,
            OUTBOX_NOW,
            lease_id(CASE, 0x74)?,
            OUTBOX_NOW + OUTBOX_LEASE_MILLIS,
        )
        .map_err(|error| ConformanceFailure::new(CASE, error.to_string()))?,
    );
    if due_claim
        != DurableOutboxClaimOutcome::Rejected(
            DurableOutboxClaimRejection::DeadlineExceededBeforeCommit,
        )
    {
        return Err(mismatch(
            CASE,
            "an expired due claim must be a definite pre-dispatch rejection",
            &due_claim,
        ));
    }
    let acknowledgement: DurableOutboxAcknowledgementOutcome = store.acknowledge_outbox(
        &expired_context,
        DurableOutboxAcknowledgement::new(domain, outbox_request, 0, lease_id(CASE, 0x75)?),
    );
    if acknowledgement
        != DurableOutboxAcknowledgementOutcome::Rejected(
            DurableOutboxAcknowledgementRejection::DeadlineExceededBeforeCommit,
        )
    {
        return Err(mismatch(
            CASE,
            "an expired acknowledgement must be a definite pre-dispatch rejection",
            &acknowledgement,
        ));
    }

    let live_context: DurableOperationContext = build_context(fixture, fence, 0x07)?;
    let unchanged: VersionedStateValue =
        store
            .get_versioned_durable(&live_context, domain, &key)
            .map_err(|error| mismatch(CASE, "post-deadline state read must succeed", &error))?;
    if unchanged.revision() != StateRevision::INITIAL || unchanged.value().is_some() {
        return Err(mismatch(
            CASE,
            "deadline rejection must publish no state mutation",
            &unchanged,
        ));
    }
    let receipt: Option<DurableRequestReceipt> = store
        .get_request_receipt(&live_context, domain, request_id(CASE, request_byte)?)
        .map_err(|error| mismatch(CASE, "post-deadline receipt read must succeed", &error))?;
    if receipt.is_some() {
        return Err(mismatch(
            CASE,
            "deadline rejection must publish no receipt",
            &receipt,
        ));
    }
    let live_claim: DurableOutboxClaimOutcome = store.claim_request_outbox(
        &live_context,
        RequestOutboxClaimRequest::new(
            domain,
            outbox_request,
            OUTBOX_NOW,
            lease_id(CASE, 0x76)?,
            OUTBOX_NOW + OUTBOX_LEASE_MILLIS,
        )
        .map_err(|error| ConformanceFailure::new(CASE, error.to_string()))?,
    );
    if live_claim != DurableOutboxClaimOutcome::NoDueWork {
        return Err(mismatch(
            CASE,
            "deadline rejection must publish no outbox work",
            &live_claim,
        ));
    }
    Ok(())
}

fn complete_read_and_serialization_conformance<F: DurableStoreFixture>(
    fixture: &F,
    context: DurableOperationContext,
) -> ConformanceResult {
    const ABSENT_CASE: &str = "absent-key-race";
    let store: Arc<F::Store> = fixture.store();
    let domain: AtomicityDomainId = fixture.domain();
    let absent_key: Vec<u8> = b"conformance/absent-race".to_vec();
    let absent_invocations: [DurableInvocationTransaction; 2] = [
        invocation(
            ABSENT_CASE,
            domain,
            0x11,
            vec![(absent_key.clone(), StateRevision::INITIAL)],
            vec![(absent_key.clone(), StateMutation::Put(vec![1]))],
            Vec::new(),
        )?,
        invocation(
            ABSENT_CASE,
            domain,
            0x12,
            vec![(absent_key.clone(), StateRevision::INITIAL)],
            vec![(absent_key.clone(), StateMutation::Put(vec![2]))],
            Vec::new(),
        )?,
    ];
    let absent_outcomes: [DurableCommitOutcome; 2] = commit_concurrently(
        ABSENT_CASE,
        Arc::clone(&store),
        [
            context,
            build_context(fixture, context.writer_fence(), 0x04)?,
        ],
        absent_invocations,
    )?;
    let absent_winner: usize =
        expect_one_commit_one_definite_rejection(ABSENT_CASE, &absent_outcomes)?;
    let absent_loser: usize = 1_usize.saturating_sub(absent_winner);
    if let DurableCommitOutcome::Rejected(DurableCommitRejection::Conflict {
        key,
        current_revision,
    }) = &absent_outcomes[absent_loser]
        && (key != &absent_key || *current_revision != StateRevision::new(1))
    {
        return Err(mismatch(
            ABSENT_CASE,
            "a conflict rejection must name the exact winning key and revision",
            &absent_outcomes[absent_loser],
        ));
    }
    let absent_value: VersionedStateValue = store
        .get_versioned_durable(&context, domain, &absent_key)
        .map_err(|error| mismatch(ABSENT_CASE, "final absent-race read must succeed", &error))?;
    let winning_value: u8 = if absent_winner == 0 { 1 } else { 2 };
    if absent_value.revision() != StateRevision::new(1)
        || absent_value.value() != Some([winning_value].as_slice())
    {
        return Err(mismatch(
            ABSENT_CASE,
            "the winning create must be the only state mutation",
            &absent_value,
        ));
    }
    for (index, byte) in [0x11_u8, 0x12_u8].into_iter().enumerate() {
        let receipt: Option<DurableRequestReceipt> = store
            .get_request_receipt(&context, domain, request_id(ABSENT_CASE, byte)?)
            .map_err(|error| mismatch(ABSENT_CASE, "receipt read must succeed", &error))?;
        if (index == absent_winner) != receipt.is_some() {
            return Err(mismatch(
                ABSENT_CASE,
                "only the committed invocation may publish a receipt",
                &receipt,
            ));
        }
    }
    let delete: DurableCommitOutcome = store.commit_invocation(
        &context,
        invocation(
            ABSENT_CASE,
            domain,
            0x13,
            vec![(absent_key.clone(), StateRevision::new(1))],
            vec![(absent_key.clone(), StateMutation::Delete)],
            Vec::new(),
        )?,
    );
    if delete != DurableCommitOutcome::Committed {
        return Err(mismatch(
            ABSENT_CASE,
            "deleting the winning value must commit",
            &delete,
        ));
    }
    let tombstone: VersionedStateValue = store
        .get_versioned_durable(&context, domain, &absent_key)
        .map_err(|error| mismatch(ABSENT_CASE, "tombstone read must succeed", &error))?;
    if tombstone.revision() != StateRevision::new(2) || tombstone.value().is_some() {
        return Err(mismatch(
            ABSENT_CASE,
            "delete must retain a non-initial tombstone revision",
            &tombstone,
        ));
    }
    let stale_recreate: DurableCommitOutcome = store.commit_invocation(
        &context,
        invocation(
            ABSENT_CASE,
            domain,
            0x14,
            vec![(absent_key.clone(), StateRevision::INITIAL)],
            vec![(absent_key.clone(), StateMutation::Put(vec![3]))],
            Vec::new(),
        )?,
    );
    if !matches!(
        stale_recreate,
        DurableCommitOutcome::Rejected(DurableCommitRejection::Conflict {
            current_revision,
            ..
        }) if current_revision == StateRevision::new(2)
    ) {
        return Err(mismatch(
            ABSENT_CASE,
            "an absent assertion must not match a retained tombstone",
            &stale_recreate,
        ));
    }
    let valid_recreate: DurableCommitOutcome = store.commit_invocation(
        &context,
        invocation(
            ABSENT_CASE,
            domain,
            0x15,
            vec![(absent_key.clone(), StateRevision::new(2))],
            vec![(absent_key.clone(), StateMutation::Put(vec![3]))],
            Vec::new(),
        )?,
    );
    if valid_recreate != DurableCommitOutcome::Committed {
        return Err(mismatch(
            ABSENT_CASE,
            "a matching tombstone revision must allow recreation",
            &valid_recreate,
        ));
    }
    let recreated: VersionedStateValue = store
        .get_versioned_durable(&context, domain, &absent_key)
        .map_err(|error| mismatch(ABSENT_CASE, "recreated read must succeed", &error))?;
    if recreated.revision() != StateRevision::new(3) || recreated.value() != Some([3].as_slice()) {
        return Err(mismatch(
            ABSENT_CASE,
            "delete and recreate must not reset the revision",
            &recreated,
        ));
    }

    const WRITE_SKEW_CASE: &str = "complete-read-write-skew";
    let left_key: Vec<u8> = b"conformance/write-skew-left".to_vec();
    let right_key: Vec<u8> = b"conformance/write-skew-right".to_vec();
    let shared_reads: Vec<(Vec<u8>, StateRevision)> = vec![
        (left_key.clone(), StateRevision::INITIAL),
        (right_key.clone(), StateRevision::INITIAL),
    ];
    let skew_invocations: [DurableInvocationTransaction; 2] = [
        invocation(
            WRITE_SKEW_CASE,
            domain,
            0x21,
            shared_reads.clone(),
            vec![(left_key.clone(), StateMutation::Put(vec![1]))],
            Vec::new(),
        )?,
        invocation(
            WRITE_SKEW_CASE,
            domain,
            0x22,
            shared_reads,
            vec![(right_key.clone(), StateMutation::Put(vec![1]))],
            Vec::new(),
        )?,
    ];
    let skew_outcomes: [DurableCommitOutcome; 2] = commit_concurrently(
        WRITE_SKEW_CASE,
        Arc::clone(&store),
        [
            context,
            build_context(fixture, context.writer_fence(), 0x05)?,
        ],
        skew_invocations,
    )?;
    let skew_winner: usize =
        expect_one_commit_one_definite_rejection(WRITE_SKEW_CASE, &skew_outcomes)?;
    let skew_loser: usize = 1_usize.saturating_sub(skew_winner);
    let expected_conflict_key: &Vec<u8> = if skew_winner == 0 {
        &left_key
    } else {
        &right_key
    };
    if let DurableCommitOutcome::Rejected(DurableCommitRejection::Conflict {
        key,
        current_revision,
    }) = &skew_outcomes[skew_loser]
        && (key != expected_conflict_key || *current_revision != StateRevision::new(1))
    {
        return Err(mismatch(
            WRITE_SKEW_CASE,
            "a conflict rejection must name the exact changed dependency revision",
            &skew_outcomes[skew_loser],
        ));
    }
    let left: VersionedStateValue = store
        .get_versioned_durable(&context, domain, &left_key)
        .map_err(|error| mismatch(WRITE_SKEW_CASE, "left read must succeed", &error))?;
    let right: VersionedStateValue = store
        .get_versioned_durable(&context, domain, &right_key)
        .map_err(|error| mismatch(WRITE_SKEW_CASE, "right read must succeed", &error))?;
    let expected_values: [Option<&[u8]>; 2] = if skew_winner == 0 {
        [Some(&[1]), None]
    } else {
        [None, Some(&[1])]
    };
    if left.value() != expected_values[0] || right.value() != expected_values[1] {
        return Err(ConformanceFailure::new(
            WRITE_SKEW_CASE,
            format!(
                "only the winner's disjoint mutation may publish; left={left:?}, right={right:?}"
            ),
        ));
    }
    Ok(())
}

fn outbox_lease_conformance<F: DurableStoreFixture>(
    fixture: &F,
    context: DurableOperationContext,
) -> ConformanceResult {
    const CASE: &str = "outbox-lease-fencing";
    let store: Arc<F::Store> = fixture.store();
    let domain: AtomicityDomainId = fixture.domain();
    let request_byte: u8 = 0x31;
    let durable_request: DurableRequestId = request_id(CASE, request_byte)?;
    let outbox_request: OutboxRequestId = outbox_request_id(CASE, request_byte)?;
    let committed: DurableCommitOutcome = store.commit_invocation(
        &context,
        invocation(
            CASE,
            domain,
            request_byte,
            Vec::new(),
            Vec::new(),
            vec![vec![0xA1], vec![0xA2]],
        )?,
    );
    if committed != DurableCommitOutcome::Committed {
        return Err(mismatch(
            CASE,
            "outbox fixture invocation must commit",
            &committed,
        ));
    }
    let first_lease: DurableOutboxLeaseId = lease_id(CASE, 0x41)?;
    let first_request: RequestOutboxClaimRequest = RequestOutboxClaimRequest::new(
        domain,
        outbox_request,
        OUTBOX_NOW,
        first_lease,
        OUTBOX_NOW + OUTBOX_LEASE_MILLIS,
    )
    .map_err(|error| ConformanceFailure::new(CASE, error.to_string()))?;
    let first: DurableOutboxClaimOutcome = store.claim_request_outbox(&context, first_request);
    let replay: DurableOutboxClaimOutcome = store.claim_request_outbox(&context, first_request);
    if first != replay {
        return Err(ConformanceFailure::new(
            CASE,
            format!("same lease must reconcile identical work; first={first:?}, replay={replay:?}"),
        ));
    }
    let DurableOutboxClaimOutcome::Claimed(first_claim) = first else {
        return Err(mismatch(CASE, "first message must be claimed", &first));
    };
    if first_claim.message_index() != 0 || first_claim.canonical_payload() != [0xA1] {
        return Err(mismatch(
            CASE,
            "first lease must own the first message",
            &first_claim,
        ));
    }
    let replacement_lease: DurableOutboxLeaseId = lease_id(CASE, 0x42)?;
    let replacement: DurableOutboxClaimOutcome = store.claim_request_outbox(
        &context,
        RequestOutboxClaimRequest::new(
            domain,
            outbox_request,
            OUTBOX_NOW + OUTBOX_LEASE_MILLIS,
            replacement_lease,
            OUTBOX_NOW + (2 * OUTBOX_LEASE_MILLIS),
        )
        .map_err(|error| ConformanceFailure::new(CASE, error.to_string()))?,
    );
    let DurableOutboxClaimOutcome::Claimed(replacement_claim) = replacement else {
        return Err(mismatch(
            CASE,
            "expired lease must be replaceable",
            &replacement,
        ));
    };
    if replacement_claim.message_index() != 0 || replacement_claim.canonical_payload() != [0xA1] {
        return Err(mismatch(
            CASE,
            "replacement lease must own the same first message",
            &replacement_claim,
        ));
    }
    let stale_ack: DurableOutboxAcknowledgementOutcome = store.acknowledge_outbox(
        &context,
        DurableOutboxAcknowledgement::new(domain, outbox_request, 0, first_lease),
    );
    if stale_ack
        != DurableOutboxAcknowledgementOutcome::Rejected(
            DurableOutboxAcknowledgementRejection::LeaseMismatch,
        )
    {
        return Err(mismatch(
            CASE,
            "expired lease must not acknowledge",
            &stale_ack,
        ));
    }
    let first_ack: DurableOutboxAcknowledgement =
        DurableOutboxAcknowledgement::new(domain, outbox_request, 0, replacement_lease);
    let acknowledged: DurableOutboxAcknowledgementOutcome =
        store.acknowledge_outbox(&context, first_ack);
    if acknowledged != DurableOutboxAcknowledgementOutcome::Acknowledged {
        return Err(mismatch(
            CASE,
            "replacement lease must acknowledge",
            &acknowledged,
        ));
    }
    let second_lease: DurableOutboxLeaseId = lease_id(CASE, 0x43)?;
    let second: DurableOutboxClaimOutcome = store.claim_request_outbox(
        &context,
        RequestOutboxClaimRequest::new(
            domain,
            outbox_request,
            OUTBOX_NOW + OUTBOX_LEASE_MILLIS,
            second_lease,
            OUTBOX_NOW + (2 * OUTBOX_LEASE_MILLIS),
        )
        .map_err(|error| ConformanceFailure::new(CASE, error.to_string()))?,
    );
    let DurableOutboxClaimOutcome::Claimed(second_claim) = second else {
        return Err(mismatch(CASE, "second message must be claimable", &second));
    };
    if second_claim.message_index() != 1 || second_claim.canonical_payload() != [0xA2] {
        return Err(mismatch(
            CASE,
            "second claim must advance exactly once",
            &second_claim,
        ));
    }
    let second_acknowledged: DurableOutboxAcknowledgementOutcome = store.acknowledge_outbox(
        &context,
        DurableOutboxAcknowledgement::new(domain, outbox_request, 1, second_lease),
    );
    if second_acknowledged != DurableOutboxAcknowledgementOutcome::Acknowledged {
        return Err(mismatch(
            CASE,
            "second message must acknowledge",
            &second_acknowledged,
        ));
    }
    let delayed_replay: DurableOutboxAcknowledgementOutcome =
        store.acknowledge_outbox(&context, first_ack);
    if delayed_replay != DurableOutboxAcknowledgementOutcome::Acknowledged {
        return Err(mismatch(
            CASE,
            "retained first acknowledgement must remain idempotent after later progress",
            &delayed_replay,
        ));
    }
    let receipt: Option<DurableRequestReceipt> = store
        .get_request_receipt(&context, domain, durable_request)
        .map_err(|error| mismatch(CASE, "committed receipt must remain readable", &error))?;
    if receipt.is_none() {
        return Err(ConformanceFailure::new(
            CASE,
            "outbox progress must not remove the request receipt",
        ));
    }
    Ok(())
}

fn writer_fence_conformance<F: DurableStoreFixture>(
    fixture: &F,
    stale_context: DurableOperationContext,
) -> ConformanceResult {
    const CASE: &str = "writer-fence-authority";
    let store: Arc<F::Store> = fixture.store();
    let domain: AtomicityDomainId = fixture.domain();
    let stale_fence: WriterFenceGeneration = fixture.initial_writer_fence();
    let next_fence: WriterFenceGeneration = stale_fence.checked_next().ok_or_else(|| {
        ConformanceFailure::new(CASE, "initial writer fence cannot advance without overflow")
    })?;
    let request_byte: u8 = 0x51;
    let outbox_request: OutboxRequestId = outbox_request_id(CASE, request_byte)?;
    let prepared: DurableCommitOutcome = store.commit_invocation(
        &stale_context,
        invocation(
            CASE,
            domain,
            request_byte,
            Vec::new(),
            Vec::new(),
            vec![vec![0xB1]],
        )?,
    );
    if prepared != DurableCommitOutcome::Committed {
        return Err(mismatch(
            CASE,
            "fence fixture invocation must commit",
            &prepared,
        ));
    }
    let old_lease: DurableOutboxLeaseId = lease_id(CASE, 0x52)?;
    let old_claim: DurableOutboxClaimOutcome = store.claim_request_outbox(
        &stale_context,
        RequestOutboxClaimRequest::new(
            domain,
            outbox_request,
            OUTBOX_NOW,
            old_lease,
            OUTBOX_NOW + OUTBOX_LEASE_MILLIS,
        )
        .map_err(|error| ConformanceFailure::new(CASE, error.to_string()))?,
    );
    if !matches!(old_claim, DurableOutboxClaimOutcome::Claimed(_)) {
        return Err(mismatch(
            CASE,
            "old writer must establish a lease",
            &old_claim,
        ));
    }
    fixture.advance_writer_fence(stale_fence, next_fence)?;
    let fenced_read = store.get_versioned_durable(&stale_context, domain, b"conformance/fenced");
    if fenced_read
        != Err(DurableReadError::WriterFenced {
            active_generation: next_fence,
        })
    {
        return Err(mismatch(
            CASE,
            "stale writer read must be fenced",
            &fenced_read,
        ));
    }
    let stale_commit: DurableCommitOutcome = store.commit_invocation(
        &stale_context,
        invocation(
            CASE,
            domain,
            0x53,
            vec![(b"conformance/fenced".to_vec(), StateRevision::INITIAL)],
            vec![(b"conformance/fenced".to_vec(), StateMutation::Put(vec![1]))],
            Vec::new(),
        )?,
    );
    if stale_commit
        != DurableCommitOutcome::Rejected(DurableCommitRejection::WriterFenced {
            active_generation: next_fence,
        })
    {
        return Err(mismatch(CASE, "stale commit must be fenced", &stale_commit));
    }
    let stale_claim: DurableOutboxClaimOutcome = store.claim_request_outbox(
        &stale_context,
        RequestOutboxClaimRequest::new(
            domain,
            outbox_request,
            OUTBOX_NOW,
            lease_id(CASE, 0x54)?,
            OUTBOX_NOW + OUTBOX_LEASE_MILLIS,
        )
        .map_err(|error| ConformanceFailure::new(CASE, error.to_string()))?,
    );
    if stale_claim
        != DurableOutboxClaimOutcome::Rejected(DurableOutboxClaimRejection::WriterFenced {
            active_generation: next_fence,
        })
    {
        return Err(mismatch(CASE, "stale claim must be fenced", &stale_claim));
    }
    let stale_ack: DurableOutboxAcknowledgementOutcome = store.acknowledge_outbox(
        &stale_context,
        DurableOutboxAcknowledgement::new(domain, outbox_request, 0, old_lease),
    );
    if stale_ack
        != DurableOutboxAcknowledgementOutcome::Rejected(
            DurableOutboxAcknowledgementRejection::WriterFenced {
                active_generation: next_fence,
            },
        )
    {
        return Err(mismatch(
            CASE,
            "stale acknowledgement must be fenced",
            &stale_ack,
        ));
    }
    let current_context: DurableOperationContext = build_context(fixture, next_fence, 0x55)?;
    let blocked_claim: DurableOutboxClaimOutcome = store.claim_request_outbox(
        &current_context,
        RequestOutboxClaimRequest::new(
            domain,
            outbox_request,
            OUTBOX_NOW,
            lease_id(CASE, 0x56)?,
            OUTBOX_NOW + OUTBOX_LEASE_MILLIS,
        )
        .map_err(|error| ConformanceFailure::new(CASE, error.to_string()))?,
    );
    if blocked_claim != DurableOutboxClaimOutcome::NoDueWork {
        return Err(mismatch(
            CASE,
            "fence advance must not silently invalidate an unexpired lease",
            &blocked_claim,
        ));
    }
    let replacement_lease: DurableOutboxLeaseId = lease_id(CASE, 0x57)?;
    let replacement: DurableOutboxClaimOutcome = store.claim_request_outbox(
        &current_context,
        RequestOutboxClaimRequest::new(
            domain,
            outbox_request,
            OUTBOX_NOW + OUTBOX_LEASE_MILLIS,
            replacement_lease,
            OUTBOX_NOW + (2 * OUTBOX_LEASE_MILLIS),
        )
        .map_err(|error| ConformanceFailure::new(CASE, error.to_string()))?,
    );
    if !matches!(replacement, DurableOutboxClaimOutcome::Claimed(_)) {
        return Err(mismatch(
            CASE,
            "new writer must reclaim only after the old lease expires",
            &replacement,
        ));
    }
    let old_ack: DurableOutboxAcknowledgementOutcome = store.acknowledge_outbox(
        &current_context,
        DurableOutboxAcknowledgement::new(domain, outbox_request, 0, old_lease),
    );
    if old_ack
        != DurableOutboxAcknowledgementOutcome::Rejected(
            DurableOutboxAcknowledgementRejection::LeaseMismatch,
        )
    {
        return Err(mismatch(
            CASE,
            "replaced old lease must not acknowledge",
            &old_ack,
        ));
    }
    let current_ack: DurableOutboxAcknowledgementOutcome = store.acknowledge_outbox(
        &current_context,
        DurableOutboxAcknowledgement::new(domain, outbox_request, 0, replacement_lease),
    );
    if current_ack != DurableOutboxAcknowledgementOutcome::Acknowledged {
        return Err(mismatch(
            CASE,
            "new writer lease must acknowledge",
            &current_ack,
        ));
    }
    Ok(())
}

/// Runs the typed object lifecycle against one fresh object-capable fixture.
///
/// In addition to lifecycle/replay/rollback, this exercises bound-domain,
/// non-active-fence, exact-deadline, and blob-reference store behavior. The
/// object read-count limit is a constructor invariant, so its deterministic
/// rejection is shared here but necessarily occurs before either backend is
/// dispatched.
///
/// This remains separate from [`run_durable_store_conformance`] until durable
/// providers implement normalized immutable versions and object heads.
#[cfg(any(test, feature = "durable-conformance"))]
pub fn run_durable_object_conformance<F: DurableStoreFixture>(fixture: &F) -> ConformanceResult {
    const CASE: &str = "durable-object-lifecycle";
    let store: Arc<F::Store> = fixture.store();
    let domain: AtomicityDomainId = fixture.domain();
    let fence: WriterFenceGeneration = fixture.initial_writer_fence();
    let context: DurableOperationContext = build_context(fixture, fence, 0x51)?;
    let chain_id: ChainId = fixture.object_provenance_chain_id()?;

    // Count bounds are constructor invariants rather than backend behavior,
    // but keeping this case in the shared suite proves both fixtures consume
    // the identical bounded object envelope before storage dispatch.
    let too_many_reads: Vec<DurableObjectHeadRead> = (0..=MAX_DURABLE_OBJECT_READS)
        .map(|index: usize| {
            let mut bytes: [u8; 32] = [0; 32];
            bytes[..size_of::<usize>()].copy_from_slice(&index.to_be_bytes());
            DurableObjectHeadRead::new(ObjectId::new(bytes), DurableObjectHead::Absent)
        })
        .collect();
    if DurableObjectChanges::new(too_many_reads, Vec::new())
        != Err(DurableInvocationError::TooManyObjectReads {
            count: MAX_DURABLE_OBJECT_READS + 1,
            maximum: MAX_DURABLE_OBJECT_READS,
        })
    {
        return Err(ConformanceFailure::new(
            CASE,
            "object read count bound was not deterministic",
        ));
    }

    let mut wrong_domain_bytes: [u8; 32] = *domain.as_bytes();
    wrong_domain_bytes[0] ^= 0xFF;
    let wrong_domain: AtomicityDomainId = AtomicityDomainId::new(wrong_domain_bytes)
        .map_err(|error| ConformanceFailure::new(CASE, error.to_string()))?;
    let authority_object_id: ObjectId = ObjectId::new([0x41; 32]);
    let wrong_domain_read = store.get_object_head(&context, wrong_domain, authority_object_id);
    if wrong_domain_read
        != Err(DurableReadError::InvalidRequest(
            RuntimeError::AtomicityDomainMismatch,
        ))
    {
        return Err(mismatch(
            CASE,
            "object read accepted a domain other than the bound domain",
            &wrong_domain_read,
        ));
    }
    let (authority_owner, authority_routing) = object_projections(CASE, 0x41)?;
    let wrong_domain_invocation: DurableInvocationTransaction = object_invocation(
        CASE,
        wrong_domain,
        0x41,
        None,
        object_changes(
            CASE,
            authority_object_id,
            DurableObjectHead::Absent,
            DurableObjectMutation::Create {
                version: object_version(CASE, &chain_id, authority_object_id, 1, 0x41, 1)?,
                owner_projection: authority_owner,
                routing_projection: authority_routing,
            },
        )?,
        None,
    )?;
    let wrong_domain_commit: DurableCommitOutcome =
        store.commit_invocation(&context, wrong_domain_invocation);
    if wrong_domain_commit
        != DurableCommitOutcome::Rejected(DurableCommitRejection::AtomicityDomainMismatch)
    {
        return Err(mismatch(
            CASE,
            "object commit accepted a domain other than the bound domain",
            &wrong_domain_commit,
        ));
    }

    let non_active_fence_value: u64 = fence
        .get()
        .checked_add(1)
        .or_else(|| fence.get().checked_sub(1))
        .ok_or_else(|| ConformanceFailure::new(CASE, "no unequal writer fence exists"))?;
    let non_active_fence: WriterFenceGeneration =
        WriterFenceGeneration::new(non_active_fence_value)
            .ok_or_else(|| ConformanceFailure::new(CASE, "non-active test fence was zero"))?;
    let stale_context: DurableOperationContext =
        fixture.live_context(non_active_fence, 0x42, LIVE_CONTEXT_BUDGET)?;
    let stale_read = store.get_object_head(&stale_context, domain, authority_object_id);
    if stale_read
        != Err(DurableReadError::WriterFenced {
            active_generation: fence,
        })
    {
        return Err(mismatch(
            CASE,
            "object read did not reject a non-active writer fence",
            &stale_read,
        ));
    }
    let stale_object_id: ObjectId = ObjectId::new([0x42; 32]);
    let (stale_owner, stale_routing) = object_projections(CASE, 0x42)?;
    let stale_invocation: DurableInvocationTransaction = object_invocation(
        CASE,
        domain,
        0x42,
        None,
        object_changes(
            CASE,
            stale_object_id,
            DurableObjectHead::Absent,
            DurableObjectMutation::Create {
                version: object_version(CASE, &chain_id, stale_object_id, 1, 0x42, 2)?,
                owner_projection: stale_owner,
                routing_projection: stale_routing,
            },
        )?,
        None,
    )?;
    let stale_commit: DurableCommitOutcome =
        store.commit_invocation(&stale_context, stale_invocation);
    if stale_commit
        != DurableCommitOutcome::Rejected(DurableCommitRejection::WriterFenced {
            active_generation: fence,
        })
    {
        return Err(mismatch(
            CASE,
            "object commit did not reject a non-active writer fence",
            &stale_commit,
        ));
    }
    let expired_context: DurableOperationContext =
        fixture.live_context(fence, 0x43, std::time::Duration::ZERO)?;
    let expired_read = store.get_object_head(&expired_context, domain, authority_object_id);
    if expired_read != Err(DurableReadError::DeadlineExceeded) {
        return Err(mismatch(
            CASE,
            "object read did not reject the exact expired deadline boundary",
            &expired_read,
        ));
    }
    let expired_object_id: ObjectId = ObjectId::new([0x43; 32]);
    let (expired_owner, expired_routing) = object_projections(CASE, 0x43)?;
    let expired_invocation: DurableInvocationTransaction = object_invocation(
        CASE,
        domain,
        0x43,
        None,
        object_changes(
            CASE,
            expired_object_id,
            DurableObjectHead::Absent,
            DurableObjectMutation::Create {
                version: object_version(CASE, &chain_id, expired_object_id, 1, 0x43, 3)?,
                owner_projection: expired_owner,
                routing_projection: expired_routing,
            },
        )?,
        None,
    )?;
    let expired_commit: DurableCommitOutcome =
        store.commit_invocation(&expired_context, expired_invocation);
    if expired_commit
        != DurableCommitOutcome::Rejected(DurableCommitRejection::DeadlineExceededBeforeCommit)
    {
        return Err(mismatch(
            CASE,
            "object commit did not reject the exact expired deadline boundary",
            &expired_commit,
        ));
    }
    for authority_case_id in [authority_object_id, stale_object_id, expired_object_id] {
        let authority_head: DurableObjectHead = store
            .get_object_head(&context, domain, authority_case_id)
            .map_err(|error| mismatch(CASE, "authority rollback read must succeed", &error))?;
        if authority_head != DurableObjectHead::Absent {
            return Err(mismatch(
                CASE,
                "rejected authority case leaked an object",
                &authority_head,
            ));
        }
    }

    let object_id: ObjectId = ObjectId::new([0x51; 32]);

    let absent: DurableObjectHead = store
        .get_object_head(&context, domain, object_id)
        .map_err(|error| mismatch(CASE, "initial object read must succeed", &error))?;
    if absent != DurableObjectHead::Absent {
        return Err(mismatch(CASE, "new object must be absent", &absent));
    }

    let (owner_one, routing_one) = object_projections(CASE, 0x11)?;
    let create_mutation: DurableObjectMutation = DurableObjectMutation::Create {
        version: object_version(CASE, &chain_id, object_id, 1, 0x11, 10)?,
        owner_projection: owner_one,
        routing_projection: routing_one,
    };
    let create: DurableInvocationTransaction = object_invocation(
        CASE,
        domain,
        0x51,
        None,
        object_changes(CASE, object_id, absent, create_mutation)?,
        None,
    )?;
    if store.commit_invocation(&context, create) != DurableCommitOutcome::Committed {
        return Err(ConformanceFailure::new(CASE, "object create failed"));
    }
    let current_one: DurableObjectHead = store
        .get_object_head(&context, domain, object_id)
        .map_err(|error| mismatch(CASE, "created object read must succeed", &error))?;
    if current_one.head_revision() != Some(ObjectHeadRevision::FIRST)
        || current_one.object_version() != Some(DurableObjectVersion::FIRST)
    {
        return Err(mismatch(CASE, "create installed wrong head", &current_one));
    }
    let stored_one: DurableObjectVersionRecord = store
        .get_object_version(&context, domain, object_id, DurableObjectVersion::FIRST)
        .map_err(|error| mismatch(CASE, "created version read must succeed", &error))?
        .ok_or_else(|| ConformanceFailure::new(CASE, "created version is missing"))?;
    let inline_one: &DurableInlineObject = stored_one
        .payload()
        .inline()
        .ok_or_else(|| ConformanceFailure::new(CASE, "created version is not inline"))?;
    if inline_one.object().id != object_id
        || inline_one.object().version != 1
        || inline_one.object().owner != Owner::Address(objects::Address::new([0x11; 32]))
        || inline_one.object().type_hash
            != Digest32::new(protocol_types::HashAlgorithmId::Sha2_256, [0x12; 32])
        || stored_one.canonical_record_type_id() != u32::from(OBJECT_CANONICAL_TYPE_ID)
    {
        return Err(mismatch(
            CASE,
            "created immutable version projection is incoherent",
            &stored_one,
        ));
    }
    if stored_one.provenance().chain_id() != &chain_id
        || stored_one.provenance().protocol_version() != ProtocolVersion::new(1)
    {
        return Err(mismatch(
            CASE,
            "created version provenance was not preserved",
            &stored_one,
        ));
    }

    let (owner_two, routing_two) = object_projections(CASE, 0x22)?;
    // Written under a different protocol version than version one, so the
    // cross-version read-back below proves version one's provenance is not
    // overwritten or reinterpreted under a later version's context.
    let update_version: DurableObjectVersionRecord = object_version_with_protocol_version(
        CASE,
        &chain_id,
        object_id,
        2,
        0x22,
        11,
        ProtocolVersion::new(2),
    )?;
    let update_digest: Digest32 = update_version.digest();
    let update_mutation: DurableObjectMutation = DurableObjectMutation::Update {
        version: update_version,
        owner_projection: owner_two,
        routing_projection: routing_two,
    };
    let update: DurableInvocationTransaction = object_invocation(
        CASE,
        domain,
        0x52,
        None,
        object_changes(CASE, object_id, current_one, update_mutation)?,
        None,
    )?;
    if store.commit_invocation(&context, update) != DurableCommitOutcome::Committed {
        return Err(ConformanceFailure::new(CASE, "object update failed"));
    }
    let current_two: DurableObjectHead = store
        .get_object_head(&context, domain, object_id)
        .map_err(|error| mismatch(CASE, "updated object read must succeed", &error))?;
    if current_two.head_revision() != ObjectHeadRevision::new(2)
        || current_two.object_version() != DurableObjectVersion::new(2)
        || current_two.digest() != Some(update_digest)
    {
        return Err(mismatch(CASE, "update installed wrong head", &current_two));
    }
    let version_two: DurableObjectVersion = DurableObjectVersion::new(2)
        .ok_or_else(|| ConformanceFailure::new(CASE, "version two is invalid"))?;
    let stored_two: DurableObjectVersionRecord = store
        .get_object_version(&context, domain, object_id, version_two)
        .map_err(|error| mismatch(CASE, "updated version read must succeed", &error))?
        .ok_or_else(|| ConformanceFailure::new(CASE, "updated version is missing"))?;
    if stored_two.provenance().chain_id() != &chain_id
        || stored_two.provenance().protocol_version() != ProtocolVersion::new(2)
    {
        return Err(mismatch(
            CASE,
            "updated version provenance was not preserved",
            &stored_two,
        ));
    }
    // Naive digest recomputation under the reader's current protocol version
    // would misjudge this untouched historical version, so re-reading it
    // after a later version was written under a different protocol version
    // proves its own provenance is unaffected.
    let restored_one: DurableObjectVersionRecord = store
        .get_object_version(&context, domain, object_id, DurableObjectVersion::FIRST)
        .map_err(|error| mismatch(CASE, "re-read of version one must succeed", &error))?
        .ok_or_else(|| ConformanceFailure::new(CASE, "version one disappeared after update"))?;
    if restored_one.provenance().chain_id() != &chain_id
        || restored_one.provenance().protocol_version() != ProtocolVersion::new(1)
    {
        return Err(mismatch(
            CASE,
            "version one provenance changed after a later version was written",
            &restored_one,
        ));
    }

    let delete: DurableInvocationTransaction = object_invocation(
        CASE,
        domain,
        0x53,
        None,
        object_changes(CASE, object_id, current_two, DurableObjectMutation::Delete)?,
        None,
    )?;
    if store.commit_invocation(&context, delete) != DurableCommitOutcome::Committed {
        return Err(ConformanceFailure::new(CASE, "object delete failed"));
    }
    let tombstone: DurableObjectHead = store
        .get_object_head(&context, domain, object_id)
        .map_err(|error| mismatch(CASE, "tombstone read must succeed", &error))?;
    if tombstone.head_revision() != ObjectHeadRevision::new(3)
        || tombstone.object_version() != DurableObjectVersion::new(2)
        || tombstone.digest().is_some()
    {
        return Err(mismatch(
            CASE,
            "delete installed wrong tombstone",
            &tombstone,
        ));
    }

    let (owner_three, routing_three) = object_projections(CASE, 0x33)?;
    let recreate_mutation: DurableObjectMutation = DurableObjectMutation::Create {
        version: object_version(CASE, &chain_id, object_id, 3, 0x33, 12)?,
        owner_projection: owner_three.clone(),
        routing_projection: routing_three.clone(),
    };
    let recreate: DurableInvocationTransaction = object_invocation(
        CASE,
        domain,
        0x54,
        None,
        object_changes(
            CASE,
            object_id,
            tombstone.clone(),
            recreate_mutation.clone(),
        )?,
        None,
    )?;
    if store.commit_invocation(&context, recreate) != DurableCommitOutcome::Committed {
        return Err(ConformanceFailure::new(CASE, "object recreate failed"));
    }
    let current_three: DurableObjectHead = store
        .get_object_head(&context, domain, object_id)
        .map_err(|error| mismatch(CASE, "recreated object read must succeed", &error))?;
    if current_three.head_revision() != ObjectHeadRevision::new(4)
        || current_three.object_version() != DurableObjectVersion::new(3)
    {
        return Err(mismatch(CASE, "recreate permitted ABA", &current_three));
    }
    let version_three: DurableObjectVersion = DurableObjectVersion::new(3)
        .ok_or_else(|| ConformanceFailure::new(CASE, "version three is invalid"))?;
    let stored_three: DurableObjectVersionRecord = store
        .get_object_version(&context, domain, object_id, version_three)
        .map_err(|error| mismatch(CASE, "recreated version read must succeed", &error))?
        .ok_or_else(|| ConformanceFailure::new(CASE, "recreated version is missing"))?;
    if stored_three.provenance().chain_id() != &chain_id
        || stored_three.provenance().protocol_version() != ProtocolVersion::new(1)
    {
        return Err(mismatch(
            CASE,
            "recreated version provenance was not preserved",
            &stored_three,
        ));
    }

    let replay: DurableInvocationTransaction = object_invocation(
        CASE,
        domain,
        0x54,
        None,
        object_changes(
            CASE,
            object_id,
            current_three.clone(),
            DurableObjectMutation::Delete,
        )?,
        None,
    )?;
    if store.commit_invocation(&context, replay)
        != DurableCommitOutcome::Rejected(DurableCommitRejection::RequestAlreadyCommitted)
    {
        return Err(ConformanceFailure::new(CASE, "object replay was reapplied"));
    }
    let after_replay: DurableObjectHead = store
        .get_object_head(&context, domain, object_id)
        .map_err(|error| mismatch(CASE, "post-replay read must succeed", &error))?;
    if after_replay != current_three {
        return Err(mismatch(
            CASE,
            "object replay changed the head",
            &after_replay,
        ));
    }

    let advance: DurableInvocationTransaction = object_invocation(
        CASE,
        domain,
        0x56,
        None,
        object_changes(
            CASE,
            object_id,
            current_three.clone(),
            DurableObjectMutation::Delete,
        )?,
        None,
    )?;
    if store.commit_invocation(&context, advance) != DurableCommitOutcome::Committed {
        return Err(ConformanceFailure::new(
            CASE,
            "conflict setup delete failed",
        ));
    }

    let (owner_four, routing_four) = object_projections(CASE, 0x44)?;
    let stale_update: DurableObjectMutation = DurableObjectMutation::Update {
        version: object_version(CASE, &chain_id, object_id, 4, 0x44, 13)?,
        owner_projection: owner_four,
        routing_projection: routing_four,
    };
    let rollback_key: Vec<u8> = b"conformance/object-conflict".to_vec();
    let rollback_state: DurableStateTransaction = DurableStateTransaction::new(
        domain,
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(rollback_key.clone(), StateRevision::INITIAL)
                .map_err(|error| ConformanceFailure::new(CASE, error.to_string()))?,
        ])
        .map_err(|error| ConformanceFailure::new(CASE, error.to_string()))?,
        vec![
            StateMutationEntry::new(rollback_key.clone(), StateMutation::Put(vec![0x55]))
                .map_err(|error| ConformanceFailure::new(CASE, error.to_string()))?,
        ],
    )
    .map_err(|error| ConformanceFailure::new(CASE, error.to_string()))?;
    let stale: DurableInvocationTransaction = object_invocation(
        CASE,
        domain,
        0x55,
        Some(rollback_state),
        object_changes(CASE, object_id, current_three, stale_update)?,
        Some(vec![0x55]),
    )?;
    let stale_outcome: DurableCommitOutcome = store.commit_invocation(&context, stale);
    if !matches!(
        stale_outcome,
        DurableCommitOutcome::Rejected(DurableCommitRejection::ObjectConflict {
            object_id: conflicting_id,
            current: DurableObjectHeadSummary::Tombstoned { .. },
        }) if conflicting_id == object_id
    ) {
        return Err(mismatch(CASE, "stale update must conflict", &stale_outcome));
    }
    let rolled_back: VersionedStateValue = store
        .get_versioned_durable(&context, domain, &rollback_key)
        .map_err(|error| mismatch(CASE, "rollback read must succeed", &error))?;
    if rolled_back.revision() != StateRevision::INITIAL || rolled_back.value().is_some() {
        return Err(mismatch(CASE, "object conflict leaked state", &rolled_back));
    }
    let rolled_back_receipt: Option<DurableRequestReceipt> = store
        .get_request_receipt(&context, domain, request_id(CASE, 0x55)?)
        .map_err(|error| mismatch(CASE, "rollback receipt read must succeed", &error))?;
    if rolled_back_receipt.is_some() {
        return Err(mismatch(
            CASE,
            "object conflict leaked a receipt",
            &rolled_back_receipt,
        ));
    }
    let leaked_version: Option<DurableObjectVersionRecord> = store
        .get_object_version(
            &context,
            domain,
            object_id,
            DurableObjectVersion::new(4)
                .ok_or_else(|| ConformanceFailure::new(CASE, "version four is invalid"))?,
        )
        .map_err(|error| mismatch(CASE, "rollback version read must succeed", &error))?;
    if leaked_version.is_some() {
        return Err(mismatch(
            CASE,
            "object conflict leaked an immutable version",
            &leaked_version,
        ));
    }
    let due_claim: DurableOutboxClaimOutcome = store.claim_due_outbox(
        &context,
        DueOutboxClaimRequest::new(
            domain,
            OUTBOX_NOW,
            lease_id(CASE, 0x57)?,
            OUTBOX_NOW + OUTBOX_LEASE_MILLIS,
        )
        .map_err(|error| ConformanceFailure::new(CASE, error.to_string()))?,
    );
    if due_claim != DurableOutboxClaimOutcome::NoDueWork {
        return Err(mismatch(
            CASE,
            "object conflict leaked due work",
            &due_claim,
        ));
    }

    let blob_object_id: ObjectId = ObjectId::new([0x58; 32]);
    let blob_version: DurableObjectVersionRecord = DurableObjectVersionRecord::from_blob_reference(
        blob_object_id,
        DurableObjectVersion::FIRST,
        Digest32::new(protocol_types::HashAlgorithmId::Sha2_256, [0x59; 32]),
        9,
        DurableObjectProvenance::new(chain_id.clone(), ProtocolVersion::new(1)),
        14,
        Digest32::new(protocol_types::HashAlgorithmId::Sha3_256, [0x5A; 32]),
    );
    let blob_create: DurableInvocationTransaction = object_invocation(
        CASE,
        domain,
        0x58,
        None,
        object_changes(
            CASE,
            blob_object_id,
            DurableObjectHead::Absent,
            DurableObjectMutation::Create {
                version: blob_version.clone(),
                owner_projection: DurableObjectOwnerProjection::default(),
                routing_projection: DurableObjectRoutingProjection::default(),
            },
        )?,
        None,
    )?;
    if store.commit_invocation(&context, blob_create) != DurableCommitOutcome::Committed {
        return Err(ConformanceFailure::new(
            CASE,
            "blob-reference object create failed",
        ));
    }
    let stored_blob: Option<DurableObjectVersionRecord> = store
        .get_object_version(
            &context,
            domain,
            blob_object_id,
            DurableObjectVersion::FIRST,
        )
        .map_err(|error| mismatch(CASE, "blob-reference version read must succeed", &error))?;
    if stored_blob.as_ref() != Some(&blob_version) {
        return Err(mismatch(
            CASE,
            "blob-reference version did not round trip",
            &stored_blob,
        ));
    }
    let blob_head: DurableObjectHead = store
        .get_object_head(&context, domain, blob_object_id)
        .map_err(|error| mismatch(CASE, "blob-reference head read must succeed", &error))?;
    if blob_head
        != (DurableObjectHead::Current {
            head_revision: ObjectHeadRevision::FIRST,
            object_version: DurableObjectVersion::FIRST,
            digest: blob_version.digest(),
            owner_projection: DurableObjectOwnerProjection::default(),
            routing_projection: DurableObjectRoutingProjection::default(),
        })
    {
        return Err(mismatch(
            CASE,
            "blob-reference head projection was not preserved",
            &blob_head,
        ));
    }

    // A mutation-free object section still carries a complete head assertion.
    // Build it from one observed head, advance that head independently, and
    // prove the stale read-only invocation rejects without publishing a receipt.
    let read_only_object_id: ObjectId = ObjectId::new([0x5B; 32]);
    let (read_only_owner_one, read_only_routing_one) = object_projections(CASE, 0x5B)?;
    let read_only_create: DurableInvocationTransaction = object_invocation(
        CASE,
        domain,
        0x5B,
        None,
        object_changes(
            CASE,
            read_only_object_id,
            DurableObjectHead::Absent,
            DurableObjectMutation::Create {
                version: object_version(CASE, &chain_id, read_only_object_id, 1, 0x5B, 15)?,
                owner_projection: read_only_owner_one,
                routing_projection: read_only_routing_one,
            },
        )?,
        None,
    )?;
    if store.commit_invocation(&context, read_only_create) != DurableCommitOutcome::Committed {
        return Err(ConformanceFailure::new(
            CASE,
            "read-only assertion setup create failed",
        ));
    }
    let read_only_observed: DurableObjectHead = store
        .get_object_head(&context, domain, read_only_object_id)
        .map_err(|error| mismatch(CASE, "read-only assertion head read failed", &error))?;
    let read_only_changes: DurableObjectChanges = DurableObjectChanges::new(
        vec![DurableObjectHeadRead::new(
            read_only_object_id,
            read_only_observed.clone(),
        )],
        Vec::new(),
    )
    .map_err(|error| ConformanceFailure::new(CASE, error.to_string()))?;
    let stale_read_only: DurableInvocationTransaction =
        object_invocation(CASE, domain, 0x5C, None, read_only_changes, None)?;
    let (read_only_owner_two, read_only_routing_two) = object_projections(CASE, 0x5D)?;
    let read_only_advance: DurableInvocationTransaction = object_invocation(
        CASE,
        domain,
        0x5D,
        None,
        object_changes(
            CASE,
            read_only_object_id,
            read_only_observed,
            DurableObjectMutation::Update {
                version: object_version(CASE, &chain_id, read_only_object_id, 2, 0x5D, 16)?,
                owner_projection: read_only_owner_two,
                routing_projection: read_only_routing_two,
            },
        )?,
        None,
    )?;
    if store.commit_invocation(&context, read_only_advance) != DurableCommitOutcome::Committed {
        return Err(ConformanceFailure::new(
            CASE,
            "read-only assertion setup update failed",
        ));
    }
    let stale_read_only_outcome: DurableCommitOutcome =
        store.commit_invocation(&context, stale_read_only);
    if !matches!(
        stale_read_only_outcome,
        DurableCommitOutcome::Rejected(DurableCommitRejection::ObjectConflict {
            object_id: conflicting_id,
            current: DurableObjectHeadSummary::Current { .. },
        }) if conflicting_id == read_only_object_id
    ) {
        return Err(mismatch(
            CASE,
            "stale read-only object assertion must conflict",
            &stale_read_only_outcome,
        ));
    }
    let stale_read_only_receipt: Option<DurableRequestReceipt> = store
        .get_request_receipt(&context, domain, request_id(CASE, 0x5C)?)
        .map_err(|error| mismatch(CASE, "stale read-only receipt read failed", &error))?;
    if stale_read_only_receipt.is_some() {
        return Err(mismatch(
            CASE,
            "stale read-only object assertion leaked a receipt",
            &stale_read_only_receipt,
        ));
    }
    Ok(())
}

/// Runs the shared complete-read, contention, lease, and writer-fence cases.
///
/// The fixture is consumed logically: it must not be reused for another run.
pub fn run_durable_store_conformance<F: DurableStoreFixture>(fixture: &F) -> ConformanceResult {
    let initial_fence: WriterFenceGeneration = fixture.initial_writer_fence();
    deadline_conformance(fixture)?;
    let complete_read_context: DurableOperationContext =
        build_context(fixture, initial_fence, 0x01)?;
    complete_read_and_serialization_conformance(fixture, complete_read_context)?;
    let outbox_context: DurableOperationContext = build_context(fixture, initial_fence, 0x02)?;
    outbox_lease_conformance(fixture, outbox_context)?;
    let writer_fence_context: DurableOperationContext =
        build_context(fixture, initial_fence, 0x03)?;
    writer_fence_conformance(fixture, writer_fence_context)
}

/// Verifies fail-closed typed outcomes for a real persisted schema mismatch.
pub fn run_schema_skew_conformance<F: SchemaSkewFixture>(fixture: &F) -> ConformanceResult {
    const CASE: &str = "schema-version-skew";
    let store: Arc<F::Store> = fixture.store();
    let domain: AtomicityDomainId = fixture.domain();
    let fence: WriterFenceGeneration = fixture.initial_writer_fence();
    let context: DurableOperationContext = build_context(fixture, fence, 0x61)?;
    let prepared_request_byte: u8 = 0x62;
    let prepared_request: OutboxRequestId = outbox_request_id(CASE, prepared_request_byte)?;
    let prepared: DurableCommitOutcome = store.commit_invocation(
        &context,
        invocation(
            CASE,
            domain,
            prepared_request_byte,
            Vec::new(),
            Vec::new(),
            vec![vec![0xC1]],
        )?,
    );
    if prepared != DurableCommitOutcome::Committed {
        return Err(mismatch(
            CASE,
            "schema fixture invocation must commit",
            &prepared,
        ));
    }
    let prepared_lease: DurableOutboxLeaseId = lease_id(CASE, 0x63)?;
    let prepared_claim: DurableOutboxClaimOutcome = store.claim_request_outbox(
        &context,
        RequestOutboxClaimRequest::new(
            domain,
            prepared_request,
            OUTBOX_NOW,
            prepared_lease,
            OUTBOX_NOW + OUTBOX_LEASE_MILLIS,
        )
        .map_err(|error| ConformanceFailure::new(CASE, error.to_string()))?,
    );
    if !matches!(prepared_claim, DurableOutboxClaimOutcome::Claimed(_)) {
        return Err(mismatch(
            CASE,
            "schema fixture lease must be installed before skew",
            &prepared_claim,
        ));
    }
    fixture.install_unsupported_schema()?;

    let skew_result: ConformanceResult = (|| {
        let read = store.get_versioned_durable(&context, domain, b"conformance/schema-skew");
        if read != Err(DurableReadError::SchemaMismatch) {
            return Err(mismatch(CASE, "state read must fail closed", &read));
        }
        let receipt_read = store.get_request_receipt(&context, domain, request_id(CASE, 0x64)?);
        if receipt_read != Err(DurableReadError::SchemaMismatch) {
            return Err(mismatch(
                CASE,
                "receipt read must fail closed",
                &receipt_read,
            ));
        }
        let atomic_key: Vec<u8> = b"conformance/schema-skew-atomic".to_vec();
        let atomic = AtomicStateTransaction::new(
            domain,
            AtomicStateReadSet::new(vec![
                StateReadAssertion::new(atomic_key.clone(), StateRevision::INITIAL)
                    .map_err(|error| ConformanceFailure::new(CASE, error.to_string()))?,
            ])
            .map_err(|error| ConformanceFailure::new(CASE, error.to_string()))?,
            AtomicStateMutationSet::new(vec![
                StateMutationEntry::new(atomic_key, StateMutation::Put(vec![1]))
                    .map_err(|error| ConformanceFailure::new(CASE, error.to_string()))?,
            ])
            .map_err(|error| ConformanceFailure::new(CASE, error.to_string()))?,
        )
        .map_err(|error| ConformanceFailure::new(CASE, error.to_string()))?;
        let atomic_outcome: DurableCommitOutcome = store.commit_durable(&context, atomic);
        if atomic_outcome != DurableCommitOutcome::Rejected(DurableCommitRejection::SchemaMismatch)
        {
            return Err(mismatch(
                CASE,
                "atomic commit must fail closed",
                &atomic_outcome,
            ));
        }
        let invocation_outcome: DurableCommitOutcome = store.commit_invocation(
            &context,
            invocation(
                CASE,
                domain,
                0x64,
                vec![(
                    b"conformance/schema-skew-invocation".to_vec(),
                    StateRevision::INITIAL,
                )],
                vec![(
                    b"conformance/schema-skew-invocation".to_vec(),
                    StateMutation::Put(vec![1]),
                )],
                Vec::new(),
            )?,
        );
        if invocation_outcome
            != DurableCommitOutcome::Rejected(DurableCommitRejection::SchemaMismatch)
        {
            return Err(mismatch(
                CASE,
                "structured commit must fail closed",
                &invocation_outcome,
            ));
        }
        let exact_claim: DurableOutboxClaimOutcome = store.claim_request_outbox(
            &context,
            RequestOutboxClaimRequest::new(
                domain,
                prepared_request,
                OUTBOX_NOW,
                lease_id(CASE, 0x65)?,
                OUTBOX_NOW + OUTBOX_LEASE_MILLIS,
            )
            .map_err(|error| ConformanceFailure::new(CASE, error.to_string()))?,
        );
        if exact_claim
            != DurableOutboxClaimOutcome::Rejected(DurableOutboxClaimRejection::SchemaMismatch)
        {
            return Err(mismatch(CASE, "exact claim must fail closed", &exact_claim));
        }
        let due_claim: DurableOutboxClaimOutcome = store.claim_due_outbox(
            &context,
            DueOutboxClaimRequest::new(
                domain,
                OUTBOX_NOW,
                lease_id(CASE, 0x66)?,
                OUTBOX_NOW + OUTBOX_LEASE_MILLIS,
            )
            .map_err(|error| ConformanceFailure::new(CASE, error.to_string()))?,
        );
        if due_claim
            != DurableOutboxClaimOutcome::Rejected(DurableOutboxClaimRejection::SchemaMismatch)
        {
            return Err(mismatch(CASE, "due claim must fail closed", &due_claim));
        }
        let acknowledgement: DurableOutboxAcknowledgementOutcome = store.acknowledge_outbox(
            &context,
            DurableOutboxAcknowledgement::new(domain, prepared_request, 0, prepared_lease),
        );
        if acknowledgement
            != DurableOutboxAcknowledgementOutcome::Rejected(
                DurableOutboxAcknowledgementRejection::SchemaMismatch,
            )
        {
            return Err(mismatch(
                CASE,
                "acknowledgement must fail closed",
                &acknowledgement,
            ));
        }
        Ok(())
    })();
    let restore_result: ConformanceResult = fixture.restore_supported_schema();
    match (skew_result, restore_result) {
        (Ok(()), Ok(())) => {}
        (Err(error), Ok(())) => return Err(error),
        (Ok(()), Err(error)) => return Err(error),
        (Err(skew_error), Err(restore_error)) => {
            return Err(ConformanceFailure::new(
                CASE,
                format!(
                    "{skew_error}; additionally failed to restore supported schema: {restore_error}"
                ),
            ));
        }
    }
    let rejected_request_byte: u8 = 0x64;
    let rejected_receipt: Option<DurableRequestReceipt> = store
        .get_request_receipt(&context, domain, request_id(CASE, rejected_request_byte)?)
        .map_err(|error| mismatch(CASE, "restored receipt read must succeed", &error))?;
    if rejected_receipt.is_some() {
        return Err(mismatch(
            CASE,
            "schema-skew rejection must publish no receipt",
            &rejected_receipt,
        ));
    }
    let restored_ack: DurableOutboxAcknowledgementOutcome = store.acknowledge_outbox(
        &context,
        DurableOutboxAcknowledgement::new(domain, prepared_request, 0, prepared_lease),
    );
    if restored_ack != DurableOutboxAcknowledgementOutcome::Acknowledged {
        return Err(mismatch(
            CASE,
            "failed skewed acknowledgement must leave the original lease active",
            &restored_ack,
        ));
    }
    Ok(())
}

/// Verifies commit-boundary connection-loss evidence. Every case proves that
/// its injected fault actually fired.
///
/// [`CommitFaultPoint::BeforeCommitDispatch`] is injected once, for one plain
/// state commit, and proves no state ground truth was published: an
/// unfaulted retry of the same read assertion then commits successfully.
///
/// [`CommitFaultPoint::AfterBackendCommitAccepted`] is injected separately
/// three times, after confirming the backend actually returned a successful
/// acknowledgement before severing. A same-lease claim replay or
/// same-identity acknowledgement replay alone cannot distinguish a persisted
/// commit from an uncommitted one, so each case first probes the store with
/// an independent operation whose outcome differs only if the prior
/// transaction actually persisted:
/// - for one structured invocation commit, proving the exact committed state
///   revision/value and exact receipt content were published, and that
///   replaying the same invocation observes `RequestAlreadyCommitted`;
/// - for an outbox claim on that invocation's message, first proving with a
///   different, never-used lease that the original lease is still active
///   (`NoDueWork`), then that a same-lease replay reconciles to the identical
///   claimed message;
/// - for the corresponding acknowledgement, first proving that reclaiming
///   with the original lease is rejected as lease-ID reuse, then that a
///   same-identity replay reconciles to acknowledged with no message left
///   due for this one-message batch.
///
/// A final unfaulted commit proves the connection pool recovers a healthy
/// connection afterward.
///
/// This proves the backend returned a successful acknowledgement before the
/// driver lost the connection; it is not evidence that the commit would
/// survive an abrupt process/power loss. It also covers only the two
/// connection-loss instants named by [`CommitFaultPoint`] on whatever
/// transport the fixture severs, is not evidence for disk exhaustion,
/// TLS-path connection loss, capacity/load/soak, real writer failover, or
/// client disconnect/in-flight cancellation; those remain open per
/// `POSTGRES.md`.
pub fn run_commit_loss_conformance<F: CommitLossFixture>(fixture: &F) -> ConformanceResult {
    let store: Arc<F::Store> = fixture.store();
    let domain: AtomicityDomainId = fixture.domain();
    let fence: WriterFenceGeneration = fixture.initial_writer_fence();

    const BEFORE_CASE: &str = "commit-loss-before-dispatch";
    let before_key: Vec<u8> = b"conformance/commit-loss-before".to_vec();
    let before_context: DurableOperationContext = build_context(fixture, fence, 0xC1)?;
    fixture.arm_commit_loss(CommitFaultPoint::BeforeCommitDispatch)?;
    let before_transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(before_key.clone(), StateRevision::INITIAL)
                .map_err(|error| ConformanceFailure::new(BEFORE_CASE, error.to_string()))?,
        ])
        .map_err(|error| ConformanceFailure::new(BEFORE_CASE, error.to_string()))?,
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(before_key.clone(), StateMutation::Put(vec![0xC1]))
                .map_err(|error| ConformanceFailure::new(BEFORE_CASE, error.to_string()))?,
        ])
        .map_err(|error| ConformanceFailure::new(BEFORE_CASE, error.to_string()))?,
    )
    .map_err(|error| ConformanceFailure::new(BEFORE_CASE, error.to_string()))?;
    let before_outcome: DurableCommitOutcome =
        store.commit_durable(&before_context, before_transaction);
    if before_outcome
        != DurableCommitOutcome::Indeterminate(IndeterminateCommitReason::ConnectionLost)
    {
        return Err(mismatch(
            BEFORE_CASE,
            "severing before COMMIT dispatch must be reported as indeterminate connection loss",
            &before_outcome,
        ));
    }
    if !fixture.commit_loss_fired()? {
        return Err(ConformanceFailure::new(
            BEFORE_CASE,
            "fixture did not observe its own injected fault",
        ));
    }
    let after_before_read: VersionedStateValue = store
        .get_versioned_durable(&before_context, domain, &before_key)
        .map_err(|error| mismatch(BEFORE_CASE, "post-fault read must succeed", &error))?;
    if after_before_read.revision() != StateRevision::INITIAL || after_before_read.value().is_some()
    {
        return Err(mismatch(
            BEFORE_CASE,
            "a connection severed before COMMIT dispatch must publish no state",
            &after_before_read,
        ));
    }
    let before_retry: AtomicStateTransaction = AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(before_key.clone(), StateRevision::INITIAL)
                .map_err(|error| ConformanceFailure::new(BEFORE_CASE, error.to_string()))?,
        ])
        .map_err(|error| ConformanceFailure::new(BEFORE_CASE, error.to_string()))?,
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(before_key, StateMutation::Put(vec![0xC2]))
                .map_err(|error| ConformanceFailure::new(BEFORE_CASE, error.to_string()))?,
        ])
        .map_err(|error| ConformanceFailure::new(BEFORE_CASE, error.to_string()))?,
    )
    .map_err(|error| ConformanceFailure::new(BEFORE_CASE, error.to_string()))?;
    let before_retry_outcome: DurableCommitOutcome =
        store.commit_durable(&before_context, before_retry);
    if before_retry_outcome != DurableCommitOutcome::Committed {
        return Err(mismatch(
            BEFORE_CASE,
            "an unfaulted retry of the same absent assertion must commit, proving no ground truth was published and that the pool recovered a healthy connection",
            &before_retry_outcome,
        ));
    }

    const AFTER_CASE: &str = "commit-loss-invocation-after-backend-commit";
    let after_context: DurableOperationContext = build_context(fixture, fence, 0xC3)?;
    let after_request_byte: u8 = 0xC4;
    let after_key: Vec<u8> = b"conformance/commit-loss-after".to_vec();
    fixture.arm_commit_loss(CommitFaultPoint::AfterBackendCommitAccepted)?;
    let after_invocation: DurableInvocationTransaction = invocation(
        AFTER_CASE,
        domain,
        after_request_byte,
        vec![(after_key.clone(), StateRevision::INITIAL)],
        vec![(after_key.clone(), StateMutation::Put(vec![0xD2]))],
        vec![vec![0xD1]],
    )?;
    let expected_after_receipt: DurableRequestReceipt = after_invocation.receipt().clone();
    let after_outcome: DurableCommitOutcome =
        store.commit_invocation(&after_context, after_invocation.clone());
    if after_outcome
        != DurableCommitOutcome::Indeterminate(IndeterminateCommitReason::ConnectionLost)
    {
        return Err(mismatch(
            AFTER_CASE,
            "severing after the backend accepts COMMIT must be reported as indeterminate connection loss",
            &after_outcome,
        ));
    }
    if !fixture.commit_loss_fired()? {
        return Err(ConformanceFailure::new(
            AFTER_CASE,
            "fixture did not observe its own injected fault",
        ));
    }
    if !fixture.backend_commit_accepted()? {
        return Err(ConformanceFailure::new(
            AFTER_CASE,
            "fixture did not observe a genuine backend COMMIT acceptance before severing",
        ));
    }
    let after_state: VersionedStateValue = store
        .get_versioned_durable(&after_context, domain, &after_key)
        .map_err(|error| mismatch(AFTER_CASE, "post-fault state read must succeed", &error))?;
    if after_state.revision() != StateRevision::new(1)
        || after_state.value() != Some([0xD2].as_slice())
    {
        return Err(mismatch(
            AFTER_CASE,
            "a connection severed after the backend accepts COMMIT must still publish the exact committed state revision and value",
            &after_state,
        ));
    }
    let after_request_id: DurableRequestId = request_id(AFTER_CASE, after_request_byte)?;
    let receipt: Option<DurableRequestReceipt> = store
        .get_request_receipt(&after_context, domain, after_request_id)
        .map_err(|error| mismatch(AFTER_CASE, "post-fault receipt read must succeed", &error))?;
    if receipt != Some(expected_after_receipt) {
        return Err(mismatch(
            AFTER_CASE,
            "a connection severed after the backend accepts COMMIT must still publish the exact committed receipt content",
            &receipt,
        ));
    }
    let reconciled_invocation: DurableCommitOutcome =
        store.commit_invocation(&after_context, after_invocation);
    if reconciled_invocation
        != DurableCommitOutcome::Rejected(DurableCommitRejection::RequestAlreadyCommitted)
    {
        return Err(mismatch(
            AFTER_CASE,
            "replaying an indeterminate but backend-committed invocation must observe RequestAlreadyCommitted rather than recommitting or losing the effect",
            &reconciled_invocation,
        ));
    }

    const CLAIM_CASE: &str = "commit-loss-claim-after-backend-commit";
    let claim_outbox_request: OutboxRequestId = outbox_request_id(CLAIM_CASE, after_request_byte)?;
    let claim_context: DurableOperationContext = build_context(fixture, fence, 0xC5)?;
    let claim_lease: DurableOutboxLeaseId = lease_id(CLAIM_CASE, 0xC6)?;
    fixture.arm_commit_loss(CommitFaultPoint::AfterBackendCommitAccepted)?;
    let claim_request: RequestOutboxClaimRequest = RequestOutboxClaimRequest::new(
        domain,
        claim_outbox_request,
        OUTBOX_NOW,
        claim_lease,
        OUTBOX_NOW + OUTBOX_LEASE_MILLIS,
    )
    .map_err(|error| ConformanceFailure::new(CLAIM_CASE, error.to_string()))?;
    let claim_outcome: DurableOutboxClaimOutcome =
        store.claim_request_outbox(&claim_context, claim_request);
    if claim_outcome
        != DurableOutboxClaimOutcome::Indeterminate(IndeterminateCommitReason::ConnectionLost)
    {
        return Err(mismatch(
            CLAIM_CASE,
            "severing an outbox claim after the backend accepts COMMIT must be reported as indeterminate connection loss",
            &claim_outcome,
        ));
    }
    if !fixture.commit_loss_fired()? {
        return Err(ConformanceFailure::new(
            CLAIM_CASE,
            "fixture did not observe its own injected fault",
        ));
    }
    if !fixture.backend_commit_accepted()? {
        return Err(ConformanceFailure::new(
            CLAIM_CASE,
            "fixture did not observe a genuine backend COMMIT acceptance before severing",
        ));
    }
    // A same-lease replay alone cannot distinguish a persisted claim from an
    // uncommitted one: if the original claim never landed, replaying it would
    // simply perform a fresh claim and return an indistinguishable `Claimed`
    // outcome. Probe with a different, never-used lease at the same
    // `OUTBOX_NOW` instead: the original lease has not yet expired, so this
    // only observes `NoDueWork` if the original attempt's active lease is
    // genuinely persisted and still bound to the request.
    let claim_probe_lease: DurableOutboxLeaseId = lease_id(CLAIM_CASE, 0xCA)?;
    let claim_probe_outcome: DurableOutboxClaimOutcome = store.claim_request_outbox(
        &claim_context,
        RequestOutboxClaimRequest::new(
            domain,
            claim_outbox_request,
            OUTBOX_NOW,
            claim_probe_lease,
            OUTBOX_NOW + OUTBOX_LEASE_MILLIS,
        )
        .map_err(|error| ConformanceFailure::new(CLAIM_CASE, error.to_string()))?,
    );
    if claim_probe_outcome != DurableOutboxClaimOutcome::NoDueWork {
        return Err(mismatch(
            CLAIM_CASE,
            "a different-lease claim while the original lease is unexpired must observe no due work, proving the indeterminate claim's active lease persisted",
            &claim_probe_outcome,
        ));
    }
    let reconciled_claim_outcome: DurableOutboxClaimOutcome =
        store.claim_request_outbox(&claim_context, claim_request);
    let DurableOutboxClaimOutcome::Claimed(reconciled_claim) = reconciled_claim_outcome else {
        return Err(mismatch(
            CLAIM_CASE,
            "a same-lease replay after an indeterminate but backend-committed claim must reconcile the already-claimed message",
            &reconciled_claim_outcome,
        ));
    };
    if reconciled_claim.message_index() != 0 || reconciled_claim.canonical_payload() != [0xD1] {
        return Err(mismatch(
            CLAIM_CASE,
            "the reconciled claim must own the exact message the backend committed",
            &reconciled_claim,
        ));
    }

    const ACK_CASE: &str = "commit-loss-acknowledgement-after-backend-commit";
    let ack_context: DurableOperationContext = build_context(fixture, fence, 0xC7)?;
    fixture.arm_commit_loss(CommitFaultPoint::AfterBackendCommitAccepted)?;
    let acknowledgement: DurableOutboxAcknowledgement =
        DurableOutboxAcknowledgement::new(domain, claim_outbox_request, 0, claim_lease);
    let ack_outcome: DurableOutboxAcknowledgementOutcome =
        store.acknowledge_outbox(&ack_context, acknowledgement);
    if ack_outcome
        != DurableOutboxAcknowledgementOutcome::Indeterminate(
            IndeterminateCommitReason::ConnectionLost,
        )
    {
        return Err(mismatch(
            ACK_CASE,
            "severing an acknowledgement after the backend accepts COMMIT must be reported as indeterminate connection loss",
            &ack_outcome,
        ));
    }
    if !fixture.commit_loss_fired()? {
        return Err(ConformanceFailure::new(
            ACK_CASE,
            "fixture did not observe its own injected fault",
        ));
    }
    if !fixture.backend_commit_accepted()? {
        return Err(ConformanceFailure::new(
            ACK_CASE,
            "fixture did not observe a genuine backend COMMIT acceptance before severing",
        ));
    }
    // A same-identity acknowledgement replay alone cannot distinguish a
    // persisted acknowledgement from an uncommitted one: the active lease
    // from the claim case would still satisfy a first-time acknowledgement
    // just as well as an idempotent replay. Probe by attempting to claim
    // again with the original lease: a lease already consumed by a persisted
    // acknowledgement is no longer active work and must be rejected as
    // lease-ID reuse, whereas an uncommitted acknowledgement would leave the
    // lease active and this probe would instead reconcile to `Claimed`.
    let ack_probe_outcome: DurableOutboxClaimOutcome = store.claim_request_outbox(
        &ack_context,
        RequestOutboxClaimRequest::new(
            domain,
            claim_outbox_request,
            OUTBOX_NOW,
            claim_lease,
            OUTBOX_NOW + OUTBOX_LEASE_MILLIS,
        )
        .map_err(|error| ConformanceFailure::new(ACK_CASE, error.to_string()))?,
    );
    if ack_probe_outcome
        != DurableOutboxClaimOutcome::Rejected(DurableOutboxClaimRejection::LeaseIdReuse)
    {
        return Err(mismatch(
            ACK_CASE,
            "reclaiming with the original lease after an indeterminate acknowledgement must be rejected as lease-ID reuse, proving the acknowledgement persisted",
            &ack_probe_outcome,
        ));
    }
    let reconciled_ack: DurableOutboxAcknowledgementOutcome =
        store.acknowledge_outbox(&ack_context, acknowledgement);
    if reconciled_ack != DurableOutboxAcknowledgementOutcome::Acknowledged {
        return Err(mismatch(
            ACK_CASE,
            "a replay after an indeterminate but backend-committed acknowledgement must reconcile as acknowledged",
            &reconciled_ack,
        ));
    }
    let post_ack_claim: DurableOutboxClaimOutcome = store.claim_request_outbox(
        &ack_context,
        RequestOutboxClaimRequest::new(
            domain,
            claim_outbox_request,
            OUTBOX_NOW,
            lease_id(ACK_CASE, 0xC9)?,
            OUTBOX_NOW + OUTBOX_LEASE_MILLIS,
        )
        .map_err(|error| ConformanceFailure::new(ACK_CASE, error.to_string()))?,
    );
    if post_ack_claim != DurableOutboxClaimOutcome::NoDueWork {
        return Err(mismatch(
            ACK_CASE,
            "the acknowledgement must persist and leave no due work for this one-message batch",
            &post_ack_claim,
        ));
    }

    const RECOVERY_CASE: &str = "commit-loss-pool-recovery";
    let recovery_key: Vec<u8> = b"conformance/commit-loss-recovery".to_vec();
    let recovery_context: DurableOperationContext = build_context(fixture, fence, 0xC8)?;
    let recovery_transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(recovery_key.clone(), StateRevision::INITIAL)
                .map_err(|error| ConformanceFailure::new(RECOVERY_CASE, error.to_string()))?,
        ])
        .map_err(|error| ConformanceFailure::new(RECOVERY_CASE, error.to_string()))?,
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(recovery_key, StateMutation::Put(vec![0xC8]))
                .map_err(|error| ConformanceFailure::new(RECOVERY_CASE, error.to_string()))?,
        ])
        .map_err(|error| ConformanceFailure::new(RECOVERY_CASE, error.to_string()))?,
    )
    .map_err(|error| ConformanceFailure::new(RECOVERY_CASE, error.to_string()))?;
    let recovery_outcome: DurableCommitOutcome =
        store.commit_durable(&recovery_context, recovery_transaction);
    if recovery_outcome != DurableCommitOutcome::Committed {
        return Err(mismatch(
            RECOVERY_CASE,
            "the connection pool must recover a healthy connection after repeated commit-boundary connection loss",
            &recovery_outcome,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct MemoryFixture {
        store: Arc<MemoryDurableStateStore>,
        domain: AtomicityDomainId,
        fence: WriterFenceGeneration,
        now_unix_millis: Mutex<u64>,
    }

    impl MemoryFixture {
        fn new() -> Self {
            let fence: WriterFenceGeneration = WriterFenceGeneration::new(7).unwrap();
            Self::with_fence(fence)
        }

        fn with_fence(fence: WriterFenceGeneration) -> Self {
            let domain: AtomicityDomainId = AtomicityDomainId::new([0x71; 32]).unwrap();
            let store: Arc<MemoryDurableStateStore> =
                Arc::new(MemoryDurableStateStore::new_bound(domain, fence));
            store.set_time(OUTBOX_NOW);
            Self {
                store,
                domain,
                fence,
                now_unix_millis: Mutex::new(OUTBOX_NOW),
            }
        }
    }

    impl DurableStoreFixture for MemoryFixture {
        type Store = MemoryDurableStateStore;

        fn store(&self) -> Arc<Self::Store> {
            Arc::clone(&self.store)
        }

        fn domain(&self) -> AtomicityDomainId {
            self.domain
        }

        fn initial_writer_fence(&self) -> WriterFenceGeneration {
            self.fence
        }

        fn live_context(
            &self,
            writer_fence: WriterFenceGeneration,
            correlation_byte: u8,
            budget: std::time::Duration,
        ) -> ConformanceResult<DurableOperationContext> {
            let now: u64 = *self.now_unix_millis.lock().map_err(|_| {
                ConformanceFailure::new("memory-fixture", "fixture clock lock poisoned")
            })?;
            let budget_millis: u64 = u64::try_from(budget.as_millis()).map_err(|_| {
                ConformanceFailure::new("memory-fixture", "context budget exceeds u64")
            })?;
            let deadline: u64 = now.checked_add(budget_millis).ok_or_else(|| {
                ConformanceFailure::new("memory-fixture", "context deadline overflow")
            })?;
            Ok(DurableOperationContext::new(
                writer_fence,
                StorageDeadline::new(deadline).ok_or_else(|| {
                    ConformanceFailure::new("memory-fixture", "zero context deadline")
                })?,
                StorageCorrelationId::new([correlation_byte; 16]).ok_or_else(|| {
                    ConformanceFailure::new("memory-fixture", "zero correlation identity")
                })?,
            ))
        }

        fn advance_writer_fence(
            &self,
            expected: WriterFenceGeneration,
            next: WriterFenceGeneration,
        ) -> ConformanceResult<()> {
            if expected != self.fence || next.get() <= expected.get() {
                return Err(ConformanceFailure::new(
                    "memory-fixture",
                    "invalid writer-fence advance",
                ));
            }
            self.store.set_active_writer_fence(next);
            Ok(())
        }

        fn object_provenance_chain_id(&self) -> ConformanceResult<ChainId> {
            // `MemoryDurableStateStore` has no chain namespace to derive
            // this from (unlike PostgreSQL's `object_versions.chain_id_bytes`),
            // so this fixture's sole source of truth is this one literal.
            ChainId::new("sunrise-runtime-conformance")
                .map_err(|error| ConformanceFailure::new("memory-fixture", error.to_string()))
        }
    }

    #[test]
    fn memory_durable_store_passes_shared_conformance() {
        run_durable_store_conformance(&MemoryFixture::new()).unwrap();
    }

    #[test]
    fn memory_durable_store_passes_object_conformance() {
        run_durable_object_conformance(&MemoryFixture::new()).unwrap();
    }

    #[test]
    fn object_conformance_accepts_boundary_initial_fences() {
        for fence_value in [1_u64, u64::MAX] {
            let fence: WriterFenceGeneration = WriterFenceGeneration::new(fence_value).unwrap();
            run_durable_object_conformance(&MemoryFixture::with_fence(fence)).unwrap();
        }
    }
}
