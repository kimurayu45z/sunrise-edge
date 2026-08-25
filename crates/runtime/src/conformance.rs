//! Shared behavioral conformance for production durable-store implementations.
//!
//! This module is test support. It is available to `runtime` unit tests and to
//! adapter test targets that explicitly enable the `durable-conformance`
//! feature. Passing these cases is contract evidence, not production
//! certification or fault/capacity evidence.
//! Concurrent cases use only bounded threads that are joined before returning;
//! no background work or process lifetime is part of the store contract.

use super::*;
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
            let store: Arc<MemoryDurableStateStore> = Arc::new(MemoryDurableStateStore::new(fence));
            store.set_time(OUTBOX_NOW);
            Self {
                store,
                domain: AtomicityDomainId::new([0x71; 32]).unwrap(),
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
    }

    #[test]
    fn memory_durable_store_passes_shared_conformance() {
        run_durable_store_conformance(&MemoryFixture::new()).unwrap();
    }
}
