#![forbid(unsafe_code)]

//! Native HTTP adapter for the runtime-neutral node-core boundary.
//!
//! This crate owns HTTP routing and status mapping. It does not add HTTP types
//! to protocol crates, and it accepts only canonical binary node events.

use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State, rejection::BytesRejection},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use core::fmt;
use execution::{ExecutionError, WasmExecutionEngine};
use hashing::HashSuiteResolver;
use node_core::{
    FeeEffectComposer, MAX_NODE_OUTPUT_ITEMS, MAX_NODE_PAYLOAD_BYTES, NodeConfig, NodeCoreError,
    NodeEvent, NodeEventKind, NodeOutboxBatch, NodeOutboxDelivery, OutboxClaim, OutboxLeaseId,
    PreinstalledFeeComposition, PreinstalledModuleCatalog, RequestId, TransactionAuthError,
    TransactionalNodeStateMachine, acknowledge_outbox_message,
    acknowledge_outbox_message_in_domain, authenticate_submit_transaction_event,
    claim_next_outbox_message, claim_next_outbox_message_in_domain,
    handle_authenticated_resolved_durable_submit_transaction,
    handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution,
    handle_idempotent_event, handle_resolved_idempotent_event, query_object, query_request_receipt,
    query_sender_next_nonce,
};
use objects::{Address, ObjectId};
use protocol_config::{
    DomainPlacementManifest, ProtocolConfig, ProtocolConfigError, resolve_transaction_auth_profile,
};
use protocol_types::ProtocolVersion;
use runtime::{
    AtomicityDomainId, BlobStore, Clock, DomainTransactionalStateStore, DueOutboxClaimRequest,
    DurableOperationContext, DurableOutboxAcknowledgement, DurableOutboxAcknowledgementOutcome,
    DurableOutboxAcknowledgementRejection, DurableOutboxClaimOutcome, DurableOutboxClaimRejection,
    DurableOutboxLeaseId, IndeterminateCommitReason, IndexedOutboxContractError,
    IndexedOutboxRepository, InvocationCancellation, MAX_DURABLE_OUTBOX_LEASE_MILLIS,
    OutboxRequestId, PersistenceLayout, RequestOutboxClaimRequest, Runtime, RuntimeError,
    StateKeyScan, StateKeyScanner, StorageCorrelationId, StorageDeadline,
    StructuredDurableDomainStateStore, TransactionalStateStore, Transport, WriterFenceGeneration,
};
use std::{
    error::Error,
    future::Future,
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
};
use tokio::sync::{Semaphore, TryAcquireError};

// Canonical HTTP event/query-result codecs and route/media-type constants
// live in `node-wire` (DR-0083) and are re-exported below so existing
// callers keep their original `native-http` import paths and byte-identical
// wire behavior.
pub use node_wire::{
    CONTEXT_QUERY_RESULT_TYPE_ID, HttpContextQueryResult, HttpContractError,
    HttpNextNonceQueryResult, HttpNodeResult, HttpObjectQueryResult, HttpReceiptQueryResult,
    LIVENESS_PATH, NEXT_NONCE_QUERY_RESULT_TYPE_ID, NODE_EVENT_MEDIA_TYPE, NODE_EVENT_PATH,
    NODE_RESULT_MEDIA_TYPE, OBJECT_QUERY_RESULT_TYPE_ID, ObjectQueryStatus, QUERY_CONTEXT_PATH,
    QUERY_NEXT_NONCE_PATH, QUERY_OBJECT_PATH, QUERY_RECEIPT_PATH, QUERY_RESULT_MEDIA_TYPE,
    QueryResultError, RECEIPT_QUERY_RESULT_TYPE_ID, ReceiptQueryStatus, http_receipt_query_result,
};

/// Maximum HTTP body size. The allowance above the inner payload covers framing.
pub const MAX_HTTP_EVENT_BODY_BYTES: usize = MAX_NODE_PAYLOAD_BYTES + 512;
/// Bounded native delivery lease; expired work is deliberately redelivered.
pub const NATIVE_OUTBOX_LEASE_MILLIS: u64 = 30_000;
/// Maximum storage-operation budget accepted by indexed native recovery.
pub const MAX_INDEXED_OUTBOX_OPERATION_MILLIS: u64 = 30_000;

/// Trusted storage authority for one normalized native request.
///
/// The embedding host fixes writer fencing and time budgets. The HTTP request
/// supplies none of these values, and node-core still resolves the logical
/// domain from the protocol manifest before any storage read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StructuredDurableRequestAuthority {
    writer_fence: WriterFenceGeneration,
    operation_timeout_millis: NonZeroU64,
    lease_duration_millis: NonZeroU64,
}

impl StructuredDurableRequestAuthority {
    /// Creates bounded request authority whose storage budget is below a lease.
    pub fn new(
        writer_fence: WriterFenceGeneration,
        operation_timeout_millis: u64,
        lease_duration_millis: u64,
    ) -> Result<Self, IndexedOutboxRecoveryAuthorityError> {
        let operation_timeout_millis = NonZeroU64::new(operation_timeout_millis)
            .ok_or(IndexedOutboxRecoveryAuthorityError::InvalidOperationTimeout)?;
        let lease_duration_millis = NonZeroU64::new(lease_duration_millis)
            .filter(|duration| duration.get() <= MAX_DURABLE_OUTBOX_LEASE_MILLIS)
            .ok_or(IndexedOutboxRecoveryAuthorityError::InvalidLeaseDuration)?;
        if operation_timeout_millis.get() > MAX_INDEXED_OUTBOX_OPERATION_MILLIS
            || operation_timeout_millis >= lease_duration_millis
        {
            return Err(IndexedOutboxRecoveryAuthorityError::InvalidOperationTimeout);
        }
        Ok(Self {
            writer_fence,
            operation_timeout_millis,
            lease_duration_millis,
        })
    }

    /// Returns the configured authoritative writer generation.
    #[must_use]
    pub const fn writer_fence(self) -> WriterFenceGeneration {
        self.writer_fence
    }
}

/// Misconfiguration detected while composing the structured durable router.
///
/// These are host-configuration invariants checked once, at composition time,
/// so a diverging protocol-version or domain-placement authority can never
/// reach a request. [`node_core::TrustedTransactionContext`] resolves its
/// `protocol_version` and `TransactionAuthProfile` authority solely from the
/// committed [`ProtocolConfig`] passed to [`structured_durable_router`]; this
/// keeps that authority identical to the one [`NodeConfig`] uses to validate
/// every ingress [`NodeEvent`], rather than letting the two silently diverge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StructuredDurableRouterError {
    /// [`ProtocolConfig::protocol_version`] did not match
    /// [`NodeConfig::protocol_version`].
    ProtocolVersionAuthorityMismatch {
        /// Version fixed by the ingress [`NodeConfig`].
        node_config: ProtocolVersion,
        /// Version committed in the [`ProtocolConfig`].
        protocol_config: ProtocolVersion,
    },
    /// The committed [`ProtocolConfig`] carried no domain-placement manifest,
    /// so no logical domain could be resolved for storage.
    MissingDomainPlacement,
}

impl fmt::Display for StructuredDurableRouterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProtocolVersionAuthorityMismatch {
                node_config,
                protocol_config,
            } => write!(
                f,
                "node config protocol version {} does not match committed protocol config version {}",
                node_config.get(),
                protocol_config.get()
            ),
            Self::MissingDomainPlacement => {
                f.write_str("committed protocol config carries no domain placement manifest")
            }
        }
    }
}

impl Error for StructuredDurableRouterError {}

/// Explicit components used by the normalized durable native request path.
///
/// Keeping these components separate from [`Runtime`] lets normalized stores
/// avoid implementing the legacy opaque [`runtime::StateStore`] interface.
#[derive(Debug)]
pub struct StructuredDurableNativeComponents<S, B, T, C, I> {
    store: Arc<S>,
    blob_store: Arc<B>,
    transport: Arc<T>,
    clock: Arc<C>,
    identities: Arc<I>,
    cancellation: Option<Arc<dyn InvocationCancellation>>,
}

impl<S, B, T, C, I> StructuredDurableNativeComponents<S, B, T, C, I> {
    /// Creates a composition that never cancels before storage dispatch.
    ///
    /// `blob_store` is a separate explicit component from `store`: normalized
    /// stores are never required to also implement [`runtime::BlobStore`].
    /// Existing compositions retain their original behavior. Use
    /// [`Self::with_cancellation`] when the host has an explicit trusted signal.
    #[must_use]
    pub const fn new(
        store: Arc<S>,
        blob_store: Arc<B>,
        transport: Arc<T>,
        clock: Arc<C>,
        identities: Arc<I>,
    ) -> Self {
        Self {
            store,
            blob_store,
            transport,
            clock,
            identities,
            cancellation: None,
        }
    }

    /// Creates a composition with an explicit trusted pre-storage cancellation signal.
    #[must_use]
    pub fn with_cancellation(
        store: Arc<S>,
        blob_store: Arc<B>,
        transport: Arc<T>,
        clock: Arc<C>,
        identities: Arc<I>,
        cancellation: Arc<dyn InvocationCancellation>,
    ) -> Self {
        Self {
            store,
            blob_store,
            transport,
            clock,
            identities,
            cancellation: Some(cancellation),
        }
    }

    fn is_cancelled(&self) -> bool {
        match &self.cancellation {
            Some(cancellation) => cancellation.is_cancelled(),
            None => false,
        }
    }
}

/// Trusted node composition's fee-charging capability, owned so it can be
/// stored inside [`PreinstalledWasmComposition`] and cloned across requests.
///
/// `treasury_object_id` and `composer` never come from HTTP request bytes,
/// exactly like `catalog`/`engine`/`created_checkpoint`. Each request builds
/// the borrowed [`node_core::PreinstalledFeeComposition`] this crate's
/// entrypoint call needs from this owned value.
#[derive(Clone, Debug)]
pub struct PreinstalledFeeCompositionConfig {
    treasury_object_id: ObjectId,
    composer: Arc<dyn FeeEffectComposer>,
}

impl PreinstalledFeeCompositionConfig {
    /// Creates a trusted fee-charging capability.
    #[must_use]
    pub fn new(treasury_object_id: ObjectId, composer: Arc<dyn FeeEffectComposer>) -> Self {
        Self {
            treasury_object_id,
            composer,
        }
    }
}

/// Trusted preinstalled-WASM composition input for
/// [`preinstalled_wasm_structured_durable_router`].
///
/// Every field is fixed by trusted node composition, exactly like
/// [`node_core::handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution`]
/// requires: `catalog` and `engine` never come from HTTP request bytes, and
/// `created_checkpoint` never comes from request bytes or wall-clock time. It
/// is the caller's already-validated chain-progress value, identical in
/// origin and trust level to the `created_checkpoint` accepted by that
/// function. `fee` is optional only as a composition capability: `None`
/// preserves byte-identical historical behavior exclusively when the
/// committed schedule's worst-case fee is zero and the transaction declares
/// neither `fee_payment` nor a treasury access. A non-zero committed schedule
/// or a declared payment fails closed when this capability is absent.
#[derive(Clone, Debug)]
pub struct PreinstalledWasmComposition {
    catalog: Arc<PreinstalledModuleCatalog>,
    engine: WasmExecutionEngine,
    created_checkpoint: u64,
    fee: Option<PreinstalledFeeCompositionConfig>,
}

impl PreinstalledWasmComposition {
    /// Creates a trusted preinstalled-WASM composition input with no fee
    /// composition wired. This is executable only under a committed zero-fee
    /// schedule with no declared `fee_payment`; fee-bearing requests fail
    /// closed until [`Self::with_fee_composition`] is applied.
    ///
    /// `created_checkpoint` must be non-decreasing across process restarts
    /// for every object this composition may mutate: node-core rejects a
    /// Write whose `created_checkpoint` is lower than the previous immutable
    /// version's own stored checkpoint
    /// (`NodeCoreError::ObjectCreatedCheckpointRegression`), and that check
    /// fails closed rather than silently accepting a regressed value. This
    /// function does not derive or persist `created_checkpoint` itself; the
    /// caller must source it from its own already-validated, durably
    /// advancing chain progress (never wall-clock time, never HTTP request
    /// bytes), exactly like the node-core entrypoint this composition feeds.
    #[must_use]
    pub const fn new(
        catalog: Arc<PreinstalledModuleCatalog>,
        engine: WasmExecutionEngine,
        created_checkpoint: u64,
    ) -> Self {
        Self {
            catalog,
            engine,
            created_checkpoint,
            fee: None,
        }
    }

    /// Returns an equivalent composition with a trusted fee-charging
    /// capability wired in.
    #[must_use]
    pub fn with_fee_composition(mut self, fee: PreinstalledFeeCompositionConfig) -> Self {
        self.fee = Some(fee);
        self
    }
}

/// Admission policy for synchronous node and runtime work.
///
/// The limit is intentionally supplied by the embedding process because its
/// safe value depends on the database connection strategy and host capacity.
/// There is no hidden unbounded queue: excess requests fail immediately.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeBlockingPolicy {
    max_concurrent_invocations: NonZeroUsize,
}

impl NativeBlockingPolicy {
    /// Creates a policy with an explicit non-zero concurrency limit.
    #[must_use]
    pub const fn new(max_concurrent_invocations: NonZeroUsize) -> Self {
        Self {
            max_concurrent_invocations,
        }
    }

    /// Returns the maximum synchronous invocations admitted at once.
    #[must_use]
    pub const fn max_concurrent_invocations(self) -> NonZeroUsize {
        self.max_concurrent_invocations
    }
}

/// Shared admission pool for native HTTP and scheduler-triggered recovery.
///
/// Clone and pass the same executor to request routing and either one-shot
/// recovery entrypoint so recovery cannot bypass request capacity.
#[derive(Clone, Debug)]
pub struct NativeBlockingExecutor {
    permits: Arc<Semaphore>,
}

impl NativeBlockingExecutor {
    /// Creates a shared executor from an explicit host capacity policy.
    #[must_use]
    pub fn new(policy: NativeBlockingPolicy) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(policy.max_concurrent_invocations().get())),
        }
    }

    fn try_acquire(&self) -> Result<tokio::sync::OwnedSemaphorePermit, TryAcquireError> {
        Arc::clone(&self.permits).try_acquire_owned()
    }
}

/// Supplies process-independent identities for persisted outbox leases.
///
/// An implementation must not reuse an identifier for the same request, even
/// across process restarts. Reuse could allow a delayed acknowledgement from
/// an expired attempt to acknowledge a newer delivery attempt.
pub trait OutboxLeaseIdSource {
    /// Returns the next unique lease identity for one request-scoped outbox.
    fn next_lease_id(
        &self,
        request_id: RequestId,
    ) -> Result<OutboxLeaseId, OutboxLeaseIdSourceError>;
}

/// Failures from the adapter-owned lease identity source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutboxLeaseIdSourceError {
    /// The backing entropy or durable sequence is temporarily unavailable.
    Unavailable,
    /// The source exhausted its non-repeating identity space.
    Exhausted,
}

impl fmt::Display for OutboxLeaseIdSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => f.write_str("outbox lease identity source is unavailable"),
            Self::Exhausted => f.write_str("outbox lease identity source is exhausted"),
        }
    }
}

impl Error for OutboxLeaseIdSourceError {}

/// Trusted deployment authority for one indexed outbox recovery domain.
///
/// The embedding host derives this from fenced physical placement. An
/// untrusted scheduler may trigger recovery but must never construct or alter
/// this value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexedOutboxRecoveryAuthority {
    domain: AtomicityDomainId,
    writer_fence: WriterFenceGeneration,
    operation_timeout_millis: NonZeroU64,
    lease_duration_millis: NonZeroU64,
}

impl IndexedOutboxRecoveryAuthority {
    /// Creates bounded recovery authority for one logical domain.
    pub fn new(
        domain: AtomicityDomainId,
        writer_fence: WriterFenceGeneration,
        operation_timeout_millis: u64,
        lease_duration_millis: u64,
    ) -> Result<Self, IndexedOutboxRecoveryAuthorityError> {
        let operation_timeout_millis = NonZeroU64::new(operation_timeout_millis)
            .ok_or(IndexedOutboxRecoveryAuthorityError::InvalidOperationTimeout)?;
        let lease_duration_millis = NonZeroU64::new(lease_duration_millis)
            .filter(|duration| duration.get() <= MAX_DURABLE_OUTBOX_LEASE_MILLIS)
            .ok_or(IndexedOutboxRecoveryAuthorityError::InvalidLeaseDuration)?;
        if operation_timeout_millis.get() > MAX_INDEXED_OUTBOX_OPERATION_MILLIS
            || operation_timeout_millis >= lease_duration_millis
        {
            return Err(IndexedOutboxRecoveryAuthorityError::InvalidOperationTimeout);
        }
        Ok(Self {
            domain,
            writer_fence,
            operation_timeout_millis,
            lease_duration_millis,
        })
    }

    /// Returns the configured logical domain.
    #[must_use]
    pub const fn domain(self) -> AtomicityDomainId {
        self.domain
    }

    /// Returns the configured authoritative writer generation.
    #[must_use]
    pub const fn writer_fence(self) -> WriterFenceGeneration {
        self.writer_fence
    }
}

/// Invalid indexed recovery authority configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndexedOutboxRecoveryAuthorityError {
    /// The operation timeout was zero, above its bound, or not below the lease.
    InvalidOperationTimeout,
    /// The lease duration was zero or above the shared durable bound.
    InvalidLeaseDuration,
}

impl fmt::Display for IndexedOutboxRecoveryAuthorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOperationTimeout => {
                f.write_str("indexed outbox operation timeout is invalid")
            }
            Self::InvalidLeaseDuration => f.write_str("indexed outbox lease duration is invalid"),
        }
    }
}

impl Error for IndexedOutboxRecoveryAuthorityError {}

/// One pair of restart-safe operational identities for an indexed claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexedOutboxAttemptIdentity {
    lease_id: DurableOutboxLeaseId,
    correlation_id: StorageCorrelationId,
}

impl IndexedOutboxAttemptIdentity {
    /// Creates one already-validated identity pair.
    #[must_use]
    pub const fn new(lease_id: DurableOutboxLeaseId, correlation_id: StorageCorrelationId) -> Self {
        Self {
            lease_id,
            correlation_id,
        }
    }
}

/// Supplies restart-safe lease and correlation identities before work is known.
pub trait IndexedOutboxIdentitySource {
    /// Returns identities that have never been used by another claim attempt.
    fn next_attempt_identity(
        &self,
    ) -> Result<IndexedOutboxAttemptIdentity, IndexedOutboxIdentitySourceError>;
}

/// Failures from the indexed recovery identity source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndexedOutboxIdentitySourceError {
    /// The backing entropy or durable sequence is temporarily unavailable.
    Unavailable,
    /// The source exhausted its non-repeating identity space.
    Exhausted,
}

impl fmt::Display for IndexedOutboxIdentitySourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => f.write_str("indexed outbox identity source is unavailable"),
            Self::Exhausted => f.write_str("indexed outbox identity source is exhausted"),
        }
    }
}

impl Error for IndexedOutboxIdentitySourceError {}

struct NativeHttpState<R, M, L> {
    runtime: Arc<R>,
    config: NodeConfig,
    resolver: HashSuiteResolver,
    machine: Arc<M>,
    lease_ids: Arc<L>,
    blocking_executor: NativeBlockingExecutor,
}

struct ResolvedDomainNativeHttpState<R, M, L> {
    runtime: Arc<R>,
    placement: DomainPlacementManifest,
    config: NodeConfig,
    resolver: HashSuiteResolver,
    machine: Arc<M>,
    lease_ids: Arc<L>,
    blocking_executor: NativeBlockingExecutor,
}

struct StructuredDurableNativeHttpState<S, B, M, T, C, I> {
    components: StructuredDurableNativeComponents<S, B, T, C, I>,
    protocol_config: ProtocolConfig,
    authority: StructuredDurableRequestAuthority,
    config: NodeConfig,
    resolver: HashSuiteResolver,
    machine: Arc<M>,
    blocking_executor: NativeBlockingExecutor,
}

type SharedStructuredDurableNativeHttpState<S, B, M, T, C, I> =
    Arc<StructuredDurableNativeHttpState<S, B, M, T, C, I>>;

struct PreinstalledWasmStructuredDurableNativeHttpState<S, B, M, T, C, I> {
    components: StructuredDurableNativeComponents<S, B, T, C, I>,
    preinstalled_wasm: PreinstalledWasmComposition,
    protocol_config: ProtocolConfig,
    authority: StructuredDurableRequestAuthority,
    config: NodeConfig,
    resolver: HashSuiteResolver,
    machine: Arc<M>,
    blocking_executor: NativeBlockingExecutor,
}

type SharedPreinstalledWasmStructuredDurableNativeHttpState<S, B, M, T, C, I> =
    Arc<PreinstalledWasmStructuredDurableNativeHttpState<S, B, M, T, C, I>>;

/// Builds the recoverable native HTTP router.
///
/// Application state, request deduplication, responses, and the ordered outbox
/// commit atomically. Outbound messages are sent only through persisted
/// lease/ack state, so a retry can recover a committed invocation.
pub fn router<R, M, L>(
    runtime: Arc<R>,
    config: NodeConfig,
    resolver: HashSuiteResolver,
    machine: Arc<M>,
    lease_ids: Arc<L>,
    blocking_policy: NativeBlockingPolicy,
) -> Router
where
    R: Runtime + Send + Sync + 'static,
    R::State: TransactionalStateStore,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    L: OutboxLeaseIdSource + Send + Sync + 'static,
{
    router_with_executor(
        runtime,
        config,
        resolver,
        machine,
        lease_ids,
        NativeBlockingExecutor::new(blocking_policy),
    )
}

/// Builds the native router with a reusable blocking admission executor.
///
/// Native embeddings that run unattended outbox recovery should share this
/// executor with [`recover_outboxes_once`].
pub fn router_with_executor<R, M, L>(
    runtime: Arc<R>,
    config: NodeConfig,
    resolver: HashSuiteResolver,
    machine: Arc<M>,
    lease_ids: Arc<L>,
    blocking_executor: NativeBlockingExecutor,
) -> Router
where
    R: Runtime + Send + Sync + 'static,
    R::State: TransactionalStateStore,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    L: OutboxLeaseIdSource + Send + Sync + 'static,
{
    let state = Arc::new(NativeHttpState {
        runtime,
        config,
        resolver,
        machine,
        lease_ids,
        blocking_executor,
    });
    Router::new()
        .route(LIVENESS_PATH, get(liveness))
        .route(NODE_EVENT_PATH, post(submit_event::<R, M, L>))
        .layer(DefaultBodyLimit::max(MAX_HTTP_EVENT_BODY_BYTES))
        .with_state(state)
}

/// Builds a native router that resolves state authority from protocol config.
///
/// This route is available only for stores implementing the explicit-domain
/// transaction contract. It never accepts a domain from the HTTP request and
/// carries node-core's resolved domain into request-scoped outbox delivery.
pub fn resolved_domain_router<R, M, L>(
    runtime: Arc<R>,
    placement: DomainPlacementManifest,
    config: NodeConfig,
    resolver: HashSuiteResolver,
    machine: Arc<M>,
    lease_ids: Arc<L>,
    blocking_policy: NativeBlockingPolicy,
) -> Router
where
    R: Runtime + Send + Sync + 'static,
    R::State: DomainTransactionalStateStore,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    L: OutboxLeaseIdSource + Send + Sync + 'static,
{
    resolved_domain_router_with_executor(
        runtime,
        placement,
        config,
        resolver,
        machine,
        lease_ids,
        NativeBlockingExecutor::new(blocking_policy),
    )
}

/// Builds a resolved-domain router with shared blocking admission.
pub fn resolved_domain_router_with_executor<R, M, L>(
    runtime: Arc<R>,
    placement: DomainPlacementManifest,
    config: NodeConfig,
    resolver: HashSuiteResolver,
    machine: Arc<M>,
    lease_ids: Arc<L>,
    blocking_executor: NativeBlockingExecutor,
) -> Router
where
    R: Runtime + Send + Sync + 'static,
    R::State: DomainTransactionalStateStore,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    L: OutboxLeaseIdSource + Send + Sync + 'static,
{
    let state = Arc::new(ResolvedDomainNativeHttpState {
        runtime,
        placement,
        config,
        resolver,
        machine,
        lease_ids,
        blocking_executor,
    });
    Router::new()
        .route(LIVENESS_PATH, get(liveness))
        .route(
            NODE_EVENT_PATH,
            post(submit_resolved_domain_event::<R, M, L>),
        )
        .layer(DefaultBodyLimit::max(MAX_HTTP_EVENT_BODY_BYTES))
        .with_state(state)
}

/// Builds the normalized durable native router.
///
/// This is the production-oriented composition seam: node-core commits typed
/// state, receipt, and outbox sections through one fenced transaction, then
/// native delivery claims only that committed request through the indexed
/// repository. Storage authority and operational identities come solely from
/// the embedding host.
///
/// This is also the only native route that authenticates `SubmitTransaction`
/// events: for that event kind, [`authenticate_submit_transaction_event`] runs
/// from `protocol_config` and the validated ingress context before any access-plan
/// derivation, identity allocation, clock read, storage I/O, transition,
/// outbox claim, or send. `protocol_config.protocol_version` must equal
/// `config.protocol_version()` and `protocol_config` must carry a
/// domain-placement manifest, checked once here rather than per request, so
/// this route never resolves its logical domain and its transaction-auth
/// authority from two silently diverging sources.
pub fn structured_durable_router<S, B, M, T, C, I>(
    components: StructuredDurableNativeComponents<S, B, T, C, I>,
    protocol_config: ProtocolConfig,
    authority: StructuredDurableRequestAuthority,
    config: NodeConfig,
    resolver: HashSuiteResolver,
    machine: Arc<M>,
    blocking_policy: NativeBlockingPolicy,
) -> Result<Router, StructuredDurableRouterError>
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
    B: BlobStore + Send + Sync + 'static,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    T: Transport + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    structured_durable_router_with_executor(
        components,
        protocol_config,
        authority,
        config,
        resolver,
        machine,
        NativeBlockingExecutor::new(blocking_policy),
    )
}

/// Builds the normalized durable router with shared blocking admission.
pub fn structured_durable_router_with_executor<S, B, M, T, C, I>(
    components: StructuredDurableNativeComponents<S, B, T, C, I>,
    protocol_config: ProtocolConfig,
    authority: StructuredDurableRequestAuthority,
    config: NodeConfig,
    resolver: HashSuiteResolver,
    machine: Arc<M>,
    blocking_executor: NativeBlockingExecutor,
) -> Result<Router, StructuredDurableRouterError>
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
    B: BlobStore + Send + Sync + 'static,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    T: Transport + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    validate_structured_durable_router_authority(&protocol_config, &config)?;
    let state = Arc::new(StructuredDurableNativeHttpState {
        components,
        protocol_config,
        authority,
        config,
        resolver,
        machine,
        blocking_executor,
    });
    Ok(Router::new()
        .route(LIVENESS_PATH, get(liveness))
        .route(
            NODE_EVENT_PATH,
            post(submit_structured_durable_event::<S, B, M, T, C, I>),
        )
        .route(
            QUERY_CONTEXT_PATH,
            get(get_structured_durable_context::<S, B, M, T, C, I>),
        )
        .route(
            QUERY_OBJECT_PATH,
            get(get_structured_durable_object::<S, B, M, T, C, I>),
        )
        .route(
            QUERY_RECEIPT_PATH,
            get(get_structured_durable_receipt::<S, B, M, T, C, I>),
        )
        .route(
            QUERY_NEXT_NONCE_PATH,
            get(get_structured_durable_next_nonce::<S, B, M, T, C, I>),
        )
        .layer(DefaultBodyLimit::max(MAX_HTTP_EVENT_BODY_BYTES))
        .with_state(state))
}

/// Builds the normalized durable native router with preinstalled-WASM
/// `SubmitTransaction` execution.
///
/// This is [`structured_durable_router`] with one difference: a
/// `SubmitTransaction` event is committed through
/// [`node_core::handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution`]
/// instead of the read-only entrypoint, so a signed owned `Write`/`Consume`
/// object access can execute a trusted preinstalled deterministic WASM
/// contract call and commit its object effects. Every other event kind
/// still runs through the same generic [`TransactionalNodeStateMachine`]
/// path as [`structured_durable_router`]. `preinstalled_wasm`'s catalog,
/// engine, and `created_checkpoint` are fixed, composition-trusted values
/// (see [`PreinstalledWasmComposition`]); none of them is ever derived from
/// an HTTP request or wall-clock time. [`structured_durable_router`] itself
/// is unaffected by this composition and remains read-only.
#[allow(clippy::too_many_arguments)]
pub fn preinstalled_wasm_structured_durable_router<S, B, M, T, C, I>(
    components: StructuredDurableNativeComponents<S, B, T, C, I>,
    preinstalled_wasm: PreinstalledWasmComposition,
    protocol_config: ProtocolConfig,
    authority: StructuredDurableRequestAuthority,
    config: NodeConfig,
    resolver: HashSuiteResolver,
    machine: Arc<M>,
    blocking_policy: NativeBlockingPolicy,
) -> Result<Router, StructuredDurableRouterError>
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
    B: BlobStore + Send + Sync + 'static,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    T: Transport + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    preinstalled_wasm_structured_durable_router_with_executor(
        components,
        preinstalled_wasm,
        protocol_config,
        authority,
        config,
        resolver,
        machine,
        NativeBlockingExecutor::new(blocking_policy),
    )
}

/// Builds the preinstalled-WASM durable router with shared blocking admission.
#[allow(clippy::too_many_arguments)]
pub fn preinstalled_wasm_structured_durable_router_with_executor<S, B, M, T, C, I>(
    components: StructuredDurableNativeComponents<S, B, T, C, I>,
    preinstalled_wasm: PreinstalledWasmComposition,
    protocol_config: ProtocolConfig,
    authority: StructuredDurableRequestAuthority,
    config: NodeConfig,
    resolver: HashSuiteResolver,
    machine: Arc<M>,
    blocking_executor: NativeBlockingExecutor,
) -> Result<Router, StructuredDurableRouterError>
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
    B: BlobStore + Send + Sync + 'static,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    T: Transport + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    validate_structured_durable_router_authority(&protocol_config, &config)?;
    let state = Arc::new(PreinstalledWasmStructuredDurableNativeHttpState {
        components,
        preinstalled_wasm,
        protocol_config,
        authority,
        config,
        resolver,
        machine,
        blocking_executor,
    });
    Ok(Router::new()
        .route(LIVENESS_PATH, get(liveness))
        .route(
            NODE_EVENT_PATH,
            post(submit_preinstalled_wasm_structured_durable_event::<S, B, M, T, C, I>),
        )
        .route(
            QUERY_CONTEXT_PATH,
            get(get_preinstalled_wasm_structured_durable_context::<S, B, M, T, C, I>),
        )
        .route(
            QUERY_OBJECT_PATH,
            get(get_preinstalled_wasm_structured_durable_object::<S, B, M, T, C, I>),
        )
        .route(
            QUERY_RECEIPT_PATH,
            get(get_preinstalled_wasm_structured_durable_receipt::<S, B, M, T, C, I>),
        )
        .route(
            QUERY_NEXT_NONCE_PATH,
            get(get_preinstalled_wasm_structured_durable_next_nonce::<S, B, M, T, C, I>),
        )
        .layer(DefaultBodyLimit::max(MAX_HTTP_EVENT_BODY_BYTES))
        .with_state(state))
}

/// Checked once at composition time by both [`structured_durable_router`] and
/// [`preinstalled_wasm_structured_durable_router`]: see
/// [`StructuredDurableRouterError`] for why this must never diverge per
/// request.
fn validate_structured_durable_router_authority(
    protocol_config: &ProtocolConfig,
    config: &NodeConfig,
) -> Result<(), StructuredDurableRouterError> {
    if protocol_config.protocol_version != config.protocol_version() {
        return Err(
            StructuredDurableRouterError::ProtocolVersionAuthorityMismatch {
                node_config: config.protocol_version(),
                protocol_config: protocol_config.protocol_version,
            },
        );
    }
    if protocol_config.domain_placement.is_none() {
        return Err(StructuredDurableRouterError::MissingDomainPlacement);
    }
    Ok(())
}

/// Serves a configured native router until the shutdown future completes.
///
/// Build `app` with [`router`], [`structured_durable_router`], or
/// [`preinstalled_wasm_structured_durable_router`] so the blocking admission
/// policy is explicit at the composition boundary.
pub async fn serve<F>(
    listener: tokio::net::TcpListener,
    app: Router,
    shutdown: F,
) -> std::io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
}

/// Result of one bounded scheduler-triggered recovery invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativeOutboxRecoveryOutcome {
    /// This page contained no expired or unleased pending outbox.
    NoEligibleOutbox,
    /// One pending outbox was delivered through its persisted cursor.
    Recovered(RequestId),
    /// Another invocation won the lease or state transaction race.
    Contended(RequestId),
}

/// Bounded progress returned to an untrusted external scheduler.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeOutboxRecoveryReport {
    outcome: NativeOutboxRecoveryOutcome,
    continuation_cursor: Option<Vec<u8>>,
}

impl NativeOutboxRecoveryReport {
    /// Returns what this invocation observed or recovered.
    #[must_use]
    pub const fn outcome(&self) -> &NativeOutboxRecoveryOutcome {
        &self.outcome
    }

    /// Returns the exclusive key cursor for the next page/invocation.
    ///
    /// `None` ends this sweep. A later scheduled sweep must start from `None`
    /// again to discover concurrent inserts and expired leases.
    #[must_use]
    pub fn continuation_cursor(&self) -> Option<&[u8]> {
        self.continuation_cursor.as_deref()
    }
}

/// Failures from one scheduler-triggered recovery invocation.
#[derive(Debug)]
pub enum NativeOutboxRecoveryError {
    /// Request work already occupies the configured blocking capacity.
    CapacityExhausted,
    /// The shared admission pool was closed.
    AdmissionClosed,
    /// Tokio could not join the blocking task.
    BlockingTaskFailed,
    /// Key discovery or durable state access failed.
    Runtime(RuntimeError),
    /// Persisted outbox state or a lease transition failed validation.
    Node(NodeCoreError),
    /// The outbound transport rejected a leased message.
    Send,
    /// A restart-safe lease identifier could not be allocated.
    LeaseId(OutboxLeaseIdSourceError),
}

impl fmt::Display for NativeOutboxRecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapacityExhausted => f.write_str("native blocking capacity is exhausted"),
            Self::AdmissionClosed => f.write_str("native blocking admission is closed"),
            Self::BlockingTaskFailed => f.write_str("native blocking recovery task failed"),
            Self::Runtime(error) => write!(f, "outbox discovery failed: {error}"),
            Self::Node(error) => write!(f, "outbox recovery failed: {error}"),
            Self::Send => f.write_str("outbox recovery transport send failed"),
            Self::LeaseId(error) => write!(f, "outbox recovery lease identity failed: {error}"),
        }
    }
}

impl Error for NativeOutboxRecoveryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Runtime(error) => Some(error),
            Self::Node(error) => Some(error),
            Self::LeaseId(error) => Some(error),
            _ => None,
        }
    }
}

/// Failures from one indexed production outbox recovery invocation.
#[derive(Debug)]
pub enum IndexedOutboxRecoveryError {
    /// Request work already occupies the configured blocking capacity.
    CapacityExhausted,
    /// The shared admission pool was closed.
    AdmissionClosed,
    /// Tokio could not join the bounded blocking task.
    BlockingTaskFailed,
    /// Trusted clock or transport runtime failed.
    Runtime(RuntimeError),
    /// Deadline or lease arithmetic overflowed.
    TimeOverflow,
    /// Restart-safe operational identities could not be allocated.
    Identity(IndexedOutboxIdentitySourceError),
    /// The indexed claim request or returned claim violated shared bounds.
    Contract(IndexedOutboxContractError),
    /// The repository proved that no claim lease was installed.
    ClaimRejected(DurableOutboxClaimRejection),
    /// The claim lease may have committed but could not be reconciled.
    ClaimIndeterminate(IndeterminateCommitReason),
    /// The repository returned a claim that did not match the requested lease.
    ClaimIdentityMismatch,
    /// The claimed canonical outbound event was invalid.
    Node(NodeCoreError),
    /// The outbound transport rejected the claimed canonical bytes.
    Send,
    /// The repository proved that the sent message was not acknowledged.
    AcknowledgementRejected(DurableOutboxAcknowledgementRejection),
    /// The acknowledgement may have committed but could not be reconciled.
    AcknowledgementIndeterminate(IndeterminateCommitReason),
}

impl fmt::Display for IndexedOutboxRecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapacityExhausted => f.write_str("native blocking capacity is exhausted"),
            Self::AdmissionClosed => f.write_str("native blocking admission is closed"),
            Self::BlockingTaskFailed => f.write_str("indexed recovery blocking task failed"),
            Self::Runtime(error) => write!(f, "indexed recovery runtime failed: {error}"),
            Self::TimeOverflow => f.write_str("indexed recovery time arithmetic overflowed"),
            Self::Identity(error) => write!(f, "indexed recovery identity failed: {error}"),
            Self::Contract(error) => write!(f, "indexed recovery contract failed: {error}"),
            Self::ClaimRejected(reason) => {
                write!(f, "indexed outbox claim was rejected: {reason:?}")
            }
            Self::ClaimIndeterminate(reason) => {
                write!(f, "indexed outbox claim is indeterminate: {reason:?}")
            }
            Self::ClaimIdentityMismatch => {
                f.write_str("indexed outbox claim identity did not match request")
            }
            Self::Node(error) => write!(f, "indexed outbox payload is invalid: {error}"),
            Self::Send => f.write_str("indexed outbox transport send failed"),
            Self::AcknowledgementRejected(reason) => {
                write!(f, "indexed outbox acknowledgement was rejected: {reason:?}")
            }
            Self::AcknowledgementIndeterminate(reason) => write!(
                f,
                "indexed outbox acknowledgement is indeterminate: {reason:?}"
            ),
        }
    }
}

impl Error for IndexedOutboxRecoveryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Runtime(error) => Some(error),
            Self::Identity(error) => Some(error),
            Self::Contract(error) => Some(error),
            Self::Node(error) => Some(error),
            _ => None,
        }
    }
}

/// Claims, sends, and acknowledges at most one indexed due outbox message.
///
/// The scheduler supplies no cursor, domain, clock, fence, or deadline. Trusted
/// embedding composition supplies immutable authority and identity sources.
/// Claim and acknowledgement ambiguity each receive one same-identity
/// reconciliation attempt; an unreconciled claim is never sent.
pub async fn recover_indexed_outbox_once<R, I>(
    runtime: Arc<R>,
    authority: IndexedOutboxRecoveryAuthority,
    identities: Arc<I>,
    blocking_executor: NativeBlockingExecutor,
) -> Result<NativeOutboxRecoveryReport, IndexedOutboxRecoveryError>
where
    R: Runtime + Send + Sync + 'static,
    R::State: IndexedOutboxRepository,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    let permit = match blocking_executor.try_acquire() {
        Ok(permit) => permit,
        Err(TryAcquireError::NoPermits) => {
            return Err(IndexedOutboxRecoveryError::CapacityExhausted);
        }
        Err(TryAcquireError::Closed) => {
            return Err(IndexedOutboxRecoveryError::AdmissionClosed);
        }
    };
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        recover_indexed_outbox_once_blocking(runtime.as_ref(), authority, identities.as_ref())
    })
    .await
    .map_err(|_| IndexedOutboxRecoveryError::BlockingTaskFailed)?
}

fn recover_indexed_outbox_once_blocking<R, I>(
    runtime: &R,
    authority: IndexedOutboxRecoveryAuthority,
    identities: &I,
) -> Result<NativeOutboxRecoveryReport, IndexedOutboxRecoveryError>
where
    R: Runtime,
    R::State: IndexedOutboxRepository,
    I: IndexedOutboxIdentitySource,
{
    let now_unix_millis = runtime
        .clock()
        .now_unix_millis()
        .map_err(IndexedOutboxRecoveryError::Runtime)?;
    let deadline_unix_millis = now_unix_millis
        .checked_add(authority.operation_timeout_millis.get())
        .ok_or(IndexedOutboxRecoveryError::TimeOverflow)?;
    let lease_expires_at_unix_millis = now_unix_millis
        .checked_add(authority.lease_duration_millis.get())
        .ok_or(IndexedOutboxRecoveryError::TimeOverflow)?;
    let identity = identities
        .next_attempt_identity()
        .map_err(IndexedOutboxRecoveryError::Identity)?;
    let context = DurableOperationContext::new(
        authority.writer_fence,
        StorageDeadline::new(deadline_unix_millis)
            .ok_or(IndexedOutboxRecoveryError::TimeOverflow)?,
        identity.correlation_id,
    );
    let claim_request = DueOutboxClaimRequest::new(
        authority.domain,
        now_unix_millis,
        identity.lease_id,
        lease_expires_at_unix_millis,
    )
    .map_err(IndexedOutboxRecoveryError::Contract)?;

    let claim = reconcile_indexed_claim(runtime.state_store(), &context, claim_request)?;
    let Some(claim) = claim else {
        return Ok(NativeOutboxRecoveryReport {
            outcome: NativeOutboxRecoveryOutcome::NoEligibleOutbox,
            continuation_cursor: None,
        });
    };
    if claim.lease_id() != identity.lease_id
        || claim.lease_expires_at_unix_millis() != lease_expires_at_unix_millis
    {
        return Err(IndexedOutboxRecoveryError::ClaimIdentityMismatch);
    }
    let event =
        NodeEvent::decode(claim.canonical_payload()).map_err(IndexedOutboxRecoveryError::Node)?;
    let canonical_payload = event.encode().map_err(IndexedOutboxRecoveryError::Node)?;
    if canonical_payload != claim.canonical_payload() {
        return Err(IndexedOutboxRecoveryError::Node(
            NodeCoreError::PersistenceInvariant("indexed outbox payload is not canonical"),
        ));
    }
    runtime
        .transport()
        .send(canonical_payload)
        .map_err(|_| IndexedOutboxRecoveryError::Send)?;

    let acknowledgement = DurableOutboxAcknowledgement::new(
        authority.domain,
        claim.request_id(),
        claim.message_index(),
        claim.lease_id(),
    );
    reconcile_indexed_acknowledgement(runtime.state_store(), &context, acknowledgement)?;
    let request_id =
        RequestId::new(*claim.request_id().as_bytes()).map_err(IndexedOutboxRecoveryError::Node)?;
    Ok(NativeOutboxRecoveryReport {
        outcome: NativeOutboxRecoveryOutcome::Recovered(request_id),
        continuation_cursor: None,
    })
}

fn reconcile_indexed_claim<S>(
    store: &S,
    context: &DurableOperationContext,
    request: DueOutboxClaimRequest,
) -> Result<Option<runtime::DurableOutboxClaim>, IndexedOutboxRecoveryError>
where
    S: IndexedOutboxRepository,
{
    match store.claim_due_outbox(context, request) {
        DurableOutboxClaimOutcome::Claimed(claim) => Ok(Some(claim)),
        DurableOutboxClaimOutcome::NoDueWork => Ok(None),
        DurableOutboxClaimOutcome::Rejected(reason) => {
            Err(IndexedOutboxRecoveryError::ClaimRejected(reason))
        }
        DurableOutboxClaimOutcome::Indeterminate(first_reason) => {
            match store.claim_due_outbox(context, request) {
                DurableOutboxClaimOutcome::Claimed(claim) => Ok(Some(claim)),
                _ => Err(IndexedOutboxRecoveryError::ClaimIndeterminate(first_reason)),
            }
        }
    }
}

fn reconcile_indexed_acknowledgement<S>(
    store: &S,
    context: &DurableOperationContext,
    acknowledgement: DurableOutboxAcknowledgement,
) -> Result<(), IndexedOutboxRecoveryError>
where
    S: IndexedOutboxRepository,
{
    match store.acknowledge_outbox(context, acknowledgement) {
        DurableOutboxAcknowledgementOutcome::Acknowledged => Ok(()),
        DurableOutboxAcknowledgementOutcome::Rejected(reason) => {
            Err(IndexedOutboxRecoveryError::AcknowledgementRejected(reason))
        }
        DurableOutboxAcknowledgementOutcome::Indeterminate(first_reason) => {
            match store.acknowledge_outbox(context, acknowledgement) {
                DurableOutboxAcknowledgementOutcome::Acknowledged => Ok(()),
                _ => Err(IndexedOutboxRecoveryError::AcknowledgementIndeterminate(
                    first_reason,
                )),
            }
        }
    }
}

/// Recovers at most one unattended outbox without requiring a live request.
///
/// The caller is an untrusted scheduler: it supplies only a bounded scan cursor
/// and page size, and must invoke this function again while a continuation is
/// returned. A later sweep restarts with `after = None`. This function creates
/// no loop or background task and shares admission with HTTP when given the
/// same [`NativeBlockingExecutor`].
pub async fn recover_outboxes_once<R, L>(
    runtime: Arc<R>,
    config: NodeConfig,
    lease_ids: Arc<L>,
    blocking_executor: NativeBlockingExecutor,
    after: Option<Vec<u8>>,
    scan_limit: NonZeroUsize,
) -> Result<NativeOutboxRecoveryReport, NativeOutboxRecoveryError>
where
    R: Runtime + Send + Sync + 'static,
    R::State: TransactionalStateStore + StateKeyScanner,
    L: OutboxLeaseIdSource + Send + Sync + 'static,
{
    let layout = PersistenceLayout::new(config.chain_id().clone(), config.protocol_version());
    let scan = StateKeyScan::new(layout.outbox_prefix(), after, scan_limit)
        .map_err(NativeOutboxRecoveryError::Runtime)?;
    let permit = match blocking_executor.try_acquire() {
        Ok(permit) => permit,
        Err(TryAcquireError::NoPermits) => {
            return Err(NativeOutboxRecoveryError::CapacityExhausted);
        }
        Err(TryAcquireError::Closed) => {
            return Err(NativeOutboxRecoveryError::AdmissionClosed);
        }
    };
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        recover_outboxes_once_blocking(runtime.as_ref(), &config, lease_ids.as_ref(), &scan)
    })
    .await
    .map_err(|_| NativeOutboxRecoveryError::BlockingTaskFailed)?
}

fn recover_outboxes_once_blocking<R, L>(
    runtime: &R,
    config: &NodeConfig,
    lease_ids: &L,
    scan: &StateKeyScan,
) -> Result<NativeOutboxRecoveryReport, NativeOutboxRecoveryError>
where
    R: Runtime,
    R::State: TransactionalStateStore + StateKeyScanner,
    L: OutboxLeaseIdSource,
{
    let page = runtime
        .state_store()
        .scan_keys(scan)
        .map_err(NativeOutboxRecoveryError::Runtime)?;
    let layout = PersistenceLayout::new(config.chain_id().clone(), config.protocol_version());
    let now_unix_millis = runtime
        .clock()
        .now_unix_millis()
        .map_err(NativeOutboxRecoveryError::Runtime)?;

    for (index, key) in page.keys().iter().enumerate() {
        if !key.ends_with(b"/delivery") {
            continue;
        }
        let delivery_value = runtime
            .state_store()
            .get_versioned(key)
            .map_err(NativeOutboxRecoveryError::Runtime)?;
        let Some(delivery_bytes) = delivery_value.value() else {
            continue;
        };
        let delivery =
            NodeOutboxDelivery::decode(delivery_bytes).map_err(NativeOutboxRecoveryError::Node)?;
        let request_id = delivery.request_id();
        if layout.outbox_delivery_key(*request_id.as_bytes()) != *key {
            return Err(NativeOutboxRecoveryError::Node(
                NodeCoreError::PersistenceInvariant("outbox delivery key does not match record"),
            ));
        }
        let batch_value = runtime
            .state_store()
            .get_versioned(&layout.outbox_batch_key(*request_id.as_bytes()))
            .map_err(NativeOutboxRecoveryError::Runtime)?;
        let batch = NodeOutboxBatch::decode(batch_value.value().ok_or({
            NativeOutboxRecoveryError::Node(NodeCoreError::PersistenceInvariant(
                "outbox delivery exists without batch",
            ))
        })?)
        .map_err(NativeOutboxRecoveryError::Node)?;
        if batch.request_id() != request_id || batch.event_digest() != delivery.event_digest() {
            return Err(NativeOutboxRecoveryError::Node(
                NodeCoreError::PersistenceInvariant("outbox batch and delivery identities differ"),
            ));
        }
        let next_index = usize::try_from(delivery.next_index()).map_err(|_| {
            NativeOutboxRecoveryError::Node(NodeCoreError::OutboxArithmeticOverflow)
        })?;
        if next_index > batch.messages().len() {
            return Err(NativeOutboxRecoveryError::Node(
                NodeCoreError::PersistenceInvariant("outbox cursor exceeds batch length"),
            ));
        }
        if next_index == batch.messages().len()
            || delivery
                .lease()
                .is_some_and(|(_, expires_at)| expires_at > now_unix_millis)
        {
            continue;
        }

        let has_later_keys = index + 1 < page.keys().len() || page.continuation_cursor().is_some();
        let continuation_cursor = has_later_keys.then(|| key.clone());
        let outcome = match deliver_request_outbox(runtime, config, lease_ids, request_id) {
            Ok(0) => NativeOutboxRecoveryOutcome::Contended(request_id),
            Ok(_) => NativeOutboxRecoveryOutcome::Recovered(request_id),
            Err(OutboxDeliveryError::Node(
                NodeCoreError::OutboxLeaseActive { .. } | NodeCoreError::StateConflict,
            )) => NativeOutboxRecoveryOutcome::Contended(request_id),
            Err(error) => return Err(recovery_delivery_error(error)),
        };
        return Ok(NativeOutboxRecoveryReport {
            outcome,
            continuation_cursor,
        });
    }

    Ok(NativeOutboxRecoveryReport {
        outcome: NativeOutboxRecoveryOutcome::NoEligibleOutbox,
        continuation_cursor: page.continuation_cursor().map(<[u8]>::to_vec),
    })
}

async fn liveness() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn submit_event<R, M, L>(
    State(state): State<Arc<NativeHttpState<R, M, L>>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response
where
    R: Runtime + Send + Sync + 'static,
    R::State: TransactionalStateStore,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    L: OutboxLeaseIdSource + Send + Sync + 'static,
{
    if !has_supported_content_type(&headers) {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-content-type",
        );
    }
    if has_unsupported_content_encoding(&headers) {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-content-encoding",
        );
    }
    let body = match body {
        Ok(body) => body,
        Err(error) => return error_response(error.status(), "body-rejected"),
    };
    let permit = match state.blocking_executor.try_acquire() {
        Ok(permit) => permit,
        Err(TryAcquireError::NoPermits) => return overload_response(),
        Err(TryAcquireError::Closed) => {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "blocking-admission-closed");
        }
    };
    let blocking_state = Arc::clone(&state);
    let work = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        invoke_event(blocking_state.as_ref(), &body)
    });
    let result = match work.await {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => return invocation_error_response(&error),
        Err(_) => {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "blocking-task-failed");
        }
    };
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, NODE_RESULT_MEDIA_TYPE),
            (header::CACHE_CONTROL, "no-store"),
        ],
        result,
    )
        .into_response()
}

async fn submit_resolved_domain_event<R, M, L>(
    State(state): State<Arc<ResolvedDomainNativeHttpState<R, M, L>>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response
where
    R: Runtime + Send + Sync + 'static,
    R::State: DomainTransactionalStateStore,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    L: OutboxLeaseIdSource + Send + Sync + 'static,
{
    if !has_supported_content_type(&headers) {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-content-type",
        );
    }
    if has_unsupported_content_encoding(&headers) {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-content-encoding",
        );
    }
    let body = match body {
        Ok(body) => body,
        Err(error) => return error_response(error.status(), "body-rejected"),
    };
    let permit = match state.blocking_executor.try_acquire() {
        Ok(permit) => permit,
        Err(TryAcquireError::NoPermits) => return overload_response(),
        Err(TryAcquireError::Closed) => {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "blocking-admission-closed");
        }
    };
    let blocking_state = Arc::clone(&state);
    let work = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        invoke_resolved_domain_event(blocking_state.as_ref(), &body)
    });
    let result = match work.await {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => return invocation_error_response(&error),
        Err(_) => {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "blocking-task-failed");
        }
    };
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, NODE_RESULT_MEDIA_TYPE),
            (header::CACHE_CONTROL, "no-store"),
        ],
        result,
    )
        .into_response()
}

/// Shared request-shape/admission/cancellation plumbing behind both
/// [`submit_structured_durable_event`] and
/// [`submit_preinstalled_wasm_structured_durable_event`].
///
/// `initial_cancelled` is the caller's own pre-storage cancellation
/// observation, taken from its typed state before this call; the inner
/// structured-durable core (`invoke_structured_durable_event_with_execution`)
/// still re-checks cancellation itself once the durable operation context is
/// built, so cancellation is checked at both points on every route, not only
/// here. `work` runs the caller's exact blocking invocation (`invoke_*`)
/// against the extracted body bytes inside the shared blocking-admission
/// isolation.
async fn submit_structured_durable_event_common<F>(
    initial_cancelled: bool,
    blocking_executor: NativeBlockingExecutor,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
    work: F,
) -> Response
where
    F: FnOnce(Bytes) -> Result<Vec<u8>, InvocationError> + Send + 'static,
{
    if !has_supported_content_type(&headers) {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-content-type",
        );
    }
    if has_unsupported_content_encoding(&headers) {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-content-encoding",
        );
    }
    let body = match body {
        Ok(body) => body,
        Err(error) => return error_response(error.status(), "body-rejected"),
    };
    if initial_cancelled {
        return cancelled_before_storage_response();
    }
    let permit = match blocking_executor.try_acquire() {
        Ok(permit) => permit,
        Err(TryAcquireError::NoPermits) => return overload_response(),
        Err(TryAcquireError::Closed) => {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "blocking-admission-closed");
        }
    };
    let blocking_work = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work(body)
    });
    let result = match blocking_work.await {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => return invocation_error_response(&error),
        Err(_) => {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "blocking-task-failed");
        }
    };
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, NODE_RESULT_MEDIA_TYPE),
            (header::CACHE_CONTROL, "no-store"),
        ],
        result,
    )
        .into_response()
}

async fn submit_structured_durable_event<S, B, M, T, C, I>(
    State(state): State<SharedStructuredDurableNativeHttpState<S, B, M, T, C, I>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
    B: BlobStore + Send + Sync + 'static,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    T: Transport + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    let initial_cancelled = state.components.is_cancelled();
    let blocking_executor = state.blocking_executor.clone();
    submit_structured_durable_event_common(
        initial_cancelled,
        blocking_executor,
        headers,
        body,
        move |body| invoke_structured_durable_event(state.as_ref(), &body),
    )
    .await
}

async fn submit_preinstalled_wasm_structured_durable_event<S, B, M, T, C, I>(
    State(state): State<SharedPreinstalledWasmStructuredDurableNativeHttpState<S, B, M, T, C, I>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
    B: BlobStore + Send + Sync + 'static,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    T: Transport + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    let initial_cancelled = state.components.is_cancelled();
    let blocking_executor = state.blocking_executor.clone();
    submit_structured_durable_event_common(
        initial_cancelled,
        blocking_executor,
        headers,
        body,
        move |body| invoke_preinstalled_wasm_structured_durable_event(state.as_ref(), &body),
    )
    .await
}

/// Failures from one bounded query invocation (DR-0082).
///
/// A syntactically valid, admitted query maps transient host/storage
/// conditions to an opaque `503` and invalid persisted state or permanent
/// host failures to an opaque `500`; caller-supplied malformed selectors are
/// rejected before this point.
enum QueryInvocationError {
    CancelledBeforeStorage,
    /// The restart-safe identity source could not allocate an identity right
    /// now: a transient host condition, classified `503`.
    IdentityUnavailable,
    /// The restart-safe identity source permanently exhausted its identity
    /// space: a host/operator failure distinct from transient unavailability,
    /// classified `500`.
    IdentityExhausted,
    Node(NodeCoreError),
    ResultEncoding,
}

async fn query_structured_durable_common<F>(
    initial_cancelled: bool,
    blocking_executor: NativeBlockingExecutor,
    work: F,
) -> Response
where
    F: FnOnce() -> Result<Vec<u8>, QueryInvocationError> + Send + 'static,
{
    if initial_cancelled {
        return cancelled_before_storage_response();
    }
    let permit = match blocking_executor.try_acquire() {
        Ok(permit) => permit,
        Err(TryAcquireError::NoPermits) => return overload_response(),
        Err(TryAcquireError::Closed) => {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "blocking-admission-closed");
        }
    };
    let blocking_work = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    });
    let result = match blocking_work.await {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => return query_invocation_error_response(&error),
        Err(_) => {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "blocking-task-failed");
        }
    };
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, QUERY_RESULT_MEDIA_TYPE),
            (header::CACHE_CONTROL, "no-store"),
        ],
        result,
    )
        .into_response()
}

fn query_invocation_error_response(error: &QueryInvocationError) -> Response {
    match error {
        QueryInvocationError::CancelledBeforeStorage => cancelled_before_storage_response(),
        QueryInvocationError::IdentityUnavailable => {
            error_response(StatusCode::SERVICE_UNAVAILABLE, "query-unavailable")
        }
        QueryInvocationError::IdentityExhausted | QueryInvocationError::ResultEncoding => {
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "query-state-invalid")
        }
        QueryInvocationError::Node(error) => {
            let (status, code) = query_node_error_response_parts(error);
            error_response(status, code)
        }
    }
}

/// Classifies a query-path [`NodeCoreError`] into one of exactly two opaque
/// query responses (DR-0082).
///
/// `503 query-unavailable` covers a transient host or storage-availability
/// condition: clock/runtime failure, a durable read that proves writer
/// fencing, deadline exhaustion, or backend unavailability, an unsupported
/// durable schema identity/generation
/// (`runtime::DurableReadError::SchemaMismatch`), or committed
/// `ProtocolConfig` inactivity/misconfiguration (missing domain placement,
/// an inactive placement at the current epoch, or a missing/invalid
/// transaction-auth profile). `500 query-state-invalid` covers everything
/// else: corrupt or unverifiable persisted content and result-encoding
/// failure, which by construction can only arise from storage corruption or
/// a host bug, never from caller-supplied input (malformed selectors are
/// rejected before any of this runs).
///
/// `SchemaMismatch` is deliberately grouped with `503`, not `500`: it proves
/// the adapter's durable schema generation disagrees with what was persisted
/// — an operator/deployment condition an operator can resolve by restoring a
/// compatible adapter or completing a migration — never that the persisted
/// bytes themselves are corrupt or unverifiable.
fn query_node_error_response_parts(error: &NodeCoreError) -> (StatusCode, &'static str) {
    let unavailable = matches!(
        error,
        NodeCoreError::Runtime(_)
            | NodeCoreError::ProtocolConfig(_)
            | NodeCoreError::DurableRead(
                runtime::DurableReadError::WriterFenced { .. }
                    | runtime::DurableReadError::DeadlineExceeded
                    | runtime::DurableReadError::Unavailable
                    | runtime::DurableReadError::SchemaMismatch,
            )
    );
    if unavailable {
        (StatusCode::SERVICE_UNAVAILABLE, "query-unavailable")
    } else {
        (StatusCode::INTERNAL_SERVER_ERROR, "query-state-invalid")
    }
}

/// Decodes exactly 64 lowercase ASCII hex characters into 32 bytes.
///
/// Every path selector accepted by the bounded query API must be validated
/// through this function before any identity allocation, clock access, or
/// storage I/O runs.
fn decode_hex64_selector(input: &str) -> Option<[u8; 32]> {
    let bytes = input.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0_u8; 32];
    for (index, chunk) in bytes.chunks_exact(2).enumerate() {
        out[index] = (hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?;
    }
    Some(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Resolves the logical domain for a query request through
/// [`DomainPlacementManifest::resolve_domain`] at `config.epoch()` with one
/// bounded access — the same activation-epoch-checked path the authenticated
/// write path uses — rather than reading `placement.domain()`
/// unconditionally, so an inactive placement classifies identically across
/// every query route, including `/v1/context`, instead of only where storage
/// I/O happens to run.
fn resolve_query_domain(
    placement: &DomainPlacementManifest,
    config: &NodeConfig,
) -> Result<AtomicityDomainId, QueryInvocationError> {
    placement
        .resolve_domain(config.epoch(), 1)
        .map_err(NodeCoreError::from)
        .map_err(QueryInvocationError::Node)
}

fn invoke_query_context(
    config: &NodeConfig,
    protocol_config: &ProtocolConfig,
) -> Result<Vec<u8>, QueryInvocationError> {
    let placement = protocol_config
        .domain_placement
        .as_ref()
        .ok_or(ProtocolConfigError::MissingDomainPlacement)
        .map_err(NodeCoreError::from)
        .map_err(QueryInvocationError::Node)?;
    let domain = resolve_query_domain(placement, config)?;
    let profile = resolve_transaction_auth_profile(protocol_config)
        .map_err(NodeCoreError::from)
        .map_err(QueryInvocationError::Node)?;
    let protocol_config_bytes = protocol_config
        .canonical_bytes()
        .map_err(NodeCoreError::from)
        .map_err(QueryInvocationError::Node)?;
    let result = HttpContextQueryResult::new(
        config.chain_id().clone(),
        config.protocol_version(),
        config.epoch(),
        protocol_config.hash_suite_id,
        profile.profile_id(),
        profile.signature_scheme_id().as_u16(),
        profile.address_binding().as_u16(),
        domain,
        protocol_config_bytes,
    )
    .map_err(|_| QueryInvocationError::ResultEncoding)?;
    result
        .encode()
        .map_err(|_| QueryInvocationError::ResultEncoding)
}

/// Allocates the same trusted storage authority every storage-backed query
/// route shares: a resolved logical domain, a restart-safe correlation
/// identity, and a bounded deadline, all from trusted composition rather
/// than the HTTP request.
///
/// The domain is resolved through [`resolve_query_domain`], so an inactive
/// placement rejects before identity allocation, clock access, or storage
/// I/O exactly like every other storage-backed query failure.
fn prepare_query_storage_context<S, B, T, C, I>(
    components: &StructuredDurableNativeComponents<S, B, T, C, I>,
    protocol_config: &ProtocolConfig,
    authority: &StructuredDurableRequestAuthority,
    config: &NodeConfig,
) -> Result<(AtomicityDomainId, DurableOperationContext), QueryInvocationError>
where
    I: IndexedOutboxIdentitySource,
    C: Clock,
{
    let placement = protocol_config
        .domain_placement
        .as_ref()
        .ok_or(ProtocolConfigError::MissingDomainPlacement)
        .map_err(NodeCoreError::from)
        .map_err(QueryInvocationError::Node)?;
    let domain = resolve_query_domain(placement, config)?;
    let identity = components
        .identities
        .next_attempt_identity()
        .map_err(|error| match error {
            IndexedOutboxIdentitySourceError::Unavailable => {
                QueryInvocationError::IdentityUnavailable
            }
            IndexedOutboxIdentitySourceError::Exhausted => QueryInvocationError::IdentityExhausted,
        })?;
    let now_unix_millis = components
        .clock
        .now_unix_millis()
        .map_err(|error| QueryInvocationError::Node(NodeCoreError::Runtime(error)))?;
    let deadline_unix_millis = now_unix_millis
        .checked_add(authority.operation_timeout_millis.get())
        .ok_or(QueryInvocationError::Node(
            NodeCoreError::PersistenceInvariant("query deadline arithmetic overflowed"),
        ))?;
    let deadline = StorageDeadline::new(deadline_unix_millis).ok_or(QueryInvocationError::Node(
        NodeCoreError::PersistenceInvariant("query deadline arithmetic overflowed"),
    ))?;
    let context =
        DurableOperationContext::new(authority.writer_fence, deadline, identity.correlation_id);
    Ok((domain, context))
}

fn invoke_query_object<S, B, T, C, I>(
    components: &StructuredDurableNativeComponents<S, B, T, C, I>,
    protocol_config: &ProtocolConfig,
    authority: &StructuredDurableRequestAuthority,
    config: &NodeConfig,
    object_id: ObjectId,
) -> Result<Vec<u8>, QueryInvocationError>
where
    S: StructuredDurableDomainStateStore,
    T: Transport,
    C: Clock,
    I: IndexedOutboxIdentitySource,
{
    if components.is_cancelled() {
        return Err(QueryInvocationError::CancelledBeforeStorage);
    }
    let (domain, context) =
        prepare_query_storage_context(components, protocol_config, authority, config)?;
    if components.is_cancelled() {
        return Err(QueryInvocationError::CancelledBeforeStorage);
    }
    let result = query_object(
        components.store.as_ref(),
        &context,
        domain,
        config.chain_id(),
        object_id,
    )
    .map_err(QueryInvocationError::Node)?;
    // Defense in depth: never bind the answer to a different selector than
    // was requested, even under a future node-core regression.
    if result.object_id() != object_id {
        return Err(QueryInvocationError::Node(
            NodeCoreError::PersistenceInvariant(
                "query result object id disagreed with the requested selector",
            ),
        ));
    }
    HttpObjectQueryResult::from(result)
        .encode()
        .map_err(|_| QueryInvocationError::ResultEncoding)
}

fn invoke_query_receipt<S, B, T, C, I>(
    components: &StructuredDurableNativeComponents<S, B, T, C, I>,
    protocol_config: &ProtocolConfig,
    authority: &StructuredDurableRequestAuthority,
    config: &NodeConfig,
    request_id: RequestId,
) -> Result<Vec<u8>, QueryInvocationError>
where
    S: StructuredDurableDomainStateStore,
    T: Transport,
    C: Clock,
    I: IndexedOutboxIdentitySource,
{
    if components.is_cancelled() {
        return Err(QueryInvocationError::CancelledBeforeStorage);
    }
    let (domain, context) =
        prepare_query_storage_context(components, protocol_config, authority, config)?;
    if components.is_cancelled() {
        return Err(QueryInvocationError::CancelledBeforeStorage);
    }
    let result = query_request_receipt(components.store.as_ref(), &context, domain, request_id)
        .map_err(QueryInvocationError::Node)?;
    // Defense in depth: never bind the answer to a different selector than
    // was requested, even under a future node-core regression.
    if result.request_id() != request_id {
        return Err(QueryInvocationError::Node(
            NodeCoreError::PersistenceInvariant(
                "query result request id disagreed with the requested selector",
            ),
        ));
    }
    let wire = http_receipt_query_result(result).map_err(QueryInvocationError::Node)?;
    wire.encode()
        .map_err(|_| QueryInvocationError::ResultEncoding)
}

fn invoke_query_next_nonce<S, B, T, C, I>(
    components: &StructuredDurableNativeComponents<S, B, T, C, I>,
    protocol_config: &ProtocolConfig,
    authority: &StructuredDurableRequestAuthority,
    config: &NodeConfig,
    sender: [u8; 32],
) -> Result<Vec<u8>, QueryInvocationError>
where
    S: StructuredDurableDomainStateStore,
    T: Transport,
    C: Clock,
    I: IndexedOutboxIdentitySource,
{
    if components.is_cancelled() {
        return Err(QueryInvocationError::CancelledBeforeStorage);
    }
    let (domain, context) =
        prepare_query_storage_context(components, protocol_config, authority, config)?;
    if components.is_cancelled() {
        return Err(QueryInvocationError::CancelledBeforeStorage);
    }
    let epoch = config.epoch();
    let next_nonce = query_sender_next_nonce(
        components.store.as_ref(),
        &context,
        domain,
        config.chain_id().clone(),
        config.protocol_version(),
        epoch,
        sender,
    )
    .map_err(QueryInvocationError::Node)?;
    HttpNextNonceQueryResult::new(Address::new(sender), epoch, next_nonce)
        .encode()
        .map_err(|_| QueryInvocationError::ResultEncoding)
}

async fn get_structured_durable_context<S, B, M, T, C, I>(
    State(state): State<SharedStructuredDurableNativeHttpState<S, B, M, T, C, I>>,
) -> Response
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
    B: BlobStore + Send + Sync + 'static,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    T: Transport + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    let initial_cancelled = state.components.is_cancelled();
    let blocking_executor = state.blocking_executor.clone();
    query_structured_durable_common(initial_cancelled, blocking_executor, move || {
        invoke_query_context(&state.config, &state.protocol_config)
    })
    .await
}

async fn get_structured_durable_object<S, B, M, T, C, I>(
    State(state): State<SharedStructuredDurableNativeHttpState<S, B, M, T, C, I>>,
    Path(object_id_hex): Path<String>,
) -> Response
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
    B: BlobStore + Send + Sync + 'static,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    T: Transport + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    let object_id = match decode_hex64_selector(&object_id_hex) {
        Some(bytes) => ObjectId::new(bytes),
        None => return error_response(StatusCode::BAD_REQUEST, "invalid-object-id"),
    };
    let initial_cancelled = state.components.is_cancelled();
    let blocking_executor = state.blocking_executor.clone();
    query_structured_durable_common(initial_cancelled, blocking_executor, move || {
        invoke_query_object(
            &state.components,
            &state.protocol_config,
            &state.authority,
            &state.config,
            object_id,
        )
    })
    .await
}

async fn get_structured_durable_receipt<S, B, M, T, C, I>(
    State(state): State<SharedStructuredDurableNativeHttpState<S, B, M, T, C, I>>,
    Path(request_id_hex): Path<String>,
) -> Response
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
    B: BlobStore + Send + Sync + 'static,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    T: Transport + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    let request_id =
        match decode_hex64_selector(&request_id_hex).and_then(|bytes| RequestId::new(bytes).ok()) {
            Some(request_id) => request_id,
            None => return error_response(StatusCode::BAD_REQUEST, "invalid-request-id"),
        };
    let initial_cancelled = state.components.is_cancelled();
    let blocking_executor = state.blocking_executor.clone();
    query_structured_durable_common(initial_cancelled, blocking_executor, move || {
        invoke_query_receipt(
            &state.components,
            &state.protocol_config,
            &state.authority,
            &state.config,
            request_id,
        )
    })
    .await
}

async fn get_structured_durable_next_nonce<S, B, M, T, C, I>(
    State(state): State<SharedStructuredDurableNativeHttpState<S, B, M, T, C, I>>,
    Path(sender_hex): Path<String>,
) -> Response
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
    B: BlobStore + Send + Sync + 'static,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    T: Transport + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    let sender = match decode_hex64_selector(&sender_hex) {
        Some(sender) => sender,
        None => return error_response(StatusCode::BAD_REQUEST, "invalid-sender"),
    };
    let initial_cancelled = state.components.is_cancelled();
    let blocking_executor = state.blocking_executor.clone();
    query_structured_durable_common(initial_cancelled, blocking_executor, move || {
        invoke_query_next_nonce(
            &state.components,
            &state.protocol_config,
            &state.authority,
            &state.config,
            sender,
        )
    })
    .await
}

async fn get_preinstalled_wasm_structured_durable_context<S, B, M, T, C, I>(
    State(state): State<SharedPreinstalledWasmStructuredDurableNativeHttpState<S, B, M, T, C, I>>,
) -> Response
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
    B: BlobStore + Send + Sync + 'static,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    T: Transport + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    let initial_cancelled = state.components.is_cancelled();
    let blocking_executor = state.blocking_executor.clone();
    query_structured_durable_common(initial_cancelled, blocking_executor, move || {
        invoke_query_context(&state.config, &state.protocol_config)
    })
    .await
}

async fn get_preinstalled_wasm_structured_durable_object<S, B, M, T, C, I>(
    State(state): State<SharedPreinstalledWasmStructuredDurableNativeHttpState<S, B, M, T, C, I>>,
    Path(object_id_hex): Path<String>,
) -> Response
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
    B: BlobStore + Send + Sync + 'static,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    T: Transport + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    let object_id = match decode_hex64_selector(&object_id_hex) {
        Some(bytes) => ObjectId::new(bytes),
        None => return error_response(StatusCode::BAD_REQUEST, "invalid-object-id"),
    };
    let initial_cancelled = state.components.is_cancelled();
    let blocking_executor = state.blocking_executor.clone();
    query_structured_durable_common(initial_cancelled, blocking_executor, move || {
        invoke_query_object(
            &state.components,
            &state.protocol_config,
            &state.authority,
            &state.config,
            object_id,
        )
    })
    .await
}

async fn get_preinstalled_wasm_structured_durable_receipt<S, B, M, T, C, I>(
    State(state): State<SharedPreinstalledWasmStructuredDurableNativeHttpState<S, B, M, T, C, I>>,
    Path(request_id_hex): Path<String>,
) -> Response
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
    B: BlobStore + Send + Sync + 'static,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    T: Transport + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    let request_id =
        match decode_hex64_selector(&request_id_hex).and_then(|bytes| RequestId::new(bytes).ok()) {
            Some(request_id) => request_id,
            None => return error_response(StatusCode::BAD_REQUEST, "invalid-request-id"),
        };
    let initial_cancelled = state.components.is_cancelled();
    let blocking_executor = state.blocking_executor.clone();
    query_structured_durable_common(initial_cancelled, blocking_executor, move || {
        invoke_query_receipt(
            &state.components,
            &state.protocol_config,
            &state.authority,
            &state.config,
            request_id,
        )
    })
    .await
}

async fn get_preinstalled_wasm_structured_durable_next_nonce<S, B, M, T, C, I>(
    State(state): State<SharedPreinstalledWasmStructuredDurableNativeHttpState<S, B, M, T, C, I>>,
    Path(sender_hex): Path<String>,
) -> Response
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
    B: BlobStore + Send + Sync + 'static,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    T: Transport + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    let sender = match decode_hex64_selector(&sender_hex) {
        Some(sender) => sender,
        None => return error_response(StatusCode::BAD_REQUEST, "invalid-sender"),
    };
    let initial_cancelled = state.components.is_cancelled();
    let blocking_executor = state.blocking_executor.clone();
    query_structured_durable_common(initial_cancelled, blocking_executor, move || {
        invoke_query_next_nonce(
            &state.components,
            &state.protocol_config,
            &state.authority,
            &state.config,
            sender,
        )
    })
    .await
}

enum InvocationError {
    CancelledBeforeStorage,
    Node(NodeCoreError),
    Delivery(OutboxDeliveryError),
    Indexed(IndexedOutboxRecoveryError),
    ResultEncoding,
    /// A known [`NodeEventKind`] whose family requires per-family
    /// authentication and authorization that no native route implements yet
    /// (DR-0099). `SubmitTransaction` is the only kind any native route
    /// authenticates; every other kind must fail closed here, before any
    /// identity allocation, clock read, storage I/O, machine access-plan or
    /// transition, outbox work, or transport send. The error deliberately
    /// carries no event-kind detail so every family maps to the same opaque
    /// response.
    EventFamilyRequiresAuthenticatedRoute,
}

/// Rejects a `SubmitTransaction` event before any machine or storage work.
///
/// `router` and `resolved_domain_router` never authenticate a transaction:
/// only [`structured_durable_router`] does. Calling either of those legacy
/// routes with a `SubmitTransaction` event must fail closed here rather than
/// let it reach [`TransactionalNodeStateMachine::access_plan`] or storage
/// under the appearance of having been authenticated.
fn reject_unauthenticated_submit_transaction(event: &NodeEvent) -> Result<(), InvocationError> {
    if event.kind() == NodeEventKind::SubmitTransaction {
        return Err(InvocationError::Node(
            NodeCoreError::UnauthenticatedTransactionSubmission,
        ));
    }
    Ok(())
}

/// Rejects every known `NodeEventKind` other than `SubmitTransaction` before
/// any identity allocation, clock read, storage I/O, machine access-plan or
/// transition, outbox work, or transport send (DR-0099).
///
/// This is an external-boundary policy, not a node-core change: node-core's
/// generic [`TransactionalNodeStateMachine`] path remains fully implemented
/// and reusable, and this function only decides which event kinds native-http
/// is currently willing to hand to it. `ReceiveVote`, `ReceiveCertificate`,
/// `ReceiveConsensusMessage`, `ApplyGovernanceCertificate`,
/// `ApplyProtocolUpgrade`, `ApplyValidatorSetChange`, and `Tick` each need
/// their own authentication and authorization the native adapter does not
/// implement yet, so every one of them maps to the same opaque
/// `501 event-family-requires-authenticated-route` response on every native
/// route, including the two legacy routes that never authenticate
/// `SubmitTransaction` either. The match is exhaustive over
/// [`NodeEventKind`] so a future kind must be classified here explicitly
/// rather than silently falling through to acceptance.
fn reject_unauthenticated_event_family(event: &NodeEvent) -> Result<(), InvocationError> {
    match event.kind() {
        NodeEventKind::SubmitTransaction => Ok(()),
        NodeEventKind::ReceiveVote
        | NodeEventKind::ReceiveCertificate
        | NodeEventKind::ReceiveConsensusMessage
        | NodeEventKind::ApplyGovernanceCertificate
        | NodeEventKind::ApplyProtocolUpgrade
        | NodeEventKind::ApplyValidatorSetChange
        | NodeEventKind::Tick => Err(InvocationError::EventFamilyRequiresAuthenticatedRoute),
    }
}

fn invoke_event<R, M, L>(
    state: &NativeHttpState<R, M, L>,
    body: &[u8],
) -> Result<Vec<u8>, InvocationError>
where
    R: Runtime,
    R::State: TransactionalStateStore,
    M: TransactionalNodeStateMachine,
    L: OutboxLeaseIdSource,
{
    let event = NodeEvent::decode(body).map_err(InvocationError::Node)?;
    reject_unauthenticated_event_family(&event)?;
    reject_unauthenticated_submit_transaction(&event)?;
    let request_id = event.request_id();
    let output = handle_idempotent_event(
        state.runtime.as_ref(),
        &state.config,
        &state.resolver,
        event,
        state.machine.as_ref(),
    )
    .map_err(InvocationError::Node)?;
    let _delivered_messages = deliver_request_outbox(
        state.runtime.as_ref(),
        &state.config,
        state.lease_ids.as_ref(),
        request_id,
    )
    .map_err(InvocationError::Delivery)?;
    HttpNodeResult::new(request_id, output.responses().to_vec())
        .and_then(|result| result.encode())
        .map_err(|_| InvocationError::ResultEncoding)
}

fn invoke_resolved_domain_event<R, M, L>(
    state: &ResolvedDomainNativeHttpState<R, M, L>,
    body: &[u8],
) -> Result<Vec<u8>, InvocationError>
where
    R: Runtime,
    R::State: DomainTransactionalStateStore,
    M: TransactionalNodeStateMachine,
    L: OutboxLeaseIdSource,
{
    let event = NodeEvent::decode(body).map_err(InvocationError::Node)?;
    reject_unauthenticated_event_family(&event)?;
    reject_unauthenticated_submit_transaction(&event)?;
    let request_id = event.request_id();
    let resolved = handle_resolved_idempotent_event(
        state.runtime.as_ref(),
        &state.placement,
        &state.config,
        &state.resolver,
        event,
        state.machine.as_ref(),
    )
    .map_err(InvocationError::Node)?;
    let _delivered_messages = deliver_request_outbox_in_domain(
        state.runtime.as_ref(),
        resolved.domain(),
        &state.config,
        state.lease_ids.as_ref(),
        request_id,
    )
    .map_err(InvocationError::Delivery)?;
    HttpNodeResult::new(request_id, resolved.output().responses().to_vec())
        .and_then(|result| result.encode())
        .map_err(|_| InvocationError::ResultEncoding)
}

/// Distinguishes how one authenticated `SubmitTransaction` is executed by
/// [`invoke_structured_durable_event_with_execution`], the shared core behind
/// both [`invoke_structured_durable_event`] and
/// [`invoke_preinstalled_wasm_structured_durable_event`]. Every other stage
/// of the request path (authenticated preparation, storage context, exact
/// request-scoped outbox claim/send/ack) is identical for every variant.
enum StructuredDurableAuthenticatedExecution<'a> {
    /// [`handle_authenticated_resolved_durable_submit_transaction`]: read-only.
    ReadOnly,
    /// [`handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution`].
    PreinstalledWasm {
        catalog: &'a PreinstalledModuleCatalog,
        engine: WasmExecutionEngine,
        created_checkpoint: u64,
        fee_composition: Option<PreinstalledFeeComposition<'a>>,
    },
}

fn invoke_structured_durable_event<S, B, M, T, C, I>(
    state: &StructuredDurableNativeHttpState<S, B, M, T, C, I>,
    body: &[u8],
) -> Result<Vec<u8>, InvocationError>
where
    S: IndexedOutboxRepository,
    B: BlobStore,
    M: TransactionalNodeStateMachine,
    T: Transport,
    C: Clock,
    I: IndexedOutboxIdentitySource,
{
    invoke_structured_durable_event_with_execution(
        &state.components,
        &state.protocol_config,
        &state.authority,
        &state.config,
        &state.resolver,
        state.machine.as_ref(),
        StructuredDurableAuthenticatedExecution::ReadOnly,
        body,
    )
}

fn invoke_preinstalled_wasm_structured_durable_event<S, B, M, T, C, I>(
    state: &PreinstalledWasmStructuredDurableNativeHttpState<S, B, M, T, C, I>,
    body: &[u8],
) -> Result<Vec<u8>, InvocationError>
where
    S: IndexedOutboxRepository,
    B: BlobStore,
    M: TransactionalNodeStateMachine,
    T: Transport,
    C: Clock,
    I: IndexedOutboxIdentitySource,
{
    invoke_structured_durable_event_with_execution(
        &state.components,
        &state.protocol_config,
        &state.authority,
        &state.config,
        &state.resolver,
        state.machine.as_ref(),
        StructuredDurableAuthenticatedExecution::PreinstalledWasm {
            catalog: state.preinstalled_wasm.catalog.as_ref(),
            engine: state.preinstalled_wasm.engine,
            created_checkpoint: state.preinstalled_wasm.created_checkpoint,
            fee_composition: state.preinstalled_wasm.fee.as_ref().map(|fee| {
                PreinstalledFeeComposition::new(fee.treasury_object_id, fee.composer.as_ref())
            }),
        },
        body,
    )
}

#[allow(clippy::too_many_arguments)]
fn invoke_structured_durable_event_with_execution<S, B, M, T, C, I>(
    components: &StructuredDurableNativeComponents<S, B, T, C, I>,
    protocol_config: &ProtocolConfig,
    authority: &StructuredDurableRequestAuthority,
    config: &NodeConfig,
    resolver: &HashSuiteResolver,
    machine: &M,
    execution: StructuredDurableAuthenticatedExecution<'_>,
    body: &[u8],
) -> Result<Vec<u8>, InvocationError>
where
    S: IndexedOutboxRepository,
    B: BlobStore,
    M: TransactionalNodeStateMachine,
    T: Transport,
    C: Clock,
    I: IndexedOutboxIdentitySource,
{
    if components.is_cancelled() {
        return Err(InvocationError::CancelledBeforeStorage);
    }
    let event = NodeEvent::decode(body).map_err(InvocationError::Node)?;
    reject_unauthenticated_event_family(&event)?;
    validate_native_event_context(&event, config).map_err(InvocationError::Node)?;
    let request_id = event.request_id();
    let submission = Box::new(
        authenticate_submit_transaction_event(event, config, protocol_config)
            .map_err(InvocationError::Node)?,
    );
    let identity = components
        .identities
        .next_attempt_identity()
        .map_err(|error| InvocationError::Indexed(IndexedOutboxRecoveryError::Identity(error)))?;
    let now_unix_millis = components
        .clock
        .now_unix_millis()
        .map_err(|error| InvocationError::Indexed(IndexedOutboxRecoveryError::Runtime(error)))?;
    let deadline_unix_millis = now_unix_millis
        .checked_add(authority.operation_timeout_millis.get())
        .ok_or(InvocationError::Indexed(
            IndexedOutboxRecoveryError::TimeOverflow,
        ))?;
    let lease_expires_at_unix_millis = now_unix_millis
        .checked_add(authority.lease_duration_millis.get())
        .ok_or(InvocationError::Indexed(
            IndexedOutboxRecoveryError::TimeOverflow,
        ))?;
    let deadline = StorageDeadline::new(deadline_unix_millis).ok_or(InvocationError::Indexed(
        IndexedOutboxRecoveryError::TimeOverflow,
    ))?;
    let context =
        DurableOperationContext::new(authority.writer_fence, deadline, identity.correlation_id);
    if components.is_cancelled() {
        return Err(InvocationError::CancelledBeforeStorage);
    }
    let resolved = match execution {
        StructuredDurableAuthenticatedExecution::ReadOnly => {
            handle_authenticated_resolved_durable_submit_transaction(
                components.blob_store.as_ref(),
                components.store.as_ref(),
                &context,
                resolver,
                *submission,
                machine,
            )
        }
        StructuredDurableAuthenticatedExecution::PreinstalledWasm {
            catalog,
            engine,
            created_checkpoint,
            fee_composition,
        } => handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            components.blob_store.as_ref(),
            components.store.as_ref(),
            &context,
            resolver,
            catalog,
            &engine,
            *submission,
            created_checkpoint,
            fee_composition,
        ),
    }
    .map_err(InvocationError::Node)?;

    let outbox_request_id = OutboxRequestId::new(*request_id.as_bytes())
        .map_err(|error| InvocationError::Indexed(IndexedOutboxRecoveryError::Contract(error)))?;
    let claim_request = RequestOutboxClaimRequest::new(
        resolved.domain(),
        outbox_request_id,
        now_unix_millis,
        identity.lease_id,
        lease_expires_at_unix_millis,
    )
    .map_err(|error| InvocationError::Indexed(IndexedOutboxRecoveryError::Contract(error)))?;
    let claim = reconcile_request_outbox_claim(components.store.as_ref(), &context, claim_request)
        .map_err(InvocationError::Indexed)?;
    if let Some(claim) = claim {
        if claim.request_id() != outbox_request_id
            || claim.lease_id() != identity.lease_id
            || claim.lease_expires_at_unix_millis() != lease_expires_at_unix_millis
        {
            return Err(InvocationError::Indexed(
                IndexedOutboxRecoveryError::ClaimIdentityMismatch,
            ));
        }
        let outbound = NodeEvent::decode(claim.canonical_payload())
            .map_err(|error| InvocationError::Indexed(IndexedOutboxRecoveryError::Node(error)))?;
        validate_native_event_context(&outbound, config)
            .map_err(|error| InvocationError::Indexed(IndexedOutboxRecoveryError::Node(error)))?;
        let canonical_payload = outbound
            .encode()
            .map_err(|error| InvocationError::Indexed(IndexedOutboxRecoveryError::Node(error)))?;
        if canonical_payload != claim.canonical_payload() {
            return Err(InvocationError::Indexed(IndexedOutboxRecoveryError::Node(
                NodeCoreError::PersistenceInvariant("request outbox payload is not canonical"),
            )));
        }
        components
            .transport
            .send(canonical_payload)
            .map_err(|_| InvocationError::Indexed(IndexedOutboxRecoveryError::Send))?;
        let acknowledgement = DurableOutboxAcknowledgement::new(
            resolved.domain(),
            claim.request_id(),
            claim.message_index(),
            claim.lease_id(),
        );
        reconcile_indexed_acknowledgement(components.store.as_ref(), &context, acknowledgement)
            .map_err(InvocationError::Indexed)?;
    }

    HttpNodeResult::new(request_id, resolved.output().responses().to_vec())
        .and_then(|result| result.encode())
        .map_err(|_| InvocationError::ResultEncoding)
}

fn validate_native_event_context(
    event: &NodeEvent,
    config: &NodeConfig,
) -> Result<(), NodeCoreError> {
    if event.chain_id() != config.chain_id() {
        return Err(NodeCoreError::ChainMismatch {
            expected: config.chain_id().clone(),
            actual: event.chain_id().clone(),
        });
    }
    if event.protocol_version() != config.protocol_version() {
        return Err(NodeCoreError::ProtocolVersionMismatch {
            expected: config.protocol_version(),
            actual: event.protocol_version(),
        });
    }
    if event.epoch() != config.epoch() {
        return Err(NodeCoreError::EpochMismatch {
            expected: config.epoch(),
            actual: event.epoch(),
        });
    }
    Ok(())
}

fn reconcile_request_outbox_claim<S>(
    store: &S,
    context: &DurableOperationContext,
    request: RequestOutboxClaimRequest,
) -> Result<Option<runtime::DurableOutboxClaim>, IndexedOutboxRecoveryError>
where
    S: IndexedOutboxRepository,
{
    match store.claim_request_outbox(context, request) {
        DurableOutboxClaimOutcome::Claimed(claim) => Ok(Some(claim)),
        DurableOutboxClaimOutcome::NoDueWork => Ok(None),
        DurableOutboxClaimOutcome::Rejected(reason) => {
            Err(IndexedOutboxRecoveryError::ClaimRejected(reason))
        }
        DurableOutboxClaimOutcome::Indeterminate(first_reason) => {
            match store.claim_request_outbox(context, request) {
                DurableOutboxClaimOutcome::Claimed(claim) => Ok(Some(claim)),
                _ => Err(IndexedOutboxRecoveryError::ClaimIndeterminate(first_reason)),
            }
        }
    }
}

fn invocation_error_response(error: &InvocationError) -> Response {
    match error {
        InvocationError::CancelledBeforeStorage => cancelled_before_storage_response(),
        InvocationError::Node(error) => node_error_response(error),
        InvocationError::Delivery(OutboxDeliveryError::Node(error)) => node_error_response(error),
        InvocationError::Delivery(OutboxDeliveryError::Send) => {
            error_response(StatusCode::SERVICE_UNAVAILABLE, "outbound-send-failed")
        }
        InvocationError::Delivery(OutboxDeliveryError::LeaseId(
            OutboxLeaseIdSourceError::Unavailable,
        )) => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "lease-id-source-unavailable",
        ),
        InvocationError::Delivery(OutboxDeliveryError::LeaseId(
            OutboxLeaseIdSourceError::Exhausted,
        )) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "lease-id-source-exhausted",
        ),
        InvocationError::Indexed(error) => indexed_invocation_error_response(error),
        InvocationError::ResultEncoding => {
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "result-encoding-failed")
        }
        InvocationError::EventFamilyRequiresAuthenticatedRoute => error_response(
            StatusCode::NOT_IMPLEMENTED,
            "event-family-requires-authenticated-route",
        ),
    }
}

fn indexed_invocation_error_response(error: &IndexedOutboxRecoveryError) -> Response {
    match error {
        IndexedOutboxRecoveryError::Runtime(_) => {
            error_response(StatusCode::SERVICE_UNAVAILABLE, "runtime-unavailable")
        }
        IndexedOutboxRecoveryError::Identity(IndexedOutboxIdentitySourceError::Unavailable) => {
            error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "indexed-identity-source-unavailable",
            )
        }
        IndexedOutboxRecoveryError::Identity(IndexedOutboxIdentitySourceError::Exhausted) => {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "indexed-identity-source-exhausted",
            )
        }
        IndexedOutboxRecoveryError::ClaimRejected(
            DurableOutboxClaimRejection::WriterFenced { .. }
            | DurableOutboxClaimRejection::DeadlineExceededBeforeCommit
            | DurableOutboxClaimRejection::SerializationFailure
            | DurableOutboxClaimRejection::UnavailableBeforeCommit,
        ) => error_response(StatusCode::SERVICE_UNAVAILABLE, "outbox-claim-unavailable"),
        IndexedOutboxRecoveryError::ClaimIndeterminate(_) => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "outbox-claim-indeterminate",
        ),
        IndexedOutboxRecoveryError::Send => {
            error_response(StatusCode::SERVICE_UNAVAILABLE, "outbound-send-failed")
        }
        IndexedOutboxRecoveryError::AcknowledgementRejected(
            DurableOutboxAcknowledgementRejection::WriterFenced { .. }
            | DurableOutboxAcknowledgementRejection::DeadlineExceededBeforeCommit
            | DurableOutboxAcknowledgementRejection::SerializationFailure
            | DurableOutboxAcknowledgementRejection::UnavailableBeforeCommit,
        ) => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "outbox-acknowledgement-unavailable",
        ),
        IndexedOutboxRecoveryError::AcknowledgementIndeterminate(_) => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "outbox-acknowledgement-indeterminate",
        ),
        IndexedOutboxRecoveryError::Node(error) => node_error_response(error),
        IndexedOutboxRecoveryError::TimeOverflow
        | IndexedOutboxRecoveryError::Contract(_)
        | IndexedOutboxRecoveryError::ClaimIdentityMismatch
        | IndexedOutboxRecoveryError::ClaimRejected(_)
        | IndexedOutboxRecoveryError::AcknowledgementRejected(_) => {
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "invalid-durable-outbox")
        }
        IndexedOutboxRecoveryError::CapacityExhausted
        | IndexedOutboxRecoveryError::AdmissionClosed
        | IndexedOutboxRecoveryError::BlockingTaskFailed => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid-indexed-invocation-state",
        ),
    }
}

enum OutboxDeliveryError {
    Node(NodeCoreError),
    Send,
    LeaseId(OutboxLeaseIdSourceError),
}

impl From<NodeCoreError> for OutboxDeliveryError {
    fn from(value: NodeCoreError) -> Self {
        Self::Node(value)
    }
}

impl From<RuntimeError> for OutboxDeliveryError {
    fn from(value: RuntimeError) -> Self {
        Self::Node(NodeCoreError::Runtime(value))
    }
}

impl From<OutboxLeaseIdSourceError> for OutboxDeliveryError {
    fn from(value: OutboxLeaseIdSourceError) -> Self {
        Self::LeaseId(value)
    }
}

fn recovery_delivery_error(error: OutboxDeliveryError) -> NativeOutboxRecoveryError {
    match error {
        OutboxDeliveryError::Node(error) => NativeOutboxRecoveryError::Node(error),
        OutboxDeliveryError::Send => NativeOutboxRecoveryError::Send,
        OutboxDeliveryError::LeaseId(error) => NativeOutboxRecoveryError::LeaseId(error),
    }
}

fn deliver_request_outbox<R, L>(
    runtime: &R,
    config: &NodeConfig,
    lease_ids: &L,
    request_id: RequestId,
) -> Result<usize, OutboxDeliveryError>
where
    R: Runtime,
    R::State: TransactionalStateStore,
    L: OutboxLeaseIdSource,
{
    deliver_request_outbox_inner(
        runtime,
        config,
        lease_ids,
        request_id,
        |layout, request_id, lease_id, now_unix_millis| {
            claim_next_outbox_message(
                runtime.state_store(),
                layout,
                request_id,
                lease_id,
                now_unix_millis,
                NATIVE_OUTBOX_LEASE_MILLIS,
            )
        },
        |layout, request_id, index, lease_id| {
            acknowledge_outbox_message(runtime.state_store(), layout, request_id, index, lease_id)
        },
    )
}

fn deliver_request_outbox_in_domain<R, L>(
    runtime: &R,
    domain: AtomicityDomainId,
    config: &NodeConfig,
    lease_ids: &L,
    request_id: RequestId,
) -> Result<usize, OutboxDeliveryError>
where
    R: Runtime,
    R::State: DomainTransactionalStateStore,
    L: OutboxLeaseIdSource,
{
    deliver_request_outbox_inner(
        runtime,
        config,
        lease_ids,
        request_id,
        |layout, request_id, lease_id, now_unix_millis| {
            claim_next_outbox_message_in_domain(
                runtime.state_store(),
                domain,
                layout,
                request_id,
                lease_id,
                now_unix_millis,
                NATIVE_OUTBOX_LEASE_MILLIS,
            )
        },
        |layout, request_id, index, lease_id| {
            acknowledge_outbox_message_in_domain(
                runtime.state_store(),
                domain,
                layout,
                request_id,
                index,
                lease_id,
            )
        },
    )
}

fn deliver_request_outbox_inner<R, L, C, A>(
    runtime: &R,
    config: &NodeConfig,
    lease_ids: &L,
    request_id: RequestId,
    mut claim_next: C,
    mut acknowledge: A,
) -> Result<usize, OutboxDeliveryError>
where
    R: Runtime,
    L: OutboxLeaseIdSource,
    C: FnMut(
        &PersistenceLayout,
        RequestId,
        OutboxLeaseId,
        u64,
    ) -> Result<Option<OutboxClaim>, NodeCoreError>,
    A: FnMut(&PersistenceLayout, RequestId, u32, OutboxLeaseId) -> Result<(), NodeCoreError>,
{
    let layout = PersistenceLayout::new(config.chain_id().clone(), config.protocol_version());
    let mut delivered_messages = 0_usize;
    for _ in 0..MAX_NODE_OUTPUT_ITEMS {
        let lease_id = lease_ids.next_lease_id(request_id)?;
        let now_unix_millis = runtime.clock().now_unix_millis()?;
        let Some(claim) = claim_next(&layout, request_id, lease_id, now_unix_millis)? else {
            return Ok(delivered_messages);
        };
        let encoded = claim.message().event().encode()?;
        runtime
            .transport()
            .send(encoded)
            .map_err(|_| OutboxDeliveryError::Send)?;
        acknowledge(&layout, claim.request_id(), claim.index(), claim.lease_id())?;
        delivered_messages = delivered_messages
            .checked_add(1)
            .ok_or(NodeCoreError::OutboxArithmeticOverflow)?;
    }
    Ok(delivered_messages)
}

fn has_supported_content_type(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    let supported = values
        .next()
        .and_then(|value| value.to_str().ok())
        .is_some_and(|media_type| {
            media_type
                .trim()
                .eq_ignore_ascii_case(NODE_EVENT_MEDIA_TYPE)
        });
    supported && values.next().is_none()
}

fn has_unsupported_content_encoding(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(header::CONTENT_ENCODING).iter();
    match values.next() {
        None => false,
        Some(value) => {
            value
                .to_str()
                .map_or(true, |value| !value.trim().eq_ignore_ascii_case("identity"))
                || values.next().is_some()
        }
    }
}

fn node_error_response(error: &NodeCoreError) -> Response {
    if let NodeCoreError::TransactionAuth(error) = error {
        return transaction_auth_error_response(error);
    }
    let (status, code) = match error {
        NodeCoreError::UnauthenticatedTransactionSubmission => (
            StatusCode::NOT_IMPLEMENTED,
            "submit-transaction-requires-authenticated-route",
        ),
        NodeCoreError::ProtocolConfigVersionMismatch { .. } => (
            StatusCode::SERVICE_UNAVAILABLE,
            "protocol-config-authority-mismatch",
        ),
        NodeCoreError::PayloadTooLarge(_) => (StatusCode::PAYLOAD_TOO_LARGE, "payload-too-large"),
        NodeCoreError::SenderNonceMismatch { .. } => {
            (StatusCode::CONFLICT, "sender-nonce-mismatch")
        }
        NodeCoreError::SenderNonceOverflow { .. } => {
            (StatusCode::UNPROCESSABLE_ENTITY, "sender-nonce-overflow")
        }
        NodeCoreError::ChainMismatch { .. }
        | NodeCoreError::ProtocolVersionMismatch { .. }
        | NodeCoreError::EpochMismatch { .. }
        | NodeCoreError::StateConflict
        | NodeCoreError::RequestIdReuse
        | NodeCoreError::DurableCommitRejected(runtime::DurableCommitRejection::Conflict {
            ..
        }) => (StatusCode::CONFLICT, "state-or-context-conflict"),
        NodeCoreError::OutboxLeaseActive { .. } => {
            (StatusCode::SERVICE_UNAVAILABLE, "outbox-lease-active")
        }
        NodeCoreError::TransitionRejected(_) => {
            (StatusCode::UNPROCESSABLE_ENTITY, "transition-rejected")
        }
        NodeCoreError::Runtime(_) => (StatusCode::SERVICE_UNAVAILABLE, "runtime-unavailable"),
        NodeCoreError::DurableRead(
            runtime::DurableReadError::WriterFenced { .. }
            | runtime::DurableReadError::DeadlineExceeded
            | runtime::DurableReadError::Unavailable,
        )
        | NodeCoreError::DurableCommitRejected(
            runtime::DurableCommitRejection::WriterFenced { .. }
            | runtime::DurableCommitRejection::DeadlineExceededBeforeCommit
            | runtime::DurableCommitRejection::SerializationFailure
            | runtime::DurableCommitRejection::UnavailableBeforeCommit,
        )
        | NodeCoreError::DurableCommitIndeterminate(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "durable-storage-unavailable",
        ),
        NodeCoreError::ProtocolConfig(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "protocol-config-unavailable",
        ),
        NodeCoreError::DurableRead(runtime::DurableReadError::InvalidRequest(
            runtime::RuntimeError::UnsupportedObjectStorage,
        )) => (StatusCode::NOT_IMPLEMENTED, "object-storage-unsupported"),
        NodeCoreError::ObjectNotFound { .. } => {
            (StatusCode::UNPROCESSABLE_ENTITY, "object-not-found")
        }
        NodeCoreError::ObjectVersionMismatch { .. } => {
            (StatusCode::CONFLICT, "object-version-mismatch")
        }
        NodeCoreError::ObjectDigestMismatch { .. } => {
            (StatusCode::CONFLICT, "object-digest-mismatch")
        }
        NodeCoreError::ObjectOwnerMismatch { .. } => {
            (StatusCode::FORBIDDEN, "object-owner-mismatch")
        }
        NodeCoreError::ObjectAccessModeUnsupported { .. } => (
            StatusCode::NOT_IMPLEMENTED,
            "object-mutating-access-unsupported",
        ),
        NodeCoreError::ObjectOwnerKindUnsupported { .. } => {
            (StatusCode::NOT_IMPLEMENTED, "object-owner-kind-unsupported")
        }
        // A blob absent from the supplied `BlobStore`, or a store `RuntimeError`
        // (mapped generically below), is host/storage unavailability, not a
        // caller fault: it never exposes blob bytes or storage details.
        NodeCoreError::ObjectBlobMissing { .. } => {
            (StatusCode::SERVICE_UNAVAILABLE, "object-blob-unavailable")
        }
        // Fetched bytes that do not hash to their own claimed content digest
        // are storage corruption, not a caller fault: opaque like every other
        // digest/record-corruption variant below.
        NodeCoreError::ObjectBlobDigestMismatch { .. } => {
            (StatusCode::INTERNAL_SERVER_ERROR, "invalid-node-output")
        }
        // A `BlobStore::put_blob` failure while publishing a new version is
        // host/storage unavailability, distinct from a caller fault or from
        // corruption discovered on read: it never exposes blob bytes or
        // storage details.
        NodeCoreError::ObjectBlobPublishFailed { .. } => {
            (StatusCode::SERVICE_UNAVAILABLE, "object-blob-publish-failed")
        }
        NodeCoreError::ObjectManifestTooLarge { .. } => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "object-manifest-too-large",
        ),
        NodeCoreError::DuplicateObjectAccess { .. } => {
            (StatusCode::BAD_REQUEST, "object-manifest-duplicate")
        }
        NodeCoreError::InvalidObjectVersion { .. } => {
            (StatusCode::BAD_REQUEST, "object-version-invalid")
        }
        NodeCoreError::ObjectConflict { .. } => (StatusCode::CONFLICT, "object-head-conflict"),
        // An object at its maximum immutable version can never be mutated
        // again: a real conflict, not a malformed request.
        NodeCoreError::ObjectVersionOverflow { .. } => {
            (StatusCode::CONFLICT, "object-version-overflow")
        }
        // Object-creating effects are outside this MVP slice; consistent
        // with every other `*Unsupported` object variant below.
        NodeCoreError::ObjectCreationUnsupported { .. } => {
            (StatusCode::NOT_IMPLEMENTED, "object-creation-unsupported")
        }
        // A declared signed access and its deterministic execution effect
        // disagreed: deterministic given the same signed transaction and
        // trusted module, so a client/request fault, not a server fault.
        NodeCoreError::ObjectEffectMismatch { .. } => {
            (StatusCode::UNPROCESSABLE_ENTITY, "object-effect-mismatch")
        }
        NodeCoreError::ObjectRecordMissing { .. }
        | NodeCoreError::ObjectRecordMismatch { .. }
        | NodeCoreError::ObjectBodyDigestMismatch { .. }
        | NodeCoreError::ObjectProvenanceMismatch { .. }
        // These can only mean deterministic execution (over a trusted
        // catalog module) or the owned-effects translator produced output
        // that disagrees with its own documented invariants: impossible in
        // practice, never a caller-supplied fault.
        | NodeCoreError::DuplicateObjectEffect { .. }
        | NodeCoreError::TooManyObjectEffects { .. }
        | NodeCoreError::UndeclaredObjectEffect { .. }
        | NodeCoreError::ObjectMutationContextMissing { .. }
        | NodeCoreError::SystemModules(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "invalid-node-output")
        }
        NodeCoreError::ObjectDigestUnverifiable { .. } => (
            StatusCode::NOT_IMPLEMENTED,
            "object-digest-algorithm-unsupported",
        ),
        NodeCoreError::ObjectBodyTooLarge { .. } => {
            (StatusCode::UNPROCESSABLE_ENTITY, "object-body-too-large")
        }
        NodeCoreError::Execution(execution_error) => execution_error_response(execution_error),
        // Malformed/inactive/unknown module reference: deterministic,
        // request-dependent client faults.
        NodeCoreError::PreinstalledModuleUnknown { .. } => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "preinstalled-module-unknown",
        ),
        NodeCoreError::PreinstalledModuleInactive { .. } => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "preinstalled-module-inactive",
        ),
        NodeCoreError::PreinstalledModuleNotYetActive { .. } => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "preinstalled-module-not-yet-active",
        ),
        NodeCoreError::PreinstalledModuleReferenceDigestMismatch { .. } => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "preinstalled-module-reference-invalid",
        ),
        // Args/gas/zero-object request faults: deterministic client errors.
        NodeCoreError::PreinstalledModuleArgsTooLarge { .. } => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "preinstalled-module-args-too-large",
        ),
        NodeCoreError::PreinstalledModuleGasLimitExceedsCeiling { .. } => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "preinstalled-module-gas-limit-exceeded",
        ),
        NodeCoreError::PreinstalledModuleZeroObjectAccess => (
            StatusCode::BAD_REQUEST,
            "preinstalled-module-zero-object-access",
        ),
        NodeCoreError::FeePaymentRequired => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "fee-payment-required",
        ),
        NodeCoreError::FeePaymentNotRequired => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "fee-payment-not-required",
        ),
        NodeCoreError::FeePaymentUnsupportedOnPath => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "fee-payment-unsupported-on-path",
        ),
        NodeCoreError::FeePaymentRejected(
            fees::FeeError::UnknownAsset(_)
            | fees::FeeError::AssetDisabled(_)
            | fees::FeeError::MaxFeeExceeded { .. },
        ) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "fee-payment-rejected",
        ),
        NodeCoreError::FeePaymentRejected(fees::FeeError::ArithmeticOverflow) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "fee-settlement-overflow",
        ),
        NodeCoreError::FeePaymentRejected(
            fees::FeeError::InvalidAssetIdLength(_)
            | fees::FeeError::ZeroFeeUnitsPerAssetUnit
            | fees::FeeError::RegistryTooLarge(_)
            | fees::FeeError::TooManySigners(_)
            | fees::FeeError::DuplicateAsset(_)
            | fees::FeeError::EmptySignerSet
            | fees::FeeError::DuplicateSigner(_)
            | fees::FeeError::CanonicalEncoding(_)
            | fees::FeeError::CanonicalDecoding(_)
            | fees::FeeError::Object(_),
        ) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "fee-policy-invalid",
        ),
        NodeCoreError::FeeObjectNotDeclaredWrite => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "fee-object-not-declared-write",
        ),
        NodeCoreError::FeeObjectNotOwnedBySender => (
            StatusCode::FORBIDDEN,
            "fee-object-owner-mismatch",
        ),
        NodeCoreError::FeeObjectIsTreasury => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "fee-object-is-treasury",
        ),
        NodeCoreError::FeeTreasuryAccessMisdeclared => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "fee-treasury-access-misdeclared",
        ),
        NodeCoreError::FeeCompositionFailed(node_core::FeeCompositionError::InsufficientBalance) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "fee-balance-insufficient",
        ),
        NodeCoreError::FeeCompositionFailed(
            node_core::FeeCompositionError::MalformedBody
            | node_core::FeeCompositionError::AssetMismatch
            | node_core::FeeCompositionError::Overflow,
        ) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "fee-composition-invalid",
        ),
        NodeCoreError::FeeCompositionUnavailable => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "fee-composition-unavailable",
        ),
        NodeCoreError::FeeCompositionNoOp => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "fee-composition-no-op",
        ),
        NodeCoreError::FeeAmountZero => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "fee-settlement-zero",
        ),
        // The committed `GasSchedule` itself is malformed for this path
        // (see `node_core::GasScheduleShapeFault`): trusted configuration,
        // never anything the caller controls, so it is opaque to the caller
        // beyond a generic server-fault code.
        NodeCoreError::UnsupportedGasScheduleShape(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "fee-schedule-unsupported",
        ),
        // Catalog/commitment mismatch: the composition-trusted catalog
        // disagrees with the governance-committed registry, which is a host
        // misconfiguration rather than anything the caller controls.
        NodeCoreError::PreinstalledModuleNotCataloged { .. }
        | NodeCoreError::PreinstalledModuleCodeHashMismatch { .. }
        | NodeCoreError::PreinstalledModuleManifestHashMismatch { .. }
        | NodeCoreError::PreinstalledModuleSemanticsHashMismatch { .. } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "preinstalled-module-catalog-mismatch",
        ),
        // `created_checkpoint` is trusted node composition, never request
        // input; a regression here is a host/operator failure.
        NodeCoreError::ObjectCreatedCheckpointRegression { .. } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "object-created-checkpoint-regression",
        ),
        NodeCoreError::ResponseRequestMismatch { .. }
        | NodeCoreError::StateTooLarge(_)
        | NodeCoreError::TooManyOutputItems { .. }
        | NodeCoreError::OutputTooLarge(_)
        | NodeCoreError::ZeroOutboxLeaseId
        | NodeCoreError::InvalidOutboxLeaseDuration(_)
        | NodeCoreError::PersistenceInvariant(_)
        | NodeCoreError::OutboxNotFound
        | NodeCoreError::OutboxLeaseMismatch
        | NodeCoreError::OutboxIndexMismatch
        | NodeCoreError::OutboxArithmeticOverflow
        | NodeCoreError::DurableRead(_)
        | NodeCoreError::DurableInvocation(_)
        | NodeCoreError::DurableCommitRejected(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "invalid-node-output")
        }
        _ => (StatusCode::BAD_REQUEST, "invalid-node-event"),
    };
    error_response(status, code)
}

/// Coarse HTTP classification for every [`ExecutionError`] variant reachable
/// from the preinstalled-WASM route, matched exhaustively (no wildcard) so a
/// future variant forces an explicit classification decision here.
///
/// By the time [`node_core::handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution`]'s
/// machine ever runs, [`node_core::authenticate_submit_transaction_event`]
/// has already decoded and re-encoded the exact same transaction once
/// (`transaction_auth::authenticate_transaction_bytes` calls
/// `execution::encode_transaction_signable`), so `EmptyEntrypoint`,
/// `TransactionFieldTooLarge`, `NonCanonicalTransactionEncoding`, and every
/// other canonical-encoding-shaped variant can only recur here as a
/// host/composition invariant violation, never a fresh caller-supplied
/// fault; the same is true of `HashChainMismatch`/`HashProtocolVersionMismatch`,
/// since this route's `resolver` is the same trusted value already used to
/// authenticate the event's chain/protocol version.
fn execution_error_response(error: &ExecutionError) -> (StatusCode, &'static str) {
    match error {
        // The transaction's client-chosen entrypoint name does not exist in
        // an otherwise trusted, catalog-verified module: deterministic and
        // request-dependent, so a client fault.
        ExecutionError::MissingEntrypoint(_) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "preinstalled-module-entrypoint-unknown",
        ),
        // Deterministic execution resource bounds (args/input-object/
        // input-data size) exceeded; scales with the caller's own manifest
        // and args, so a client fault. Malformed trusted catalog WASM bytes
        // cannot reach this arm: `PreinstalledModuleCatalogEntry::new`
        // already enforces the same module-byte bound at composition time.
        ExecutionError::ResourceLimitExceeded(_) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "preinstalled-module-resource-limit-exceeded",
        ),
        // The trusted catalog module itself failed fuel setup, compilation,
        // host-function linking, instantiation, or start: a host/catalog
        // defect (malformed trusted catalog WASM), never something the
        // caller can control. A wrong-signature entrypoint does not reach
        // this arm; it normalizes as a deterministic execution
        // failure/trap instead. Bounded only by this route's
        // admission/pre-activation limits, not production fee accounting.
        ExecutionError::WasmEngine(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "preinstalled-module-engine-failure",
        ),
        // Mirrors `NodeCoreError::ObjectVersionOverflow`'s classification:
        // the object can no longer be mutated, a real conflict rather than a
        // malformed request.
        ExecutionError::ObjectVersionOverflow(_) => {
            (StatusCode::CONFLICT, "object-version-overflow")
        }
        // Every remaining variant is internal encoding/hashing/context
        // machinery over an already-authenticated, already-bounded
        // transaction; see this function's doc comment for why reaching one
        // here is a host/composition invariant violation.
        ExecutionError::CanonicalEncoding(_)
        | ExecutionError::CanonicalDecoding(_)
        | ExecutionError::Abi(_)
        | ExecutionError::Object(_)
        | ExecutionError::Hashing(_)
        | ExecutionError::Fee(_)
        | ExecutionError::ProtocolType(_)
        | ExecutionError::EmptyEntrypoint
        | ExecutionError::EmptySignature
        | ExecutionError::TransactionFieldTooLarge { .. }
        | ExecutionError::NonCanonicalTransactionEncoding
        | ExecutionError::UnknownExecutionStatusTag(_)
        | ExecutionError::UnknownObjectEffectTag(_)
        | ExecutionError::TooManyObjectEffects(_)
        | ExecutionError::TooManyEvents(_)
        | ExecutionError::ExecutionEffectsListCountMismatch { .. }
        | ExecutionError::NonCanonicalExecutionEffectsEncoding
        | ExecutionError::HashChainMismatch
        | ExecutionError::HashProtocolVersionMismatch { .. } => {
            (StatusCode::INTERNAL_SERVER_ERROR, "invalid-node-output")
        }
    }
}

fn transaction_auth_error_response(error: &TransactionAuthError) -> Response {
    let (status, code) = match error {
        TransactionAuthError::Config(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "transaction-auth-config-unavailable",
        ),
        TransactionAuthError::Decode(_) => (StatusCode::BAD_REQUEST, "invalid-transaction-bytes"),
        TransactionAuthError::ChainMismatch { .. }
        | TransactionAuthError::ProtocolVersionMismatch { .. }
        | TransactionAuthError::EpochMismatch { .. } => {
            (StatusCode::BAD_REQUEST, "transaction-context-mismatch")
        }
        TransactionAuthError::SignableTransactionTooLarge { .. } => (
            StatusCode::PAYLOAD_TOO_LARGE,
            "transaction-signable-too-large",
        ),
        TransactionAuthError::Crypto(_) | TransactionAuthError::InvalidTransactionSignature => {
            (StatusCode::UNAUTHORIZED, "transaction-signature-invalid")
        }
    };
    error_response(status, code)
}

fn error_response(status: StatusCode, code: &'static str) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        code,
    )
        .into_response()
}

fn cancelled_before_storage_response() -> Response {
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "invocation-cancelled-before-storage",
    )
}

fn overload_response() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        "blocking-capacity-exhausted",
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::{AccessEntry, AccessManifest};
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use canonical_encoding::{CanonicalDecodingError, CanonicalStruct, decode_canonical_frame};
    use crypto::{SignatureDomain, SignatureMessageType};
    use execution::{
        Transaction, decode_transaction, encode_transaction, encode_transaction_signable,
    };
    use node_core::{
        MAX_AUTHENTICATED_OBJECT_BODY_BYTES, MAX_CHAIN_ID_BYTES, NodeDedupRecord,
        NodeOutboxDelivery, NodeOutput, NodeResponse, NodeResponseStatus, NodeStateAccess,
        NodeStateAccessMode, NodeStateAccessPlan, NodeStateSnapshot, NodeStateUpdate,
        OutboundMessage, PreinstalledModuleCatalogEntry, PreinstalledModuleSemanticsEnvelope,
        TransactionalNodeTransition, encode_preinstalled_semantics_envelope,
        handle_resolved_durable_idempotent_event,
    };
    use objects::{
        AccessMode, Address, Object, ObjectId, ObjectRef, Owner, decode_object, encode_object,
    };
    use protocol_config::TransactionAuthProfile;
    use protocol_types::{
        ChainId, Digest32, Epoch, HashAlgorithmId, HashPurpose, HashSuite, HashSuiteId,
        HashSuiteSchedule, ProtocolVersion, SignatureSchemeId, ValidatorId,
    };
    use runtime::{
        AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, AtomicStateWriteResult,
        AtomicStateWriteSet, CompareAndSwapResult, ComposedRuntime, DurableCommitOutcome,
        DurableCommitRejection, DurableDomainStateStore, DurableInvocationTransaction,
        DurableObjectChanges, DurableObjectHead, DurableObjectHeadRead, DurableObjectMutation,
        DurableObjectMutationEntry, DurableObjectOwnerProjection, DurableObjectPayload,
        DurableObjectProvenance, DurableObjectRoutingProjection, DurableObjectVersion,
        DurableObjectVersionRecord, DurableOutboxClaim, DurableReadError, DurableRequestId,
        DurableRequestReceipt, IndexedOutboxRepository, ManualClock, MemoryBlobStore,
        MemoryDurableStateStore, MemoryRuntime, MemoryScheduler, MemorySigner, MemoryStateStore,
        MemoryTransport, ObjectHeadRevision, OutboxRequestId, RequestOutboxClaimRequest,
        RuntimeError, StateMutation, StateMutationEntry, StateReadAssertion, StateRevision,
        StateStore, StructuredDurableDomainStateStore, SystemClock, TransactionalStateStore,
        Transport, VersionedStateValue,
    };
    use runtime_sqlite::{SqliteDurableStore, SqliteNamespace, SqliteStateStore};
    use std::{
        collections::VecDeque,
        fs,
        path::PathBuf,
        sync::{
            Condvar, Mutex,
            atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        },
        time::{SystemTime, UNIX_EPOCH},
    };
    use system_modules::{
        GasModel, ModuleId, ModuleStatus, SystemModule, SystemModuleError, SystemModuleManifest,
        SystemModuleRegistry, TypeSchema, encode_system_module_manifest,
    };
    use tokio::sync::Notify;
    use tower::ServiceExt;

    const TEST_STATE_TYPE_ID: u16 = 0xEF11;
    const TEST_PAYLOAD_TYPE_ID: u16 = 0xEF12;
    static NEXT_DATABASE_PATH: AtomicU64 = AtomicU64::new(0);

    struct TestDatabase {
        path: PathBuf,
    }

    impl TestDatabase {
        fn new() -> Self {
            let nonce = NEXT_DATABASE_PATH.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "sunrise-edge-native-recovery-{}-{nanos}-{nonce}.db",
                std::process::id()
            ));
            Self { path }
        }
    }

    impl Drop for TestDatabase {
        fn drop(&mut self) {
            for suffix in ["", "-wal", "-shm"] {
                let mut path = self.path.as_os_str().to_owned();
                path.push(suffix);
                let path = PathBuf::from(path);
                if path.exists() {
                    fs::remove_file(path).unwrap();
                }
            }
        }
    }

    fn canonical(type_id: u16, value: u64) -> Vec<u8> {
        let mut frame = CanonicalStruct::new(type_id, 1);
        frame.field_u64(1, value).unwrap();
        frame.finish().unwrap()
    }

    fn request_id(byte: u8) -> RequestId {
        RequestId::new([byte; 32]).unwrap()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn config() -> NodeConfig {
        NodeConfig::new(
            ChainId::new("sunrise-test").unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(7),
            b"http/node-state".to_vec(),
        )
        .unwrap()
    }

    fn placement(byte: u8, activation_epoch: u64) -> DomainPlacementManifest {
        DomainPlacementManifest::single_domain(
            1,
            AtomicityDomainId::new([byte; 32]).unwrap(),
            Epoch::new(activation_epoch),
        )
        .unwrap()
    }

    /// A committed protocol configuration whose `protocol_version` matches
    /// [`config`] and whose `transaction_auth_profile` is active, used to
    /// compose [`structured_durable_router`].
    fn active_protocol_config(domain: AtomicityDomainId) -> ProtocolConfig {
        let mut protocol_config = ProtocolConfig::genesis();
        protocol_config.protocol_version = ProtocolVersion::new(3);
        protocol_config.domain_placement =
            Some(DomainPlacementManifest::single_domain(1, domain, Epoch::new(0)).unwrap());
        protocol_config.transaction_auth_profile =
            Some(TransactionAuthProfile::ed25519_address_is_public_key());
        protocol_config
    }

    fn resolver() -> HashSuiteResolver {
        HashSuiteResolver::new(
            ChainId::new("sunrise-test").unwrap(),
            ProtocolVersion::new(3),
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            }],
        )
        .unwrap()
    }

    fn sqlite_runtime<T>(
        path: &std::path::Path,
        transport: T,
        now_unix_millis: u64,
    ) -> ComposedRuntime<
        SqliteStateStore,
        MemoryBlobStore,
        MemorySigner,
        T,
        ManualClock,
        MemoryScheduler,
    > {
        ComposedRuntime::new(
            SqliteStateStore::open(path).unwrap(),
            MemoryBlobStore::default(),
            MemorySigner::new(ValidatorId::new([0x44; 32])),
            transport,
            ManualClock::new(now_unix_millis),
            MemoryScheduler::default(),
        )
    }

    /// A generic, non-transaction event used by direct node-core/recovery
    /// fixture setup. Native HTTP rejects this family at its external boundary.
    fn event(request_id: RequestId) -> NodeEvent {
        NodeEvent::new(
            ChainId::new("sunrise-test").unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(7),
            request_id,
            node_core::NodeEventKind::ReceiveVote,
            canonical(TEST_PAYLOAD_TYPE_ID, 9),
        )
        .unwrap()
    }

    fn externally_unsupported_event_kinds() -> [NodeEventKind; 7] {
        [
            NodeEventKind::ReceiveVote,
            NodeEventKind::ReceiveCertificate,
            NodeEventKind::ReceiveConsensusMessage,
            NodeEventKind::ApplyGovernanceCertificate,
            NodeEventKind::ApplyProtocolUpgrade,
            NodeEventKind::ApplyValidatorSetChange,
            NodeEventKind::Tick,
        ]
    }

    fn event_with_kind(request_id: RequestId, kind: NodeEventKind, chain_id: ChainId) -> NodeEvent {
        NodeEvent::new(
            chain_id,
            ProtocolVersion::new(3),
            Epoch::new(7),
            request_id,
            kind,
            canonical(TEST_PAYLOAD_TYPE_ID, 9),
        )
        .unwrap()
    }

    /// Builds an unsigned `SubmitTransaction` `NodeEvent` carrying `payload`
    /// verbatim, for tests that construct malformed or deliberately
    /// mis-signed transaction bytes.
    fn submit_transaction_event(request_id: RequestId, payload: Vec<u8>) -> NodeEvent {
        NodeEvent::new(
            ChainId::new("sunrise-test").unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(7),
            request_id,
            node_core::NodeEventKind::SubmitTransaction,
            payload,
        )
        .unwrap()
    }

    fn raw_submit_transaction_event_bytes(request_id: RequestId, payload: Vec<u8>) -> Vec<u8> {
        let mut frame = CanonicalStruct::new(0xE001, 1);
        frame.field_str(1, "sunrise-test").unwrap();
        frame.field_u32(2, 3).unwrap();
        frame.field_u64(3, 7).unwrap();
        frame
            .field_bytes(4, request_id.as_bytes().to_vec())
            .unwrap();
        frame
            .field_u16(5, NodeEventKind::SubmitTransaction.as_u16())
            .unwrap();
        frame.field_bytes(6, payload).unwrap();
        frame.finish().unwrap()
    }

    /// A dev-only deterministic Ed25519 signing key. Test infrastructure
    /// only; mirrors `node_core::transaction_auth`'s test-only signer.
    fn dev_signing_key(seed: u8) -> ed25519_zebra::SigningKey {
        ed25519_zebra::SigningKey::from([seed; 32])
    }

    fn dev_sender_address(signing_key: &ed25519_zebra::SigningKey) -> Address {
        let verification_key = ed25519_zebra::VerificationKey::from(signing_key);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(verification_key.as_ref());
        Address::new(bytes)
    }

    fn transaction_module_ref() -> ObjectRef {
        ObjectRef {
            id: ObjectId::new([0u8; 32]),
            version: 1,
            digest: Digest32::new(HashAlgorithmId::Sha2_256, [0u8; 32]),
        }
    }

    fn unsigned_transaction(
        sender: Address,
        chain: ChainId,
        epoch: Epoch,
        nonce: u64,
    ) -> Transaction {
        Transaction {
            chain_id: chain,
            protocol_version: ProtocolVersion::new(3),
            epoch,
            sender,
            nonce,
            access_manifest: AccessManifest::new(),
            module_ref: transaction_module_ref(),
            entrypoint: "noop".to_string(),
            args: vec![1, 2, 3],
            gas_limit: 1_000,
            fee_payment: None,
            signature: Vec::new(),
        }
    }

    /// The exact production transaction-v1 signature domain, matching
    /// `node_core::transaction_auth::authenticate_transaction_bytes`.
    fn production_transaction_domain(chain: ChainId, epoch: Epoch) -> SignatureDomain {
        SignatureDomain {
            chain_id: chain,
            protocol_version: ProtocolVersion::new(3),
            epoch,
            message_type: SignatureMessageType::new("transaction-v1").unwrap(),
            signature_scheme_id: SignatureSchemeId::Ed25519,
        }
    }

    fn sign_under_domain(
        signing_key: &ed25519_zebra::SigningKey,
        domain: &SignatureDomain,
        signable: &[u8],
    ) -> Vec<u8> {
        let framed = crypto::frame_signature_message(domain, signable).unwrap();
        let signature = signing_key.sign(&framed);
        signature.to_bytes().to_vec()
    }

    /// Encodes `tx` signed for the exact production domain, matching what
    /// `authenticate_transaction_bytes` itself verifies.
    fn signed_transaction_bytes(
        signing_key: &ed25519_zebra::SigningKey,
        tx: &Transaction,
    ) -> Vec<u8> {
        let signable = encode_transaction_signable(tx).unwrap();
        let domain = production_transaction_domain(tx.chain_id.clone(), tx.epoch);
        let mut signed = tx.clone();
        signed.signature = sign_under_domain(signing_key, &domain, &signable);
        encode_transaction(&signed).unwrap()
    }

    /// A real, deterministically Ed25519-signed `SubmitTransaction`
    /// `NodeEvent` that authenticates under [`active_protocol_config`] and
    /// [`config`]'s trusted chain/epoch.
    fn signed_submit_transaction_event(
        signing_key: &ed25519_zebra::SigningKey,
        request_id: RequestId,
        nonce: u64,
    ) -> NodeEvent {
        let sender = dev_sender_address(signing_key);
        let tx = unsigned_transaction(
            sender,
            ChainId::new("sunrise-test").unwrap(),
            Epoch::new(7),
            nonce,
        );
        let bytes = signed_transaction_bytes(signing_key, &tx);
        submit_transaction_event(request_id, bytes)
    }

    // ── preinstalled WASM native HTTP composition ───────────────────────

    /// A contract that overwrites `object[0]`'s data with a fixed byte,
    /// matching `execution::wasm_engine`'s stable host ABI.
    fn preinstalled_write_wasm_bytes() -> Vec<u8> {
        wat::parse_str(
            r#"(module
                (import "env" "get_object_count"   (func $get_object_count   (result i32)))
                (import "env" "get_object_data_len"(func $get_object_data_len(param i32)(result i32)))
                (import "env" "read_object_data"   (func $read_object_data   (param i32 i32 i32 i32)(result i32)))
                (import "env" "write_object_data"  (func $write_object_data  (param i32 i32 i32)(result i32)))
                (import "env" "consume_object"     (func $consume_object     (param i32)(result i32)))
                (import "env" "create_object"      (func $create_object      (param i32 i32 i32 i32 i32 i32)(result i32)))
                (import "env" "emit_event"         (func $emit_event         (param i32 i32 i32 i32)(result i32)))
                (import "env" "get_args_len"       (func $get_args_len       (result i32)))
                (import "env" "read_args"          (func $read_args          (param i32 i32 i32)(result i32)))
                (import "env" "abort"              (func $abort              (param i32 i32)))
                (memory 1)
                (export "memory" (memory 0))
                (data (i32.const 0) "\CA\FE")
                (func (export "run")
                  (drop (call $write_object_data (i32.const 0) (i32.const 0) (i32.const 2)))))"#,
        )
        .unwrap()
    }

    /// A contract that always traps via `abort`.
    fn preinstalled_trap_wasm_bytes() -> Vec<u8> {
        wat::parse_str(
            r#"(module
                (import "env" "get_object_count"   (func $get_object_count   (result i32)))
                (import "env" "get_object_data_len"(func $get_object_data_len(param i32)(result i32)))
                (import "env" "read_object_data"   (func $read_object_data   (param i32 i32 i32 i32)(result i32)))
                (import "env" "write_object_data"  (func $write_object_data  (param i32 i32 i32)(result i32)))
                (import "env" "consume_object"     (func $consume_object     (param i32)(result i32)))
                (import "env" "create_object"      (func $create_object      (param i32 i32 i32 i32 i32 i32)(result i32)))
                (import "env" "emit_event"         (func $emit_event         (param i32 i32 i32 i32)(result i32)))
                (import "env" "get_args_len"       (func $get_args_len       (result i32)))
                (import "env" "read_args"          (func $read_args          (param i32 i32 i32)(result i32)))
                (import "env" "abort"              (func $abort              (param i32 i32)))
                (memory 1)
                (export "memory" (memory 0))
                (data (i32.const 0) "http-preinstalled-trap-marker")
                (func (export "run")
                  (call $abort (i32.const 0) (i32.const 30))))"#,
        )
        .unwrap()
    }

    fn preinstalled_manifest(module_id: ModuleId, max_input_size: u64) -> SystemModuleManifest {
        SystemModuleManifest {
            module_id,
            input_schema: TypeSchema {
                descriptor: "http.preinstalled.input.v1".to_string(),
                schema_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0x11; 32]),
            },
            output_schema: TypeSchema {
                descriptor: "http.preinstalled.output.v1".to_string(),
                schema_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0x22; 32]),
            },
            max_input_size,
            gas_model: GasModel {
                base_cost: 1,
                per_input_byte_cost: 1,
            },
            zk_hint: None,
        }
    }

    /// Builds a committed [`SystemModuleRegistry`] entry and a matching
    /// [`node_core::PreinstalledModuleCatalog`] entry whose commitments
    /// agree, plus the `ObjectRef` a transaction must declare as
    /// `module_ref` to reference it. Every digest is computed from
    /// `resolver`, matching
    /// `node_core::preinstalled_wasm::resolve_preinstalled_module`'s exact
    /// verification rules, rather than a pasted constant.
    fn preinstalled_module_fixture(
        resolver: &HashSuiteResolver,
        module_id: ModuleId,
        version: u64,
        wasm_bytes: Vec<u8>,
        max_input_size: u64,
    ) -> (SystemModuleRegistry, PreinstalledModuleCatalog, ObjectRef) {
        let manifest = preinstalled_manifest(module_id, max_input_size);
        let semantics_envelope: PreinstalledModuleSemanticsEnvelope =
            PreinstalledModuleSemanticsEnvelope::opaque_only(
                b"http-preinstalled-semantics-v1".to_vec(),
            )
            .unwrap();
        let semantics_bytes: Vec<u8> =
            encode_preinstalled_semantics_envelope(&semantics_envelope).unwrap();
        let semantics_hash: Digest32 = resolver
            .hash_for_purpose(
                Epoch::new(0),
                HashPurpose::SystemModuleManifest,
                &semantics_bytes,
            )
            .unwrap();
        let code_hash = resolver
            .hash_for_purpose(Epoch::new(0), HashPurpose::ContractCode, &wasm_bytes)
            .unwrap();
        let manifest_bytes = encode_system_module_manifest(&manifest).unwrap();
        let manifest_hash = resolver
            .hash_for_purpose(
                Epoch::new(0),
                HashPurpose::SystemModuleManifest,
                &manifest_bytes,
            )
            .unwrap();
        let module = SystemModule {
            module_id,
            version,
            canonical_code_hash: code_hash,
            semantics_hash,
            manifest_hash,
            activation_epoch: Epoch::new(0),
            status: ModuleStatus::Active,
        };
        let mut registry = SystemModuleRegistry::new();
        registry.add_module(module).unwrap();
        let entry = PreinstalledModuleCatalogEntry::new(
            module_id,
            version,
            wasm_bytes,
            manifest,
            semantics_envelope,
        )
        .unwrap();
        let catalog = PreinstalledModuleCatalog::new(vec![entry]).unwrap();
        let module_ref = ObjectRef {
            id: ObjectId::new(*module_id.as_bytes()),
            version,
            digest: code_hash,
        };
        (registry, catalog, module_ref)
    }

    #[allow(clippy::too_many_arguments)]
    fn preinstalled_wasm_transaction(
        sender: Address,
        chain: ChainId,
        epoch: Epoch,
        nonce: u64,
        access_manifest: AccessManifest,
        module_ref: ObjectRef,
        args: Vec<u8>,
    ) -> Transaction {
        Transaction {
            chain_id: chain,
            protocol_version: ProtocolVersion::new(3),
            epoch,
            sender,
            nonce,
            access_manifest,
            module_ref,
            entrypoint: "run".to_string(),
            args,
            gas_limit: 1_000_000,
            fee_payment: None,
            signature: Vec::new(),
        }
    }

    /// A real, deterministically Ed25519-signed `SubmitTransaction`
    /// `NodeEvent` invoking a preinstalled module, matching
    /// [`signed_submit_transaction_event`]'s signing but with a caller-chosen
    /// access manifest, module reference, and args.
    fn signed_preinstalled_wasm_submit_transaction_event(
        signing_key: &ed25519_zebra::SigningKey,
        request_id: RequestId,
        nonce: u64,
        access_manifest: AccessManifest,
        module_ref: ObjectRef,
        args: Vec<u8>,
    ) -> NodeEvent {
        signed_preinstalled_wasm_submit_transaction_event_with_entrypoint(
            signing_key,
            request_id,
            nonce,
            access_manifest,
            module_ref,
            "run",
            args,
        )
    }

    /// Same as [`signed_preinstalled_wasm_submit_transaction_event`], with a
    /// caller-chosen entrypoint name instead of the fixed `"run"` export.
    #[allow(clippy::too_many_arguments)]
    fn signed_preinstalled_wasm_submit_transaction_event_with_entrypoint(
        signing_key: &ed25519_zebra::SigningKey,
        request_id: RequestId,
        nonce: u64,
        access_manifest: AccessManifest,
        module_ref: ObjectRef,
        entrypoint: &str,
        args: Vec<u8>,
    ) -> NodeEvent {
        let sender = dev_sender_address(signing_key);
        let mut tx = preinstalled_wasm_transaction(
            sender,
            ChainId::new("sunrise-test").unwrap(),
            Epoch::new(7),
            nonce,
            access_manifest,
            module_ref,
            args,
        );
        tx.entrypoint = entrypoint.to_string();
        let bytes = signed_transaction_bytes(signing_key, &tx);
        submit_transaction_event(request_id, bytes)
    }

    /// A committed protocol configuration like [`active_protocol_config`],
    /// additionally carrying `registry` as the committed system-module
    /// registry a preinstalled-WASM call resolves `module_ref` against.
    fn preinstalled_protocol_config(
        domain: AtomicityDomainId,
        registry: SystemModuleRegistry,
    ) -> ProtocolConfig {
        let mut protocol_config = active_protocol_config(domain);
        protocol_config.system_modules = registry;
        protocol_config
    }

    /// A [`DurableOperationContext`] deadline computed from real wall-clock
    /// time, required by [`SqliteDurableStore`] (unlike [`MemoryDurableStateStore`],
    /// it compares the deadline against actual `SystemTime::now()`, not a
    /// settable virtual clock), matching `runtime-sqlite`'s own
    /// `live_context` test helper.
    fn live_operation_context(
        fence: WriterFenceGeneration,
        correlation_byte: u8,
    ) -> DurableOperationContext {
        let now = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();
        DurableOperationContext::new(
            fence,
            StorageDeadline::new(now + 60_000).unwrap(),
            StorageCorrelationId::new([correlation_byte; 16]).unwrap(),
        )
    }

    /// Directly commits one address-owned inline object version and head as
    /// fixture setup, bypassing every HTTP/node-core entrypoint, exactly like
    /// `node_core`'s own `commit_memory_inline_object` test helper.
    fn commit_owned_object<S>(
        store: &S,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object: Object,
        chain: &str,
        created_checkpoint: u64,
        receipt_byte: u8,
    ) -> ObjectRef
    where
        S: IndexedOutboxRepository,
    {
        let object_id = object.id;
        let object_version = object.version;
        let owner = object.owner.clone();
        let canonical_bytes = encode_object(&object).unwrap();
        let chain_id = ChainId::new(chain).unwrap();
        let digest = resolver()
            .hash_for_purpose(Epoch::new(0), HashPurpose::Object, &canonical_bytes)
            .unwrap();
        let provenance = DurableObjectProvenance::new(chain_id, ProtocolVersion::new(3));
        let record = DurableObjectVersionRecord::from_inline_object(
            object,
            digest,
            provenance,
            created_checkpoint,
        )
        .unwrap();
        let changes = DurableObjectChanges::new(
            vec![DurableObjectHeadRead::new(
                object_id,
                DurableObjectHead::Absent,
            )],
            vec![DurableObjectMutationEntry::new(
                object_id,
                DurableObjectMutation::Create {
                    version: record,
                    owner_projection: DurableObjectOwnerProjection::from_owner(owner).unwrap(),
                    routing_projection: DurableObjectRoutingProjection::default(),
                },
            )],
        )
        .unwrap();
        let receipt_request_id: RequestId = request_id(receipt_byte);
        let receipt_event_digest: Digest32 = Digest32::new(
            HashAlgorithmId::Sha2_256,
            [receipt_byte.wrapping_add(1); 32],
        );
        let receipt_response: NodeResponse =
            NodeResponse::new(receipt_request_id, NodeResponseStatus::Accepted, None).unwrap();
        let receipt_record: NodeDedupRecord = NodeDedupRecord::new(
            receipt_request_id,
            receipt_event_digest,
            vec![receipt_response],
        )
        .unwrap();
        let receipt = DurableRequestReceipt::new(
            DurableRequestId::new(*receipt_request_id.as_bytes()).unwrap(),
            receipt_event_digest,
            receipt_record.encode().unwrap(),
        )
        .unwrap();
        let invocation =
            DurableInvocationTransaction::new(domain, None, changes, receipt, None).unwrap();
        assert_eq!(
            store.commit_invocation(context, invocation),
            DurableCommitOutcome::Committed
        );
        ObjectRef {
            id: object_id,
            version: object_version,
            digest,
        }
    }

    /// A [`BlobStore`] test double that counts every [`BlobStore::get_blob`]
    /// call, so an end-to-end HTTP composition test can prove the exact
    /// supplied blob store (not some other default) served the request.
    #[derive(Clone, Default)]
    struct CountingBlobStore {
        blobs: Arc<std::sync::Mutex<std::collections::BTreeMap<Digest32, Vec<u8>>>>,
        get_calls: Arc<AtomicUsize>,
    }

    impl CountingBlobStore {
        fn get_calls(&self) -> usize {
            self.get_calls.load(Ordering::SeqCst)
        }
    }

    impl BlobStore for CountingBlobStore {
        fn put_blob(&self, digest: Digest32, bytes: Vec<u8>) -> Result<(), RuntimeError> {
            self.blobs.lock().unwrap().insert(digest, bytes);
            Ok(())
        }

        fn get_blob(&self, digest: &Digest32) -> Result<Option<Vec<u8>>, RuntimeError> {
            self.get_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.blobs.lock().unwrap().get(digest).cloned())
        }
    }

    /// Directly commits one address-owned blob-backed object version and
    /// head as fixture setup, bypassing every HTTP/node-core entrypoint,
    /// exactly like [`commit_owned_object`] but with the canonical body
    /// stored only in `blob_store`, keyed under its own content digest.
    #[allow(clippy::too_many_arguments)]
    fn commit_owned_blob_object<S>(
        store: &S,
        blob_store: &CountingBlobStore,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object: Object,
        chain: &str,
        created_checkpoint: u64,
        receipt_byte: u8,
    ) -> ObjectRef
    where
        S: IndexedOutboxRepository,
    {
        let object_id = object.id;
        let object_version = object.version;
        let owner = object.owner.clone();
        let schema_version = object.schema_version;
        let canonical_bytes = encode_object(&object).unwrap();
        let chain_id = ChainId::new(chain).unwrap();
        let digest = resolver()
            .hash_for_purpose(Epoch::new(0), HashPurpose::Object, &canonical_bytes)
            .unwrap();
        blob_store.put_blob(digest, canonical_bytes).unwrap();
        let provenance = DurableObjectProvenance::new(chain_id, ProtocolVersion::new(3));
        let record = DurableObjectVersionRecord::from_blob_reference(
            object_id,
            DurableObjectVersion::new(object_version).unwrap(),
            digest,
            schema_version,
            provenance,
            created_checkpoint,
            digest,
        );
        let changes = DurableObjectChanges::new(
            vec![DurableObjectHeadRead::new(
                object_id,
                DurableObjectHead::Absent,
            )],
            vec![DurableObjectMutationEntry::new(
                object_id,
                DurableObjectMutation::Create {
                    version: record,
                    owner_projection: DurableObjectOwnerProjection::from_owner(owner).unwrap(),
                    routing_projection: DurableObjectRoutingProjection::default(),
                },
            )],
        )
        .unwrap();
        let receipt_request_id: RequestId = request_id(receipt_byte);
        let receipt_event_digest: Digest32 = Digest32::new(
            HashAlgorithmId::Sha2_256,
            [receipt_byte.wrapping_add(1); 32],
        );
        let receipt_response: NodeResponse =
            NodeResponse::new(receipt_request_id, NodeResponseStatus::Accepted, None).unwrap();
        let receipt_record: NodeDedupRecord = NodeDedupRecord::new(
            receipt_request_id,
            receipt_event_digest,
            vec![receipt_response],
        )
        .unwrap();
        let receipt = DurableRequestReceipt::new(
            DurableRequestId::new(*receipt_request_id.as_bytes()).unwrap(),
            receipt_event_digest,
            receipt_record.encode().unwrap(),
        )
        .unwrap();
        let invocation =
            DurableInvocationTransaction::new(domain, None, changes, receipt, None).unwrap();
        assert_eq!(
            store.commit_invocation(context, invocation),
            DurableCommitOutcome::Committed
        );
        ObjectRef {
            id: object_id,
            version: object_version,
            digest,
        }
    }

    /// Builds the preinstalled-WASM durable router with an explicit,
    /// caller-supplied `BlobStore` component instead of a default
    /// [`MemoryBlobStore`], so a test can prove the exact supplied store is
    /// the one the composition dispatches through.
    #[allow(clippy::too_many_arguments)]
    fn preinstalled_app_with_blob_store<S, B, C>(
        store: Arc<S>,
        blob_store: Arc<B>,
        transport: Arc<MemoryTransport>,
        clock: Arc<C>,
        protocol_config: ProtocolConfig,
        config: NodeConfig,
        catalog: Arc<PreinstalledModuleCatalog>,
        created_checkpoint: u64,
    ) -> Router
    where
        S: IndexedOutboxRepository + Send + Sync + 'static,
        B: BlobStore + Send + Sync + 'static,
        C: Clock + Send + Sync + 'static,
    {
        let machine: Arc<IncrementMachine> = Arc::new(IncrementMachine::new(config.state_key()));
        preinstalled_wasm_structured_durable_router(
            StructuredDurableNativeComponents::new(
                store,
                blob_store,
                transport,
                clock,
                Arc::new(SequenceIndexedIdentities::default()),
            ),
            PreinstalledWasmComposition::new(catalog, WasmExecutionEngine, created_checkpoint),
            protocol_config,
            structured_request_authority(),
            config,
            resolver(),
            machine,
            NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
        )
        .unwrap()
    }

    /// Decodes a committed version's typed object regardless of whether its
    /// payload is inline or blob-backed, so tests written against either
    /// shape can assert on the same decoded `Object` without caring which
    /// storage representation a given commit chose.
    fn committed_object(
        version: &DurableObjectVersionRecord,
        blob_store: &impl BlobStore,
    ) -> Object {
        match version.payload() {
            DurableObjectPayload::Inline(inline) => inline.object().clone(),
            DurableObjectPayload::BlobReference(blob_digest) => {
                let bytes = blob_store.get_blob(blob_digest).unwrap().unwrap();
                decode_object(&bytes).unwrap()
            }
        }
    }

    fn owned_object(id: ObjectId, owner: Address, byte: u8) -> Object {
        Object {
            id,
            version: 1,
            owner: Owner::Address(owner),
            type_hash: Digest32::new(HashAlgorithmId::Sha2_256, [byte.wrapping_add(1); 32]),
            schema_version: u32::from(byte),
            data: vec![byte],
        }
    }

    struct IncrementMachine {
        state_key: Vec<u8>,
    }

    impl IncrementMachine {
        fn new(state_key: &[u8]) -> Self {
            Self {
                state_key: state_key.to_vec(),
            }
        }
    }

    impl TransactionalNodeStateMachine for IncrementMachine {
        fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
            NodeStateAccessPlan::new(vec![NodeStateAccess::new(
                self.state_key.clone(),
                NodeStateAccessMode::ReadWrite,
            )?])
        }

        fn transition(
            &self,
            state: &NodeStateSnapshot,
            event: &NodeEvent,
        ) -> Result<TransactionalNodeTransition, NodeCoreError> {
            let current = state
                .get(&self.state_key)
                .ok_or(NodeCoreError::TransitionRejected("test state missing"))?
                .value()
                .map(decode_canonical_frame)
                .transpose()?
                .map(|frame| frame.required_u64(1))
                .transpose()?
                .unwrap_or(0);
            let next = current
                .checked_add(1)
                .ok_or(NodeCoreError::TransitionRejected("test overflow"))?;
            let response = NodeResponse::new(
                event.request_id(),
                NodeResponseStatus::Accepted,
                Some(canonical(TEST_PAYLOAD_TYPE_ID, next)),
            )?;
            let outbound = NodeEvent::new(
                event.chain_id().clone(),
                event.protocol_version(),
                event.epoch(),
                request_id(0xF0),
                node_core::NodeEventKind::ReceiveVote,
                canonical(TEST_PAYLOAD_TYPE_ID, next),
            )?;
            TransactionalNodeTransition::new(
                vec![NodeStateUpdate::put(
                    self.state_key.clone(),
                    canonical(TEST_STATE_TYPE_ID, next),
                )?],
                NodeOutput::new(vec![response], vec![OutboundMessage::new(outbound)])?,
            )
        }
    }

    struct CountingMachine {
        inner: IncrementMachine,
        access_plan_calls: AtomicUsize,
        transition_calls: AtomicUsize,
    }

    impl CountingMachine {
        fn new(state_key: &[u8]) -> Self {
            Self {
                inner: IncrementMachine::new(state_key),
                access_plan_calls: AtomicUsize::new(0),
                transition_calls: AtomicUsize::new(0),
            }
        }
    }

    impl TransactionalNodeStateMachine for CountingMachine {
        fn access_plan(&self, event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
            self.access_plan_calls.fetch_add(1, Ordering::SeqCst);
            self.inner.access_plan(event)
        }

        fn transition(
            &self,
            state: &NodeStateSnapshot,
            event: &NodeEvent,
        ) -> Result<TransactionalNodeTransition, NodeCoreError> {
            self.transition_calls.fetch_add(1, Ordering::SeqCst);
            self.inner.transition(state, event)
        }
    }

    struct BlockingMachine {
        inner: IncrementMachine,
        entered: Arc<Notify>,
        release: Arc<(Mutex<bool>, Condvar)>,
    }

    impl TransactionalNodeStateMachine for BlockingMachine {
        fn access_plan(&self, event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
            self.inner.access_plan(event)
        }

        fn transition(
            &self,
            state: &NodeStateSnapshot,
            event: &NodeEvent,
        ) -> Result<TransactionalNodeTransition, NodeCoreError> {
            self.entered.notify_one();
            let (released, release_signal) = self.release.as_ref();
            let mut is_released = released
                .lock()
                .map_err(|_| NodeCoreError::TransitionRejected("test release lock poisoned"))?;
            while !*is_released {
                is_released = release_signal
                    .wait(is_released)
                    .map_err(|_| NodeCoreError::TransitionRejected("test release lock poisoned"))?;
            }
            self.inner.transition(state, event)
        }
    }

    #[derive(Default)]
    struct CountingStateStore {
        inner: MemoryStateStore,
        calls: AtomicUsize,
    }

    impl CountingStateStore {
        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl StateStore for CountingStateStore {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, RuntimeError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.get(key)
        }

        fn put(&self, key: Vec<u8>, value: Vec<u8>) -> Result<(), RuntimeError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.put(key, value)
        }

        fn compare_and_swap(
            &self,
            key: Vec<u8>,
            expected: Option<Vec<u8>>,
            new_value: Vec<u8>,
        ) -> Result<CompareAndSwapResult, RuntimeError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.compare_and_swap(key, expected, new_value)
        }
    }

    impl TransactionalStateStore for CountingStateStore {
        fn get_versioned(&self, key: &[u8]) -> Result<VersionedStateValue, RuntimeError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.get_versioned(key)
        }

        fn commit_atomic(
            &self,
            write_set: AtomicStateWriteSet,
        ) -> Result<AtomicStateWriteResult, RuntimeError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.commit_atomic(write_set)
        }
    }

    impl runtime::DomainTransactionalStateStore for CountingStateStore {
        fn get_versioned_in_domain(
            &self,
            domain: AtomicityDomainId,
            key: &[u8],
        ) -> Result<VersionedStateValue, RuntimeError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.get_versioned_in_domain(domain, key)
        }

        fn commit_transaction(
            &self,
            transaction: AtomicStateTransaction,
        ) -> Result<AtomicStateWriteResult, RuntimeError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.commit_transaction(transaction)
        }
    }

    #[derive(Default)]
    struct CountingTransport {
        send_calls: AtomicUsize,
    }

    impl Transport for CountingTransport {
        fn send(&self, _message: Vec<u8>) -> Result<(), RuntimeError> {
            self.send_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn drain_outbound(&self) -> Result<Vec<Vec<u8>>, RuntimeError> {
            Ok(Vec::new())
        }
    }

    #[derive(Default)]
    struct SequenceLeaseIds {
        next: Mutex<u64>,
    }

    impl OutboxLeaseIdSource for SequenceLeaseIds {
        fn next_lease_id(
            &self,
            _request_id: RequestId,
        ) -> Result<OutboxLeaseId, OutboxLeaseIdSourceError> {
            let mut next = self
                .next
                .lock()
                .map_err(|_| OutboxLeaseIdSourceError::Unavailable)?;
            *next = next
                .checked_add(1)
                .ok_or(OutboxLeaseIdSourceError::Exhausted)?;
            let mut bytes = [0_u8; 32];
            bytes[..8].copy_from_slice(&next.to_le_bytes());
            OutboxLeaseId::new(bytes).map_err(|_| OutboxLeaseIdSourceError::Exhausted)
        }
    }

    #[derive(Default)]
    struct CountingLeaseIds {
        calls: AtomicUsize,
    }

    impl OutboxLeaseIdSource for CountingLeaseIds {
        fn next_lease_id(
            &self,
            _request_id: RequestId,
        ) -> Result<OutboxLeaseId, OutboxLeaseIdSourceError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            OutboxLeaseId::new([0x73; 32]).map_err(|_| OutboxLeaseIdSourceError::Exhausted)
        }
    }

    struct FixedIndexedIdentity;

    impl IndexedOutboxIdentitySource for FixedIndexedIdentity {
        fn next_attempt_identity(
            &self,
        ) -> Result<IndexedOutboxAttemptIdentity, IndexedOutboxIdentitySourceError> {
            Ok(IndexedOutboxAttemptIdentity::new(
                DurableOutboxLeaseId::new([0x71; 32]).unwrap(),
                StorageCorrelationId::new([0x72; 16]).unwrap(),
            ))
        }
    }

    #[derive(Default)]
    struct SequenceIndexedIdentities {
        next: Mutex<u64>,
    }

    impl IndexedOutboxIdentitySource for SequenceIndexedIdentities {
        fn next_attempt_identity(
            &self,
        ) -> Result<IndexedOutboxAttemptIdentity, IndexedOutboxIdentitySourceError> {
            let mut next = self
                .next
                .lock()
                .map_err(|_| IndexedOutboxIdentitySourceError::Unavailable)?;
            *next = next
                .checked_add(1)
                .ok_or(IndexedOutboxIdentitySourceError::Exhausted)?;
            let mut lease = [0_u8; 32];
            lease[..8].copy_from_slice(&next.to_le_bytes());
            let mut correlation = [0_u8; 16];
            correlation[..8].copy_from_slice(&next.to_le_bytes());
            Ok(IndexedOutboxAttemptIdentity::new(
                DurableOutboxLeaseId::new(lease)
                    .map_err(|_| IndexedOutboxIdentitySourceError::Exhausted)?,
                StorageCorrelationId::new(correlation)
                    .ok_or(IndexedOutboxIdentitySourceError::Exhausted)?,
            ))
        }
    }

    #[derive(Default)]
    struct CountingIndexedIdentities {
        calls: AtomicUsize,
        next: Mutex<u64>,
    }

    impl IndexedOutboxIdentitySource for CountingIndexedIdentities {
        fn next_attempt_identity(
            &self,
        ) -> Result<IndexedOutboxAttemptIdentity, IndexedOutboxIdentitySourceError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut next = self
                .next
                .lock()
                .map_err(|_| IndexedOutboxIdentitySourceError::Unavailable)?;
            *next = next
                .checked_add(1)
                .ok_or(IndexedOutboxIdentitySourceError::Exhausted)?;
            let mut lease = [0_u8; 32];
            lease[..8].copy_from_slice(&next.to_le_bytes());
            let mut correlation = [0_u8; 16];
            correlation[..8].copy_from_slice(&next.to_le_bytes());
            Ok(IndexedOutboxAttemptIdentity::new(
                DurableOutboxLeaseId::new(lease)
                    .map_err(|_| IndexedOutboxIdentitySourceError::Exhausted)?,
                StorageCorrelationId::new(correlation)
                    .ok_or(IndexedOutboxIdentitySourceError::Exhausted)?,
            ))
        }
    }

    struct CountingClock {
        now_unix_millis: u64,
        calls: AtomicUsize,
    }

    impl CountingClock {
        fn new(now_unix_millis: u64) -> Self {
            Self {
                now_unix_millis,
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl Clock for CountingClock {
        fn now_unix_millis(&self) -> Result<u64, RuntimeError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.now_unix_millis)
        }
    }

    /// An identity source that always fails with a fixed, chosen error, for
    /// exercising the query path's `Unavailable`/`Exhausted` classification.
    struct FailingIndexedIdentities {
        error: IndexedOutboxIdentitySourceError,
    }

    impl IndexedOutboxIdentitySource for FailingIndexedIdentities {
        fn next_attempt_identity(
            &self,
        ) -> Result<IndexedOutboxAttemptIdentity, IndexedOutboxIdentitySourceError> {
            Err(self.error)
        }
    }

    /// A clock that always fails, for exercising the query path's
    /// `NodeCoreError::Runtime` classification.
    struct FailingClock;

    impl Clock for FailingClock {
        fn now_unix_millis(&self) -> Result<u64, RuntimeError> {
            Err(RuntimeError::EmptyKey)
        }
    }

    #[derive(Debug)]
    struct StepCancellation {
        cancel_at_call: usize,
        calls: AtomicUsize,
    }

    impl StepCancellation {
        fn new(cancel_at_call: usize) -> Self {
            Self {
                cancel_at_call,
                calls: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl InvocationCancellation for StepCancellation {
        fn is_cancelled(&self) -> bool {
            self.calls.fetch_add(1, Ordering::SeqCst) + 1 >= self.cancel_at_call
        }
    }

    #[derive(Debug, Default)]
    struct ManualCancellation {
        cancelled: AtomicBool,
    }

    impl ManualCancellation {
        fn cancel(&self) {
            self.cancelled.store(true, Ordering::SeqCst);
        }
    }

    impl InvocationCancellation for ManualCancellation {
        fn is_cancelled(&self) -> bool {
            self.cancelled.load(Ordering::SeqCst)
        }
    }

    struct ScriptedIndexedStore {
        claims: Mutex<VecDeque<DurableOutboxClaimOutcome>>,
        acknowledgements: Mutex<VecDeque<DurableOutboxAcknowledgementOutcome>>,
        claim_requests: Mutex<Vec<DueOutboxClaimRequest>>,
        acknowledgement_requests: Mutex<Vec<DurableOutboxAcknowledgement>>,
        storage_calls: AtomicUsize,
    }

    impl ScriptedIndexedStore {
        fn new(
            claims: Vec<DurableOutboxClaimOutcome>,
            acknowledgements: Vec<DurableOutboxAcknowledgementOutcome>,
        ) -> Self {
            Self {
                claims: Mutex::new(claims.into()),
                acknowledgements: Mutex::new(acknowledgements.into()),
                claim_requests: Mutex::new(Vec::new()),
                acknowledgement_requests: Mutex::new(Vec::new()),
                storage_calls: AtomicUsize::new(0),
            }
        }
    }

    impl StateStore for ScriptedIndexedStore {
        fn get(&self, _key: &[u8]) -> Result<Option<Vec<u8>>, RuntimeError> {
            self.storage_calls.fetch_add(1, Ordering::SeqCst);
            Err(RuntimeError::DurableStoreUnavailable)
        }

        fn put(&self, _key: Vec<u8>, _value: Vec<u8>) -> Result<(), RuntimeError> {
            self.storage_calls.fetch_add(1, Ordering::SeqCst);
            Err(RuntimeError::DurableStoreUnavailable)
        }

        fn compare_and_swap(
            &self,
            _key: Vec<u8>,
            _expected: Option<Vec<u8>>,
            _new_value: Vec<u8>,
        ) -> Result<CompareAndSwapResult, RuntimeError> {
            self.storage_calls.fetch_add(1, Ordering::SeqCst);
            Err(RuntimeError::DurableStoreUnavailable)
        }
    }

    impl DurableDomainStateStore for ScriptedIndexedStore {
        fn get_versioned_durable(
            &self,
            _context: &DurableOperationContext,
            _domain: AtomicityDomainId,
            _key: &[u8],
        ) -> Result<VersionedStateValue, DurableReadError> {
            self.storage_calls.fetch_add(1, Ordering::SeqCst);
            Err(DurableReadError::Unavailable)
        }

        fn commit_durable(
            &self,
            _context: &DurableOperationContext,
            _transaction: AtomicStateTransaction,
        ) -> DurableCommitOutcome {
            self.storage_calls.fetch_add(1, Ordering::SeqCst);
            DurableCommitOutcome::Rejected(DurableCommitRejection::UnavailableBeforeCommit)
        }
    }

    impl StructuredDurableDomainStateStore for ScriptedIndexedStore {
        fn get_request_receipt(
            &self,
            _context: &DurableOperationContext,
            _domain: AtomicityDomainId,
            _request_id: DurableRequestId,
        ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
            self.storage_calls.fetch_add(1, Ordering::SeqCst);
            Err(DurableReadError::Unavailable)
        }

        fn commit_invocation(
            &self,
            _context: &DurableOperationContext,
            _transaction: DurableInvocationTransaction,
        ) -> DurableCommitOutcome {
            self.storage_calls.fetch_add(1, Ordering::SeqCst);
            DurableCommitOutcome::Rejected(DurableCommitRejection::UnavailableBeforeCommit)
        }
    }

    impl IndexedOutboxRepository for ScriptedIndexedStore {
        fn claim_request_outbox(
            &self,
            _context: &DurableOperationContext,
            _request: RequestOutboxClaimRequest,
        ) -> DurableOutboxClaimOutcome {
            self.storage_calls.fetch_add(1, Ordering::SeqCst);
            self.claims
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(DurableOutboxClaimOutcome::NoDueWork)
        }

        fn claim_due_outbox(
            &self,
            _context: &DurableOperationContext,
            request: DueOutboxClaimRequest,
        ) -> DurableOutboxClaimOutcome {
            self.storage_calls.fetch_add(1, Ordering::SeqCst);
            self.claim_requests.lock().unwrap().push(request);
            self.claims
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(DurableOutboxClaimOutcome::NoDueWork)
        }

        fn acknowledge_outbox(
            &self,
            _context: &DurableOperationContext,
            acknowledgement: DurableOutboxAcknowledgement,
        ) -> DurableOutboxAcknowledgementOutcome {
            self.storage_calls.fetch_add(1, Ordering::SeqCst);
            self.acknowledgement_requests
                .lock()
                .unwrap()
                .push(acknowledgement);
            self.acknowledgements
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(DurableOutboxAcknowledgementOutcome::Acknowledged)
        }
    }

    struct IndeterminateRequestClaimStore {
        inner: MemoryDurableStateStore,
        commit_contexts: Mutex<Vec<DurableOperationContext>>,
        claim_contexts: Mutex<Vec<DurableOperationContext>>,
        claim_requests: Mutex<Vec<RequestOutboxClaimRequest>>,
    }

    impl IndeterminateRequestClaimStore {
        fn new(inner: MemoryDurableStateStore) -> Self {
            Self {
                inner,
                commit_contexts: Mutex::new(Vec::new()),
                claim_contexts: Mutex::new(Vec::new()),
                claim_requests: Mutex::new(Vec::new()),
            }
        }
    }

    impl DurableDomainStateStore for IndeterminateRequestClaimStore {
        fn get_versioned_durable(
            &self,
            context: &DurableOperationContext,
            domain: AtomicityDomainId,
            key: &[u8],
        ) -> Result<VersionedStateValue, DurableReadError> {
            self.inner.get_versioned_durable(context, domain, key)
        }

        fn commit_durable(
            &self,
            context: &DurableOperationContext,
            transaction: AtomicStateTransaction,
        ) -> DurableCommitOutcome {
            self.inner.commit_durable(context, transaction)
        }
    }

    impl StructuredDurableDomainStateStore for IndeterminateRequestClaimStore {
        fn get_request_receipt(
            &self,
            context: &DurableOperationContext,
            domain: AtomicityDomainId,
            request_id: DurableRequestId,
        ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
            self.inner.get_request_receipt(context, domain, request_id)
        }

        fn commit_invocation(
            &self,
            context: &DurableOperationContext,
            transaction: DurableInvocationTransaction,
        ) -> DurableCommitOutcome {
            self.commit_contexts.lock().unwrap().push(*context);
            self.inner.commit_invocation(context, transaction)
        }
    }

    impl IndexedOutboxRepository for IndeterminateRequestClaimStore {
        fn claim_request_outbox(
            &self,
            context: &DurableOperationContext,
            request: RequestOutboxClaimRequest,
        ) -> DurableOutboxClaimOutcome {
            self.claim_contexts.lock().unwrap().push(*context);
            self.claim_requests.lock().unwrap().push(request);
            DurableOutboxClaimOutcome::Indeterminate(IndeterminateCommitReason::ConnectionLost)
        }

        fn claim_due_outbox(
            &self,
            context: &DurableOperationContext,
            request: DueOutboxClaimRequest,
        ) -> DurableOutboxClaimOutcome {
            self.inner.claim_due_outbox(context, request)
        }

        fn acknowledge_outbox(
            &self,
            context: &DurableOperationContext,
            acknowledgement: DurableOutboxAcknowledgement,
        ) -> DurableOutboxAcknowledgementOutcome {
            self.inner.acknowledge_outbox(context, acknowledgement)
        }
    }

    struct CancelOnFirstReceiptReadStore {
        inner: MemoryDurableStateStore,
        cancellation: Arc<ManualCancellation>,
        cancelled: AtomicBool,
        receipt_reads: AtomicUsize,
    }

    impl CancelOnFirstReceiptReadStore {
        fn new(inner: MemoryDurableStateStore, cancellation: Arc<ManualCancellation>) -> Self {
            Self {
                inner,
                cancellation,
                cancelled: AtomicBool::new(false),
                receipt_reads: AtomicUsize::new(0),
            }
        }

        fn receipt_reads(&self) -> usize {
            self.receipt_reads.load(Ordering::SeqCst)
        }
    }

    impl DurableDomainStateStore for CancelOnFirstReceiptReadStore {
        fn get_versioned_durable(
            &self,
            context: &DurableOperationContext,
            domain: AtomicityDomainId,
            key: &[u8],
        ) -> Result<VersionedStateValue, DurableReadError> {
            self.inner.get_versioned_durable(context, domain, key)
        }

        fn commit_durable(
            &self,
            context: &DurableOperationContext,
            transaction: AtomicStateTransaction,
        ) -> DurableCommitOutcome {
            self.inner.commit_durable(context, transaction)
        }
    }

    impl StructuredDurableDomainStateStore for CancelOnFirstReceiptReadStore {
        fn get_request_receipt(
            &self,
            context: &DurableOperationContext,
            domain: AtomicityDomainId,
            request_id: DurableRequestId,
        ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
            self.receipt_reads.fetch_add(1, Ordering::SeqCst);
            if !self.cancelled.swap(true, Ordering::SeqCst) {
                self.cancellation.cancel();
            }
            self.inner.get_request_receipt(context, domain, request_id)
        }

        fn commit_invocation(
            &self,
            context: &DurableOperationContext,
            transaction: DurableInvocationTransaction,
        ) -> DurableCommitOutcome {
            self.inner.commit_invocation(context, transaction)
        }
    }

    impl IndexedOutboxRepository for CancelOnFirstReceiptReadStore {
        fn claim_request_outbox(
            &self,
            context: &DurableOperationContext,
            request: RequestOutboxClaimRequest,
        ) -> DurableOutboxClaimOutcome {
            self.inner.claim_request_outbox(context, request)
        }

        fn claim_due_outbox(
            &self,
            context: &DurableOperationContext,
            request: DueOutboxClaimRequest,
        ) -> DurableOutboxClaimOutcome {
            self.inner.claim_due_outbox(context, request)
        }

        fn acknowledge_outbox(
            &self,
            context: &DurableOperationContext,
            acknowledgement: DurableOutboxAcknowledgement,
        ) -> DurableOutboxAcknowledgementOutcome {
            self.inner.acknowledge_outbox(context, acknowledgement)
        }
    }

    fn indexed_runtime(
        store: ScriptedIndexedStore,
    ) -> ComposedRuntime<
        ScriptedIndexedStore,
        MemoryBlobStore,
        MemorySigner,
        MemoryTransport,
        ManualClock,
        MemoryScheduler,
    > {
        ComposedRuntime::new(
            store,
            MemoryBlobStore::default(),
            MemorySigner::new(ValidatorId::new([0x44; 32])),
            MemoryTransport::default(),
            ManualClock::new(10_000),
            MemoryScheduler::default(),
        )
    }

    fn indexed_authority() -> IndexedOutboxRecoveryAuthority {
        IndexedOutboxRecoveryAuthority::new(
            AtomicityDomainId::new([0x61; 32]).unwrap(),
            WriterFenceGeneration::new(3).unwrap(),
            1_000,
            NATIVE_OUTBOX_LEASE_MILLIS,
        )
        .unwrap()
    }

    fn app<R>(runtime: Arc<R>, config: NodeConfig) -> Router
    where
        R: Runtime + Send + Sync + 'static,
        R::State: TransactionalStateStore,
    {
        let machine = Arc::new(IncrementMachine::new(config.state_key()));
        router(
            runtime,
            config,
            resolver(),
            machine,
            Arc::new(SequenceLeaseIds::default()),
            NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
        )
    }

    type ObservedLegacyRuntime = ComposedRuntime<
        CountingStateStore,
        CountingBlobStore,
        MemorySigner,
        CountingTransport,
        CountingClock,
        MemoryScheduler,
    >;

    fn observed_legacy_runtime() -> Arc<ObservedLegacyRuntime> {
        Arc::new(ComposedRuntime::new(
            CountingStateStore::default(),
            CountingBlobStore::default(),
            MemorySigner::new(ValidatorId::new([0x44; 32])),
            CountingTransport::default(),
            CountingClock::new(10_000),
            MemoryScheduler::default(),
        ))
    }

    fn resolved_app(
        runtime: Arc<MemoryRuntime>,
        placement: DomainPlacementManifest,
        config: NodeConfig,
    ) -> Router {
        let machine = Arc::new(IncrementMachine::new(config.state_key()));
        resolved_domain_router(
            runtime,
            placement,
            config,
            resolver(),
            machine,
            Arc::new(SequenceLeaseIds::default()),
            NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
        )
    }

    fn structured_request_authority() -> StructuredDurableRequestAuthority {
        StructuredDurableRequestAuthority::new(
            WriterFenceGeneration::new(3).unwrap(),
            1_000,
            NATIVE_OUTBOX_LEASE_MILLIS,
        )
        .unwrap()
    }

    fn structured_app<S>(
        store: Arc<S>,
        transport: Arc<MemoryTransport>,
        clock: Arc<ManualClock>,
        protocol_config: ProtocolConfig,
        config: NodeConfig,
    ) -> Router
    where
        S: IndexedOutboxRepository + Send + Sync + 'static,
    {
        let machine: Arc<IncrementMachine> = Arc::new(IncrementMachine::new(config.state_key()));
        structured_durable_router(
            StructuredDurableNativeComponents::new(
                store,
                Arc::new(MemoryBlobStore::default()),
                transport,
                clock,
                Arc::new(SequenceIndexedIdentities::default()),
            ),
            protocol_config,
            structured_request_authority(),
            config,
            resolver(),
            machine,
            NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
        )
        .unwrap()
    }

    /// Builds the read-only structured durable router with an explicit,
    /// caller-supplied `BlobStore` component instead of a default
    /// [`MemoryBlobStore`], so a test can prove the exact supplied store is
    /// (or is not) the one the composition dispatches through.
    fn structured_app_with_blob_store<S, B>(
        store: Arc<S>,
        blob_store: Arc<B>,
        transport: Arc<MemoryTransport>,
        clock: Arc<ManualClock>,
        protocol_config: ProtocolConfig,
        config: NodeConfig,
    ) -> Router
    where
        S: IndexedOutboxRepository + Send + Sync + 'static,
        B: BlobStore + Send + Sync + 'static,
    {
        let machine: Arc<IncrementMachine> = Arc::new(IncrementMachine::new(config.state_key()));
        structured_durable_router(
            StructuredDurableNativeComponents::new(
                store,
                blob_store,
                transport,
                clock,
                Arc::new(SequenceIndexedIdentities::default()),
            ),
            protocol_config,
            structured_request_authority(),
            config,
            resolver(),
            machine,
            NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
        )
        .unwrap()
    }

    fn structured_app_with_cancellation<S>(
        store: Arc<S>,
        transport: Arc<MemoryTransport>,
        clock: Arc<ManualClock>,
        protocol_config: ProtocolConfig,
        config: NodeConfig,
        cancellation: Arc<dyn InvocationCancellation>,
    ) -> Router
    where
        S: IndexedOutboxRepository + Send + Sync + 'static,
    {
        let machine = Arc::new(IncrementMachine::new(config.state_key()));
        structured_durable_router(
            StructuredDurableNativeComponents::with_cancellation(
                store,
                Arc::new(MemoryBlobStore::default()),
                transport,
                clock,
                Arc::new(SequenceIndexedIdentities::default()),
                cancellation,
            ),
            protocol_config,
            structured_request_authority(),
            config,
            resolver(),
            machine,
            NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
        )
        .unwrap()
    }

    fn observed_structured_app(
        store: Arc<CancelOnFirstReceiptReadStore>,
        transport: Arc<MemoryTransport>,
        clock: Arc<CountingClock>,
        identities: Arc<CountingIndexedIdentities>,
        protocol_config: ProtocolConfig,
        config: NodeConfig,
        machine: Arc<CountingMachine>,
    ) -> Router {
        structured_durable_router(
            StructuredDurableNativeComponents::new(
                store,
                Arc::new(MemoryBlobStore::default()),
                transport,
                clock,
                identities,
            ),
            protocol_config,
            structured_request_authority(),
            config,
            resolver(),
            machine,
            NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
        )
        .unwrap()
    }

    fn preinstalled_app<S, C>(
        store: Arc<S>,
        transport: Arc<MemoryTransport>,
        clock: Arc<C>,
        protocol_config: ProtocolConfig,
        config: NodeConfig,
        catalog: Arc<PreinstalledModuleCatalog>,
        created_checkpoint: u64,
    ) -> Router
    where
        S: IndexedOutboxRepository + Send + Sync + 'static,
        C: Clock + Send + Sync + 'static,
    {
        let machine: Arc<IncrementMachine> = Arc::new(IncrementMachine::new(config.state_key()));
        preinstalled_wasm_structured_durable_router(
            StructuredDurableNativeComponents::new(
                store,
                Arc::new(MemoryBlobStore::default()),
                transport,
                clock,
                Arc::new(SequenceIndexedIdentities::default()),
            ),
            PreinstalledWasmComposition::new(catalog, WasmExecutionEngine, created_checkpoint),
            protocol_config,
            structured_request_authority(),
            config,
            resolver(),
            machine,
            NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
        )
        .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn preinstalled_app_with_cancellation<S>(
        store: Arc<S>,
        transport: Arc<MemoryTransport>,
        clock: Arc<ManualClock>,
        protocol_config: ProtocolConfig,
        config: NodeConfig,
        catalog: Arc<PreinstalledModuleCatalog>,
        created_checkpoint: u64,
        cancellation: Arc<dyn InvocationCancellation>,
    ) -> Router
    where
        S: IndexedOutboxRepository + Send + Sync + 'static,
    {
        let machine = Arc::new(IncrementMachine::new(config.state_key()));
        preinstalled_wasm_structured_durable_router(
            StructuredDurableNativeComponents::with_cancellation(
                store,
                Arc::new(MemoryBlobStore::default()),
                transport,
                clock,
                Arc::new(SequenceIndexedIdentities::default()),
                cancellation,
            ),
            PreinstalledWasmComposition::new(catalog, WasmExecutionEngine, created_checkpoint),
            protocol_config,
            structured_request_authority(),
            config,
            resolver(),
            machine,
            NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
        )
        .unwrap()
    }

    async fn assert_submit_rejected_before_side_effects_with_config(
        body: Vec<u8>,
        protocol_config: ProtocolConfig,
        config: NodeConfig,
        expected_status: StatusCode,
        expected_body: &'static str,
    ) {
        let fence = WriterFenceGeneration::new(3).unwrap();
        let inner = MemoryDurableStateStore::new(fence);
        inner.set_time(10_000);
        let cancellation = Arc::new(ManualCancellation::default());
        let store = Arc::new(CancelOnFirstReceiptReadStore::new(
            inner,
            Arc::clone(&cancellation),
        ));
        let transport = Arc::new(MemoryTransport::default());
        let clock = Arc::new(CountingClock::new(10_000));
        let identities = Arc::new(CountingIndexedIdentities::default());
        let machine = Arc::new(CountingMachine::new(config.state_key()));
        let app = observed_structured_app(
            Arc::clone(&store),
            Arc::clone(&transport),
            Arc::clone(&clock),
            Arc::clone(&identities),
            protocol_config,
            config,
            Arc::clone(&machine),
        );

        let response = app
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), expected_status);
        assert_eq!(
            to_bytes(response.into_body(), 256).await.unwrap(),
            expected_body
        );
        assert_eq!(machine.access_plan_calls.load(Ordering::SeqCst), 0);
        assert_eq!(machine.transition_calls.load(Ordering::SeqCst), 0);
        assert_eq!(identities.calls.load(Ordering::SeqCst), 0);
        assert_eq!(clock.calls.load(Ordering::SeqCst), 0);
        assert_eq!(store.receipt_reads(), 0);
        assert!(!cancellation.is_cancelled());
        assert!(transport.drain_outbound().unwrap().is_empty());
    }

    async fn assert_submit_rejected_before_side_effects(
        body: Vec<u8>,
        protocol_config: ProtocolConfig,
        expected_status: StatusCode,
        expected_body: &'static str,
    ) {
        assert_submit_rejected_before_side_effects_with_config(
            body,
            protocol_config,
            config(),
            expected_status,
            expected_body,
        )
        .await;
    }

    #[test]
    fn structured_router_rejects_diverging_or_missing_config_authority() {
        let fence = WriterFenceGeneration::new(3).unwrap();
        let store = Arc::new(MemoryDurableStateStore::new(fence));
        let transport = Arc::new(MemoryTransport::default());
        let clock = Arc::new(ManualClock::new(10_000));
        let identities = Arc::new(SequenceIndexedIdentities::default());
        let machine = Arc::new(IncrementMachine::new(config().state_key()));
        let domain = AtomicityDomainId::new([0x89; 32]).unwrap();
        let mut mismatched = active_protocol_config(domain);
        mismatched.protocol_version = ProtocolVersion::new(2);

        let blob_store = Arc::new(MemoryBlobStore::default());
        let mismatch = structured_durable_router(
            StructuredDurableNativeComponents::new(
                Arc::clone(&store),
                Arc::clone(&blob_store),
                Arc::clone(&transport),
                Arc::clone(&clock),
                Arc::clone(&identities),
            ),
            mismatched,
            structured_request_authority(),
            config(),
            resolver(),
            Arc::clone(&machine),
            NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
        );
        assert!(matches!(
            mismatch,
            Err(StructuredDurableRouterError::ProtocolVersionAuthorityMismatch {
                node_config,
                protocol_config,
            }) if node_config == ProtocolVersion::new(3)
                && protocol_config == ProtocolVersion::new(2)
        ));

        let mut missing_placement = ProtocolConfig::genesis();
        missing_placement.protocol_version = ProtocolVersion::new(3);
        missing_placement.transaction_auth_profile =
            Some(TransactionAuthProfile::ed25519_address_is_public_key());
        let missing = structured_durable_router(
            StructuredDurableNativeComponents::new(store, blob_store, transport, clock, identities),
            missing_placement,
            structured_request_authority(),
            config(),
            resolver(),
            machine,
            NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
        );
        assert!(matches!(
            missing,
            Err(StructuredDurableRouterError::MissingDomainPlacement)
        ));
    }

    #[tokio::test]
    async fn structured_route_authenticates_submit_before_commit_and_replay() {
        let fence = WriterFenceGeneration::new(3).unwrap();
        let store = Arc::new(MemoryDurableStateStore::new(fence));
        store.set_time(10_000);
        let transport = Arc::new(MemoryTransport::default());
        let clock = Arc::new(CountingClock::new(10_000));
        let identities = Arc::new(CountingIndexedIdentities::default());
        let config = config();
        let machine = Arc::new(CountingMachine::new(config.state_key()));
        let domain = AtomicityDomainId::new([0x86; 32]).unwrap();
        let app = structured_durable_router(
            StructuredDurableNativeComponents::new(
                Arc::clone(&store),
                Arc::new(MemoryBlobStore::default()),
                Arc::clone(&transport),
                Arc::clone(&clock),
                Arc::clone(&identities),
            ),
            active_protocol_config(domain),
            structured_request_authority(),
            config,
            resolver(),
            Arc::clone(&machine),
            NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
        )
        .unwrap();
        let signing_key = dev_signing_key(0x31);
        let event = signed_submit_transaction_event(&signing_key, request_id(0x36), 0);
        let body = event.encode().unwrap();

        let first = app
            .clone()
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let second = app
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        let first_status = first.status();
        let first_body = to_bytes(first.into_body(), 256).await.unwrap();
        let second_status = second.status();
        let second_body = to_bytes(second.into_body(), 256).await.unwrap();
        assert_eq!(
            first_status,
            StatusCode::OK,
            "first response body: {}",
            String::from_utf8_lossy(&first_body)
        );
        assert_eq!(
            second_status,
            StatusCode::OK,
            "second response body: {}",
            String::from_utf8_lossy(&second_body)
        );
        assert_eq!(machine.access_plan_calls.load(Ordering::SeqCst), 2);
        assert_eq!(machine.transition_calls.load(Ordering::SeqCst), 1);
        assert_eq!(identities.calls.load(Ordering::SeqCst), 2);
        assert_eq!(clock.calls.load(Ordering::SeqCst), 2);
        assert_eq!(transport.drain_outbound().unwrap().len(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn structured_event_route_rejects_excess_blocking_work_without_blocking_liveness() {
        let fence: WriterFenceGeneration = WriterFenceGeneration::new(3).unwrap();
        let store: Arc<MemoryDurableStateStore> = Arc::new(MemoryDurableStateStore::new(fence));
        store.set_time(10_000);
        let transport: Arc<MemoryTransport> = Arc::new(MemoryTransport::default());
        let config: NodeConfig = config();
        let entered: Arc<Notify> = Arc::new(Notify::new());
        let release: Arc<(Mutex<bool>, Condvar)> = Arc::new((Mutex::new(false), Condvar::new()));
        let machine: Arc<BlockingMachine> = Arc::new(BlockingMachine {
            inner: IncrementMachine::new(config.state_key()),
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        });
        let blocking_executor: NativeBlockingExecutor =
            NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(1).unwrap()));
        let app: Router = structured_durable_router_with_executor(
            StructuredDurableNativeComponents::new(
                store,
                Arc::new(MemoryBlobStore::default()),
                Arc::clone(&transport),
                Arc::new(ManualClock::new(10_000)),
                Arc::new(SequenceIndexedIdentities::default()),
            ),
            active_protocol_config(AtomicityDomainId::new([0x8B; 32]).unwrap()),
            structured_request_authority(),
            config,
            resolver(),
            machine,
            blocking_executor,
        )
        .unwrap();
        let first_signing_key: ed25519_zebra::SigningKey = dev_signing_key(0x36);
        let first_event: NodeEvent =
            signed_submit_transaction_event(&first_signing_key, request_id(0x37), 0);
        let second_signing_key: ed25519_zebra::SigningKey = dev_signing_key(0x38);
        let second_event: NodeEvent =
            signed_submit_transaction_event(&second_signing_key, request_id(0x39), 0);

        let first_app: Router = app.clone();
        let first = tokio::spawn(async move {
            first_app
                .oneshot(
                    Request::post(NODE_EVENT_PATH)
                        .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                        .body(Body::from(first_event.encode().unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap()
        });
        entered.notified().await;

        let liveness: Response = app
            .clone()
            .oneshot(Request::get(LIVENESS_PATH).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let overloaded: Response = app
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(second_event.encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let (released, release_signal) = release.as_ref();
        *released.lock().unwrap() = true;
        release_signal.notify_all();
        let first: Response = first.await.unwrap();

        assert_eq!(liveness.status(), StatusCode::NO_CONTENT);
        assert_eq!(overloaded.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            to_bytes(overloaded.into_body(), 128).await.unwrap(),
            "blocking-capacity-exhausted"
        );
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(transport.drain_outbound().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn structured_route_maps_fresh_request_nonce_mismatch_without_transition_or_send() {
        let fence = WriterFenceGeneration::new(3).unwrap();
        let store = Arc::new(MemoryDurableStateStore::new(fence));
        store.set_time(10_000);
        let transport = Arc::new(MemoryTransport::default());
        let clock = Arc::new(CountingClock::new(10_000));
        let identities = Arc::new(CountingIndexedIdentities::default());
        let config = config();
        let machine = Arc::new(CountingMachine::new(config.state_key()));
        let domain = AtomicityDomainId::new([0x96; 32]).unwrap();
        let app = structured_durable_router(
            StructuredDurableNativeComponents::new(
                Arc::clone(&store),
                Arc::new(MemoryBlobStore::default()),
                Arc::clone(&transport),
                Arc::clone(&clock),
                Arc::clone(&identities),
            ),
            active_protocol_config(domain),
            structured_request_authority(),
            config,
            resolver(),
            Arc::clone(&machine),
            NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
        )
        .unwrap();
        let signing_key = dev_signing_key(0x41);
        let event = signed_submit_transaction_event(&signing_key, request_id(0x46), 1);

        let response = app
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(event.encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(
            to_bytes(response.into_body(), 128).await.unwrap(),
            "sender-nonce-mismatch"
        );
        assert_eq!(machine.access_plan_calls.load(Ordering::SeqCst), 1);
        assert_eq!(machine.transition_calls.load(Ordering::SeqCst), 0);
        assert_eq!(identities.calls.load(Ordering::SeqCst), 1);
        assert_eq!(clock.calls.load(Ordering::SeqCst), 1);
        assert!(transport.drain_outbound().unwrap().is_empty());
    }

    #[tokio::test]
    async fn native_error_mapping_keeps_nonce_overflow_distinct_from_conflict() {
        let sender = [0x55; 32];
        let mismatch = node_error_response(&NodeCoreError::SenderNonceMismatch {
            sender,
            expected: 3,
            actual: 2,
        });
        assert_eq!(mismatch.status(), StatusCode::CONFLICT);
        assert_eq!(
            to_bytes(mismatch.into_body(), 128).await.unwrap(),
            "sender-nonce-mismatch"
        );

        let overflow = node_error_response(&NodeCoreError::SenderNonceOverflow { sender });
        assert_eq!(overflow.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            to_bytes(overflow.into_body(), 128).await.unwrap(),
            "sender-nonce-overflow"
        );
    }

    #[tokio::test]
    async fn native_error_mapping_classifies_fee_request_and_composition_failures() {
        let asset_id = fees::AssetId::new([0x56; 32]);
        let cases: Vec<(NodeCoreError, StatusCode, &'static str)> = vec![
            (
                NodeCoreError::FeePaymentRequired,
                StatusCode::UNPROCESSABLE_ENTITY,
                "fee-payment-required",
            ),
            (
                NodeCoreError::FeePaymentNotRequired,
                StatusCode::UNPROCESSABLE_ENTITY,
                "fee-payment-not-required",
            ),
            (
                NodeCoreError::FeePaymentUnsupportedOnPath,
                StatusCode::UNPROCESSABLE_ENTITY,
                "fee-payment-unsupported-on-path",
            ),
            (
                NodeCoreError::FeePaymentRejected(fees::FeeError::UnknownAsset(asset_id)),
                StatusCode::UNPROCESSABLE_ENTITY,
                "fee-payment-rejected",
            ),
            (
                NodeCoreError::FeePaymentRejected(fees::FeeError::ArithmeticOverflow),
                StatusCode::UNPROCESSABLE_ENTITY,
                "fee-settlement-overflow",
            ),
            (
                NodeCoreError::FeePaymentRejected(fees::FeeError::ZeroFeeUnitsPerAssetUnit),
                StatusCode::INTERNAL_SERVER_ERROR,
                "fee-policy-invalid",
            ),
            (
                NodeCoreError::FeeObjectNotDeclaredWrite,
                StatusCode::UNPROCESSABLE_ENTITY,
                "fee-object-not-declared-write",
            ),
            (
                NodeCoreError::FeeObjectNotOwnedBySender,
                StatusCode::FORBIDDEN,
                "fee-object-owner-mismatch",
            ),
            (
                NodeCoreError::FeeObjectIsTreasury,
                StatusCode::UNPROCESSABLE_ENTITY,
                "fee-object-is-treasury",
            ),
            (
                NodeCoreError::FeeTreasuryAccessMisdeclared,
                StatusCode::UNPROCESSABLE_ENTITY,
                "fee-treasury-access-misdeclared",
            ),
            (
                NodeCoreError::FeeCompositionFailed(
                    node_core::FeeCompositionError::InsufficientBalance,
                ),
                StatusCode::UNPROCESSABLE_ENTITY,
                "fee-balance-insufficient",
            ),
            (
                NodeCoreError::FeeCompositionFailed(node_core::FeeCompositionError::MalformedBody),
                StatusCode::INTERNAL_SERVER_ERROR,
                "fee-composition-invalid",
            ),
            (
                NodeCoreError::FeeCompositionUnavailable,
                StatusCode::INTERNAL_SERVER_ERROR,
                "fee-composition-unavailable",
            ),
            (
                NodeCoreError::FeeCompositionNoOp,
                StatusCode::INTERNAL_SERVER_ERROR,
                "fee-composition-no-op",
            ),
            (
                NodeCoreError::FeeAmountZero,
                StatusCode::INTERNAL_SERVER_ERROR,
                "fee-settlement-zero",
            ),
            (
                NodeCoreError::UnsupportedGasScheduleShape(
                    node_core::GasScheduleShapeFault::UnmeasuredCategoryPriced,
                ),
                StatusCode::INTERNAL_SERVER_ERROR,
                "fee-schedule-unsupported",
            ),
            (
                NodeCoreError::UnsupportedGasScheduleShape(
                    node_core::GasScheduleShapeFault::ZeroBaseFeeWithExecutionPrice,
                ),
                StatusCode::INTERNAL_SERVER_ERROR,
                "fee-schedule-unsupported",
            ),
        ];

        for (error, expected_status, expected_code) in cases {
            let response = node_error_response(&error);
            assert_eq!(response.status(), expected_status, "error: {error:?}");
            assert_eq!(
                to_bytes(response.into_body(), 128).await.unwrap(),
                expected_code,
                "error: {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn native_error_mapping_covers_every_authenticated_object_dispatch_variant() {
        let object_id = ObjectId::new([0x61; 32]);
        let digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x62; 32]);
        let cases: Vec<(NodeCoreError, StatusCode, &str)> = vec![
            (
                NodeCoreError::DurableRead(DurableReadError::InvalidRequest(
                    RuntimeError::UnsupportedObjectStorage,
                )),
                StatusCode::NOT_IMPLEMENTED,
                "object-storage-unsupported",
            ),
            (
                NodeCoreError::ObjectNotFound { object_id },
                StatusCode::UNPROCESSABLE_ENTITY,
                "object-not-found",
            ),
            (
                NodeCoreError::ObjectVersionMismatch {
                    object_id,
                    expected: 1,
                    actual: 2,
                },
                StatusCode::CONFLICT,
                "object-version-mismatch",
            ),
            (
                NodeCoreError::ObjectDigestMismatch {
                    object_id,
                    expected: digest,
                    actual: digest,
                },
                StatusCode::CONFLICT,
                "object-digest-mismatch",
            ),
            (
                NodeCoreError::ObjectOwnerMismatch { object_id },
                StatusCode::FORBIDDEN,
                "object-owner-mismatch",
            ),
            (
                NodeCoreError::ObjectAccessModeUnsupported {
                    object_id,
                    mode: AccessMode::Write,
                },
                StatusCode::NOT_IMPLEMENTED,
                "object-mutating-access-unsupported",
            ),
            (
                NodeCoreError::ObjectOwnerKindUnsupported { object_id },
                StatusCode::NOT_IMPLEMENTED,
                "object-owner-kind-unsupported",
            ),
            (
                NodeCoreError::ObjectBlobMissing {
                    object_id,
                    blob_digest: digest,
                },
                StatusCode::SERVICE_UNAVAILABLE,
                "object-blob-unavailable",
            ),
            (
                NodeCoreError::ObjectBlobDigestMismatch {
                    object_id,
                    blob_digest: digest,
                },
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid-node-output",
            ),
            (
                NodeCoreError::ObjectBlobPublishFailed {
                    object_id,
                    blob_digest: digest,
                    source: RuntimeError::BlobDigestConflict { digest },
                },
                StatusCode::SERVICE_UNAVAILABLE,
                "object-blob-publish-failed",
            ),
            (
                NodeCoreError::ObjectManifestTooLarge {
                    count: 33,
                    maximum: 32,
                },
                StatusCode::UNPROCESSABLE_ENTITY,
                "object-manifest-too-large",
            ),
            (
                NodeCoreError::DuplicateObjectAccess { object_id },
                StatusCode::BAD_REQUEST,
                "object-manifest-duplicate",
            ),
            (
                NodeCoreError::InvalidObjectVersion {
                    object_id,
                    version: 0,
                },
                StatusCode::BAD_REQUEST,
                "object-version-invalid",
            ),
            (
                NodeCoreError::ObjectConflict { object_id },
                StatusCode::CONFLICT,
                "object-head-conflict",
            ),
            (
                NodeCoreError::ObjectRecordMissing { object_id },
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid-node-output",
            ),
            (
                NodeCoreError::ObjectRecordMismatch { object_id },
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid-node-output",
            ),
            (
                NodeCoreError::ObjectBodyDigestMismatch { object_id },
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid-node-output",
            ),
            (
                NodeCoreError::ObjectProvenanceMismatch { object_id },
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid-node-output",
            ),
            (
                NodeCoreError::ObjectDigestUnverifiable {
                    object_id,
                    algorithm: HashAlgorithmId::Blake3_256,
                },
                StatusCode::NOT_IMPLEMENTED,
                "object-digest-algorithm-unsupported",
            ),
            (
                NodeCoreError::ObjectBodyTooLarge {
                    object_id,
                    actual: 2 * 1024 * 1024,
                    maximum: 1024 * 1024,
                },
                StatusCode::UNPROCESSABLE_ENTITY,
                "object-body-too-large",
            ),
            (
                NodeCoreError::PreinstalledModuleUnknown {
                    module_id: ModuleId::new([0x63; 32]),
                    version: 1,
                },
                StatusCode::UNPROCESSABLE_ENTITY,
                "preinstalled-module-unknown",
            ),
            (
                NodeCoreError::PreinstalledModuleInactive {
                    module_id: ModuleId::new([0x63; 32]),
                    version: 1,
                },
                StatusCode::UNPROCESSABLE_ENTITY,
                "preinstalled-module-inactive",
            ),
            (
                NodeCoreError::PreinstalledModuleNotYetActive {
                    module_id: ModuleId::new([0x63; 32]),
                    version: 1,
                    activation_epoch: Epoch::new(9),
                    current_epoch: Epoch::new(7),
                },
                StatusCode::UNPROCESSABLE_ENTITY,
                "preinstalled-module-not-yet-active",
            ),
            (
                NodeCoreError::PreinstalledModuleReferenceDigestMismatch {
                    module_id: ModuleId::new([0x63; 32]),
                    version: 1,
                },
                StatusCode::UNPROCESSABLE_ENTITY,
                "preinstalled-module-reference-invalid",
            ),
            (
                NodeCoreError::PreinstalledModuleArgsTooLarge {
                    module_id: ModuleId::new([0x63; 32]),
                    version: 1,
                    actual: 128,
                    maximum: 64,
                },
                StatusCode::UNPROCESSABLE_ENTITY,
                "preinstalled-module-args-too-large",
            ),
            (
                NodeCoreError::PreinstalledModuleGasLimitExceedsCeiling {
                    requested: 20_000_000,
                    maximum: 10_000_000,
                },
                StatusCode::UNPROCESSABLE_ENTITY,
                "preinstalled-module-gas-limit-exceeded",
            ),
            (
                NodeCoreError::PreinstalledModuleZeroObjectAccess,
                StatusCode::BAD_REQUEST,
                "preinstalled-module-zero-object-access",
            ),
            (
                NodeCoreError::PreinstalledModuleNotCataloged {
                    module_id: ModuleId::new([0x63; 32]),
                    version: 1,
                },
                StatusCode::INTERNAL_SERVER_ERROR,
                "preinstalled-module-catalog-mismatch",
            ),
            (
                NodeCoreError::PreinstalledModuleCodeHashMismatch {
                    module_id: ModuleId::new([0x63; 32]),
                    version: 1,
                },
                StatusCode::INTERNAL_SERVER_ERROR,
                "preinstalled-module-catalog-mismatch",
            ),
            (
                NodeCoreError::PreinstalledModuleManifestHashMismatch {
                    module_id: ModuleId::new([0x63; 32]),
                    version: 1,
                },
                StatusCode::INTERNAL_SERVER_ERROR,
                "preinstalled-module-catalog-mismatch",
            ),
            (
                NodeCoreError::PreinstalledModuleSemanticsHashMismatch {
                    module_id: ModuleId::new([0x63; 32]),
                    version: 1,
                },
                StatusCode::INTERNAL_SERVER_ERROR,
                "preinstalled-module-catalog-mismatch",
            ),
            (
                NodeCoreError::ObjectCreatedCheckpointRegression {
                    object_id,
                    previous_created_checkpoint: 9,
                    attempted_created_checkpoint: 5,
                },
                StatusCode::INTERNAL_SERVER_ERROR,
                "object-created-checkpoint-regression",
            ),
            (
                NodeCoreError::ObjectVersionOverflow { object_id },
                StatusCode::CONFLICT,
                "object-version-overflow",
            ),
            (
                NodeCoreError::ObjectCreationUnsupported { object_id },
                StatusCode::NOT_IMPLEMENTED,
                "object-creation-unsupported",
            ),
            (
                NodeCoreError::ObjectEffectMismatch {
                    object_id,
                    reason: "test reason",
                },
                StatusCode::UNPROCESSABLE_ENTITY,
                "object-effect-mismatch",
            ),
            (
                NodeCoreError::DuplicateObjectEffect { object_id },
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid-node-output",
            ),
            (
                NodeCoreError::TooManyObjectEffects {
                    actual: 33,
                    maximum: 32,
                },
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid-node-output",
            ),
            (
                NodeCoreError::UndeclaredObjectEffect { object_id },
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid-node-output",
            ),
            (
                NodeCoreError::ObjectMutationContextMissing { object_id },
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid-node-output",
            ),
            (
                NodeCoreError::SystemModules(SystemModuleError::ZeroModuleVersion),
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid-node-output",
            ),
            (
                NodeCoreError::Execution(ExecutionError::MissingEntrypoint(
                    "does-not-exist".to_string(),
                )),
                StatusCode::UNPROCESSABLE_ENTITY,
                "preinstalled-module-entrypoint-unknown",
            ),
            (
                NodeCoreError::Execution(ExecutionError::ResourceLimitExceeded("input objects")),
                StatusCode::UNPROCESSABLE_ENTITY,
                "preinstalled-module-resource-limit-exceeded",
            ),
            (
                NodeCoreError::Execution(ExecutionError::WasmEngine("boom".to_string())),
                StatusCode::INTERNAL_SERVER_ERROR,
                "preinstalled-module-engine-failure",
            ),
            (
                NodeCoreError::Execution(ExecutionError::ObjectVersionOverflow(object_id)),
                StatusCode::CONFLICT,
                "object-version-overflow",
            ),
            (
                NodeCoreError::Execution(ExecutionError::HashChainMismatch),
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid-node-output",
            ),
        ];

        for (error, expected_status, expected_code) in cases {
            let response = node_error_response(&error);
            assert_eq!(response.status(), expected_status, "error: {error:?}");
            assert_eq!(
                to_bytes(response.into_body(), 128).await.unwrap(),
                expected_code,
                "error: {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn structured_route_rejects_invalid_submit_before_every_side_effect() {
        let domain = AtomicityDomainId::new([0x87; 32]).unwrap();
        let protocol_config = active_protocol_config(domain);
        let signing_key = dev_signing_key(0x32);
        let valid = signed_submit_transaction_event(&signing_key, request_id(0x37), 1);

        let mut invalid_signature = decode_transaction(valid.payload()).unwrap();
        invalid_signature.signature = vec![0_u8; 64];
        let invalid_signature_event = submit_transaction_event(
            request_id(0x38),
            encode_transaction(&invalid_signature).unwrap(),
        );
        assert_submit_rejected_before_side_effects(
            invalid_signature_event.encode().unwrap(),
            protocol_config.clone(),
            StatusCode::UNAUTHORIZED,
            "transaction-signature-invalid",
        )
        .await;

        let sender = dev_sender_address(&signing_key);
        let mut wrong_chain = unsigned_transaction(
            sender,
            ChainId::new("other-chain").unwrap(),
            Epoch::new(7),
            2,
        );
        wrong_chain.signature = vec![0_u8; 64];
        let wrong_chain_event =
            submit_transaction_event(request_id(0x39), encode_transaction(&wrong_chain).unwrap());
        assert_submit_rejected_before_side_effects(
            wrong_chain_event.encode().unwrap(),
            protocol_config.clone(),
            StatusCode::BAD_REQUEST,
            "transaction-context-mismatch",
        )
        .await;

        let sender = dev_sender_address(&signing_key);
        let mut wrong_version = unsigned_transaction(
            sender,
            ChainId::new("sunrise-test").unwrap(),
            Epoch::new(7),
            3,
        );
        wrong_version.protocol_version = ProtocolVersion::new(2);
        wrong_version.signature = vec![0_u8; 64];
        let wrong_version_event = submit_transaction_event(
            request_id(0x3A),
            encode_transaction(&wrong_version).unwrap(),
        );
        assert_submit_rejected_before_side_effects(
            wrong_version_event.encode().unwrap(),
            protocol_config.clone(),
            StatusCode::BAD_REQUEST,
            "transaction-context-mismatch",
        )
        .await;

        let sender = dev_sender_address(&signing_key);
        let mut wrong_epoch = unsigned_transaction(
            sender,
            ChainId::new("sunrise-test").unwrap(),
            Epoch::new(8),
            4,
        );
        wrong_epoch.signature = vec![0_u8; 64];
        let wrong_epoch_event =
            submit_transaction_event(request_id(0x3B), encode_transaction(&wrong_epoch).unwrap());
        assert_submit_rejected_before_side_effects(
            wrong_epoch_event.encode().unwrap(),
            protocol_config.clone(),
            StatusCode::BAD_REQUEST,
            "transaction-context-mismatch",
        )
        .await;

        let mut trailing_payload = valid.payload().to_vec();
        trailing_payload.push(0);
        assert_submit_rejected_before_side_effects(
            raw_submit_transaction_event_bytes(request_id(0x3C), trailing_payload),
            protocol_config.clone(),
            StatusCode::BAD_REQUEST,
            "invalid-node-event",
        )
        .await;

        let mut missing_profile = protocol_config;
        missing_profile.transaction_auth_profile = None;
        assert_submit_rejected_before_side_effects(
            valid.encode().unwrap(),
            missing_profile,
            StatusCode::SERVICE_UNAVAILABLE,
            "transaction-auth-config-unavailable",
        )
        .await;

        let premature_node_config = NodeConfig::new(
            ChainId::new("sunrise-test").unwrap(),
            ProtocolVersion::new(2),
            Epoch::new(7),
            b"http/node-state".to_vec(),
        )
        .unwrap();
        let mut premature_protocol_config = ProtocolConfig::genesis();
        premature_protocol_config.protocol_version = ProtocolVersion::new(2);
        premature_protocol_config.domain_placement =
            Some(DomainPlacementManifest::single_domain(1, domain, Epoch::new(0)).unwrap());
        let premature_event = NodeEvent::new(
            ChainId::new("sunrise-test").unwrap(),
            ProtocolVersion::new(2),
            Epoch::new(7),
            request_id(0x3E),
            NodeEventKind::SubmitTransaction,
            canonical(TEST_PAYLOAD_TYPE_ID, 9),
        )
        .unwrap();
        assert_submit_rejected_before_side_effects_with_config(
            premature_event.encode().unwrap(),
            premature_protocol_config,
            premature_node_config,
            StatusCode::SERVICE_UNAVAILABLE,
            "transaction-auth-config-unavailable",
        )
        .await;
    }

    #[tokio::test]
    async fn structured_route_rejects_outer_event_context_mismatch_before_every_side_effect() {
        let domain = AtomicityDomainId::new([0x8A; 32]).unwrap();
        let protocol_config = active_protocol_config(domain);

        let wrong_chain_event = NodeEvent::new(
            ChainId::new("other-chain").unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(7),
            request_id(0x40),
            NodeEventKind::SubmitTransaction,
            canonical(TEST_PAYLOAD_TYPE_ID, 9),
        )
        .unwrap();
        assert_submit_rejected_before_side_effects(
            wrong_chain_event.encode().unwrap(),
            protocol_config.clone(),
            StatusCode::CONFLICT,
            "state-or-context-conflict",
        )
        .await;

        let wrong_version_event = NodeEvent::new(
            ChainId::new("sunrise-test").unwrap(),
            ProtocolVersion::new(2),
            Epoch::new(7),
            request_id(0x41),
            NodeEventKind::SubmitTransaction,
            canonical(TEST_PAYLOAD_TYPE_ID, 9),
        )
        .unwrap();
        assert_submit_rejected_before_side_effects(
            wrong_version_event.encode().unwrap(),
            protocol_config.clone(),
            StatusCode::CONFLICT,
            "state-or-context-conflict",
        )
        .await;

        let wrong_epoch_event = NodeEvent::new(
            ChainId::new("sunrise-test").unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(8),
            request_id(0x42),
            NodeEventKind::SubmitTransaction,
            canonical(TEST_PAYLOAD_TYPE_ID, 9),
        )
        .unwrap();
        assert_submit_rejected_before_side_effects(
            wrong_epoch_event.encode().unwrap(),
            protocol_config,
            StatusCode::CONFLICT,
            "state-or-context-conflict",
        )
        .await;
    }

    #[tokio::test]
    async fn structured_route_rejects_canonical_non_transaction_payload_before_every_side_effect() {
        let domain = AtomicityDomainId::new([0x8B; 32]).unwrap();
        let protocol_config = active_protocol_config(domain);
        let event = submit_transaction_event(request_id(0x43), canonical(TEST_PAYLOAD_TYPE_ID, 9));

        assert_submit_rejected_before_side_effects(
            event.encode().unwrap(),
            protocol_config,
            StatusCode::BAD_REQUEST,
            "invalid-transaction-bytes",
        )
        .await;
    }

    #[tokio::test]
    async fn legacy_native_routes_reject_submit_without_machine_or_storage_work() {
        let signing_key = dev_signing_key(0x33);
        let submit = signed_submit_transaction_event(&signing_key, request_id(0x3D), 1);

        let runtime = Arc::new(MemoryRuntime::new(ValidatorId::new([0x44; 32])));
        let node_config = config();
        let legacy = app(Arc::clone(&runtime), node_config.clone());
        let response = legacy
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(submit.encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        assert_eq!(
            to_bytes(response.into_body(), 128).await.unwrap(),
            "submit-transaction-requires-authenticated-route"
        );
        assert_eq!(
            runtime.state_store().get(node_config.state_key()).unwrap(),
            None
        );

        let resolved_runtime = Arc::new(MemoryRuntime::new(ValidatorId::new([0x45; 32])));
        let placement = placement(0x88, 7);
        let domain = placement.domain();
        let resolved = resolved_app(
            Arc::clone(&resolved_runtime),
            placement,
            node_config.clone(),
        );
        let response = resolved
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(submit.encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        assert_eq!(
            to_bytes(response.into_body(), 128).await.unwrap(),
            "submit-transaction-requires-authenticated-route"
        );
        assert_eq!(
            resolved_runtime
                .state_store()
                .get_versioned_in_domain(domain, node_config.state_key())
                .unwrap()
                .value(),
            None
        );
    }

    async fn assert_event_family_rejected(app: Router, event: NodeEvent) {
        let response: Response = app
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(event.encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        assert_eq!(
            to_bytes(response.into_body(), 128).await.unwrap(),
            "event-family-requires-authenticated-route"
        );
    }

    #[tokio::test]
    async fn every_native_event_route_rejects_all_unauthenticated_families_before_side_effects() {
        for (index, kind) in externally_unsupported_event_kinds().into_iter().enumerate() {
            let request_byte: u8 = u8::try_from(0x60_usize + index).unwrap();
            let event: NodeEvent = event_with_kind(
                request_id(request_byte),
                kind,
                ChainId::new("sunrise-test").unwrap(),
            );

            let legacy_runtime: Arc<ObservedLegacyRuntime> = observed_legacy_runtime();
            let legacy_machine: Arc<CountingMachine> =
                Arc::new(CountingMachine::new(config().state_key()));
            let legacy_lease_ids: Arc<CountingLeaseIds> = Arc::new(CountingLeaseIds::default());
            let legacy: Router = router(
                Arc::clone(&legacy_runtime),
                config(),
                resolver(),
                Arc::clone(&legacy_machine),
                Arc::clone(&legacy_lease_ids),
                NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
            );
            assert_event_family_rejected(legacy, event.clone()).await;
            assert_eq!(legacy_runtime.state_store().calls(), 0);
            assert_eq!(legacy_runtime.blob_store().get_calls(), 0);
            assert_eq!(legacy_runtime.clock().calls.load(Ordering::SeqCst), 0);
            assert_eq!(
                legacy_runtime.transport().send_calls.load(Ordering::SeqCst),
                0
            );
            assert_eq!(legacy_lease_ids.calls.load(Ordering::SeqCst), 0);
            assert_eq!(legacy_machine.access_plan_calls.load(Ordering::SeqCst), 0);
            assert_eq!(legacy_machine.transition_calls.load(Ordering::SeqCst), 0);

            let resolved_runtime: Arc<ObservedLegacyRuntime> = observed_legacy_runtime();
            let resolved_machine: Arc<CountingMachine> =
                Arc::new(CountingMachine::new(config().state_key()));
            let resolved_lease_ids: Arc<CountingLeaseIds> = Arc::new(CountingLeaseIds::default());
            let resolved: Router = resolved_domain_router(
                Arc::clone(&resolved_runtime),
                placement(0x88, 7),
                config(),
                resolver(),
                Arc::clone(&resolved_machine),
                Arc::clone(&resolved_lease_ids),
                NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
            );
            assert_event_family_rejected(resolved, event.clone()).await;
            assert_eq!(resolved_runtime.state_store().calls(), 0);
            assert_eq!(resolved_runtime.blob_store().get_calls(), 0);
            assert_eq!(resolved_runtime.clock().calls.load(Ordering::SeqCst), 0);
            assert_eq!(
                resolved_runtime
                    .transport()
                    .send_calls
                    .load(Ordering::SeqCst),
                0
            );
            assert_eq!(resolved_lease_ids.calls.load(Ordering::SeqCst), 0);
            assert_eq!(resolved_machine.access_plan_calls.load(Ordering::SeqCst), 0);
            assert_eq!(resolved_machine.transition_calls.load(Ordering::SeqCst), 0);

            let structured_store: Arc<ScriptedIndexedStore> =
                Arc::new(ScriptedIndexedStore::new(Vec::new(), Vec::new()));
            let structured_blob_store: Arc<CountingBlobStore> =
                Arc::new(CountingBlobStore::default());
            let structured_transport: Arc<MemoryTransport> = Arc::new(MemoryTransport::default());
            let structured_clock: Arc<CountingClock> = Arc::new(CountingClock::new(10_000));
            let structured_identities: Arc<CountingIndexedIdentities> =
                Arc::new(CountingIndexedIdentities::default());
            let structured_machine: Arc<CountingMachine> =
                Arc::new(CountingMachine::new(config().state_key()));
            let structured: Router = structured_durable_router(
                StructuredDurableNativeComponents::new(
                    Arc::clone(&structured_store),
                    Arc::clone(&structured_blob_store),
                    Arc::clone(&structured_transport),
                    Arc::clone(&structured_clock),
                    Arc::clone(&structured_identities),
                ),
                active_protocol_config(AtomicityDomainId::new([0x89; 32]).unwrap()),
                structured_request_authority(),
                config(),
                resolver(),
                Arc::clone(&structured_machine),
                NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
            )
            .unwrap();
            assert_event_family_rejected(structured, event.clone()).await;
            assert_eq!(structured_store.storage_calls.load(Ordering::SeqCst), 0);
            assert_eq!(structured_blob_store.get_calls(), 0);
            assert_eq!(structured_clock.calls.load(Ordering::SeqCst), 0);
            assert_eq!(structured_identities.calls.load(Ordering::SeqCst), 0);
            assert_eq!(
                structured_machine.access_plan_calls.load(Ordering::SeqCst),
                0
            );
            assert_eq!(
                structured_machine.transition_calls.load(Ordering::SeqCst),
                0
            );
            assert!(structured_transport.drain_outbound().unwrap().is_empty());

            let preinstalled_store: Arc<ScriptedIndexedStore> =
                Arc::new(ScriptedIndexedStore::new(Vec::new(), Vec::new()));
            let preinstalled_blob_store: Arc<CountingBlobStore> =
                Arc::new(CountingBlobStore::default());
            let preinstalled_transport: Arc<MemoryTransport> = Arc::new(MemoryTransport::default());
            let preinstalled_clock: Arc<CountingClock> = Arc::new(CountingClock::new(10_000));
            let preinstalled_identities: Arc<CountingIndexedIdentities> =
                Arc::new(CountingIndexedIdentities::default());
            let preinstalled_machine: Arc<CountingMachine> =
                Arc::new(CountingMachine::new(config().state_key()));
            let preinstalled: Router = preinstalled_wasm_structured_durable_router(
                StructuredDurableNativeComponents::new(
                    Arc::clone(&preinstalled_store),
                    Arc::clone(&preinstalled_blob_store),
                    Arc::clone(&preinstalled_transport),
                    Arc::clone(&preinstalled_clock),
                    Arc::clone(&preinstalled_identities),
                ),
                PreinstalledWasmComposition::new(
                    Arc::new(PreinstalledModuleCatalog::new(Vec::new()).unwrap()),
                    WasmExecutionEngine,
                    9,
                ),
                active_protocol_config(AtomicityDomainId::new([0x8A; 32]).unwrap()),
                structured_request_authority(),
                config(),
                resolver(),
                Arc::clone(&preinstalled_machine),
                NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
            )
            .unwrap();
            assert_event_family_rejected(preinstalled, event).await;
            assert_eq!(preinstalled_store.storage_calls.load(Ordering::SeqCst), 0);
            assert_eq!(preinstalled_blob_store.get_calls(), 0);
            assert_eq!(preinstalled_clock.calls.load(Ordering::SeqCst), 0);
            assert_eq!(preinstalled_identities.calls.load(Ordering::SeqCst), 0);
            assert_eq!(
                preinstalled_machine
                    .access_plan_calls
                    .load(Ordering::SeqCst),
                0
            );
            assert_eq!(
                preinstalled_machine.transition_calls.load(Ordering::SeqCst),
                0
            );
            assert!(preinstalled_transport.drain_outbound().unwrap().is_empty());
        }
    }

    struct FailOnceTransport {
        fail_next: Mutex<bool>,
        outbound: Mutex<Vec<Vec<u8>>>,
    }

    impl FailOnceTransport {
        fn new() -> Self {
            Self {
                fail_next: Mutex::new(true),
                outbound: Mutex::new(Vec::new()),
            }
        }
    }

    impl Transport for FailOnceTransport {
        fn send(&self, message: Vec<u8>) -> Result<(), RuntimeError> {
            let mut fail_next = self
                .fail_next
                .lock()
                .map_err(|_| RuntimeError::TransportUnavailable)?;
            if *fail_next {
                *fail_next = false;
                return Err(RuntimeError::TransportUnavailable);
            }
            self.outbound
                .lock()
                .map_err(|_| RuntimeError::TransportUnavailable)?
                .push(message);
            Ok(())
        }

        fn drain_outbound(&self) -> Result<Vec<Vec<u8>>, RuntimeError> {
            let mut outbound = self
                .outbound
                .lock()
                .map_err(|_| RuntimeError::TransportUnavailable)?;
            Ok(std::mem::take(&mut *outbound))
        }
    }

    struct FailOnceRuntime {
        state_store: MemoryStateStore,
        blob_store: MemoryBlobStore,
        signer: MemorySigner,
        transport: FailOnceTransport,
        clock: ManualClock,
        scheduler: MemoryScheduler,
    }

    impl FailOnceRuntime {
        fn new() -> Self {
            Self {
                state_store: MemoryStateStore::default(),
                blob_store: MemoryBlobStore::default(),
                signer: MemorySigner::new(ValidatorId::new([0x44; 32])),
                transport: FailOnceTransport::new(),
                clock: ManualClock::new(1_000),
                scheduler: MemoryScheduler::default(),
            }
        }
    }

    impl Runtime for FailOnceRuntime {
        type State = MemoryStateStore;
        type Blobs = MemoryBlobStore;
        type NodeSigner = MemorySigner;
        type Network = FailOnceTransport;
        type Time = ManualClock;
        type TaskScheduler = MemoryScheduler;

        fn state_store(&self) -> &Self::State {
            &self.state_store
        }

        fn blob_store(&self) -> &Self::Blobs {
            &self.blob_store
        }

        fn signer(&self) -> &Self::NodeSigner {
            &self.signer
        }

        fn transport(&self) -> &Self::Network {
            &self.transport
        }

        fn clock(&self) -> &Self::Time {
            &self.clock
        }

        fn scheduler(&self) -> &Self::TaskScheduler {
            &self.scheduler
        }
    }

    #[test]
    fn http_result_round_trip_is_bounded_and_stable() {
        let id = request_id(0x31);
        let response = NodeResponse::new(
            id,
            NodeResponseStatus::Accepted,
            Some(canonical(TEST_PAYLOAD_TYPE_ID, 4)),
        )
        .unwrap();
        let result = HttpNodeResult::new(id, vec![response]).unwrap();
        let encoded = result.encode().unwrap();

        assert_eq!(HttpNodeResult::decode(&encoded).unwrap(), result);
        assert_eq!(
            hex(&encoded),
            "534e524501e101000300010020000000313131313131313131313131313131313131313131313131\
             31313131313131310200040000000100000003005a00000056000000534e524502e0010003000100\
             20000000313131313131313131313131313131313131313131313131313131313131313102000200\
             00000100030018000000534e524512ef010001000100080000000400000000000000"
                .replace(' ', "")
        );
    }

    // --- DR-0082 bounded query-result codecs -----------------------------

    #[test]
    fn context_query_result_round_trip_is_bounded_and_stable() {
        let result = HttpContextQueryResult::new(
            ChainId::new("sunrise-test").unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(7),
            HashSuiteId::new(1),
            1,
            1,
            1,
            AtomicityDomainId::new([0x11; 32]).unwrap(),
            vec![0xAA, 0xBB, 0xCC],
        )
        .unwrap();
        let encoded = result.encode().unwrap();

        assert_eq!(HttpContextQueryResult::decode(&encoded).unwrap(), result);
        let expected_hex = concat!(
            "534e524502e10100090001000c00000073756e726973652d746573740200040000000300000003000800",
            "00000700000000000000040002000000010005000200000001000600020000000100070002000000010008",
            "0020000000111111111111111111111111111111111111111111111111111111111111111109000300000",
            "0aabbcc",
        );
        assert_eq!(hex(&encoded), expected_hex);
    }

    #[test]
    fn context_query_result_rejects_unexpected_field() {
        let mut frame = CanonicalStruct::new(
            CONTEXT_QUERY_RESULT_TYPE_ID,
            1, /* query-result encoding version, see node_wire */
        );
        frame.field_str(1, "sunrise-test").unwrap();
        frame.field_u32(2, 3).unwrap();
        frame.field_u64(3, 7).unwrap();
        frame.field_u16(4, 1).unwrap();
        frame.field_u16(5, 1).unwrap();
        frame.field_u16(6, 1).unwrap();
        frame.field_u16(7, 1).unwrap();
        frame.field_bytes(8, vec![0x11; 32]).unwrap();
        frame.field_bytes(9, vec![0xAA]).unwrap();
        frame.field_u16(10, 0).unwrap();
        let bytes = frame.finish().unwrap();

        assert!(matches!(
            HttpContextQueryResult::decode(&bytes),
            Err(QueryResultError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedField(10)
            ))
        ));
    }

    #[test]
    fn context_query_result_rejects_zero_ids_long_chain_id_and_empty_config_bytes() {
        fn build(
            protocol_version: u32,
            hash_suite_id: u16,
            profile: u16,
            scheme: u16,
            binding: u16,
            chain: &str,
            config_bytes: Vec<u8>,
        ) -> Result<HttpContextQueryResult, QueryResultError> {
            HttpContextQueryResult::new(
                ChainId::new(chain).unwrap(),
                ProtocolVersion::new(protocol_version),
                Epoch::new(7),
                HashSuiteId::new(hash_suite_id),
                profile,
                scheme,
                binding,
                AtomicityDomainId::new([0x11; 32]).unwrap(),
                config_bytes,
            )
        }

        assert_eq!(
            build(0, 1, 1, 1, 1, "sunrise-test", vec![0xAA]),
            Err(QueryResultError::ZeroProtocolVersion)
        );
        assert_eq!(
            build(3, 0, 1, 1, 1, "sunrise-test", vec![0xAA]),
            Err(QueryResultError::ZeroHashSuiteId)
        );
        assert_eq!(
            build(3, 1, 0, 1, 1, "sunrise-test", vec![0xAA]),
            Err(QueryResultError::ZeroTransactionAuthProfileId)
        );
        assert_eq!(
            build(3, 1, 1, 0, 1, "sunrise-test", vec![0xAA]),
            Err(QueryResultError::ZeroSignatureSchemeId)
        );
        assert_eq!(
            build(3, 1, 1, 1, 0, "sunrise-test", vec![0xAA]),
            Err(QueryResultError::ZeroAddressBindingId)
        );
        let long_chain = "x".repeat(MAX_CHAIN_ID_BYTES + 1);
        assert_eq!(
            build(3, 1, 1, 1, 1, &long_chain, vec![0xAA]),
            Err(QueryResultError::ChainIdTooLong(MAX_CHAIN_ID_BYTES + 1))
        );
        assert_eq!(
            build(3, 1, 1, 1, 1, "sunrise-test", Vec::new()),
            Err(QueryResultError::EmptyProtocolConfigBytes)
        );
        assert!(build(3, 1, 1, 1, 1, "sunrise-test", vec![0xAA]).is_ok());
    }

    fn sample_inline_object_bytes(object_id: ObjectId, version: u64) -> Vec<u8> {
        let object = Object {
            id: object_id,
            version,
            owner: Owner::Address(Address::new([0x21; 32])),
            type_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0x99; 32]),
            schema_version: 1,
            data: vec![0xDD, 0xEE],
        };
        encode_object(&object).unwrap()
    }

    fn sample_object_query_results() -> Vec<HttpObjectQueryResult> {
        let object_id = ObjectId::new([0x20; 32]);
        vec![
            HttpObjectQueryResult::Absent { object_id },
            HttpObjectQueryResult::Tombstoned {
                object_id,
                head_revision: ObjectHeadRevision::new(2).unwrap(),
                last_object_version: DurableObjectVersion::new(1).unwrap(),
            },
            HttpObjectQueryResult::CurrentInline {
                object_id,
                head_revision: ObjectHeadRevision::new(1).unwrap(),
                object_version: DurableObjectVersion::new(1).unwrap(),
                digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x22; 32]),
                canonical_object_bytes: sample_inline_object_bytes(object_id, 1),
            },
            HttpObjectQueryResult::CurrentBlobReference {
                object_id,
                head_revision: ObjectHeadRevision::new(3).unwrap(),
                object_version: DurableObjectVersion::new(2).unwrap(),
                digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x23; 32]),
                blob_digest: Digest32::new(HashAlgorithmId::Sha3_256, [0x24; 32]),
            },
        ]
    }

    #[test]
    fn object_query_result_round_trips_every_status() {
        for case in sample_object_query_results() {
            let encoded = case.encode().unwrap();
            let decoded = HttpObjectQueryResult::decode(&encoded).unwrap();
            assert_eq!(decoded, case);
            assert_eq!(decoded.object_id(), case.object_id());
        }
    }

    #[test]
    fn object_query_result_current_inline_matches_pinned_stable_vector() {
        let result = &sample_object_query_results()[2];
        let encoded = result.encode().unwrap();

        let expected_hex = "534e524503e1010007000100020000000300020020000000202020202020202020202020202020202020202020202020202020202020202003000800000001000000000000000400080000000100000000000000050002000000010006002000000022222222222222222222222222222222222222222222222222222222222222220700ec000000534e5245054001000600010030000000534e524501400100010001002000000020202020202020202020202020202020202020202020202020202020202020200200080000000100000000000000030048000000534e52450340010002000100020000000100020030000000534e52450240010001000100200000002121212121212121212121212121212121212121212121212121212121212121040038000000534e52450301010002000100020000000100020020000000999999999999999999999999999999999999999999999999999999999999999905000400000001000000060002000000ddee";
        assert_eq!(hex(&encoded), expected_hex);
    }

    #[test]
    fn object_query_result_binds_the_exact_requested_selector() {
        let a = ObjectId::new([0x30; 32]);
        let b = ObjectId::new([0x31; 32]);
        let result_a = HttpObjectQueryResult::Absent { object_id: a };
        let result_b = HttpObjectQueryResult::Absent { object_id: b };

        assert_eq!(result_a.object_id(), a);
        assert_eq!(result_b.object_id(), b);
        assert_ne!(result_a.encode().unwrap(), result_b.encode().unwrap());
        assert_eq!(
            HttpObjectQueryResult::decode(&result_a.encode().unwrap())
                .unwrap()
                .object_id(),
            a
        );
        assert_ne!(
            HttpObjectQueryResult::decode(&result_a.encode().unwrap())
                .unwrap()
                .object_id(),
            b
        );
    }

    #[test]
    fn object_query_result_rejects_unknown_status_id() {
        let mut frame = CanonicalStruct::new(
            OBJECT_QUERY_RESULT_TYPE_ID,
            1, /* query-result encoding version, see node_wire */
        );
        frame.field_u16(1, 99).unwrap();
        frame
            .field_bytes(2, ObjectId::new([0x01; 32]).as_bytes().to_vec())
            .unwrap();
        let bytes = frame.finish().unwrap();

        assert_eq!(
            HttpObjectQueryResult::decode(&bytes),
            Err(QueryResultError::UnknownObjectStatus(99))
        );
    }

    #[test]
    fn object_query_result_absent_rejects_a_field_only_valid_for_another_status() {
        let object_id = ObjectId::new([0x32; 32]);
        let mut frame = CanonicalStruct::new(
            OBJECT_QUERY_RESULT_TYPE_ID,
            1, /* query-result encoding version, see node_wire */
        );
        frame
            .field_u16(1, ObjectQueryStatus::Absent.as_u16())
            .unwrap();
        frame.field_bytes(2, object_id.as_bytes().to_vec()).unwrap();
        frame.field_u64(3, 1).unwrap();
        let bytes = frame.finish().unwrap();

        assert!(matches!(
            HttpObjectQueryResult::decode(&bytes),
            Err(QueryResultError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedField(3)
            ))
        ));
    }

    #[test]
    fn object_query_result_rejects_mismatched_canonical_type_id() {
        let request_id = request_id(0x01);
        let receipt_bytes = HttpReceiptQueryResult::Absent { request_id }
            .encode()
            .unwrap();

        assert!(matches!(
            HttpObjectQueryResult::decode(&receipt_bytes),
            Err(QueryResultError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedTypeId { .. }
            ))
        ));
    }

    fn current_inline_object_frame(
        object_id: ObjectId,
        object_version: u64,
        canonical_object_bytes: Vec<u8>,
    ) -> Vec<u8> {
        let mut frame = CanonicalStruct::new(
            OBJECT_QUERY_RESULT_TYPE_ID,
            1, /* query-result encoding version, see node_wire */
        );
        frame
            .field_u16(1, ObjectQueryStatus::CurrentInline.as_u16())
            .unwrap();
        frame.field_bytes(2, object_id.as_bytes().to_vec()).unwrap();
        frame.field_u64(3, 1).unwrap();
        frame.field_u64(4, object_version).unwrap();
        frame
            .field_u16(5, HashAlgorithmId::Sha2_256.as_u16())
            .unwrap();
        frame.field_bytes(6, vec![0x22; 32]).unwrap();
        frame.field_bytes(7, canonical_object_bytes).unwrap();
        frame.finish().unwrap()
    }

    #[test]
    fn object_query_result_current_inline_rejects_oversized_body() {
        let object_id = ObjectId::new([0x25; 32]);
        let bytes = current_inline_object_frame(
            object_id,
            1,
            vec![0_u8; MAX_AUTHENTICATED_OBJECT_BODY_BYTES + 1],
        );

        assert_eq!(
            HttpObjectQueryResult::decode(&bytes),
            Err(QueryResultError::ObjectBodyTooLarge {
                actual: MAX_AUTHENTICATED_OBJECT_BODY_BYTES + 1,
                maximum: MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
            })
        );
    }

    #[test]
    fn object_query_result_current_inline_rejects_invalid_nested_object_bytes() {
        let object_id = ObjectId::new([0x26; 32]);
        let bytes = current_inline_object_frame(object_id, 1, vec![0xFF, 0x00]);

        assert!(matches!(
            HttpObjectQueryResult::decode(&bytes),
            Err(QueryResultError::InvalidCanonicalObject(_))
        ));
    }

    #[test]
    fn object_query_result_current_inline_rejects_nested_identity_mismatch() {
        let object_id = ObjectId::new([0x27; 32]);
        let other_id = ObjectId::new([0x28; 32]);
        let nested_bytes = sample_inline_object_bytes(other_id, 1);
        let bytes = current_inline_object_frame(object_id, 1, nested_bytes);

        assert_eq!(
            HttpObjectQueryResult::decode(&bytes),
            Err(QueryResultError::ObjectIdentityMismatch {
                expected: object_id,
                actual: other_id,
            })
        );
    }

    #[test]
    fn object_query_result_current_inline_rejects_nested_version_mismatch() {
        let object_id = ObjectId::new([0x29; 32]);
        let nested_bytes = sample_inline_object_bytes(object_id, 2);
        let bytes = current_inline_object_frame(object_id, 1, nested_bytes);

        assert_eq!(
            HttpObjectQueryResult::decode(&bytes),
            Err(QueryResultError::ObjectVersionMismatch {
                expected: 1,
                actual: 2,
            })
        );
    }

    fn sample_receipt_query_results() -> Vec<HttpReceiptQueryResult> {
        let request_id = request_id(0x50);
        let event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x55; 32]);
        let response = NodeResponse::new(request_id, NodeResponseStatus::Accepted, None).unwrap();
        let dedup_record_bytes = NodeDedupRecord::new(request_id, event_digest, vec![response])
            .unwrap()
            .encode()
            .unwrap();
        vec![
            HttpReceiptQueryResult::Absent { request_id },
            HttpReceiptQueryResult::Present {
                request_id,
                event_digest,
                dedup_record_bytes,
            },
        ]
    }

    #[test]
    fn receipt_query_result_round_trips_every_status() {
        for case in sample_receipt_query_results() {
            let encoded = case.encode().unwrap();
            let decoded = HttpReceiptQueryResult::decode(&encoded).unwrap();
            assert_eq!(decoded, case);
            assert_eq!(decoded.request_id(), case.request_id());
        }
    }

    #[test]
    fn receipt_query_result_present_matches_pinned_stable_vector() {
        let result = &sample_receipt_query_results()[1];
        let encoded = result.encode().unwrap();

        let expected_hex = "534e524504e10100050001000200000002000200200000005050505050505050505050505050505050505050505050505050505050505050030002000000010004002000000055555555555555555555555555555555555555555555555555555555555555550500aa000000534e524503e0010005000100200000005050505050505050505050505050505050505050505050505050505050505050020002000000010003002000000055555555555555555555555555555555555555555555555555555555555555550400040000000100000005003c00000038000000534e524502e00100020001002000000050505050505050505050505050505050505050505050505050505050505050500200020000000100";
        assert_eq!(hex(&encoded), expected_hex);
    }

    #[test]
    fn receipt_query_result_binds_the_exact_requested_selector() {
        let a = request_id(0x60);
        let b = request_id(0x61);
        let result_a = HttpReceiptQueryResult::Absent { request_id: a };
        let result_b = HttpReceiptQueryResult::Absent { request_id: b };

        assert_eq!(result_a.request_id(), a);
        assert_eq!(result_b.request_id(), b);
        assert_ne!(result_a.encode().unwrap(), result_b.encode().unwrap());
        assert_eq!(
            HttpReceiptQueryResult::decode(&result_a.encode().unwrap())
                .unwrap()
                .request_id(),
            a
        );
    }

    #[test]
    fn receipt_query_result_rejects_unknown_status_id() {
        let mut frame = CanonicalStruct::new(
            RECEIPT_QUERY_RESULT_TYPE_ID,
            1, /* query-result encoding version, see node_wire */
        );
        frame.field_u16(1, 7).unwrap();
        frame
            .field_bytes(2, request_id(0x01).as_bytes().to_vec())
            .unwrap();
        let bytes = frame.finish().unwrap();

        assert_eq!(
            HttpReceiptQueryResult::decode(&bytes),
            Err(QueryResultError::UnknownReceiptStatus(7))
        );
    }

    fn present_receipt_frame(
        request_id: RequestId,
        event_digest: Digest32,
        dedup_record_bytes: Vec<u8>,
    ) -> Vec<u8> {
        let mut frame = CanonicalStruct::new(
            RECEIPT_QUERY_RESULT_TYPE_ID,
            1, /* query-result encoding version, see node_wire */
        );
        frame
            .field_u16(1, ReceiptQueryStatus::Present.as_u16())
            .unwrap();
        frame
            .field_bytes(2, request_id.as_bytes().to_vec())
            .unwrap();
        frame
            .field_u16(3, event_digest.algorithm().as_u16())
            .unwrap();
        frame.field_bytes(4, event_digest.bytes().to_vec()).unwrap();
        frame.field_bytes(5, dedup_record_bytes).unwrap();
        frame.finish().unwrap()
    }

    // `receipt_query_result_rejects_oversized_body` is not constructible as a
    // unit test: `runtime::MAX_DURABLE_RECEIPT_BYTES` currently equals
    // `canonical_encoding::MAX_CANONICAL_FRAME_BYTES`, so any field that large
    // already fails to canonically frame (`FrameTooLarge`) before this
    // decoder's own `ReceiptTooLarge` bound ever runs. The check is kept as
    // defense in depth in case the two bounds diverge in the future.

    #[test]
    fn receipt_query_result_rejects_invalid_nested_dedup_record_bytes() {
        let request_id = request_id(0x53);
        let event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x54; 32]);
        let bytes = present_receipt_frame(request_id, event_digest, vec![0xFF, 0x00]);

        assert!(matches!(
            HttpReceiptQueryResult::decode(&bytes),
            Err(QueryResultError::InvalidDedupRecord(_))
        ));
    }

    #[test]
    fn receipt_query_result_rejects_nested_request_id_mismatch() {
        let request_id_outer = request_id(0x56);
        let request_id_nested = request_id(0x57);
        let event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x58; 32]);
        let response =
            NodeResponse::new(request_id_nested, NodeResponseStatus::Accepted, None).unwrap();
        let dedup_record_bytes =
            NodeDedupRecord::new(request_id_nested, event_digest, vec![response])
                .unwrap()
                .encode()
                .unwrap();
        let bytes = present_receipt_frame(request_id_outer, event_digest, dedup_record_bytes);

        assert_eq!(
            HttpReceiptQueryResult::decode(&bytes),
            Err(QueryResultError::RequestIdentityMismatch {
                expected: request_id_outer,
                actual: request_id_nested,
            })
        );
    }

    #[test]
    fn receipt_query_result_rejects_nested_event_digest_mismatch() {
        let request_id = request_id(0x59);
        let event_digest_outer = Digest32::new(HashAlgorithmId::Sha2_256, [0x5A; 32]);
        let event_digest_nested = Digest32::new(HashAlgorithmId::Sha2_256, [0x5B; 32]);
        let response = NodeResponse::new(request_id, NodeResponseStatus::Accepted, None).unwrap();
        let dedup_record_bytes =
            NodeDedupRecord::new(request_id, event_digest_nested, vec![response])
                .unwrap()
                .encode()
                .unwrap();
        let bytes = present_receipt_frame(request_id, event_digest_outer, dedup_record_bytes);

        assert_eq!(
            HttpReceiptQueryResult::decode(&bytes),
            Err(QueryResultError::EventDigestMismatch)
        );
    }

    #[test]
    fn next_nonce_query_result_round_trip_is_bounded_and_stable() {
        let result = HttpNextNonceQueryResult::new(Address::new([0x61; 32]), Epoch::new(7), 42);
        let encoded = result.encode().unwrap();

        assert_eq!(HttpNextNonceQueryResult::decode(&encoded).unwrap(), result);
        let expected_hex = "534e524505e1010003000100200000006161616161616161616161616161616161616161616161616161616161616161020008000000070000000000000003000800000\
02a00000000000000";
        assert_eq!(hex(&encoded), expected_hex);
    }

    #[test]
    fn next_nonce_query_result_binds_the_exact_requested_sender() {
        let a = HttpNextNonceQueryResult::new(Address::new([0x70; 32]), Epoch::new(7), 1);
        let b = HttpNextNonceQueryResult::new(Address::new([0x71; 32]), Epoch::new(7), 1);

        assert_eq!(a.sender(), Address::new([0x70; 32]));
        assert_ne!(a.encode().unwrap(), b.encode().unwrap());
        assert_eq!(
            HttpNextNonceQueryResult::decode(&a.encode().unwrap())
                .unwrap()
                .sender(),
            Address::new([0x70; 32])
        );
    }

    #[test]
    fn next_nonce_query_result_rejects_mismatched_canonical_type_id() {
        let object_bytes = HttpObjectQueryResult::Absent {
            object_id: ObjectId::new([0x01; 32]),
        }
        .encode()
        .unwrap();

        assert!(matches!(
            HttpNextNonceQueryResult::decode(&object_bytes),
            Err(QueryResultError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedTypeId { .. }
            ))
        ));
    }

    #[test]
    fn indexed_recovery_authority_bounds_operation_inside_lease() {
        let domain = AtomicityDomainId::new([0x61; 32]).unwrap();
        let fence = WriterFenceGeneration::new(3).unwrap();
        assert_eq!(
            IndexedOutboxRecoveryAuthority::new(domain, fence, 0, 30_000),
            Err(IndexedOutboxRecoveryAuthorityError::InvalidOperationTimeout)
        );
        assert_eq!(
            IndexedOutboxRecoveryAuthority::new(domain, fence, 30_000, 30_000),
            Err(IndexedOutboxRecoveryAuthorityError::InvalidOperationTimeout)
        );
        assert_eq!(
            IndexedOutboxRecoveryAuthority::new(
                domain,
                fence,
                1_000,
                MAX_DURABLE_OUTBOX_LEASE_MILLIS + 1,
            ),
            Err(IndexedOutboxRecoveryAuthorityError::InvalidLeaseDuration)
        );
        let authority = indexed_authority();
        assert_eq!(authority.domain(), domain);
        assert_eq!(authority.writer_fence(), fence);
        assert_eq!(
            StructuredDurableRequestAuthority::new(fence, 30_000, 30_000),
            Err(IndexedOutboxRecoveryAuthorityError::InvalidOperationTimeout)
        );
        assert_eq!(structured_request_authority().writer_fence(), fence);
    }

    #[tokio::test]
    async fn indexed_recovery_reconciles_claim_and_ack_before_returning_success() {
        let request_id = request_id(0x73);
        let payload = event(request_id).encode().unwrap();
        let lease_id = DurableOutboxLeaseId::new([0x71; 32]).unwrap();
        let claim = DurableOutboxClaim::from_parts(
            OutboxRequestId::new(*request_id.as_bytes()).unwrap(),
            0,
            lease_id,
            40_000,
            payload.clone(),
        )
        .unwrap();
        let store = ScriptedIndexedStore::new(
            vec![
                DurableOutboxClaimOutcome::Indeterminate(IndeterminateCommitReason::ConnectionLost),
                DurableOutboxClaimOutcome::Claimed(claim),
            ],
            vec![
                DurableOutboxAcknowledgementOutcome::Indeterminate(
                    IndeterminateCommitReason::ConnectionLost,
                ),
                DurableOutboxAcknowledgementOutcome::Acknowledged,
            ],
        );
        let runtime = Arc::new(indexed_runtime(store));

        let report = recover_indexed_outbox_once(
            Arc::clone(&runtime),
            indexed_authority(),
            Arc::new(FixedIndexedIdentity),
            NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(1).unwrap())),
        )
        .await
        .unwrap();

        assert_eq!(
            report.outcome(),
            &NativeOutboxRecoveryOutcome::Recovered(request_id)
        );
        assert_eq!(report.continuation_cursor(), None);
        assert_eq!(runtime.transport().drain_outbound().unwrap(), vec![payload]);
        let claim_requests = runtime.state_store().claim_requests.lock().unwrap();
        assert_eq!(claim_requests.len(), 2);
        assert_eq!(claim_requests[0], claim_requests[1]);
        drop(claim_requests);
        let acknowledgement_requests = runtime
            .state_store()
            .acknowledgement_requests
            .lock()
            .unwrap();
        assert_eq!(acknowledgement_requests.len(), 2);
        assert_eq!(acknowledgement_requests[0], acknowledgement_requests[1]);
    }

    #[tokio::test]
    async fn indexed_recovery_never_sends_an_unreconciled_claim() {
        let store = ScriptedIndexedStore::new(
            vec![
                DurableOutboxClaimOutcome::Indeterminate(IndeterminateCommitReason::ConnectionLost),
                DurableOutboxClaimOutcome::Indeterminate(
                    IndeterminateCommitReason::DeadlineExceeded,
                ),
            ],
            Vec::new(),
        );
        let runtime = Arc::new(indexed_runtime(store));

        let error = recover_indexed_outbox_once(
            Arc::clone(&runtime),
            indexed_authority(),
            Arc::new(FixedIndexedIdentity),
            NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(1).unwrap())),
        )
        .await
        .unwrap_err();

        assert!(matches!(
            error,
            IndexedOutboxRecoveryError::ClaimIndeterminate(
                IndeterminateCommitReason::ConnectionLost
            )
        ));
        assert!(runtime.transport().drain_outbound().unwrap().is_empty());
        assert!(
            runtime
                .state_store()
                .acknowledgement_requests
                .lock()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn structured_route_rejects_cancellation_at_each_pre_storage_checkpoint() {
        for cancel_at_call in 1_usize..=3_usize {
            let fence: WriterFenceGeneration = WriterFenceGeneration::new(3).unwrap();
            let store: Arc<MemoryDurableStateStore> = Arc::new(MemoryDurableStateStore::new(fence));
            store.set_time(10_000);
            let transport: Arc<MemoryTransport> = Arc::new(MemoryTransport::default());
            let clock: Arc<ManualClock> = Arc::new(ManualClock::new(10_000));
            let config: NodeConfig = config();
            let domain: AtomicityDomainId = AtomicityDomainId::new([0x84; 32]).unwrap();
            let protocol_config: ProtocolConfig = active_protocol_config(domain);
            let cancellation: Arc<StepCancellation> =
                Arc::new(StepCancellation::new(cancel_at_call));
            let app: Router = structured_app_with_cancellation(
                Arc::clone(&store),
                Arc::clone(&transport),
                clock,
                protocol_config,
                config.clone(),
                cancellation.clone(),
            );
            let id: RequestId = request_id(u8::try_from(0x30_usize + cancel_at_call).unwrap());
            let signing_key: ed25519_zebra::SigningKey = dev_signing_key(0x34);
            let submit: NodeEvent = signed_submit_transaction_event(&signing_key, id, 0);

            let response: Response = app
                .oneshot(
                    Request::post(NODE_EVENT_PATH)
                        .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                        .body(Body::from(submit.encode().unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(
                to_bytes(response.into_body(), 128).await.unwrap(),
                "invocation-cancelled-before-storage"
            );
            assert_eq!(cancellation.calls(), cancel_at_call);
            assert!(transport.drain_outbound().unwrap().is_empty());
            let verification_context: DurableOperationContext = DurableOperationContext::new(
                fence,
                StorageDeadline::new(11_000).unwrap(),
                StorageCorrelationId::new([0x41; 16]).unwrap(),
            );
            let state: VersionedStateValue = store
                .get_versioned_durable(&verification_context, domain, config.state_key())
                .unwrap();
            assert_eq!(state.revision(), runtime::StateRevision::INITIAL);
            assert_eq!(state.value(), None);
            assert_eq!(
                store
                    .get_request_receipt(
                        &verification_context,
                        domain,
                        DurableRequestId::new(*id.as_bytes()).unwrap(),
                    )
                    .unwrap(),
                None
            );
            let claim_request: RequestOutboxClaimRequest = RequestOutboxClaimRequest::new(
                domain,
                OutboxRequestId::new(*id.as_bytes()).unwrap(),
                10_000,
                DurableOutboxLeaseId::new([u8::try_from(0x44_usize + cancel_at_call).unwrap(); 32])
                    .unwrap(),
                11_000,
            )
            .unwrap();
            assert_eq!(
                store.claim_request_outbox(&verification_context, claim_request),
                DurableOutboxClaimOutcome::NoDueWork
            );
        }
    }

    #[tokio::test]
    async fn structured_route_ignores_cancellation_after_storage_dispatch_begins() {
        let fence: WriterFenceGeneration = WriterFenceGeneration::new(3).unwrap();
        let inner: MemoryDurableStateStore = MemoryDurableStateStore::new(fence);
        inner.set_time(10_000);
        let cancellation: Arc<ManualCancellation> = Arc::new(ManualCancellation::default());
        let store: Arc<CancelOnFirstReceiptReadStore> = Arc::new(
            CancelOnFirstReceiptReadStore::new(inner, Arc::clone(&cancellation)),
        );
        let transport: Arc<MemoryTransport> = Arc::new(MemoryTransport::default());
        let config: NodeConfig = config();
        let domain: AtomicityDomainId = AtomicityDomainId::new([0x85; 32]).unwrap();
        let protocol_config: ProtocolConfig = active_protocol_config(domain);
        let id: RequestId = request_id(0x35);
        let signing_key: ed25519_zebra::SigningKey = dev_signing_key(0x35);
        let submit: NodeEvent = signed_submit_transaction_event(&signing_key, id, 0);
        let app: Router = structured_app_with_cancellation(
            Arc::clone(&store),
            Arc::clone(&transport),
            Arc::new(ManualClock::new(10_000)),
            protocol_config,
            config,
            cancellation.clone(),
        );

        let response: Response = app
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(submit.encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(cancellation.is_cancelled());
        assert_eq!(transport.drain_outbound().unwrap().len(), 1);
        let verification_context: DurableOperationContext = DurableOperationContext::new(
            fence,
            StorageDeadline::new(11_000).unwrap(),
            StorageCorrelationId::new([0x42; 16]).unwrap(),
        );
        let claim_request: RequestOutboxClaimRequest = RequestOutboxClaimRequest::new(
            domain,
            OutboxRequestId::new(*id.as_bytes()).unwrap(),
            10_000,
            DurableOutboxLeaseId::new([0x43; 32]).unwrap(),
            11_000,
        )
        .unwrap();
        assert_eq!(
            store.claim_request_outbox(&verification_context, claim_request),
            DurableOutboxClaimOutcome::NoDueWork
        );
    }

    #[tokio::test]
    async fn structured_route_commits_and_claims_only_the_exact_request() {
        let fence = WriterFenceGeneration::new(3).unwrap();
        let store = Arc::new(MemoryDurableStateStore::new(fence));
        store.set_time(10_000);
        let transport = Arc::new(MemoryTransport::default());
        let clock = Arc::new(ManualClock::new(10_000));
        let config = config();
        let placement = placement(0x81, 7);
        let domain = placement.domain();
        let machine = IncrementMachine::new(config.state_key());
        let older_request_id = request_id(0x21);
        let older_context = DurableOperationContext::new(
            fence,
            StorageDeadline::new(11_000).unwrap(),
            StorageCorrelationId::new([0x31; 16]).unwrap(),
        );
        handle_resolved_durable_idempotent_event(
            store.as_ref(),
            &older_context,
            &placement,
            &config,
            &resolver(),
            event(older_request_id),
            &machine,
        )
        .unwrap();

        let current_request_id = request_id(0x22);
        let signing_key: ed25519_zebra::SigningKey = dev_signing_key(0x22);
        let submit: NodeEvent =
            signed_submit_transaction_event(&signing_key, current_request_id, 0);
        let protocol_config = active_protocol_config(domain);
        let app = structured_app(
            Arc::clone(&store),
            Arc::clone(&transport),
            Arc::clone(&clock),
            protocol_config,
            config.clone(),
        );
        let response = app
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(submit.encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let outbound = transport.drain_outbound().unwrap();
        assert_eq!(outbound.len(), 1);
        let delivered = NodeEvent::decode(&outbound[0]).unwrap();
        assert_eq!(
            decode_canonical_frame(delivered.payload())
                .unwrap()
                .required_u64(1),
            Ok(2)
        );

        let due_request = DueOutboxClaimRequest::new(
            domain,
            10_000,
            DurableOutboxLeaseId::new([0x91; 32]).unwrap(),
            40_000,
        )
        .unwrap();
        let due_context = DurableOperationContext::new(
            fence,
            StorageDeadline::new(11_000).unwrap(),
            StorageCorrelationId::new([0x32; 16]).unwrap(),
        );
        let current_claim_request = RequestOutboxClaimRequest::new(
            domain,
            OutboxRequestId::new(*current_request_id.as_bytes()).unwrap(),
            10_000,
            DurableOutboxLeaseId::new([0x92; 32]).unwrap(),
            40_000,
        )
        .unwrap();
        assert_eq!(
            store.claim_request_outbox(&due_context, current_claim_request),
            DurableOutboxClaimOutcome::NoDueWork
        );
        let DurableOutboxClaimOutcome::Claimed(older_claim) =
            store.claim_due_outbox(&due_context, due_request)
        else {
            panic!("older request should remain due after exact-request delivery");
        };
        assert_eq!(
            older_claim.request_id().as_bytes(),
            older_request_id.as_bytes()
        );
    }

    #[tokio::test]
    async fn structured_route_never_sends_an_unreconciled_request_claim() {
        let fence = WriterFenceGeneration::new(3).unwrap();
        let inner = MemoryDurableStateStore::new(fence);
        inner.set_time(10_000);
        let store = Arc::new(IndeterminateRequestClaimStore::new(inner));
        let transport = Arc::new(MemoryTransport::default());
        let config = config();
        let placement = placement(0x82, 7);
        let domain = placement.domain();
        let protocol_config = active_protocol_config(domain);
        let id = request_id(0x23);
        let signing_key: ed25519_zebra::SigningKey = dev_signing_key(0x23);
        let submit: NodeEvent = signed_submit_transaction_event(&signing_key, id, 0);
        let app = structured_app(
            Arc::clone(&store),
            Arc::clone(&transport),
            Arc::new(ManualClock::new(10_000)),
            protocol_config,
            config,
        );

        let response = app
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(submit.encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            to_bytes(response.into_body(), 128).await.unwrap(),
            "outbox-claim-indeterminate"
        );
        assert!(transport.drain_outbound().unwrap().is_empty());
        let commit_contexts = store.commit_contexts.lock().unwrap();
        let claim_contexts = store.claim_contexts.lock().unwrap();
        let claim_requests = store.claim_requests.lock().unwrap();
        assert_eq!(commit_contexts.len(), 1);
        assert_eq!(claim_contexts.len(), 2);
        assert_eq!(claim_requests.len(), 2);
        assert_eq!(commit_contexts[0], claim_contexts[0]);
        assert_eq!(claim_contexts[0], claim_contexts[1]);
        assert_eq!(claim_requests[0], claim_requests[1]);
        assert_eq!(claim_requests[0].domain(), domain);
        assert_eq!(claim_requests[0].request_id().as_bytes(), id.as_bytes());
    }

    #[tokio::test]
    async fn structured_route_maps_writer_fencing_without_publishing_output() {
        let store = Arc::new(MemoryDurableStateStore::new(
            WriterFenceGeneration::new(4).unwrap(),
        ));
        store.set_time(10_000);
        let transport = Arc::new(MemoryTransport::default());
        let config = config();
        let protocol_config = active_protocol_config(
            AtomicityDomainId::new([0x83; 32]).expect("test domain must be non-zero"),
        );
        let app = structured_app(
            store,
            Arc::clone(&transport),
            Arc::new(ManualClock::new(10_000)),
            protocol_config,
            config,
        );
        let signing_key: ed25519_zebra::SigningKey = dev_signing_key(0x24);
        let submit: NodeEvent = signed_submit_transaction_event(&signing_key, request_id(0x24), 0);

        let response = app
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(submit.encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            to_bytes(response.into_body(), 128).await.unwrap(),
            "durable-storage-unavailable"
        );
        assert!(transport.drain_outbound().unwrap().is_empty());
    }

    // ── preinstalled-WASM structured durable route ──────────────────────

    #[tokio::test]
    async fn preinstalled_route_write_commits_accepted_and_advances_object_version_and_nonce_receipt()
     {
        let fence = WriterFenceGeneration::new(3).unwrap();
        let store = Arc::new(MemoryDurableStateStore::new(fence));
        store.set_time(10_000);
        let transport = Arc::new(MemoryTransport::default());
        let config = config();
        let domain = AtomicityDomainId::new([0xB1; 32]).unwrap();
        let module_id = ModuleId::new([0x70; 32]);
        let (registry, catalog, module_ref) = preinstalled_module_fixture(
            &resolver(),
            module_id,
            1,
            preinstalled_write_wasm_bytes(),
            64,
        );
        let protocol_config = preinstalled_protocol_config(domain, registry);
        let signing_key = dev_signing_key(0x51);
        let sender = dev_sender_address(&signing_key);
        let setup_context = DurableOperationContext::new(
            fence,
            StorageDeadline::new(20_000).unwrap(),
            StorageCorrelationId::new([0xB1; 16]).unwrap(),
        );
        let write_object = owned_object(ObjectId::new([0xB2; 32]), sender, 0x40);
        let write_ref = commit_owned_object(
            store.as_ref(),
            &setup_context,
            domain,
            write_object,
            "sunrise-test",
            9,
            0x41,
        );
        let write_object_id = write_ref.id;
        let catalog = Arc::new(catalog);
        let blob_store = Arc::new(MemoryBlobStore::default());
        let app = preinstalled_app_with_blob_store(
            Arc::clone(&store),
            Arc::clone(&blob_store),
            Arc::clone(&transport),
            Arc::new(ManualClock::new(10_000)),
            protocol_config,
            config,
            Arc::clone(&catalog),
            9,
        );
        let mut manifest = AccessManifest::new();
        manifest.push(AccessEntry {
            object_ref: write_ref,
            mode: AccessMode::Write,
        });
        let id = request_id(0xB3);
        let event = signed_preinstalled_wasm_submit_transaction_event(
            &signing_key,
            id,
            0,
            manifest.clone(),
            module_ref.clone(),
            vec![1, 2],
        );

        let response = app
            .clone()
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(event.encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
            .await
            .unwrap();
        let result = HttpNodeResult::decode(&bytes).unwrap();
        assert_eq!(result.responses().len(), 1);
        assert_eq!(result.responses()[0].status(), NodeResponseStatus::Accepted);
        assert!(result.responses()[0].payload().is_some());

        let write_head = store
            .get_object_head(&setup_context, domain, write_object_id)
            .unwrap();
        assert_eq!(write_head.object_version(), DurableObjectVersion::new(2));
        let write_v2 = store
            .get_object_version(
                &setup_context,
                domain,
                write_object_id,
                DurableObjectVersion::new(2).unwrap(),
            )
            .unwrap()
            .unwrap();
        assert!(
            matches!(write_v2.payload(), DurableObjectPayload::Inline(_)),
            "a body at or under the threshold must stay inline"
        );
        assert_eq!(
            committed_object(&write_v2, blob_store.as_ref()).data,
            vec![0xCA, 0xFE]
        );
        assert!(
            store
                .get_request_receipt(
                    &setup_context,
                    domain,
                    DurableRequestId::new(*id.as_bytes()).unwrap()
                )
                .unwrap()
                .is_some()
        );

        // A fresh request at the same already-spent nonce fails with a
        // conflict, proving the nonce advanced past 0.
        let replay_nonce_event = signed_preinstalled_wasm_submit_transaction_event(
            &signing_key,
            request_id(0xB4),
            0,
            manifest,
            module_ref,
            vec![1, 2],
        );
        let nonce_response = app
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(replay_nonce_event.encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(nonce_response.status(), StatusCode::CONFLICT);
        assert_eq!(
            to_bytes(nonce_response.into_body(), 128).await.unwrap(),
            "sender-nonce-mismatch"
        );
    }

    /// End-to-end composition proof: a signed `Write` access naming a
    /// blob-backed previous version is only readable at all because the
    /// router dispatches through the exact `BlobStore` supplied to
    /// [`StructuredDurableNativeComponents::new`], not a hidden default. The
    /// counting double proves the fetch was dispatched through it, and the
    /// committed new version — an ordinary small body, so it stays inline
    /// rather than being republished — carries the fetched blob's own data.
    #[tokio::test]
    async fn preinstalled_route_reads_blob_backed_object_through_supplied_blob_store() {
        let fence = WriterFenceGeneration::new(3).unwrap();
        let store = Arc::new(MemoryDurableStateStore::new(fence));
        store.set_time(10_000);
        let blob_store = Arc::new(CountingBlobStore::default());
        let transport = Arc::new(MemoryTransport::default());
        let config = config();
        let domain = AtomicityDomainId::new([0xBB; 32]).unwrap();
        let module_id = ModuleId::new([0x72; 32]);
        let (registry, catalog, module_ref) = preinstalled_module_fixture(
            &resolver(),
            module_id,
            1,
            preinstalled_write_wasm_bytes(),
            64,
        );
        let protocol_config = preinstalled_protocol_config(domain, registry);
        let signing_key = dev_signing_key(0x53);
        let sender = dev_sender_address(&signing_key);
        let setup_context = DurableOperationContext::new(
            fence,
            StorageDeadline::new(20_000).unwrap(),
            StorageCorrelationId::new([0xBB; 16]).unwrap(),
        );
        let write_object = owned_object(ObjectId::new([0xBC; 32]), sender, 0x40);
        let write_ref = commit_owned_blob_object(
            store.as_ref(),
            blob_store.as_ref(),
            &setup_context,
            domain,
            write_object,
            "sunrise-test",
            9,
            0x41,
        );
        let write_object_id = write_ref.id;
        let catalog = Arc::new(catalog);
        let app = preinstalled_app_with_blob_store(
            Arc::clone(&store),
            Arc::clone(&blob_store),
            Arc::clone(&transport),
            Arc::new(ManualClock::new(10_000)),
            protocol_config,
            config,
            Arc::clone(&catalog),
            9,
        );
        let mut manifest = AccessManifest::new();
        manifest.push(AccessEntry {
            object_ref: write_ref,
            mode: AccessMode::Write,
        });
        let id = request_id(0xBD);
        let event = signed_preinstalled_wasm_submit_transaction_event(
            &signing_key,
            id,
            0,
            manifest,
            module_ref,
            vec![1, 2],
        );

        let response = app
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(event.encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
            .await
            .unwrap();
        let result = HttpNodeResult::decode(&bytes).unwrap();
        assert_eq!(result.responses()[0].status(), NodeResponseStatus::Accepted);

        assert_eq!(
            blob_store.get_calls(),
            1,
            "the request must dispatch through the exact supplied blob store"
        );
        let write_v2 = store
            .get_object_version(
                &setup_context,
                domain,
                write_object_id,
                DurableObjectVersion::new(2).unwrap(),
            )
            .unwrap()
            .unwrap();
        assert!(
            matches!(write_v2.payload(), DurableObjectPayload::Inline(_)),
            "a body at or under the threshold must stay inline"
        );
        assert_eq!(
            committed_object(&write_v2, blob_store.as_ref()).data,
            vec![0xCA, 0xFE]
        );
    }

    #[tokio::test]
    async fn preinstalled_route_exact_duplicate_does_not_reexecute_or_reapply() {
        let fence = WriterFenceGeneration::new(3).unwrap();
        let store = Arc::new(MemoryDurableStateStore::new(fence));
        store.set_time(10_000);
        let transport = Arc::new(MemoryTransport::default());
        let config = config();
        let domain = AtomicityDomainId::new([0xB5; 32]).unwrap();
        let module_id = ModuleId::new([0x71; 32]);
        let (registry, catalog, module_ref) = preinstalled_module_fixture(
            &resolver(),
            module_id,
            1,
            preinstalled_write_wasm_bytes(),
            64,
        );
        let protocol_config = preinstalled_protocol_config(domain, registry);
        let signing_key = dev_signing_key(0x52);
        let sender = dev_sender_address(&signing_key);
        let setup_context = DurableOperationContext::new(
            fence,
            StorageDeadline::new(20_000).unwrap(),
            StorageCorrelationId::new([0xB5; 16]).unwrap(),
        );
        let write_object = owned_object(ObjectId::new([0xB6; 32]), sender, 0x42);
        let write_ref = commit_owned_object(
            store.as_ref(),
            &setup_context,
            domain,
            write_object,
            "sunrise-test",
            9,
            0x43,
        );
        let write_object_id = write_ref.id;
        let catalog = Arc::new(catalog);
        let app = preinstalled_app(
            Arc::clone(&store),
            Arc::clone(&transport),
            Arc::new(ManualClock::new(10_000)),
            protocol_config,
            config,
            catalog,
            9,
        );
        let mut manifest = AccessManifest::new();
        manifest.push(AccessEntry {
            object_ref: write_ref,
            mode: AccessMode::Write,
        });
        let event = signed_preinstalled_wasm_submit_transaction_event(
            &signing_key,
            request_id(0xB7),
            0,
            manifest,
            module_ref,
            vec![3, 4],
        );
        let body = event.encode().unwrap();

        let first = app
            .clone()
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let first_bytes = to_bytes(first.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
            .await
            .unwrap();

        let second = app
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::OK);
        let second_bytes = to_bytes(second.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
            .await
            .unwrap();

        assert_eq!(first_bytes, second_bytes);
        let write_head = store
            .get_object_head(&setup_context, domain, write_object_id)
            .unwrap();
        assert_eq!(write_head.object_version(), DurableObjectVersion::new(2));
    }

    #[tokio::test]
    async fn preinstalled_route_replay_after_sqlite_reopen_returns_persisted_result() {
        let database = TestDatabase::new();
        let fence = WriterFenceGeneration::new(3).unwrap();
        let chain = ChainId::new("sunrise-test").unwrap();
        let validator = ValidatorId::new([0x44; 32]);
        let domain = AtomicityDomainId::new([0xB8; 32]).unwrap();
        let namespace = SqliteNamespace::new(chain, validator, domain);
        let config = config();
        let module_id = ModuleId::new([0x72; 32]);
        let (registry, catalog, module_ref) = preinstalled_module_fixture(
            &resolver(),
            module_id,
            1,
            preinstalled_write_wasm_bytes(),
            64,
        );
        let protocol_config = preinstalled_protocol_config(domain, registry);
        let catalog = Arc::new(catalog);
        let signing_key = dev_signing_key(0x53);
        let sender = dev_sender_address(&signing_key);
        let id = request_id(0xB9);
        let mut manifest = AccessManifest::new();

        let first_bytes = {
            let store = Arc::new(
                SqliteDurableStore::open(&database.path, namespace.clone(), fence).unwrap(),
            );
            let setup_context = live_operation_context(fence, 0xB9);
            let write_object = owned_object(ObjectId::new([0xBA; 32]), sender, 0x44);
            let write_ref = commit_owned_object(
                store.as_ref(),
                &setup_context,
                domain,
                write_object,
                "sunrise-test",
                9,
                0x45,
            );
            manifest.push(AccessEntry {
                object_ref: write_ref,
                mode: AccessMode::Write,
            });
            let app = preinstalled_app(
                Arc::clone(&store),
                Arc::new(MemoryTransport::default()),
                Arc::new(SystemClock),
                protocol_config.clone(),
                config.clone(),
                Arc::clone(&catalog),
                9,
            );
            let event = signed_preinstalled_wasm_submit_transaction_event(
                &signing_key,
                id,
                0,
                manifest.clone(),
                module_ref.clone(),
                vec![5, 6],
            );
            let response = app
                .oneshot(
                    Request::post(NODE_EVENT_PATH)
                        .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                        .body(Body::from(event.encode().unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            to_bytes(response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
                .await
                .unwrap()
        };

        let reopened =
            Arc::new(SqliteDurableStore::open(&database.path, namespace, fence).unwrap());

        // Directly prove the durable receipt survived the close/reopen,
        // independent of the exact-replay HTTP round trip below.
        let receipt_context = live_operation_context(fence, 0xBC);
        assert!(
            reopened
                .get_request_receipt(
                    &receipt_context,
                    domain,
                    DurableRequestId::new(*id.as_bytes()).unwrap(),
                )
                .unwrap()
                .is_some()
        );

        let replay_app = preinstalled_app(
            Arc::clone(&reopened),
            Arc::new(MemoryTransport::default()),
            Arc::new(SystemClock),
            protocol_config.clone(),
            config.clone(),
            Arc::clone(&catalog),
            9,
        );
        let replay_event = signed_preinstalled_wasm_submit_transaction_event(
            &signing_key,
            id,
            0,
            manifest.clone(),
            module_ref.clone(),
            vec![5, 6],
        );
        let replay_response = replay_app
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(replay_event.encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(replay_response.status(), StatusCode::OK);
        let replay_bytes = to_bytes(replay_response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
            .await
            .unwrap();
        assert_eq!(first_bytes, replay_bytes);

        let read_context = live_operation_context(fence, 0xBB);
        let write_head = reopened
            .get_object_head(&read_context, domain, ObjectId::new([0xBA; 32]))
            .unwrap();
        assert_eq!(write_head.object_version(), DurableObjectVersion::new(2));

        // A fresh request ID at the already-spent nonce 0, with the same
        // module/object access, conflicts. Exact replay above reconciles
        // from the persisted receipt before ever checking the nonce, so this
        // proves the sender-nonce record itself survived reopen, not just
        // the receipt.
        let nonce_probe_app = preinstalled_app(
            reopened,
            Arc::new(MemoryTransport::default()),
            Arc::new(SystemClock),
            protocol_config,
            config,
            catalog,
            9,
        );
        let nonce_probe_event = signed_preinstalled_wasm_submit_transaction_event(
            &signing_key,
            request_id(0xBD),
            0,
            manifest,
            module_ref,
            vec![5, 6],
        );
        let nonce_probe_response = nonce_probe_app
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(nonce_probe_event.encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(nonce_probe_response.status(), StatusCode::CONFLICT);
        assert_eq!(
            to_bytes(nonce_probe_response.into_body(), 128)
                .await
                .unwrap(),
            "sender-nonce-mismatch"
        );
    }

    #[tokio::test]
    async fn preinstalled_route_trap_returns_rejected_and_leaves_object_unchanged() {
        let fence = WriterFenceGeneration::new(3).unwrap();
        let store = Arc::new(MemoryDurableStateStore::new(fence));
        store.set_time(10_000);
        let transport = Arc::new(MemoryTransport::default());
        let config = config();
        let domain = AtomicityDomainId::new([0xBC; 32]).unwrap();
        let module_id = ModuleId::new([0x73; 32]);
        let (registry, catalog, module_ref) = preinstalled_module_fixture(
            &resolver(),
            module_id,
            1,
            preinstalled_trap_wasm_bytes(),
            64,
        );
        let protocol_config = preinstalled_protocol_config(domain, registry);
        let signing_key = dev_signing_key(0x54);
        let sender = dev_sender_address(&signing_key);
        let setup_context = DurableOperationContext::new(
            fence,
            StorageDeadline::new(20_000).unwrap(),
            StorageCorrelationId::new([0xBC; 16]).unwrap(),
        );
        let write_object = owned_object(ObjectId::new([0xBD; 32]), sender, 0x46);
        let write_ref = commit_owned_object(
            store.as_ref(),
            &setup_context,
            domain,
            write_object,
            "sunrise-test",
            9,
            0x47,
        );
        let write_object_id = write_ref.id;
        let catalog = Arc::new(catalog);
        let app = preinstalled_app(
            Arc::clone(&store),
            Arc::clone(&transport),
            Arc::new(ManualClock::new(10_000)),
            protocol_config,
            config,
            catalog,
            9,
        );
        let mut manifest = AccessManifest::new();
        manifest.push(AccessEntry {
            object_ref: write_ref,
            mode: AccessMode::Write,
        });
        let id = request_id(0xBE);
        let event = signed_preinstalled_wasm_submit_transaction_event(
            &signing_key,
            id,
            0,
            manifest.clone(),
            module_ref.clone(),
            vec![7, 8],
        );

        let response = app
            .clone()
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(event.encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
            .await
            .unwrap();
        let result = HttpNodeResult::decode(&bytes).unwrap();
        assert_eq!(result.responses().len(), 1);
        assert_eq!(result.responses()[0].status(), NodeResponseStatus::Rejected);

        let write_head = store
            .get_object_head(&setup_context, domain, write_object_id)
            .unwrap();
        assert_eq!(write_head.object_version(), DurableObjectVersion::new(1));

        // The trap still consumed the nonce: a fresh request at the same
        // nonce conflicts.
        let replay_nonce_event = signed_preinstalled_wasm_submit_transaction_event(
            &signing_key,
            request_id(0xBF),
            0,
            manifest,
            module_ref,
            vec![7, 8],
        );
        let nonce_response = app
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(replay_nonce_event.encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(nonce_response.status(), StatusCode::CONFLICT);
        assert_eq!(
            to_bytes(nonce_response.into_body(), 128).await.unwrap(),
            "sender-nonce-mismatch"
        );
    }

    #[tokio::test]
    async fn preinstalled_route_zero_object_call_rejects_before_storage_dispatch() {
        let fence = WriterFenceGeneration::new(3).unwrap();
        let inner = MemoryDurableStateStore::new(fence);
        inner.set_time(10_000);
        let cancellation = Arc::new(ManualCancellation::default());
        let store = Arc::new(CancelOnFirstReceiptReadStore::new(
            inner,
            Arc::clone(&cancellation),
        ));
        let transport = Arc::new(MemoryTransport::default());
        let config = config();
        let domain = AtomicityDomainId::new([0xC0; 32]).unwrap();
        let module_id = ModuleId::new([0x74; 32]);
        let (registry, catalog, module_ref) = preinstalled_module_fixture(
            &resolver(),
            module_id,
            1,
            preinstalled_write_wasm_bytes(),
            64,
        );
        let protocol_config = preinstalled_protocol_config(domain, registry);
        let signing_key = dev_signing_key(0x55);
        let catalog = Arc::new(catalog);
        let app = preinstalled_app(
            Arc::clone(&store),
            Arc::clone(&transport),
            Arc::new(ManualClock::new(10_000)),
            protocol_config,
            config,
            catalog,
            9,
        );
        let id = request_id(0xC1);
        let event = signed_preinstalled_wasm_submit_transaction_event(
            &signing_key,
            id,
            0,
            AccessManifest::new(),
            module_ref,
            vec![1],
        );

        let response = app
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(event.encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            to_bytes(response.into_body(), 128).await.unwrap(),
            "preinstalled-module-zero-object-access"
        );
        // `CancelOnFirstReceiptReadStore` flips this signal the moment
        // `get_request_receipt` is first dispatched, so it staying false
        // directly proves the structured durable path never reached its
        // first storage read for this rejected call.
        assert!(!cancellation.is_cancelled());
        assert_eq!(store.receipt_reads(), 0);
        let read_context = DurableOperationContext::new(
            fence,
            StorageDeadline::new(20_000).unwrap(),
            StorageCorrelationId::new([0xC1; 16]).unwrap(),
        );
        assert_eq!(
            store
                .inner
                .get_request_receipt(
                    &read_context,
                    domain,
                    DurableRequestId::new(*id.as_bytes()).unwrap()
                )
                .unwrap(),
            None
        );
        assert!(transport.drain_outbound().unwrap().is_empty());
    }

    /// A discriminating test proving `MissingEntrypoint` (a client-chosen
    /// entrypoint name absent from an otherwise valid, catalog-verified
    /// module) maps to `422` and never reaches object mutation or a
    /// persisted receipt, exercising `execution_error_response`'s
    /// classification through the full HTTP path rather than only as a unit
    /// case on `node_error_response`.
    #[tokio::test]
    async fn preinstalled_route_missing_entrypoint_rejects_as_client_fault_without_mutation() {
        let fence = WriterFenceGeneration::new(3).unwrap();
        let store = Arc::new(MemoryDurableStateStore::new(fence));
        store.set_time(10_000);
        let transport = Arc::new(MemoryTransport::default());
        let config = config();
        let domain = AtomicityDomainId::new([0xD2; 32]).unwrap();
        let module_id = ModuleId::new([0x75; 32]);
        let (registry, catalog, module_ref) = preinstalled_module_fixture(
            &resolver(),
            module_id,
            1,
            preinstalled_write_wasm_bytes(),
            64,
        );
        let protocol_config = preinstalled_protocol_config(domain, registry);
        let signing_key = dev_signing_key(0x57);
        let sender = dev_sender_address(&signing_key);
        let setup_context = DurableOperationContext::new(
            fence,
            StorageDeadline::new(20_000).unwrap(),
            StorageCorrelationId::new([0xD2; 16]).unwrap(),
        );
        let write_object = owned_object(ObjectId::new([0xD3; 32]), sender, 0x48);
        let write_ref = commit_owned_object(
            store.as_ref(),
            &setup_context,
            domain,
            write_object,
            "sunrise-test",
            9,
            0x49,
        );
        let write_object_id = write_ref.id;
        let catalog = Arc::new(catalog);
        let app = preinstalled_app(
            Arc::clone(&store),
            Arc::clone(&transport),
            Arc::new(ManualClock::new(10_000)),
            protocol_config,
            config,
            catalog,
            9,
        );
        let mut manifest = AccessManifest::new();
        manifest.push(AccessEntry {
            object_ref: write_ref,
            mode: AccessMode::Write,
        });
        let id = request_id(0xD4);
        // `preinstalled_write_wasm_bytes` only exports `"run"`.
        let event = signed_preinstalled_wasm_submit_transaction_event_with_entrypoint(
            &signing_key,
            id,
            0,
            manifest,
            module_ref,
            "does-not-exist",
            vec![1, 2],
        );

        let response = app
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(event.encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            to_bytes(response.into_body(), 128).await.unwrap(),
            "preinstalled-module-entrypoint-unknown"
        );
        assert_eq!(
            store
                .get_request_receipt(
                    &setup_context,
                    domain,
                    DurableRequestId::new(*id.as_bytes()).unwrap()
                )
                .unwrap(),
            None
        );
        let write_head = store
            .get_object_head(&setup_context, domain, write_object_id)
            .unwrap();
        assert_eq!(write_head.object_version(), DurableObjectVersion::new(1));
        assert!(transport.drain_outbound().unwrap().is_empty());
    }

    /// Proves the catalog/commitment-mismatch classification end to end:
    /// the caller-supplied catalog entry's exact semantics-envelope bytes no
    /// longer rehash to the governance-committed `semantics_hash`, which is a
    /// host catalog defect, so this must be an opaque `500`, not a client
    /// fault, and must never leak the internal `Display` text of the mismatch.
    #[tokio::test]
    async fn preinstalled_route_catalog_semantics_hash_mismatch_is_opaque_host_failure() {
        let fence = WriterFenceGeneration::new(3).unwrap();
        let store = Arc::new(MemoryDurableStateStore::new(fence));
        store.set_time(10_000);
        let transport = Arc::new(MemoryTransport::default());
        let config = config();
        let domain = AtomicityDomainId::new([0xD5; 32]).unwrap();
        let module_id = ModuleId::new([0x76; 32]);
        let (registry, _genuine_catalog, module_ref) = preinstalled_module_fixture(
            &resolver(),
            module_id,
            1,
            preinstalled_write_wasm_bytes(),
            64,
        );
        // Corrupt the caller-supplied catalog: same module_id/version/WASM/
        // manifest as the registry commitment, but different exact semantics
        // envelope bytes, so the catalog entry no longer rehashes to the
        // registry's committed `semantics_hash`.
        let mismatched_semantics_envelope: PreinstalledModuleSemanticsEnvelope =
            PreinstalledModuleSemanticsEnvelope::opaque_only(
                b"http-preinstalled-semantics-mismatch".to_vec(),
            )
            .unwrap();
        let mismatched_entry = PreinstalledModuleCatalogEntry::new(
            module_id,
            1,
            preinstalled_write_wasm_bytes(),
            preinstalled_manifest(module_id, 64),
            mismatched_semantics_envelope,
        )
        .unwrap();
        let catalog = Arc::new(PreinstalledModuleCatalog::new(vec![mismatched_entry]).unwrap());
        let protocol_config = preinstalled_protocol_config(domain, registry);
        let signing_key = dev_signing_key(0x58);
        let sender = dev_sender_address(&signing_key);
        let setup_context = DurableOperationContext::new(
            fence,
            StorageDeadline::new(20_000).unwrap(),
            StorageCorrelationId::new([0xD5; 16]).unwrap(),
        );
        let write_object = owned_object(ObjectId::new([0xD6; 32]), sender, 0x4A);
        let write_ref = commit_owned_object(
            store.as_ref(),
            &setup_context,
            domain,
            write_object,
            "sunrise-test",
            9,
            0x4B,
        );
        let write_object_id = write_ref.id;
        let app = preinstalled_app(
            Arc::clone(&store),
            Arc::clone(&transport),
            Arc::new(ManualClock::new(10_000)),
            protocol_config,
            config,
            catalog,
            9,
        );
        let mut manifest = AccessManifest::new();
        manifest.push(AccessEntry {
            object_ref: write_ref,
            mode: AccessMode::Write,
        });
        let id = request_id(0xD7);
        let event = signed_preinstalled_wasm_submit_transaction_event(
            &signing_key,
            id,
            0,
            manifest,
            module_ref,
            vec![1, 2],
        );

        let response = app
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(event.encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            to_bytes(response.into_body(), 128).await.unwrap(),
            "preinstalled-module-catalog-mismatch"
        );
        assert_eq!(
            store
                .get_request_receipt(
                    &setup_context,
                    domain,
                    DurableRequestId::new(*id.as_bytes()).unwrap()
                )
                .unwrap(),
            None
        );
        let write_head = store
            .get_object_head(&setup_context, domain, write_object_id)
            .unwrap();
        assert_eq!(write_head.object_version(), DurableObjectVersion::new(1));
        assert!(transport.drain_outbound().unwrap().is_empty());
    }

    #[tokio::test]
    async fn structured_route_still_rejects_write_and_consume_access() {
        let fence = WriterFenceGeneration::new(3).unwrap();
        let store = Arc::new(MemoryDurableStateStore::new(fence));
        store.set_time(10_000);
        let transport = Arc::new(MemoryTransport::default());
        let config = config();
        let domain = AtomicityDomainId::new([0xC2; 32]).unwrap();
        let protocol_config = active_protocol_config(domain);
        let app = structured_app(
            Arc::clone(&store),
            Arc::clone(&transport),
            Arc::new(ManualClock::new(10_000)),
            protocol_config,
            config,
        );
        let signing_key = dev_signing_key(0x56);
        let sender = dev_sender_address(&signing_key);

        for (byte, mode) in [(0xC3_u8, AccessMode::Write), (0xC4_u8, AccessMode::Consume)] {
            let mut tx = unsigned_transaction(
                sender,
                ChainId::new("sunrise-test").unwrap(),
                Epoch::new(7),
                0,
            );
            tx.access_manifest.push(AccessEntry {
                object_ref: ObjectRef {
                    id: ObjectId::new([byte; 32]),
                    version: 1,
                    digest: Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32]),
                },
                mode,
            });
            let signed_bytes = signed_transaction_bytes(&signing_key, &tx);
            let event = submit_transaction_event(request_id(byte), signed_bytes);

            let response = app
                .clone()
                .oneshot(
                    Request::post(NODE_EVENT_PATH)
                        .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                        .body(Body::from(event.encode().unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
            assert_eq!(
                to_bytes(response.into_body(), 128).await.unwrap(),
                "object-mutating-access-unsupported"
            );
        }
    }

    #[tokio::test]
    async fn preinstalled_route_rejects_cancellation_at_each_pre_storage_checkpoint() {
        // Both the shared axum wrapper's own initial observation (call 1) and
        // the two checkpoints inside the shared
        // `invoke_structured_durable_event_with_execution` core (calls 2 and
        // 3, mirroring `structured_route_rejects_cancellation_at_each_pre_storage_checkpoint`)
        // must reject on this route too, proving the new thin wrapper wires
        // its own state's cancellation signal through correctly.
        for cancel_at_call in 1_usize..=3_usize {
            let fence = WriterFenceGeneration::new(3).unwrap();
            let store = Arc::new(MemoryDurableStateStore::new(fence));
            store.set_time(10_000);
            let transport = Arc::new(MemoryTransport::default());
            let config = config();
            let domain = AtomicityDomainId::new([0xC5; 32]).unwrap();
            let protocol_config = active_protocol_config(domain);
            let cancellation: Arc<StepCancellation> =
                Arc::new(StepCancellation::new(cancel_at_call));
            let catalog = Arc::new(PreinstalledModuleCatalog::new(Vec::new()).unwrap());
            let app = preinstalled_app_with_cancellation(
                Arc::clone(&store),
                Arc::clone(&transport),
                Arc::new(ManualClock::new(10_000)),
                protocol_config,
                config.clone(),
                catalog,
                9,
                cancellation.clone(),
            );
            let id = request_id(u8::try_from(0xD0_usize + cancel_at_call).unwrap());
            let signing_key: ed25519_zebra::SigningKey = dev_signing_key(0x5A);
            let submit: NodeEvent = signed_submit_transaction_event(&signing_key, id, 0);

            let response = app
                .oneshot(
                    Request::post(NODE_EVENT_PATH)
                        .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                        .body(Body::from(submit.encode().unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(
                to_bytes(response.into_body(), 128).await.unwrap(),
                "invocation-cancelled-before-storage"
            );
            assert_eq!(cancellation.calls(), cancel_at_call);
            assert!(transport.drain_outbound().unwrap().is_empty());
            let verification_context = DurableOperationContext::new(
                fence,
                StorageDeadline::new(11_000).unwrap(),
                StorageCorrelationId::new([0xD1; 16]).unwrap(),
            );
            assert_eq!(
                store
                    .get_request_receipt(
                        &verification_context,
                        domain,
                        DurableRequestId::new(*id.as_bytes()).unwrap(),
                    )
                    .unwrap(),
                None
            );
        }
    }

    /// Proves `structured_durable_router` and `preinstalled_wasm_structured_durable_router`
    /// share identical unsupported-content-type/content-encoding/body rejection
    /// behavior, since both now dispatch through the one private
    /// `submit_structured_durable_event_common` helper rather than duplicated
    /// per-route logic.
    #[tokio::test]
    async fn structured_and_preinstalled_routes_share_content_type_and_body_rejection_behavior() {
        let domain = AtomicityDomainId::new([0xCA; 32]).unwrap();
        let config = config();
        let structured_store = Arc::new(MemoryDurableStateStore::new(
            WriterFenceGeneration::new(3).unwrap(),
        ));
        structured_store.set_time(10_000);
        let structured = structured_app(
            structured_store,
            Arc::new(MemoryTransport::default()),
            Arc::new(ManualClock::new(10_000)),
            active_protocol_config(domain),
            config.clone(),
        );
        let preinstalled_store = Arc::new(MemoryDurableStateStore::new(
            WriterFenceGeneration::new(3).unwrap(),
        ));
        preinstalled_store.set_time(10_000);
        let preinstalled = preinstalled_app(
            preinstalled_store,
            Arc::new(MemoryTransport::default()),
            Arc::new(ManualClock::new(10_000)),
            active_protocol_config(domain),
            config,
            Arc::new(PreinstalledModuleCatalog::new(Vec::new()).unwrap()),
            9,
        );

        for app in [structured, preinstalled] {
            let wrong_type = app
                .clone()
                .oneshot(
                    Request::post(NODE_EVENT_PATH)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(event(request_id(0xCB)).encode().unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(wrong_type.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
            assert_eq!(
                to_bytes(wrong_type.into_body(), 128).await.unwrap(),
                "unsupported-content-type"
            );

            let unsupported_encoding = app
                .clone()
                .oneshot(
                    Request::post(NODE_EVENT_PATH)
                        .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                        .header(header::CONTENT_ENCODING, "gzip")
                        .body(Body::from(event(request_id(0xCC)).encode().unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                unsupported_encoding.status(),
                StatusCode::UNSUPPORTED_MEDIA_TYPE
            );
            assert_eq!(
                to_bytes(unsupported_encoding.into_body(), 128)
                    .await
                    .unwrap(),
                "unsupported-content-encoding"
            );

            let oversized_body = app
                .oneshot(
                    Request::post(NODE_EVENT_PATH)
                        .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                        .body(Body::from(vec![0_u8; MAX_HTTP_EVENT_BODY_BYTES + 1]))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(oversized_body.status(), StatusCode::PAYLOAD_TOO_LARGE);
        }
    }

    #[tokio::test]
    async fn unattended_recovery_drains_at_most_one_outbox_and_paginates() {
        let runtime = Arc::new(MemoryRuntime::new(ValidatorId::new([0x44; 32])));
        let config = config();
        let machine = IncrementMachine::new(config.state_key());
        let resolver = resolver();
        let first_id = request_id(0x61);
        let second_id = request_id(0x62);
        handle_idempotent_event(
            runtime.as_ref(),
            &config,
            &resolver,
            event(first_id),
            &machine,
        )
        .unwrap();
        handle_idempotent_event(
            runtime.as_ref(),
            &config,
            &resolver,
            event(second_id),
            &machine,
        )
        .unwrap();
        assert!(runtime.transport().drain_outbound().unwrap().is_empty());

        let lease_ids = Arc::new(SequenceLeaseIds::default());
        let executor =
            NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(1).unwrap()));
        let first = recover_outboxes_once(
            Arc::clone(&runtime),
            config.clone(),
            Arc::clone(&lease_ids),
            executor.clone(),
            None,
            NonZeroUsize::new(4).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            first.outcome(),
            &NativeOutboxRecoveryOutcome::Recovered(first_id)
        );
        assert!(first.continuation_cursor().is_some());
        assert_eq!(runtime.transport().drain_outbound().unwrap().len(), 1);

        let second = recover_outboxes_once(
            Arc::clone(&runtime),
            config.clone(),
            Arc::clone(&lease_ids),
            executor.clone(),
            first.continuation_cursor().map(<[u8]>::to_vec),
            NonZeroUsize::new(4).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            second.outcome(),
            &NativeOutboxRecoveryOutcome::Recovered(second_id)
        );
        assert_eq!(second.continuation_cursor(), None);
        assert_eq!(runtime.transport().drain_outbound().unwrap().len(), 1);

        let completed_sweep = recover_outboxes_once(
            runtime,
            config,
            lease_ids,
            executor,
            None,
            NonZeroUsize::new(4).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            completed_sweep.outcome(),
            &NativeOutboxRecoveryOutcome::NoEligibleOutbox
        );
        assert_eq!(completed_sweep.continuation_cursor(), None);
    }

    #[tokio::test]
    async fn unattended_recovery_skips_active_lease_and_retries_after_expiry() {
        let runtime = Arc::new(MemoryRuntime::new(ValidatorId::new([0x44; 32])));
        let config = config();
        let id = request_id(0x63);
        handle_idempotent_event(
            runtime.as_ref(),
            &config,
            &resolver(),
            event(id),
            &IncrementMachine::new(config.state_key()),
        )
        .unwrap();
        let layout = PersistenceLayout::new(config.chain_id().clone(), config.protocol_version());
        claim_next_outbox_message(
            runtime.state_store(),
            &layout,
            id,
            OutboxLeaseId::new([0xAA; 32]).unwrap(),
            0,
            NATIVE_OUTBOX_LEASE_MILLIS,
        )
        .unwrap()
        .unwrap();

        let lease_ids = Arc::new(SequenceLeaseIds::default());
        let executor =
            NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(1).unwrap()));
        let active = recover_outboxes_once(
            Arc::clone(&runtime),
            config.clone(),
            Arc::clone(&lease_ids),
            executor.clone(),
            None,
            NonZeroUsize::new(4).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            active.outcome(),
            &NativeOutboxRecoveryOutcome::NoEligibleOutbox
        );
        assert!(runtime.transport().drain_outbound().unwrap().is_empty());

        runtime.clock().set(NATIVE_OUTBOX_LEASE_MILLIS);
        let expired = recover_outboxes_once(
            Arc::clone(&runtime),
            config,
            lease_ids,
            executor,
            None,
            NonZeroUsize::new(4).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            expired.outcome(),
            &NativeOutboxRecoveryOutcome::Recovered(id)
        );
        assert_eq!(runtime.transport().drain_outbound().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn unattended_recovery_redelivers_send_without_ack_after_lease_expiry() {
        let runtime = Arc::new(FailOnceRuntime::new());
        let config = config();
        let id = request_id(0x64);
        handle_idempotent_event(
            runtime.as_ref(),
            &config,
            &resolver(),
            event(id),
            &IncrementMachine::new(config.state_key()),
        )
        .unwrap();
        let lease_ids = Arc::new(SequenceLeaseIds::default());
        let executor =
            NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(1).unwrap()));

        let failed = recover_outboxes_once(
            Arc::clone(&runtime),
            config.clone(),
            Arc::clone(&lease_ids),
            executor.clone(),
            None,
            NonZeroUsize::new(4).unwrap(),
        )
        .await;
        assert!(matches!(failed, Err(NativeOutboxRecoveryError::Send)));
        assert!(runtime.transport().drain_outbound().unwrap().is_empty());

        runtime.clock.set(31_000);
        let recovered = recover_outboxes_once(
            Arc::clone(&runtime),
            config.clone(),
            lease_ids,
            executor,
            None,
            NonZeroUsize::new(4).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            recovered.outcome(),
            &NativeOutboxRecoveryOutcome::Recovered(id)
        );
        assert_eq!(runtime.transport().drain_outbound().unwrap().len(), 1);
        let state = runtime
            .state_store()
            .get(config.state_key())
            .unwrap()
            .unwrap();
        assert_eq!(
            decode_canonical_frame(&state)
                .unwrap()
                .required_u64(1)
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn unattended_recovery_fails_closed_on_mismatched_delivery_key() {
        let runtime = Arc::new(MemoryRuntime::new(ValidatorId::new([0x44; 32])));
        let config = config();
        let recorded_id = request_id(0x71);
        handle_idempotent_event(
            runtime.as_ref(),
            &config,
            &resolver(),
            event(recorded_id),
            &IncrementMachine::new(config.state_key()),
        )
        .unwrap();
        let layout = PersistenceLayout::new(config.chain_id().clone(), config.protocol_version());
        let delivery = runtime
            .state_store()
            .get(&layout.outbox_delivery_key(*recorded_id.as_bytes()))
            .unwrap()
            .unwrap();
        runtime
            .state_store()
            .put(
                layout.outbox_delivery_key(*request_id(0x70).as_bytes()),
                delivery,
            )
            .unwrap();

        let result = recover_outboxes_once(
            runtime,
            config,
            Arc::new(SequenceLeaseIds::default()),
            NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(1).unwrap())),
            None,
            NonZeroUsize::new(8).unwrap(),
        )
        .await;
        assert!(matches!(result, Err(NativeOutboxRecoveryError::Node(_))));
    }

    #[tokio::test]
    async fn sqlite_outbox_is_recovered_after_runtime_reopen_without_reapplying_state() {
        let database = TestDatabase::new();
        let config = config();
        let id = request_id(0x81);
        {
            let first_runtime = Arc::new(sqlite_runtime(
                &database.path,
                MemoryTransport::default(),
                1_000,
            ));
            handle_idempotent_event(
                first_runtime.as_ref(),
                &config,
                &resolver(),
                event(id),
                &IncrementMachine::new(config.state_key()),
            )
            .unwrap();
            assert!(
                first_runtime
                    .transport()
                    .drain_outbound()
                    .unwrap()
                    .is_empty()
            );
        }

        let reopened = Arc::new(sqlite_runtime(
            &database.path,
            MemoryTransport::default(),
            1_000,
        ));
        let recovered = recover_outboxes_once(
            Arc::clone(&reopened),
            config.clone(),
            Arc::new(SequenceLeaseIds::default()),
            NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(1).unwrap())),
            None,
            NonZeroUsize::new(4).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            recovered.outcome(),
            &NativeOutboxRecoveryOutcome::Recovered(id)
        );
        assert_eq!(reopened.transport().drain_outbound().unwrap().len(), 1);
        let state = reopened
            .state_store()
            .get(config.state_key())
            .unwrap()
            .unwrap();
        assert_eq!(
            decode_canonical_frame(&state)
                .unwrap()
                .required_u64(1)
                .unwrap(),
            1
        );
        drop(reopened);

        let completed = Arc::new(sqlite_runtime(
            &database.path,
            MemoryTransport::default(),
            1_000,
        ));
        let sweep = recover_outboxes_once(
            Arc::clone(&completed),
            config,
            Arc::new(SequenceLeaseIds::default()),
            NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(1).unwrap())),
            None,
            NonZeroUsize::new(4).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            sweep.outcome(),
            &NativeOutboxRecoveryOutcome::NoEligibleOutbox
        );
        assert!(completed.transport().drain_outbound().unwrap().is_empty());
    }

    #[tokio::test]
    async fn sqlite_send_failure_lease_survives_reopen_and_redelivers_only_after_expiry() {
        let database = TestDatabase::new();
        let config = config();
        let id = request_id(0x82);
        {
            let failing = Arc::new(sqlite_runtime(
                &database.path,
                FailOnceTransport::new(),
                1_000,
            ));
            handle_idempotent_event(
                failing.as_ref(),
                &config,
                &resolver(),
                event(id),
                &IncrementMachine::new(config.state_key()),
            )
            .unwrap();
            let failed = recover_outboxes_once(
                Arc::clone(&failing),
                config.clone(),
                Arc::new(SequenceLeaseIds::default()),
                NativeBlockingExecutor::new(NativeBlockingPolicy::new(
                    NonZeroUsize::new(1).unwrap(),
                )),
                None,
                NonZeroUsize::new(4).unwrap(),
            )
            .await;
            assert!(matches!(failed, Err(NativeOutboxRecoveryError::Send)));
        }

        let before_expiry = Arc::new(sqlite_runtime(
            &database.path,
            MemoryTransport::default(),
            30_999,
        ));
        let skipped = recover_outboxes_once(
            Arc::clone(&before_expiry),
            config.clone(),
            Arc::new(SequenceLeaseIds::default()),
            NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(1).unwrap())),
            None,
            NonZeroUsize::new(4).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            skipped.outcome(),
            &NativeOutboxRecoveryOutcome::NoEligibleOutbox
        );
        assert!(
            before_expiry
                .transport()
                .drain_outbound()
                .unwrap()
                .is_empty()
        );
        drop(before_expiry);

        let expired = Arc::new(sqlite_runtime(
            &database.path,
            MemoryTransport::default(),
            31_000,
        ));
        let recovered = recover_outboxes_once(
            Arc::clone(&expired),
            config.clone(),
            Arc::new(SequenceLeaseIds::default()),
            NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(1).unwrap())),
            None,
            NonZeroUsize::new(4).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            recovered.outcome(),
            &NativeOutboxRecoveryOutcome::Recovered(id)
        );
        assert_eq!(expired.transport().drain_outbound().unwrap().len(), 1);
        let layout = PersistenceLayout::new(config.chain_id().clone(), config.protocol_version());
        let delivery = expired
            .state_store()
            .get(&layout.outbox_delivery_key(*id.as_bytes()))
            .unwrap()
            .unwrap();
        let delivery = NodeOutboxDelivery::decode(&delivery).unwrap();
        assert_eq!(delivery.attempts(), 2);
        assert_eq!(delivery.lease(), None);
    }

    #[tokio::test]
    async fn native_route_rejects_media_type_and_malformed_event() {
        let runtime = Arc::new(MemoryRuntime::new(ValidatorId::new([0x44; 32])));
        let app = app(runtime.clone(), config());

        let wrong_type = app
            .clone()
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(event(request_id(0x42)).encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong_type.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

        let unknown_media_version = app
            .clone()
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(
                        header::CONTENT_TYPE,
                        format!("{NODE_EVENT_MEDIA_TYPE}; version=2"),
                    )
                    .body(Body::from(event(request_id(0x44)).encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            unknown_media_version.status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );

        let malformed = app
            .clone()
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(vec![1, 2, 3]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            to_bytes(malformed.into_body(), 128).await.unwrap(),
            "invalid-node-event"
        );

        let mut unknown_kind_frame = CanonicalStruct::new(0xE001, 1);
        unknown_kind_frame.field_str(1, "sunrise-test").unwrap();
        unknown_kind_frame.field_u32(2, 3).unwrap();
        unknown_kind_frame.field_u64(3, 7).unwrap();
        unknown_kind_frame
            .field_bytes(4, request_id(0x45).as_bytes().to_vec())
            .unwrap();
        unknown_kind_frame.field_u16(5, u16::MAX).unwrap();
        unknown_kind_frame
            .field_bytes(6, canonical(TEST_PAYLOAD_TYPE_ID, 9))
            .unwrap();
        let unknown_kind = app
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(unknown_kind_frame.finish().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unknown_kind.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            to_bytes(unknown_kind.into_body(), 128).await.unwrap(),
            "invalid-node-event"
        );
        assert_eq!(runtime.state_store().get(b"http/node-state").unwrap(), None);
    }

    #[tokio::test]
    async fn native_route_enforces_body_limit() {
        let runtime = Arc::new(MemoryRuntime::new(ValidatorId::new([0x44; 32])));
        let app = app(runtime, config());
        let oversized = app
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(vec![0; MAX_HTTP_EVENT_BODY_BYTES + 1]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn liveness_does_not_touch_protocol_state() {
        let runtime = Arc::new(MemoryRuntime::new(ValidatorId::new([0x44; 32])));
        let response = app(runtime.clone(), config())
            .oneshot(Request::get(LIVENESS_PATH).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(runtime.state_store().get(b"http/node-state").unwrap(), None);
    }

    // --- DR-0082 bounded query API: router integration --------------------

    fn query_object_path(object_id: ObjectId) -> String {
        format!("/v1/objects/{}", hex(object_id.as_bytes()))
    }

    fn query_receipt_path(id: RequestId) -> String {
        format!("/v1/receipts/{}", hex(id.as_bytes()))
    }

    fn query_next_nonce_path(sender: &Address) -> String {
        format!("/v1/senders/{}/next-nonce", hex(sender.as_bytes()))
    }

    #[tokio::test]
    async fn context_route_returns_trusted_composition() {
        let fence = WriterFenceGeneration::new(3).unwrap();
        let store = Arc::new(MemoryDurableStateStore::new(fence));
        store.set_time(10_000);
        let transport = Arc::new(MemoryTransport::default());
        let config = config();
        let domain = AtomicityDomainId::new([0xD1; 32]).unwrap();
        let protocol_config = active_protocol_config(domain);
        let expected_bytes = protocol_config.canonical_bytes().unwrap();
        let app = structured_app(
            store,
            transport,
            Arc::new(ManualClock::new(10_000)),
            protocol_config,
            config,
        );

        let response = app
            .oneshot(
                Request::get(QUERY_CONTEXT_PATH)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            QUERY_RESULT_MEDIA_TYPE
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let bytes = to_bytes(response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
            .await
            .unwrap();
        let result = HttpContextQueryResult::decode(&bytes).unwrap();
        assert_eq!(result.chain_id(), &ChainId::new("sunrise-test").unwrap());
        assert_eq!(result.protocol_version(), ProtocolVersion::new(3));
        assert_eq!(result.epoch(), Epoch::new(7));
        assert_eq!(result.domain(), domain);
        assert_eq!(result.protocol_config_bytes(), expected_bytes.as_slice());
    }

    #[tokio::test]
    async fn context_route_rejects_inactive_domain_placement_before_any_side_effect() {
        let fence = WriterFenceGeneration::new(3).unwrap();
        let store = Arc::new(MemoryDurableStateStore::new(fence));
        store.set_time(10_000);
        let config = config();
        // `config()`'s epoch is 7; an activation epoch of 100 makes this
        // placement inactive at the trusted current epoch, exactly like the
        // storage-backed routes' inactive-placement rejection.
        let mut protocol_config =
            active_protocol_config(AtomicityDomainId::new([0xFC; 32]).unwrap());
        protocol_config.domain_placement = Some(placement(0xFC, 100));
        let clock = Arc::new(CountingClock::new(10_000));
        let identities = Arc::new(CountingIndexedIdentities::default());
        let machine = Arc::new(IncrementMachine::new(config.state_key()));
        let app = structured_durable_router(
            StructuredDurableNativeComponents::new(
                store,
                Arc::new(MemoryBlobStore::default()),
                Arc::new(MemoryTransport::default()),
                Arc::clone(&clock),
                Arc::clone(&identities),
            ),
            protocol_config,
            structured_request_authority(),
            config,
            resolver(),
            machine,
            NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
        )
        .unwrap();

        let response = app
            .oneshot(
                Request::get(QUERY_CONTEXT_PATH)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            to_bytes(response.into_body(), 128).await.unwrap(),
            "query-unavailable"
        );
        assert_eq!(clock.calls.load(Ordering::SeqCst), 0);
        assert_eq!(identities.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn object_route_returns_true_absence() {
        let fence = WriterFenceGeneration::new(3).unwrap();
        let store = Arc::new(MemoryDurableStateStore::new(fence));
        store.set_time(10_000);
        let transport = Arc::new(MemoryTransport::default());
        let config = config();
        let domain = AtomicityDomainId::new([0xD2; 32]).unwrap();
        let protocol_config = active_protocol_config(domain);
        let app = structured_app(
            store,
            transport,
            Arc::new(ManualClock::new(10_000)),
            protocol_config,
            config,
        );
        let object_id = ObjectId::new([0x01; 32]);

        let response = app
            .oneshot(
                Request::get(query_object_path(object_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
            .await
            .unwrap();
        assert_eq!(
            HttpObjectQueryResult::decode(&bytes).unwrap(),
            HttpObjectQueryResult::Absent { object_id }
        );
    }

    #[tokio::test]
    async fn object_route_returns_verified_current_inline() {
        let fence = WriterFenceGeneration::new(3).unwrap();
        let store = Arc::new(MemoryDurableStateStore::new(fence));
        store.set_time(10_000);
        let domain = AtomicityDomainId::new([0xD3; 32]).unwrap();
        let setup_context = DurableOperationContext::new(
            fence,
            StorageDeadline::new(20_000).unwrap(),
            StorageCorrelationId::new([0xD3; 16]).unwrap(),
        );
        let owner = dev_sender_address(&dev_signing_key(0xD3));
        let object = owned_object(ObjectId::new([0xD4; 32]), owner, 0x40);
        let object_ref = commit_owned_object(
            store.as_ref(),
            &setup_context,
            domain,
            object,
            "sunrise-test",
            1,
            0x41,
        );

        let transport = Arc::new(MemoryTransport::default());
        let config = config();
        let protocol_config = active_protocol_config(domain);
        let app = structured_app(
            Arc::clone(&store),
            transport,
            Arc::new(ManualClock::new(10_000)),
            protocol_config,
            config,
        );

        let response = app
            .oneshot(
                Request::get(query_object_path(object_ref.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
            .await
            .unwrap();
        match HttpObjectQueryResult::decode(&bytes).unwrap() {
            HttpObjectQueryResult::CurrentInline {
                object_id,
                digest,
                canonical_object_bytes,
                ..
            } => {
                assert_eq!(object_id, object_ref.id);
                assert_eq!(digest, object_ref.digest);
                let decoded = objects::decode_object(&canonical_object_bytes).unwrap();
                assert_eq!(decoded.id, object_ref.id);
            }
            other => panic!("expected current inline object, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn object_route_returns_retained_tombstone() {
        let fence = WriterFenceGeneration::new(3).unwrap();
        let store = Arc::new(MemoryDurableStateStore::new(fence));
        store.set_time(10_000);
        let domain = AtomicityDomainId::new([0xD5; 32]).unwrap();
        let setup_context = DurableOperationContext::new(
            fence,
            StorageDeadline::new(20_000).unwrap(),
            StorageCorrelationId::new([0xD5; 16]).unwrap(),
        );
        let owner = dev_sender_address(&dev_signing_key(0xD5));
        let object = owned_object(ObjectId::new([0xD6; 32]), owner, 0x42);
        let object_id = object.id;
        commit_owned_object(
            store.as_ref(),
            &setup_context,
            domain,
            object,
            "sunrise-test",
            1,
            0x43,
        );
        let current_head = store
            .get_object_head(&setup_context, domain, object_id)
            .unwrap();
        let changes = DurableObjectChanges::new(
            vec![DurableObjectHeadRead::new(object_id, current_head)],
            vec![DurableObjectMutationEntry::new(
                object_id,
                DurableObjectMutation::Delete,
            )],
        )
        .unwrap();
        let receipt = DurableRequestReceipt::new(
            DurableRequestId::new([0x44; 32]).unwrap(),
            Digest32::new(HashAlgorithmId::Sha2_256, [0x45; 32]),
            vec![0x46],
        )
        .unwrap();
        let invocation =
            DurableInvocationTransaction::new(domain, None, changes, receipt, None).unwrap();
        assert_eq!(
            store.commit_invocation(&setup_context, invocation),
            DurableCommitOutcome::Committed
        );

        let transport = Arc::new(MemoryTransport::default());
        let config = config();
        let protocol_config = active_protocol_config(domain);
        let app = structured_app(
            Arc::clone(&store),
            transport,
            Arc::new(ManualClock::new(10_000)),
            protocol_config,
            config,
        );

        let response = app
            .oneshot(
                Request::get(query_object_path(object_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
            .await
            .unwrap();
        assert_eq!(
            HttpObjectQueryResult::decode(&bytes).unwrap(),
            HttpObjectQueryResult::Tombstoned {
                object_id,
                head_revision: ObjectHeadRevision::new(2).unwrap(),
                last_object_version: DurableObjectVersion::FIRST,
            }
        );
    }

    #[tokio::test]
    async fn object_route_returns_current_blob_reference_without_fetching_body() {
        let fence = WriterFenceGeneration::new(3).unwrap();
        let store = Arc::new(MemoryDurableStateStore::new(fence));
        store.set_time(10_000);
        let domain = AtomicityDomainId::new([0xD7; 32]).unwrap();
        let setup_context = DurableOperationContext::new(
            fence,
            StorageDeadline::new(20_000).unwrap(),
            StorageCorrelationId::new([0xD7; 16]).unwrap(),
        );
        let object_id = ObjectId::new([0xD8; 32]);
        let digest = Digest32::new(HashAlgorithmId::Sha2_256, [0xD9; 32]);
        let blob_digest = Digest32::new(HashAlgorithmId::Sha3_256, [0xDA; 32]);
        let record = DurableObjectVersionRecord::from_blob_reference(
            object_id,
            DurableObjectVersion::FIRST,
            digest,
            1,
            DurableObjectProvenance::new(
                ChainId::new("sunrise-test").unwrap(),
                ProtocolVersion::new(3),
            ),
            1,
            blob_digest,
        );
        let owner = dev_sender_address(&dev_signing_key(0xDB));
        let changes = DurableObjectChanges::new(
            vec![DurableObjectHeadRead::new(
                object_id,
                DurableObjectHead::Absent,
            )],
            vec![DurableObjectMutationEntry::new(
                object_id,
                DurableObjectMutation::Create {
                    version: record,
                    owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(
                        owner,
                    ))
                    .unwrap(),
                    routing_projection: DurableObjectRoutingProjection::default(),
                },
            )],
        )
        .unwrap();
        let receipt = DurableRequestReceipt::new(
            DurableRequestId::new([0xDC; 32]).unwrap(),
            Digest32::new(HashAlgorithmId::Sha2_256, [0xDD; 32]),
            vec![0xDE],
        )
        .unwrap();
        let invocation =
            DurableInvocationTransaction::new(domain, None, changes, receipt, None).unwrap();
        assert_eq!(
            store.commit_invocation(&setup_context, invocation),
            DurableCommitOutcome::Committed
        );

        let transport = Arc::new(MemoryTransport::default());
        let config = config();
        let protocol_config = active_protocol_config(domain);
        let blob_store = Arc::new(CountingBlobStore::default());
        let app = structured_app_with_blob_store(
            Arc::clone(&store),
            Arc::clone(&blob_store),
            transport,
            Arc::new(ManualClock::new(10_000)),
            protocol_config,
            config,
        );

        let response = app
            .oneshot(
                Request::get(query_object_path(object_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
            .await
            .unwrap();
        assert_eq!(
            HttpObjectQueryResult::decode(&bytes).unwrap(),
            HttpObjectQueryResult::CurrentBlobReference {
                object_id,
                head_revision: ObjectHeadRevision::FIRST,
                object_version: DurableObjectVersion::FIRST,
                digest,
                blob_digest,
            }
        );
        assert_eq!(
            blob_store.get_calls(),
            0,
            "the query route must never fetch a blob body through the supplied blob store"
        );
    }

    #[tokio::test]
    async fn object_route_tampered_digest_is_opaque_server_error() {
        let fence = WriterFenceGeneration::new(3).unwrap();
        let store = Arc::new(MemoryDurableStateStore::new(fence));
        store.set_time(10_000);
        let domain = AtomicityDomainId::new([0xE1; 32]).unwrap();
        let setup_context = DurableOperationContext::new(
            fence,
            StorageDeadline::new(20_000).unwrap(),
            StorageCorrelationId::new([0xE1; 16]).unwrap(),
        );
        let owner = dev_sender_address(&dev_signing_key(0xE2));
        let object_id = ObjectId::new([0xE3; 32]);
        let object = owned_object(object_id, owner, 0x50);
        let canonical_bytes = encode_object(&object).unwrap();
        let tampered_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x00; 32]);
        let record = DurableObjectVersionRecord::from_inline_canonical_bytes(
            canonical_bytes,
            tampered_digest,
            DurableObjectProvenance::new(
                ChainId::new("sunrise-test").unwrap(),
                ProtocolVersion::new(3),
            ),
            1,
        )
        .unwrap();
        let changes = DurableObjectChanges::new(
            vec![DurableObjectHeadRead::new(
                object_id,
                DurableObjectHead::Absent,
            )],
            vec![DurableObjectMutationEntry::new(
                object_id,
                DurableObjectMutation::Create {
                    version: record,
                    owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(
                        owner,
                    ))
                    .unwrap(),
                    routing_projection: DurableObjectRoutingProjection::default(),
                },
            )],
        )
        .unwrap();
        let receipt = DurableRequestReceipt::new(
            DurableRequestId::new([0xE4; 32]).unwrap(),
            Digest32::new(HashAlgorithmId::Sha2_256, [0xE5; 32]),
            vec![0xE6],
        )
        .unwrap();
        let invocation =
            DurableInvocationTransaction::new(domain, None, changes, receipt, None).unwrap();
        assert_eq!(
            store.commit_invocation(&setup_context, invocation),
            DurableCommitOutcome::Committed
        );

        let transport = Arc::new(MemoryTransport::default());
        let config = config();
        let protocol_config = active_protocol_config(domain);
        let app = structured_app(
            Arc::clone(&store),
            transport,
            Arc::new(ManualClock::new(10_000)),
            protocol_config,
            config,
        );

        let response = app
            .oneshot(
                Request::get(query_object_path(object_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            to_bytes(response.into_body(), 128).await.unwrap(),
            "query-state-invalid"
        );
    }

    #[tokio::test]
    async fn object_route_writer_fence_mismatch_is_opaque_unavailable() {
        let authority_fence = WriterFenceGeneration::new(3).unwrap();
        // The store's own active fence differs from the authority's fence
        // that `structured_app` fixes via `structured_request_authority()`,
        // so the durable read proves `WriterFenced` rather than corruption.
        let store_fence = WriterFenceGeneration::new(9).unwrap();
        let store = Arc::new(MemoryDurableStateStore::new(store_fence));
        store.set_time(10_000);
        let transport = Arc::new(MemoryTransport::default());
        let config = config();
        let domain = AtomicityDomainId::new([0xF6; 32]).unwrap();
        let protocol_config = active_protocol_config(domain);
        let app = structured_app(
            store,
            transport,
            Arc::new(ManualClock::new(10_000)),
            protocol_config,
            config,
        );
        let _ = authority_fence;

        let response = app
            .oneshot(
                Request::get(query_object_path(ObjectId::new([0x01; 32])))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            to_bytes(response.into_body(), 128).await.unwrap(),
            "query-unavailable"
        );
    }

    #[tokio::test]
    async fn object_route_identity_unavailable_is_opaque_unavailable() {
        let fence = WriterFenceGeneration::new(3).unwrap();
        let store = Arc::new(MemoryDurableStateStore::new(fence));
        store.set_time(10_000);
        let transport = Arc::new(MemoryTransport::default());
        let config = config();
        let domain = AtomicityDomainId::new([0xF7; 32]).unwrap();
        let protocol_config = active_protocol_config(domain);
        let machine = Arc::new(IncrementMachine::new(config.state_key()));
        let app = structured_durable_router(
            StructuredDurableNativeComponents::new(
                store,
                Arc::new(MemoryBlobStore::default()),
                transport,
                Arc::new(ManualClock::new(10_000)),
                Arc::new(FailingIndexedIdentities {
                    error: IndexedOutboxIdentitySourceError::Unavailable,
                }),
            ),
            protocol_config,
            structured_request_authority(),
            config,
            resolver(),
            machine,
            NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
        )
        .unwrap();

        let response = app
            .oneshot(
                Request::get(query_object_path(ObjectId::new([0x01; 32])))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            to_bytes(response.into_body(), 128).await.unwrap(),
            "query-unavailable"
        );
    }

    #[tokio::test]
    async fn object_route_identity_exhausted_is_opaque_invalid() {
        let fence = WriterFenceGeneration::new(3).unwrap();
        let store = Arc::new(MemoryDurableStateStore::new(fence));
        store.set_time(10_000);
        let transport = Arc::new(MemoryTransport::default());
        let config = config();
        let domain = AtomicityDomainId::new([0xF9; 32]).unwrap();
        let protocol_config = active_protocol_config(domain);
        let machine = Arc::new(IncrementMachine::new(config.state_key()));
        let app = structured_durable_router(
            StructuredDurableNativeComponents::new(
                store,
                Arc::new(MemoryBlobStore::default()),
                transport,
                Arc::new(ManualClock::new(10_000)),
                Arc::new(FailingIndexedIdentities {
                    error: IndexedOutboxIdentitySourceError::Exhausted,
                }),
            ),
            protocol_config,
            structured_request_authority(),
            config,
            resolver(),
            machine,
            NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
        )
        .unwrap();

        let response = app
            .oneshot(
                Request::get(query_object_path(ObjectId::new([0x01; 32])))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            to_bytes(response.into_body(), 128).await.unwrap(),
            "query-state-invalid"
        );
    }

    #[tokio::test]
    async fn object_route_clock_failure_is_opaque_unavailable() {
        let fence = WriterFenceGeneration::new(3).unwrap();
        let store = Arc::new(MemoryDurableStateStore::new(fence));
        store.set_time(10_000);
        let transport = Arc::new(MemoryTransport::default());
        let config = config();
        let domain = AtomicityDomainId::new([0xFA; 32]).unwrap();
        let protocol_config = active_protocol_config(domain);
        let machine = Arc::new(IncrementMachine::new(config.state_key()));
        let app = structured_durable_router(
            StructuredDurableNativeComponents::new(
                store,
                Arc::new(MemoryBlobStore::default()),
                transport,
                Arc::new(FailingClock),
                Arc::new(SequenceIndexedIdentities::default()),
            ),
            protocol_config,
            structured_request_authority(),
            config,
            resolver(),
            machine,
            NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
        )
        .unwrap();

        let response = app
            .oneshot(
                Request::get(query_object_path(ObjectId::new([0x01; 32])))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            to_bytes(response.into_body(), 128).await.unwrap(),
            "query-unavailable"
        );
    }

    #[test]
    fn query_node_error_response_parts_classifies_durable_read_variants() {
        let cases: Vec<(NodeCoreError, StatusCode, &str)> = vec![
            (
                NodeCoreError::DurableRead(DurableReadError::WriterFenced {
                    active_generation: WriterFenceGeneration::new(3).unwrap(),
                }),
                StatusCode::SERVICE_UNAVAILABLE,
                "query-unavailable",
            ),
            (
                NodeCoreError::DurableRead(DurableReadError::DeadlineExceeded),
                StatusCode::SERVICE_UNAVAILABLE,
                "query-unavailable",
            ),
            (
                NodeCoreError::DurableRead(DurableReadError::Unavailable),
                StatusCode::SERVICE_UNAVAILABLE,
                "query-unavailable",
            ),
            // `SchemaMismatch` is an explicit decision (DR-0082): it proves an
            // adapter/deployment schema disagreement, not corrupted persisted
            // bytes, so it is grouped with the other availability conditions
            // rather than with `query-state-invalid`.
            (
                NodeCoreError::DurableRead(DurableReadError::SchemaMismatch),
                StatusCode::SERVICE_UNAVAILABLE,
                "query-unavailable",
            ),
            (
                NodeCoreError::DurableRead(DurableReadError::InvalidPersistedState),
                StatusCode::INTERNAL_SERVER_ERROR,
                "query-state-invalid",
            ),
            (
                NodeCoreError::DurableRead(DurableReadError::InvalidRequest(
                    RuntimeError::UnsupportedObjectStorage,
                )),
                StatusCode::INTERNAL_SERVER_ERROR,
                "query-state-invalid",
            ),
        ];
        for (error, expected_status, expected_code) in cases {
            let (status, code) = query_node_error_response_parts(&error);
            assert_eq!(status, expected_status, "error: {error:?}");
            assert_eq!(code, expected_code, "error: {error:?}");
        }
    }

    #[tokio::test]
    async fn object_route_rejects_inactive_domain_placement_before_any_side_effect() {
        let fence = WriterFenceGeneration::new(3).unwrap();
        let store = Arc::new(MemoryDurableStateStore::new(fence));
        store.set_time(10_000);
        let config = config();
        // `config()`'s epoch is 7; an activation epoch of 100 makes this
        // placement inactive at the trusted current epoch.
        let mut protocol_config =
            active_protocol_config(AtomicityDomainId::new([0xFB; 32]).unwrap());
        protocol_config.domain_placement = Some(placement(0xFB, 100));
        let clock = Arc::new(CountingClock::new(10_000));
        let identities = Arc::new(CountingIndexedIdentities::default());
        let machine = Arc::new(IncrementMachine::new(config.state_key()));
        let app = structured_durable_router(
            StructuredDurableNativeComponents::new(
                store,
                Arc::new(MemoryBlobStore::default()),
                Arc::new(MemoryTransport::default()),
                Arc::clone(&clock),
                Arc::clone(&identities),
            ),
            protocol_config,
            structured_request_authority(),
            config,
            resolver(),
            machine,
            NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
        )
        .unwrap();

        let response = app
            .oneshot(
                Request::get(query_object_path(ObjectId::new([0x01; 32])))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            to_bytes(response.into_body(), 128).await.unwrap(),
            "query-unavailable"
        );
        assert_eq!(clock.calls.load(Ordering::SeqCst), 0);
        assert_eq!(identities.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn receipt_route_returns_true_absence() {
        let fence = WriterFenceGeneration::new(3).unwrap();
        let store = Arc::new(MemoryDurableStateStore::new(fence));
        store.set_time(10_000);
        let transport = Arc::new(MemoryTransport::default());
        let config = config();
        let domain = AtomicityDomainId::new([0xE7; 32]).unwrap();
        let protocol_config = active_protocol_config(domain);
        let app = structured_app(
            store,
            transport,
            Arc::new(ManualClock::new(10_000)),
            protocol_config,
            config,
        );
        let id = request_id(0x01);

        let response = app
            .oneshot(
                Request::get(query_receipt_path(id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
            .await
            .unwrap();
        assert_eq!(
            HttpReceiptQueryResult::decode(&bytes).unwrap(),
            HttpReceiptQueryResult::Absent { request_id: id }
        );
    }

    #[tokio::test]
    async fn receipt_route_corrupt_receipt_is_opaque_server_error() {
        let fence = WriterFenceGeneration::new(3).unwrap();
        let store = Arc::new(MemoryDurableStateStore::new(fence));
        store.set_time(10_000);
        let domain = AtomicityDomainId::new([0xE9; 32]).unwrap();
        let setup_context = DurableOperationContext::new(
            fence,
            StorageDeadline::new(20_000).unwrap(),
            StorageCorrelationId::new([0xE9; 16]).unwrap(),
        );
        let id = request_id(0x02);
        let receipt = DurableRequestReceipt::new(
            DurableRequestId::new(*id.as_bytes()).unwrap(),
            Digest32::new(HashAlgorithmId::Sha2_256, [0xEA; 32]),
            vec![0xEB, 0x00],
        )
        .unwrap();
        let invocation = DurableInvocationTransaction::new(
            domain,
            None,
            DurableObjectChanges::empty(),
            receipt,
            None,
        )
        .unwrap();
        assert_eq!(
            store.commit_invocation(&setup_context, invocation),
            DurableCommitOutcome::Committed
        );

        let transport = Arc::new(MemoryTransport::default());
        let config = config();
        let protocol_config = active_protocol_config(domain);
        let app = structured_app(
            Arc::clone(&store),
            transport,
            Arc::new(ManualClock::new(10_000)),
            protocol_config,
            config,
        );

        let response = app
            .oneshot(
                Request::get(query_receipt_path(id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            to_bytes(response.into_body(), 128).await.unwrap(),
            "query-state-invalid"
        );
    }

    #[tokio::test]
    async fn receipt_and_next_nonce_routes_reflect_a_real_submission() {
        let fence = WriterFenceGeneration::new(3).unwrap();
        let store = Arc::new(MemoryDurableStateStore::new(fence));
        store.set_time(10_000);
        let transport = Arc::new(MemoryTransport::default());
        let config = config();
        let domain = AtomicityDomainId::new([0xE8; 32]).unwrap();
        let protocol_config = active_protocol_config(domain);
        let app = structured_app(
            Arc::clone(&store),
            transport,
            Arc::new(ManualClock::new(10_000)),
            protocol_config,
            config,
        );
        let signing_key = dev_signing_key(0xE9);
        let sender = dev_sender_address(&signing_key);
        let id = request_id(0xEA);
        let event = signed_submit_transaction_event(&signing_key, id, 0);

        let submit_response = app
            .clone()
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(event.encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(submit_response.status(), StatusCode::OK);

        let receipt_response = app
            .clone()
            .oneshot(
                Request::get(query_receipt_path(id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(receipt_response.status(), StatusCode::OK);
        let receipt_bytes = to_bytes(receipt_response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
            .await
            .unwrap();
        match HttpReceiptQueryResult::decode(&receipt_bytes).unwrap() {
            HttpReceiptQueryResult::Present {
                request_id,
                dedup_record_bytes,
                ..
            } => {
                assert_eq!(request_id, id);
                let record = NodeDedupRecord::decode(&dedup_record_bytes).unwrap();
                assert_eq!(record.request_id(), id);
            }
            other => panic!("expected present receipt, got {other:?}"),
        }

        let nonce_response = app
            .oneshot(
                Request::get(query_next_nonce_path(&sender))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(nonce_response.status(), StatusCode::OK);
        let nonce_bytes = to_bytes(nonce_response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
            .await
            .unwrap();
        let nonce_result = HttpNextNonceQueryResult::decode(&nonce_bytes).unwrap();
        assert_eq!(nonce_result.sender(), sender);
        assert_eq!(nonce_result.epoch(), Epoch::new(7));
        assert_eq!(nonce_result.next_nonce(), 1);
    }

    #[tokio::test]
    async fn next_nonce_route_true_absence_returns_zero() {
        let fence = WriterFenceGeneration::new(3).unwrap();
        let store = Arc::new(MemoryDurableStateStore::new(fence));
        store.set_time(10_000);
        let transport = Arc::new(MemoryTransport::default());
        let config = config();
        let domain = AtomicityDomainId::new([0xEB; 32]).unwrap();
        let protocol_config = active_protocol_config(domain);
        let app = structured_app(
            store,
            transport,
            Arc::new(ManualClock::new(10_000)),
            protocol_config,
            config,
        );
        let sender = Address::new([0x01; 32]);

        let response = app
            .oneshot(
                Request::get(query_next_nonce_path(&sender))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
            .await
            .unwrap();
        let result = HttpNextNonceQueryResult::decode(&bytes).unwrap();
        assert_eq!(result.sender(), sender);
        assert_eq!(result.next_nonce(), 0);
        assert_eq!(result.epoch(), Epoch::new(7));
    }

    #[tokio::test]
    async fn next_nonce_route_deleted_record_is_opaque_server_error() {
        let fence = WriterFenceGeneration::new(3).unwrap();
        let store = Arc::new(MemoryDurableStateStore::new(fence));
        store.set_time(10_000);
        let domain = AtomicityDomainId::new([0xEC; 32]).unwrap();
        let setup_context = DurableOperationContext::new(
            fence,
            StorageDeadline::new(20_000).unwrap(),
            StorageCorrelationId::new([0xEC; 16]).unwrap(),
        );
        let sender = [0x02; 32];
        let key = PersistenceLayout::new(
            ChainId::new("sunrise-test").unwrap(),
            ProtocolVersion::new(3),
        )
        .sender_nonce_key(sender, Epoch::new(7));
        let transaction = AtomicStateTransaction::new(
            domain,
            AtomicStateReadSet::new(vec![
                StateReadAssertion::new(key.clone(), StateRevision::INITIAL).unwrap(),
            ])
            .unwrap(),
            AtomicStateMutationSet::new(vec![
                StateMutationEntry::new(key, StateMutation::Delete).unwrap(),
            ])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            store.commit_durable(&setup_context, transaction),
            DurableCommitOutcome::Committed
        );

        let transport = Arc::new(MemoryTransport::default());
        let config = config();
        let protocol_config = active_protocol_config(domain);
        let app = structured_app(
            Arc::clone(&store),
            transport,
            Arc::new(ManualClock::new(10_000)),
            protocol_config,
            config,
        );

        let response = app
            .oneshot(
                Request::get(query_next_nonce_path(&Address::new(sender)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            to_bytes(response.into_body(), 128).await.unwrap(),
            "query-state-invalid"
        );
    }

    #[tokio::test]
    async fn query_routes_reject_malformed_selectors_before_any_side_effect() {
        let fence = WriterFenceGeneration::new(3).unwrap();
        let store = Arc::new(MemoryDurableStateStore::new(fence));
        store.set_time(10_000);
        let transport = Arc::new(MemoryTransport::default());
        let config = config();
        let domain = AtomicityDomainId::new([0xED; 32]).unwrap();
        let protocol_config = active_protocol_config(domain);
        let clock = Arc::new(CountingClock::new(10_000));
        let identities = Arc::new(CountingIndexedIdentities::default());
        let machine = Arc::new(IncrementMachine::new(config.state_key()));
        let app = structured_durable_router(
            StructuredDurableNativeComponents::new(
                Arc::clone(&store),
                Arc::new(MemoryBlobStore::default()),
                transport,
                Arc::clone(&clock),
                Arc::clone(&identities),
            ),
            protocol_config,
            structured_request_authority(),
            config,
            resolver(),
            machine,
            NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
        )
        .unwrap();

        let malformed_paths: Vec<String> = vec![
            "/v1/objects/too-short".to_string(),
            format!("/v1/objects/{}", "A".repeat(64)),
            format!("/v1/receipts/{}", "0".repeat(64)),
            format!("/v1/receipts/{}", "g".repeat(64)),
            "/v1/senders/short/next-nonce".to_string(),
        ];
        for path in malformed_paths {
            let response = app
                .clone()
                .oneshot(Request::get(path.as_str()).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "path: {path}");
        }

        assert_eq!(clock.calls.load(Ordering::SeqCst), 0);
        assert_eq!(identities.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn both_routers_return_identical_results_for_all_four_query_routes() {
        let fence = WriterFenceGeneration::new(3).unwrap();
        let store = Arc::new(MemoryDurableStateStore::new(fence));
        store.set_time(10_000);
        let domain = AtomicityDomainId::new([0xEE; 32]).unwrap();
        let config = config();
        let protocol_config = active_protocol_config(domain);
        let catalog = Arc::new(PreinstalledModuleCatalog::new(Vec::new()).unwrap());

        // Populate one verified current-inline object and one present receipt
        // so parity is checked against real content, not only absence.
        // Tombstone and blob-reference results are covered by dedicated
        // structured-router tests and need not be duplicated here.
        let setup_context = DurableOperationContext::new(
            fence,
            StorageDeadline::new(20_000).unwrap(),
            StorageCorrelationId::new([0xEE; 16]).unwrap(),
        );
        let owner = dev_sender_address(&dev_signing_key(0xEE));
        let object = owned_object(ObjectId::new([0xEF; 32]), owner, 0x46);
        let object_ref = commit_owned_object(
            store.as_ref(),
            &setup_context,
            domain,
            object,
            "sunrise-test",
            1,
            0x47,
        );

        let structured = structured_app(
            Arc::clone(&store),
            Arc::new(MemoryTransport::default()),
            Arc::new(ManualClock::new(10_000)),
            protocol_config.clone(),
            config.clone(),
        );
        let preinstalled = preinstalled_app(
            Arc::clone(&store),
            Arc::new(MemoryTransport::default()),
            Arc::new(ManualClock::new(10_000)),
            protocol_config,
            config,
            catalog,
            9,
        );

        let populated_object_path: String = query_object_path(object_ref.id);
        let populated_receipt_path: String = query_receipt_path(request_id(0x47));
        let paths: [String; 6] = [
            QUERY_CONTEXT_PATH.to_string(),
            query_object_path(ObjectId::new([0x01; 32])),
            populated_object_path.clone(),
            query_receipt_path(request_id(0x02)),
            populated_receipt_path.clone(),
            query_next_nonce_path(&Address::new([0x03; 32])),
        ];
        for path in paths {
            let structured_response = structured
                .clone()
                .oneshot(Request::get(path.as_str()).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let preinstalled_response = preinstalled
                .clone()
                .oneshot(Request::get(path.as_str()).body(Body::empty()).unwrap())
                .await
                .unwrap();

            assert_eq!(
                structured_response.status(),
                preinstalled_response.status(),
                "path: {path}"
            );
            assert_eq!(
                structured_response.headers().get(header::CONTENT_TYPE),
                preinstalled_response.headers().get(header::CONTENT_TYPE),
                "path: {path}"
            );
            assert_eq!(
                structured_response.headers().get(header::CACHE_CONTROL),
                preinstalled_response.headers().get(header::CACHE_CONTROL),
                "path: {path}"
            );
            let structured_bytes =
                to_bytes(structured_response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
                    .await
                    .unwrap();
            let preinstalled_bytes =
                to_bytes(preinstalled_response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
                    .await
                    .unwrap();
            assert_eq!(structured_bytes, preinstalled_bytes, "path: {path}");
            if path == populated_object_path {
                assert!(matches!(
                    HttpObjectQueryResult::decode(&structured_bytes).unwrap(),
                    HttpObjectQueryResult::CurrentInline { .. }
                ));
            } else if path == populated_receipt_path {
                assert!(matches!(
                    HttpReceiptQueryResult::decode(&structured_bytes).unwrap(),
                    HttpReceiptQueryResult::Present { .. }
                ));
            }
        }
    }

    #[tokio::test]
    async fn object_route_admission_rejects_when_blocking_capacity_exhausted() {
        let fence = WriterFenceGeneration::new(3).unwrap();
        let store = Arc::new(MemoryDurableStateStore::new(fence));
        store.set_time(10_000);
        let transport = Arc::new(MemoryTransport::default());
        let config = config();
        let domain = AtomicityDomainId::new([0xEF; 32]).unwrap();
        let protocol_config = active_protocol_config(domain);
        let blocking_executor =
            NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(1).unwrap()));
        let machine = Arc::new(IncrementMachine::new(config.state_key()));
        let app = structured_durable_router_with_executor(
            StructuredDurableNativeComponents::new(
                store,
                Arc::new(MemoryBlobStore::default()),
                transport,
                Arc::new(ManualClock::new(10_000)),
                Arc::new(SequenceIndexedIdentities::default()),
            ),
            protocol_config,
            structured_request_authority(),
            config,
            resolver(),
            machine,
            blocking_executor.clone(),
        )
        .unwrap();
        let held_permit = blocking_executor.try_acquire().unwrap();

        let response = app
            .oneshot(
                Request::get(query_object_path(ObjectId::new([0x01; 32])))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        drop(held_permit);
    }

    #[tokio::test]
    async fn object_route_rejects_cancellation_at_each_pre_storage_checkpoint() {
        for cancel_at_call in 1_usize..=3_usize {
            let fence = WriterFenceGeneration::new(3).unwrap();
            let store = Arc::new(MemoryDurableStateStore::new(fence));
            store.set_time(10_000);
            let transport = Arc::new(MemoryTransport::default());
            let clock = Arc::new(ManualClock::new(10_000));
            let config = config();
            let domain = AtomicityDomainId::new([0xF5; 32]).unwrap();
            let protocol_config = active_protocol_config(domain);
            let cancellation: Arc<StepCancellation> =
                Arc::new(StepCancellation::new(cancel_at_call));
            let app = structured_app_with_cancellation(
                store,
                transport,
                clock,
                protocol_config,
                config,
                cancellation.clone(),
            );

            let response = app
                .oneshot(
                    Request::get(query_object_path(ObjectId::new([0x01; 32])))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(
                to_bytes(response.into_body(), 128).await.unwrap(),
                "invocation-cancelled-before-storage"
            );
            assert_eq!(cancellation.calls(), cancel_at_call);
        }
    }
}
