#![forbid(unsafe_code)]

//! Native HTTP adapter for the runtime-neutral node-core boundary.
//!
//! This crate owns HTTP routing and status mapping. It does not add HTTP types
//! to protocol crates, and it accepts only canonical binary node events.

use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State, rejection::BytesRejection},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use canonical_encoding::{
    CanonicalDecodingError, CanonicalEncodingError, CanonicalStruct, decode_canonical_frame,
};
use core::fmt;
use hashing::HashSuiteResolver;
use node_core::{
    AuthenticatedSubmitTransaction, MAX_NODE_OUTPUT_ITEMS, MAX_NODE_PAYLOAD_BYTES, NodeConfig,
    NodeCoreError, NodeEvent, NodeEventKind, NodeOutboxBatch, NodeOutboxDelivery, NodeResponse,
    OutboxClaim, OutboxLeaseId, RequestId, TransactionAuthError, TransactionalNodeStateMachine,
    acknowledge_outbox_message, acknowledge_outbox_message_in_domain,
    authenticate_submit_transaction_event, claim_next_outbox_message,
    claim_next_outbox_message_in_domain, handle_authenticated_resolved_durable_submit_transaction,
    handle_idempotent_event, handle_resolved_durable_idempotent_event,
    handle_resolved_idempotent_event,
};
use protocol_config::{DomainPlacementManifest, ProtocolConfig, ProtocolConfigError};
use protocol_types::ProtocolVersion;
use runtime::{
    AtomicityDomainId, Clock, DomainTransactionalStateStore, DueOutboxClaimRequest,
    DurableOperationContext, DurableOutboxAcknowledgement, DurableOutboxAcknowledgementOutcome,
    DurableOutboxAcknowledgementRejection, DurableOutboxClaimOutcome, DurableOutboxClaimRejection,
    DurableOutboxLeaseId, IndeterminateCommitReason, IndexedOutboxContractError,
    IndexedOutboxRepository, InvocationCancellation, MAX_DURABLE_OUTBOX_LEASE_MILLIS,
    OutboxRequestId, PersistenceLayout, RequestOutboxClaimRequest, Runtime, RuntimeError,
    StateKeyScan, StateKeyScanner, StorageCorrelationId, StorageDeadline, TransactionalStateStore,
    Transport, WriterFenceGeneration,
};
use std::{
    error::Error,
    future::Future,
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
};
use tokio::sync::{Semaphore, TryAcquireError};

const HTTP_RESULT_TYPE_ID: u16 = 0xE101;
const HTTP_RESULT_ENCODING_VERSION: u16 = 1;

/// Versioned media type accepted by the event endpoint.
pub const NODE_EVENT_MEDIA_TYPE: &str = "application/vnd.sunrise-edge.node-event";
/// Versioned media type returned for a successful invocation.
pub const NODE_RESULT_MEDIA_TYPE: &str = "application/vnd.sunrise-edge.node-result";
/// Native route that accepts one canonical node event.
pub const NODE_EVENT_PATH: &str = "/v1/events";
/// Liveness route. It intentionally performs no storage or protocol checks.
pub const LIVENESS_PATH: &str = "/health/live";
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
pub struct StructuredDurableNativeComponents<S, T, C, I> {
    store: Arc<S>,
    transport: Arc<T>,
    clock: Arc<C>,
    identities: Arc<I>,
    cancellation: Option<Arc<dyn InvocationCancellation>>,
}

impl<S, T, C, I> StructuredDurableNativeComponents<S, T, C, I> {
    /// Creates a composition that never cancels before storage dispatch.
    ///
    /// Existing compositions retain their original behavior. Use
    /// [`Self::with_cancellation`] when the host has an explicit trusted signal.
    #[must_use]
    pub const fn new(store: Arc<S>, transport: Arc<T>, clock: Arc<C>, identities: Arc<I>) -> Self {
        Self {
            store,
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
        transport: Arc<T>,
        clock: Arc<C>,
        identities: Arc<I>,
        cancellation: Arc<dyn InvocationCancellation>,
    ) -> Self {
        Self {
            store,
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

/// Errors in the canonical HTTP result contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpContractError {
    /// Canonical encoding failed.
    CanonicalEncoding(CanonicalEncodingError),
    /// Canonical decoding failed.
    CanonicalDecoding(CanonicalDecodingError),
    /// A nested node response failed validation.
    NodeCore(NodeCoreError),
    /// A result carried more responses than one invocation allows.
    TooManyResponses(usize),
    /// A response belonged to another request.
    RequestMismatch {
        /// Result request identifier.
        expected: RequestId,
        /// Nested response request identifier.
        actual: RequestId,
    },
    /// A request identifier had the wrong length.
    InvalidRequestIdLength(usize),
    /// The response-list bytes ended early.
    TruncatedResponseList,
    /// The response list contained trailing bytes.
    TrailingResponseListBytes(usize),
    /// A nested response length could not be represented safely.
    ResponseLengthOverflow(usize),
}

impl fmt::Display for HttpContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CanonicalEncoding(error) => write!(f, "canonical encoding failed: {error}"),
            Self::CanonicalDecoding(error) => write!(f, "canonical decoding failed: {error}"),
            Self::NodeCore(error) => write!(f, "node response validation failed: {error}"),
            Self::TooManyResponses(count) => write!(
                f,
                "HTTP result has {count} responses, maximum is {MAX_NODE_OUTPUT_ITEMS}"
            ),
            Self::RequestMismatch { expected, actual } => write!(
                f,
                "HTTP result response mismatch: expected {expected}, got {actual}"
            ),
            Self::InvalidRequestIdLength(length) => {
                write!(f, "HTTP result request id is {length} bytes, expected 32")
            }
            Self::TruncatedResponseList => f.write_str("HTTP result response list is truncated"),
            Self::TrailingResponseListBytes(length) => {
                write!(f, "HTTP result response list has {length} trailing bytes")
            }
            Self::ResponseLengthOverflow(length) => {
                write!(
                    f,
                    "HTTP result response is too large to frame: {length} bytes"
                )
            }
        }
    }
}

impl Error for HttpContractError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CanonicalEncoding(error) => Some(error),
            Self::CanonicalDecoding(error) => Some(error),
            Self::NodeCore(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CanonicalEncodingError> for HttpContractError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(value)
    }
}

impl From<CanonicalDecodingError> for HttpContractError {
    fn from(value: CanonicalDecodingError) -> Self {
        Self::CanonicalDecoding(value)
    }
}

impl From<NodeCoreError> for HttpContractError {
    fn from(value: NodeCoreError) -> Self {
        Self::NodeCore(value)
    }
}

/// Canonical success body shared by native and future edge HTTP adapters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpNodeResult {
    request_id: RequestId,
    responses: Vec<NodeResponse>,
}

impl HttpNodeResult {
    /// Creates a bounded result whose responses all match the request.
    pub fn new(
        request_id: RequestId,
        responses: Vec<NodeResponse>,
    ) -> Result<Self, HttpContractError> {
        if responses.len() > MAX_NODE_OUTPUT_ITEMS {
            return Err(HttpContractError::TooManyResponses(responses.len()));
        }
        for response in &responses {
            if response.request_id() != request_id {
                return Err(HttpContractError::RequestMismatch {
                    expected: request_id,
                    actual: response.request_id(),
                });
            }
        }
        Ok(Self {
            request_id,
            responses,
        })
    }

    /// Returns the request identifier.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Returns responses in deterministic transition order.
    #[must_use]
    pub fn responses(&self) -> &[NodeResponse] {
        &self.responses
    }

    /// Encodes the complete HTTP success body.
    pub fn encode(&self) -> Result<Vec<u8>, HttpContractError> {
        let mut response_list = Vec::new();
        for response in &self.responses {
            let encoded = response.encode()?;
            let length = u32::try_from(encoded.len())
                .map_err(|_| HttpContractError::ResponseLengthOverflow(encoded.len()))?;
            response_list.extend_from_slice(&length.to_le_bytes());
            response_list.extend_from_slice(&encoded);
        }

        let count = u32::try_from(self.responses.len())
            .map_err(|_| HttpContractError::TooManyResponses(self.responses.len()))?;
        let mut frame = CanonicalStruct::new(HTTP_RESULT_TYPE_ID, HTTP_RESULT_ENCODING_VERSION);
        frame.field_bytes(1, self.request_id.as_bytes().to_vec())?;
        frame.field_u32(2, count)?;
        frame.field_bytes(3, response_list)?;
        Ok(frame.finish()?)
    }

    /// Decodes a complete HTTP success body and all nested responses.
    pub fn decode(bytes: &[u8]) -> Result<Self, HttpContractError> {
        let frame = decode_canonical_frame(bytes)?;
        frame.require_type(HTTP_RESULT_TYPE_ID)?;
        frame.require_version(HTTP_RESULT_ENCODING_VERSION)?;
        frame.require_only_fields(&[1, 2, 3])?;

        let request_bytes = frame.required_field(1)?;
        let request_array: [u8; 32] = request_bytes
            .try_into()
            .map_err(|_| HttpContractError::InvalidRequestIdLength(request_bytes.len()))?;
        let request_id = RequestId::new(request_array)?;
        let count = usize::try_from(frame.required_u32(2)?)
            .map_err(|_| HttpContractError::TooManyResponses(usize::MAX))?;
        if count > MAX_NODE_OUTPUT_ITEMS {
            return Err(HttpContractError::TooManyResponses(count));
        }

        let list = frame.required_field(3)?;
        let mut offset = 0_usize;
        let mut responses = Vec::with_capacity(count);
        for _ in 0..count {
            let length_bytes = take_list_bytes(list, &mut offset, 4)?;
            let length = usize::try_from(u32::from_le_bytes([
                length_bytes[0],
                length_bytes[1],
                length_bytes[2],
                length_bytes[3],
            ]))
            .map_err(|_| HttpContractError::ResponseLengthOverflow(usize::MAX))?;
            let encoded = take_list_bytes(list, &mut offset, length)?;
            responses.push(NodeResponse::decode(encoded)?);
        }
        if offset != list.len() {
            return Err(HttpContractError::TrailingResponseListBytes(
                list.len() - offset,
            ));
        }
        Self::new(request_id, responses)
    }
}

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

struct StructuredDurableNativeHttpState<S, M, T, C, I> {
    components: StructuredDurableNativeComponents<S, T, C, I>,
    protocol_config: ProtocolConfig,
    authority: StructuredDurableRequestAuthority,
    config: NodeConfig,
    resolver: HashSuiteResolver,
    machine: Arc<M>,
    blocking_executor: NativeBlockingExecutor,
}

type SharedStructuredDurableNativeHttpState<S, M, T, C, I> =
    Arc<StructuredDurableNativeHttpState<S, M, T, C, I>>;

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
pub fn structured_durable_router<S, M, T, C, I>(
    components: StructuredDurableNativeComponents<S, T, C, I>,
    protocol_config: ProtocolConfig,
    authority: StructuredDurableRequestAuthority,
    config: NodeConfig,
    resolver: HashSuiteResolver,
    machine: Arc<M>,
    blocking_policy: NativeBlockingPolicy,
) -> Result<Router, StructuredDurableRouterError>
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
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
pub fn structured_durable_router_with_executor<S, M, T, C, I>(
    components: StructuredDurableNativeComponents<S, T, C, I>,
    protocol_config: ProtocolConfig,
    authority: StructuredDurableRequestAuthority,
    config: NodeConfig,
    resolver: HashSuiteResolver,
    machine: Arc<M>,
    blocking_executor: NativeBlockingExecutor,
) -> Result<Router, StructuredDurableRouterError>
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    T: Transport + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
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
            post(submit_structured_durable_event::<S, M, T, C, I>),
        )
        .layer(DefaultBodyLimit::max(MAX_HTTP_EVENT_BODY_BYTES))
        .with_state(state))
}

/// Serves a configured native router until the shutdown future completes.
///
/// Build `app` with [`router`] or [`structured_durable_router`] so the blocking
/// admission policy is explicit at the composition boundary.
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

async fn submit_structured_durable_event<S, M, T, C, I>(
    State(state): State<SharedStructuredDurableNativeHttpState<S, M, T, C, I>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    T: Transport + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
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
    if state.components.is_cancelled() {
        return cancelled_before_storage_response();
    }
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
        invoke_structured_durable_event(blocking_state.as_ref(), &body)
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

enum InvocationError {
    CancelledBeforeStorage,
    Node(NodeCoreError),
    Delivery(OutboxDeliveryError),
    Indexed(IndexedOutboxRecoveryError),
    ResultEncoding,
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

fn invoke_structured_durable_event<S, M, T, C, I>(
    state: &StructuredDurableNativeHttpState<S, M, T, C, I>,
    body: &[u8],
) -> Result<Vec<u8>, InvocationError>
where
    S: IndexedOutboxRepository,
    M: TransactionalNodeStateMachine,
    T: Transport,
    C: Clock,
    I: IndexedOutboxIdentitySource,
{
    if state.components.is_cancelled() {
        return Err(InvocationError::CancelledBeforeStorage);
    }
    let event = NodeEvent::decode(body).map_err(InvocationError::Node)?;
    validate_native_event_context(&event, &state.config).map_err(InvocationError::Node)?;
    let request_id = event.request_id();
    enum PreparedStructuredEvent {
        Authenticated(Box<AuthenticatedSubmitTransaction>),
        Generic(NodeEvent),
    }
    let prepared_event: PreparedStructuredEvent =
        if event.kind() == NodeEventKind::SubmitTransaction {
            PreparedStructuredEvent::Authenticated(Box::new(
                authenticate_submit_transaction_event(event, &state.config, &state.protocol_config)
                    .map_err(InvocationError::Node)?,
            ))
        } else {
            PreparedStructuredEvent::Generic(event)
        };
    let placement: &DomainPlacementManifest = state
        .protocol_config
        .domain_placement
        .as_ref()
        .ok_or(ProtocolConfigError::MissingDomainPlacement)
        .map_err(NodeCoreError::from)
        .map_err(InvocationError::Node)?;
    let identity = state
        .components
        .identities
        .next_attempt_identity()
        .map_err(|error| InvocationError::Indexed(IndexedOutboxRecoveryError::Identity(error)))?;
    let now_unix_millis =
        state.components.clock.now_unix_millis().map_err(|error| {
            InvocationError::Indexed(IndexedOutboxRecoveryError::Runtime(error))
        })?;
    let deadline_unix_millis = now_unix_millis
        .checked_add(state.authority.operation_timeout_millis.get())
        .ok_or(InvocationError::Indexed(
            IndexedOutboxRecoveryError::TimeOverflow,
        ))?;
    let lease_expires_at_unix_millis = now_unix_millis
        .checked_add(state.authority.lease_duration_millis.get())
        .ok_or(InvocationError::Indexed(
            IndexedOutboxRecoveryError::TimeOverflow,
        ))?;
    let deadline = StorageDeadline::new(deadline_unix_millis).ok_or(InvocationError::Indexed(
        IndexedOutboxRecoveryError::TimeOverflow,
    ))?;
    let context = DurableOperationContext::new(
        state.authority.writer_fence,
        deadline,
        identity.correlation_id,
    );
    if state.components.is_cancelled() {
        return Err(InvocationError::CancelledBeforeStorage);
    }
    let resolved = match prepared_event {
        PreparedStructuredEvent::Authenticated(submission) => {
            handle_authenticated_resolved_durable_submit_transaction(
                state.components.store.as_ref(),
                &context,
                &state.resolver,
                *submission,
                state.machine.as_ref(),
            )
        }
        PreparedStructuredEvent::Generic(event) => handle_resolved_durable_idempotent_event(
            state.components.store.as_ref(),
            &context,
            placement,
            &state.config,
            &state.resolver,
            event,
            state.machine.as_ref(),
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
    let claim =
        reconcile_request_outbox_claim(state.components.store.as_ref(), &context, claim_request)
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
        validate_native_event_context(&outbound, &state.config)
            .map_err(|error| InvocationError::Indexed(IndexedOutboxRecoveryError::Node(error)))?;
        let canonical_payload = outbound
            .encode()
            .map_err(|error| InvocationError::Indexed(IndexedOutboxRecoveryError::Node(error)))?;
        if canonical_payload != claim.canonical_payload() {
            return Err(InvocationError::Indexed(IndexedOutboxRecoveryError::Node(
                NodeCoreError::PersistenceInvariant("request outbox payload is not canonical"),
            )));
        }
        state
            .components
            .transport
            .send(canonical_payload)
            .map_err(|_| InvocationError::Indexed(IndexedOutboxRecoveryError::Send))?;
        let acknowledgement = DurableOutboxAcknowledgement::new(
            resolved.domain(),
            claim.request_id(),
            claim.message_index(),
            claim.lease_id(),
        );
        reconcile_indexed_acknowledgement(
            state.components.store.as_ref(),
            &context,
            acknowledgement,
        )
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
        NodeCoreError::ObjectBodyUnavailable { .. } => {
            (StatusCode::NOT_IMPLEMENTED, "object-blob-body-unsupported")
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
        NodeCoreError::ObjectRecordMissing { .. }
        | NodeCoreError::ObjectRecordMismatch { .. }
        | NodeCoreError::ObjectBodyDigestMismatch { .. }
        | NodeCoreError::ObjectProvenanceMismatch { .. } => {
            (StatusCode::INTERNAL_SERVER_ERROR, "invalid-node-output")
        }
        NodeCoreError::ObjectDigestUnverifiable { .. } => (
            StatusCode::NOT_IMPLEMENTED,
            "object-digest-algorithm-unsupported",
        ),
        NodeCoreError::ObjectBodyTooLarge { .. } => {
            (StatusCode::UNPROCESSABLE_ENTITY, "object-body-too-large")
        }
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

fn take_list_bytes<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    length: usize,
) -> Result<&'a [u8], HttpContractError> {
    let end = offset
        .checked_add(length)
        .ok_or(HttpContractError::TruncatedResponseList)?;
    let value = bytes
        .get(*offset..end)
        .ok_or(HttpContractError::TruncatedResponseList)?;
    *offset = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::AccessManifest;
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use canonical_encoding::CanonicalStruct;
    use crypto::{SignatureDomain, SignatureMessageType};
    use execution::{
        Transaction, decode_transaction, encode_transaction, encode_transaction_signable,
    };
    use node_core::{
        NodeOutboxDelivery, NodeOutput, NodeResponseStatus, NodeStateAccess, NodeStateAccessMode,
        NodeStateAccessPlan, NodeStateSnapshot, NodeStateUpdate, OutboundMessage,
        TransactionalNodeTransition,
    };
    use objects::{AccessMode, Address, ObjectId, ObjectRef};
    use protocol_config::TransactionAuthProfile;
    use protocol_types::{
        ChainId, Digest32, Epoch, HashAlgorithmId, HashSuite, HashSuiteSchedule, ProtocolVersion,
        SignatureSchemeId, ValidatorId,
    };
    use runtime::{
        AtomicStateTransaction, CompareAndSwapResult, ComposedRuntime, DurableCommitOutcome,
        DurableCommitRejection, DurableDomainStateStore, DurableInvocationTransaction,
        DurableOutboxClaim, DurableReadError, DurableRequestId, DurableRequestReceipt,
        IndexedOutboxRepository, ManualClock, MemoryBlobStore, MemoryDurableStateStore,
        MemoryRuntime, MemoryScheduler, MemorySigner, MemoryStateStore, MemoryTransport,
        OutboxRequestId, RequestOutboxClaimRequest, RuntimeError, StateStore,
        StructuredDurableDomainStateStore, TransactionalStateStore, VersionedStateValue,
    };
    use runtime_sqlite::SqliteStateStore;
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

    /// A generic, non-transaction event used by tests that exercise dedup,
    /// outbox, cancellation, and commit machinery independently of
    /// transaction authentication. `ReceiveVote` is an arbitrary non-
    /// `SubmitTransaction` kind: every route processes it through the same
    /// generic [`TransactionalNodeStateMachine`] path `SubmitTransaction`
    /// used before this change, so it keeps that coverage intact while
    /// `SubmitTransaction` itself now carries a real signed transaction (see
    /// [`signed_submit_transaction_event`]).
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
            }
        }
    }

    impl StateStore for ScriptedIndexedStore {
        fn get(&self, _key: &[u8]) -> Result<Option<Vec<u8>>, RuntimeError> {
            Err(RuntimeError::DurableStoreUnavailable)
        }

        fn put(&self, _key: Vec<u8>, _value: Vec<u8>) -> Result<(), RuntimeError> {
            Err(RuntimeError::DurableStoreUnavailable)
        }

        fn compare_and_swap(
            &self,
            _key: Vec<u8>,
            _expected: Option<Vec<u8>>,
            _new_value: Vec<u8>,
        ) -> Result<CompareAndSwapResult, RuntimeError> {
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
            Err(DurableReadError::Unavailable)
        }

        fn commit_durable(
            &self,
            _context: &DurableOperationContext,
            _transaction: AtomicStateTransaction,
        ) -> DurableCommitOutcome {
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
            Err(DurableReadError::Unavailable)
        }

        fn commit_invocation(
            &self,
            _context: &DurableOperationContext,
            _transaction: DurableInvocationTransaction,
        ) -> DurableCommitOutcome {
            DurableCommitOutcome::Rejected(DurableCommitRejection::UnavailableBeforeCommit)
        }
    }

    impl IndexedOutboxRepository for ScriptedIndexedStore {
        fn claim_request_outbox(
            &self,
            _context: &DurableOperationContext,
            _request: RequestOutboxClaimRequest,
        ) -> DurableOutboxClaimOutcome {
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
            StructuredDurableNativeComponents::new(store, transport, clock, identities),
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

        let mismatch = structured_durable_router(
            StructuredDurableNativeComponents::new(
                Arc::clone(&store),
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
            StructuredDurableNativeComponents::new(store, transport, clock, identities),
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
                NodeCoreError::ObjectBodyUnavailable { object_id },
                StatusCode::NOT_IMPLEMENTED,
                "object-blob-body-unsupported",
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
            resolved_runtime
                .state_store()
                .get_versioned_in_domain(domain, node_config.state_key())
                .unwrap()
                .value(),
            None
        );
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

            let response: Response = app
                .oneshot(
                    Request::post(NODE_EVENT_PATH)
                        .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                        .body(Body::from(event(id).encode().unwrap()))
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
                    .body(Body::from(event(id).encode().unwrap()))
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
                    .body(Body::from(event(current_request_id).encode().unwrap()))
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
                    .body(Body::from(event(id).encode().unwrap()))
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

        let response = app
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(event(request_id(0x24)).encode().unwrap()))
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

    #[tokio::test]
    async fn native_route_persists_dispatches_and_returns_canonical_result() {
        let runtime = Arc::new(MemoryRuntime::new(ValidatorId::new([0x44; 32])));
        let config = config();
        let id = request_id(0x41);
        let event_bytes = event(id).encode().unwrap();
        let app = app(runtime.clone(), config.clone());
        let response = app
            .clone()
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(event_bytes.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            NODE_RESULT_MEDIA_TYPE
        );
        let bytes = to_bytes(response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
            .await
            .unwrap();
        let result = HttpNodeResult::decode(&bytes).unwrap();
        assert_eq!(result.request_id(), id);
        assert_eq!(result.responses().len(), 1);

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
        assert_eq!(runtime.transport().drain_outbound().unwrap().len(), 1);

        let layout = PersistenceLayout::new(config.chain_id().clone(), config.protocol_version());
        let delivery = runtime
            .state_store()
            .get(&layout.outbox_delivery_key(*id.as_bytes()))
            .unwrap()
            .unwrap();
        let delivery = NodeOutboxDelivery::decode(&delivery).unwrap();
        assert_eq!(delivery.next_index(), 1);
        assert_eq!(delivery.lease(), None);

        let duplicate = app
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(event_bytes))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(duplicate.status(), StatusCode::OK);
        let duplicate_bytes = to_bytes(duplicate.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
            .await
            .unwrap();
        assert_eq!(HttpNodeResult::decode(&duplicate_bytes).unwrap(), result);
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
        assert!(runtime.transport().drain_outbound().unwrap().is_empty());
    }

    #[tokio::test]
    async fn resolved_domain_route_commits_and_delivers_only_in_manifest_domain() {
        let runtime = Arc::new(MemoryRuntime::new(ValidatorId::new([0x44; 32])));
        let config = config();
        let placement = placement(0x51, 7);
        let domain = placement.domain();
        let id = request_id(0x52);
        let event_bytes = event(id).encode().unwrap();
        let app = resolved_app(Arc::clone(&runtime), placement, config.clone());

        let response = app
            .clone()
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(event_bytes.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(runtime.transport().drain_outbound().unwrap().len(), 1);
        assert_eq!(runtime.state_store().get(config.state_key()).unwrap(), None);

        let state = runtime
            .state_store()
            .get_versioned_in_domain(domain, config.state_key())
            .unwrap();
        assert_eq!(
            decode_canonical_frame(state.value().unwrap())
                .unwrap()
                .required_u64(1),
            Ok(1)
        );
        let layout = PersistenceLayout::new(config.chain_id().clone(), config.protocol_version());
        let delivery = runtime
            .state_store()
            .get_versioned_in_domain(domain, &layout.outbox_delivery_key(*id.as_bytes()))
            .unwrap();
        let delivery = NodeOutboxDelivery::decode(delivery.value().unwrap()).unwrap();
        assert_eq!(delivery.next_index(), 1);
        assert_eq!(delivery.lease(), None);

        let duplicate = app
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(event_bytes))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(duplicate.status(), StatusCode::OK);
        assert!(runtime.transport().drain_outbound().unwrap().is_empty());
    }

    #[tokio::test]
    async fn resolved_domain_route_rejects_inactive_placement_without_state() {
        let runtime = Arc::new(MemoryRuntime::new(ValidatorId::new([0x44; 32])));
        let config = config();
        let placement = placement(0x53, 8);
        let domain = placement.domain();
        let app = resolved_app(Arc::clone(&runtime), placement, config.clone());
        let response = app
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(event(request_id(0x54)).encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            runtime
                .state_store()
                .get_versioned_in_domain(domain, config.state_key())
                .unwrap()
                .value(),
            None
        );
        assert!(runtime.transport().drain_outbound().unwrap().is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocking_work_is_isolated_and_excess_requests_are_not_queued() {
        let runtime = Arc::new(MemoryRuntime::new(ValidatorId::new([0x44; 32])));
        let config = config();
        let lease_ids = Arc::new(SequenceLeaseIds::default());
        let blocking_executor =
            NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(1).unwrap()));
        let entered = Arc::new(Notify::new());
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let machine = Arc::new(BlockingMachine {
            inner: IncrementMachine::new(config.state_key()),
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        });
        let app = router_with_executor(
            Arc::clone(&runtime),
            config.clone(),
            resolver(),
            machine,
            Arc::clone(&lease_ids),
            blocking_executor.clone(),
        );

        let first_app = app.clone();
        let first = tokio::spawn(async move {
            first_app
                .oneshot(
                    Request::post(NODE_EVENT_PATH)
                        .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                        .body(Body::from(event(request_id(0x51)).encode().unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap()
        });
        entered.notified().await;

        let live = app
            .clone()
            .oneshot(Request::get(LIVENESS_PATH).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let overloaded = app
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(event(request_id(0x52)).encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let recovery = recover_outboxes_once(
            runtime,
            config,
            lease_ids,
            blocking_executor,
            None,
            NonZeroUsize::new(4).unwrap(),
        )
        .await;

        let (released, release_signal) = release.as_ref();
        *released.lock().unwrap() = true;
        release_signal.notify_all();
        let first = first.await.unwrap();

        assert_eq!(live.status(), StatusCode::NO_CONTENT);
        assert_eq!(overloaded.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(matches!(
            recovery,
            Err(NativeOutboxRecoveryError::CapacityExhausted)
        ));
        let overload_body = to_bytes(overloaded.into_body(), 128).await.unwrap();
        assert_eq!(overload_body, "blocking-capacity-exhausted");
        assert_eq!(first.status(), StatusCode::OK);
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
    async fn native_route_recovers_failed_send_after_lease_expiry_without_reapplying_state() {
        let runtime = Arc::new(FailOnceRuntime::new());
        let config = config();
        let id = request_id(0x45);
        let event_bytes = event(id).encode().unwrap();
        let app = app(runtime.clone(), config.clone());

        let failed_send = app
            .clone()
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(event_bytes.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(failed_send.status(), StatusCode::SERVICE_UNAVAILABLE);

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
        assert!(runtime.transport().drain_outbound().unwrap().is_empty());

        let active_lease = app
            .clone()
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(event_bytes.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(active_lease.status(), StatusCode::SERVICE_UNAVAILABLE);

        runtime.clock.set(31_000);
        let recovered = app
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(event_bytes))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(recovered.status(), StatusCode::OK);
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
        let layout = PersistenceLayout::new(config.chain_id().clone(), config.protocol_version());
        let delivery = runtime
            .state_store()
            .get(&layout.outbox_delivery_key(*id.as_bytes()))
            .unwrap()
            .unwrap();
        let delivery = NodeOutboxDelivery::decode(&delivery).unwrap();
        assert_eq!(delivery.attempts(), 2);
        assert_eq!(delivery.next_index(), 1);
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
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(vec![1, 2, 3]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
        assert_eq!(runtime.state_store().get(b"http/node-state").unwrap(), None);
    }

    #[tokio::test]
    async fn native_route_maps_context_conflict_and_body_limit() {
        let runtime = Arc::new(MemoryRuntime::new(ValidatorId::new([0x44; 32])));
        let app = app(runtime, config());
        let wrong_context = NodeEvent::new(
            ChainId::new("other-chain").unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(7),
            request_id(0x43),
            node_core::NodeEventKind::Tick,
            canonical(TEST_PAYLOAD_TYPE_ID, 1),
        )
        .unwrap();

        let conflict = app
            .clone()
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(wrong_context.encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(conflict.status(), StatusCode::CONFLICT);

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
}
