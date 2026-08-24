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
    MAX_NODE_OUTPUT_ITEMS, MAX_NODE_PAYLOAD_BYTES, NodeConfig, NodeCoreError, NodeEvent,
    NodeResponse, OutboxLeaseId, RequestId, TransactionalNodeStateMachine,
    acknowledge_outbox_message, claim_next_outbox_message, handle_idempotent_event,
};
use runtime::{
    Clock, PersistenceLayout, Runtime, RuntimeError, TransactionalStateStore, Transport,
};
use std::{error::Error, future::Future, num::NonZeroUsize, sync::Arc};
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
    blocking_permits: Arc<Semaphore>,
}

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
    let state = Arc::new(NativeHttpState {
        runtime,
        config,
        resolver,
        machine,
        lease_ids,
        blocking_permits: Arc::new(Semaphore::new(
            blocking_policy.max_concurrent_invocations().get(),
        )),
    });
    Router::new()
        .route(LIVENESS_PATH, get(liveness))
        .route(NODE_EVENT_PATH, post(submit_event::<R, M, L>))
        .layer(DefaultBodyLimit::max(MAX_HTTP_EVENT_BODY_BYTES))
        .with_state(state)
}

/// Serves a configured native router until the shutdown future completes.
///
/// Build `app` with [`router`] so the blocking admission policy is explicit at
/// the composition boundary.
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
    let permit = match Arc::clone(&state.blocking_permits).try_acquire_owned() {
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

enum InvocationError {
    Node(NodeCoreError),
    Delivery(OutboxDeliveryError),
    ResultEncoding,
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
    let request_id = event.request_id();
    let output = handle_idempotent_event(
        state.runtime.as_ref(),
        &state.config,
        &state.resolver,
        event,
        state.machine.as_ref(),
    )
    .map_err(InvocationError::Node)?;
    deliver_request_outbox(state, request_id).map_err(InvocationError::Delivery)?;
    HttpNodeResult::new(request_id, output.responses().to_vec())
        .and_then(|result| result.encode())
        .map_err(|_| InvocationError::ResultEncoding)
}

fn invocation_error_response(error: &InvocationError) -> Response {
    match error {
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
        InvocationError::ResultEncoding => {
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "result-encoding-failed")
        }
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

fn deliver_request_outbox<R, M, L>(
    state: &NativeHttpState<R, M, L>,
    request_id: RequestId,
) -> Result<(), OutboxDeliveryError>
where
    R: Runtime,
    R::State: TransactionalStateStore,
    L: OutboxLeaseIdSource,
{
    let layout = PersistenceLayout::new(
        state.config.chain_id().clone(),
        state.config.protocol_version(),
    );
    for _ in 0..MAX_NODE_OUTPUT_ITEMS {
        let lease_id = state.lease_ids.next_lease_id(request_id)?;
        let now_unix_millis = state.runtime.clock().now_unix_millis()?;
        let Some(claim) = claim_next_outbox_message(
            state.runtime.state_store(),
            &layout,
            request_id,
            lease_id,
            now_unix_millis,
            NATIVE_OUTBOX_LEASE_MILLIS,
        )?
        else {
            return Ok(());
        };
        let encoded = claim.message().event().encode()?;
        state
            .runtime
            .transport()
            .send(encoded)
            .map_err(|_| OutboxDeliveryError::Send)?;
        acknowledge_outbox_message(
            state.runtime.state_store(),
            &layout,
            claim.request_id(),
            claim.index(),
            claim.lease_id(),
        )?;
    }
    Ok(())
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
    let (status, code) = match error {
        NodeCoreError::PayloadTooLarge(_) => (StatusCode::PAYLOAD_TOO_LARGE, "payload-too-large"),
        NodeCoreError::ChainMismatch { .. }
        | NodeCoreError::ProtocolVersionMismatch { .. }
        | NodeCoreError::EpochMismatch { .. }
        | NodeCoreError::StateConflict
        | NodeCoreError::RequestIdReuse => (StatusCode::CONFLICT, "state-or-context-conflict"),
        NodeCoreError::OutboxLeaseActive { .. } => {
            (StatusCode::SERVICE_UNAVAILABLE, "outbox-lease-active")
        }
        NodeCoreError::TransitionRejected(_) => {
            (StatusCode::UNPROCESSABLE_ENTITY, "transition-rejected")
        }
        NodeCoreError::Runtime(_) => (StatusCode::SERVICE_UNAVAILABLE, "runtime-unavailable"),
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
        | NodeCoreError::OutboxArithmeticOverflow => {
            (StatusCode::INTERNAL_SERVER_ERROR, "invalid-node-output")
        }
        _ => (StatusCode::BAD_REQUEST, "invalid-node-event"),
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
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use canonical_encoding::CanonicalStruct;
    use node_core::{
        NodeOutboxDelivery, NodeOutput, NodeResponseStatus, NodeStateAccess, NodeStateAccessMode,
        NodeStateAccessPlan, NodeStateSnapshot, NodeStateUpdate, OutboundMessage,
        TransactionalNodeTransition,
    };
    use protocol_types::{
        ChainId, Epoch, HashSuite, HashSuiteSchedule, ProtocolVersion, ValidatorId,
    };
    use runtime::{
        ManualClock, MemoryBlobStore, MemoryRuntime, MemoryScheduler, MemorySigner,
        MemoryStateStore, RuntimeError, StateStore, TransactionalStateStore,
    };
    use std::sync::{Condvar, Mutex};
    use tokio::sync::Notify;
    use tower::ServiceExt;

    const TEST_STATE_TYPE_ID: u16 = 0xEF11;
    const TEST_PAYLOAD_TYPE_ID: u16 = 0xEF12;

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

    fn event(request_id: RequestId) -> NodeEvent {
        NodeEvent::new(
            ChainId::new("sunrise-test").unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(7),
            request_id,
            node_core::NodeEventKind::SubmitTransaction,
            canonical(TEST_PAYLOAD_TYPE_ID, 9),
        )
        .unwrap()
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

    #[tokio::test(flavor = "current_thread")]
    async fn blocking_work_is_isolated_and_excess_requests_are_not_queued() {
        let runtime = Arc::new(MemoryRuntime::new(ValidatorId::new([0x44; 32])));
        let config = config();
        let entered = Arc::new(Notify::new());
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let machine = Arc::new(BlockingMachine {
            inner: IncrementMachine::new(config.state_key()),
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        });
        let app = router(
            runtime,
            config,
            resolver(),
            machine,
            Arc::new(SequenceLeaseIds::default()),
            NativeBlockingPolicy::new(NonZeroUsize::new(1).unwrap()),
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

        let (released, release_signal) = release.as_ref();
        *released.lock().unwrap() = true;
        release_signal.notify_all();
        let first = first.await.unwrap();

        assert_eq!(live.status(), StatusCode::NO_CONTENT);
        assert_eq!(overloaded.status(), StatusCode::TOO_MANY_REQUESTS);
        let overload_body = to_bytes(overloaded.into_body(), 128).await.unwrap();
        assert_eq!(overload_body, "blocking-capacity-exhausted");
        assert_eq!(first.status(), StatusCode::OK);
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
