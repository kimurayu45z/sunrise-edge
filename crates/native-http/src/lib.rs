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
use node_core::{
    MAX_NODE_OUTPUT_ITEMS, MAX_NODE_PAYLOAD_BYTES, NodeConfig, NodeCoreError, NodeEvent,
    NodeResponse, NodeStateMachine, RequestId, handle_event,
};
use runtime::{Runtime, Transport};
use std::{error::Error, future::Future, sync::Arc};

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

struct NativeHttpState<R, M> {
    runtime: Arc<R>,
    config: NodeConfig,
    machine: Arc<M>,
}

/// Builds a native HTTP router around one runtime and deterministic state machine.
pub fn router<R, M>(runtime: Arc<R>, config: NodeConfig, machine: Arc<M>) -> Router
where
    R: Runtime + Send + Sync + 'static,
    M: NodeStateMachine + Send + Sync + 'static,
{
    let state = Arc::new(NativeHttpState {
        runtime,
        config,
        machine,
    });
    Router::new()
        .route(LIVENESS_PATH, get(liveness))
        .route(NODE_EVENT_PATH, post(submit_event::<R, M>))
        .layer(DefaultBodyLimit::max(MAX_HTTP_EVENT_BODY_BYTES))
        .with_state(state)
}

/// Serves the native router until the supplied shutdown future completes.
pub async fn serve<R, M, F>(
    listener: tokio::net::TcpListener,
    runtime: Arc<R>,
    config: NodeConfig,
    machine: Arc<M>,
    shutdown: F,
) -> std::io::Result<()>
where
    R: Runtime + Send + Sync + 'static,
    M: NodeStateMachine + Send + Sync + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    axum::serve(listener, router(runtime, config, machine))
        .with_graceful_shutdown(shutdown)
        .await
}

async fn liveness() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn submit_event<R, M>(
    State(state): State<Arc<NativeHttpState<R, M>>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response
where
    R: Runtime + Send + Sync + 'static,
    M: NodeStateMachine + Send + Sync + 'static,
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
    let event = match NodeEvent::decode(&body) {
        Ok(event) => event,
        Err(error) => return node_error_response(&error),
    };
    let request_id = event.request_id();
    let output = match handle_event(
        state.runtime.as_ref(),
        &state.config,
        event,
        state.machine.as_ref(),
    ) {
        Ok(output) => output,
        Err(error) => return node_error_response(&error),
    };

    for outbound in output.outbound_messages() {
        let encoded = match outbound.event().encode() {
            Ok(encoded) => encoded,
            Err(error) => return node_error_response(&error),
        };
        if state.runtime.transport().send(encoded).is_err() {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "outbound-send-failed");
        }
    }

    let result = match HttpNodeResult::new(request_id, output.responses().to_vec())
        .and_then(|result| result.encode())
    {
        Ok(result) => result,
        Err(_) => {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "result-encoding-failed");
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
        | NodeCoreError::StateConflict => (StatusCode::CONFLICT, "state-or-context-conflict"),
        NodeCoreError::TransitionRejected(_) => {
            (StatusCode::UNPROCESSABLE_ENTITY, "transition-rejected")
        }
        NodeCoreError::Runtime(_) => (StatusCode::SERVICE_UNAVAILABLE, "runtime-unavailable"),
        NodeCoreError::ResponseRequestMismatch { .. }
        | NodeCoreError::StateTooLarge(_)
        | NodeCoreError::TooManyOutputItems { .. }
        | NodeCoreError::OutputTooLarge(_) => {
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
    use node_core::{NodeOutput, NodeResponseStatus, NodeTransition, OutboundMessage};
    use protocol_types::{ChainId, Epoch, ProtocolVersion, ValidatorId};
    use runtime::{MemoryRuntime, StateStore};
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

    struct IncrementMachine;

    impl NodeStateMachine for IncrementMachine {
        fn transition(
            &self,
            current_state: Option<&[u8]>,
            event: &NodeEvent,
        ) -> Result<NodeTransition, NodeCoreError> {
            let current = current_state
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
            NodeTransition::new(
                canonical(TEST_STATE_TYPE_ID, next),
                NodeOutput::new(vec![response], vec![OutboundMessage::new(outbound)])?,
            )
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
        let response = router(runtime.clone(), config.clone(), Arc::new(IncrementMachine))
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(event(id).encode().unwrap()))
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
        assert!(
            runtime
                .state_store()
                .get(config.state_key())
                .unwrap()
                .is_some()
        );
        assert_eq!(runtime.transport().drain_outbound().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn native_route_rejects_media_type_and_malformed_event() {
        let runtime = Arc::new(MemoryRuntime::new(ValidatorId::new([0x44; 32])));
        let app = router(runtime.clone(), config(), Arc::new(IncrementMachine));

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
        let app = router(runtime, config(), Arc::new(IncrementMachine));
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
        let response = router(runtime.clone(), config(), Arc::new(IncrementMachine))
            .oneshot(Request::get(LIVENESS_PATH).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(runtime.state_store().get(b"http/node-state").unwrap(), None);
    }
}
