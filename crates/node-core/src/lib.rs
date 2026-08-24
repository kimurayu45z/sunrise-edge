#![forbid(unsafe_code)]

//! Deterministic, runtime-neutral ingress and persistence boundary for one node event.
//!
//! The core consumes exactly one bounded canonical event, loads one explicit state
//! value, delegates a pure transition, and conditionally persists the returned
//! state with compare-and-swap. It deliberately does not sign, send, schedule,
//! spawn, retry, or keep process-local protocol state.

use canonical_encoding::{
    CanonicalDecodingError, CanonicalEncodingError, CanonicalStruct, decode_canonical_frame,
};
use core::fmt;
use protocol_types::{ChainId, Epoch, ProtocolVersion, TypeError};
use runtime::{Runtime, RuntimeError, StateStore};
use std::error::Error;

const NODE_EVENT_TYPE_ID: u16 = 0xE001;
const NODE_RESPONSE_TYPE_ID: u16 = 0xE002;
const ENCODING_VERSION: u16 = 1;

/// Maximum UTF-8 byte length of a chain identifier accepted at node ingress.
pub const MAX_CHAIN_ID_BYTES: usize = 128;
/// Maximum canonical payload length carried by one node event or response.
pub const MAX_NODE_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
/// Maximum canonical state value replaced by one node-core invocation.
pub const MAX_NODE_STATE_BYTES: usize = 32 * 1024 * 1024;
/// Maximum responses or outbound messages produced by one invocation.
pub const MAX_NODE_OUTPUT_ITEMS: usize = 1_024;
/// Maximum aggregate payload bytes returned by one invocation.
pub const MAX_NODE_OUTPUT_BYTES: usize = 32 * 1024 * 1024;

/// Errors returned by node-core validation, transition, and persistence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeCoreError {
    /// Canonical encoding failed.
    CanonicalEncoding(CanonicalEncodingError),
    /// Canonical decoding failed.
    CanonicalDecoding(CanonicalDecodingError),
    /// A decoded chain identifier was invalid.
    InvalidChainId(TypeError),
    /// A chain identifier exceeded the ingress resource bound.
    ChainIdTooLong(usize),
    /// A request identifier must not be all zeroes.
    ZeroRequestId,
    /// A request identifier had the wrong encoded length.
    InvalidRequestIdLength(usize),
    /// An event kind identifier is unknown.
    UnknownEventKind(u16),
    /// A response status identifier is unknown.
    UnknownResponseStatus(u16),
    /// The event belongs to a different chain.
    ChainMismatch {
        /// Configured chain.
        expected: ChainId,
        /// Event chain.
        actual: ChainId,
    },
    /// The event targets a different protocol version.
    ProtocolVersionMismatch {
        /// Configured protocol version.
        expected: ProtocolVersion,
        /// Event protocol version.
        actual: ProtocolVersion,
    },
    /// The event targets a different epoch.
    EpochMismatch {
        /// Configured epoch.
        expected: Epoch,
        /// Event epoch.
        actual: Epoch,
    },
    /// A persistence key was empty.
    EmptyStateKey,
    /// An event or response payload exceeded its resource bound.
    PayloadTooLarge(usize),
    /// A state value exceeded its resource bound.
    StateTooLarge(usize),
    /// Too many output items were returned by one transition.
    TooManyOutputItems {
        /// Output collection name.
        collection: &'static str,
        /// Actual item count.
        count: usize,
    },
    /// Aggregate output payload bytes exceeded their resource bound.
    OutputTooLarge(usize),
    /// The transition produced a response for another request.
    ResponseRequestMismatch {
        /// Event request identifier.
        expected: RequestId,
        /// Response request identifier.
        actual: RequestId,
    },
    /// The persisted state changed between read and conditional write.
    StateConflict,
    /// A runtime storage operation failed.
    Runtime(RuntimeError),
    /// The application-specific state machine rejected the event.
    TransitionRejected(&'static str),
}

impl fmt::Display for NodeCoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CanonicalEncoding(error) => write!(f, "canonical encoding failed: {error}"),
            Self::CanonicalDecoding(error) => write!(f, "canonical decoding failed: {error}"),
            Self::InvalidChainId(error) => write!(f, "invalid chain id: {error}"),
            Self::ChainIdTooLong(length) => write!(
                f,
                "chain id is {length} bytes, maximum is {MAX_CHAIN_ID_BYTES}"
            ),
            Self::ZeroRequestId => f.write_str("request id must not be all zeroes"),
            Self::InvalidRequestIdLength(length) => {
                write!(f, "request id is {length} bytes, expected 32")
            }
            Self::UnknownEventKind(kind) => write!(f, "unknown node event kind: {kind:#06x}"),
            Self::UnknownResponseStatus(status) => {
                write!(f, "unknown node response status: {status:#06x}")
            }
            Self::ChainMismatch { expected, actual } => {
                write!(f, "event chain mismatch: expected {expected}, got {actual}")
            }
            Self::ProtocolVersionMismatch { expected, actual } => write!(
                f,
                "event protocol version mismatch: expected {}, got {}",
                expected.get(),
                actual.get()
            ),
            Self::EpochMismatch { expected, actual } => write!(
                f,
                "event epoch mismatch: expected {}, got {}",
                expected.get(),
                actual.get()
            ),
            Self::EmptyStateKey => f.write_str("node-core state key must not be empty"),
            Self::PayloadTooLarge(length) => write!(
                f,
                "node payload is {length} bytes, maximum is {MAX_NODE_PAYLOAD_BYTES}"
            ),
            Self::StateTooLarge(length) => write!(
                f,
                "node state is {length} bytes, maximum is {MAX_NODE_STATE_BYTES}"
            ),
            Self::TooManyOutputItems { collection, count } => write!(
                f,
                "node output has {count} {collection}, maximum is {MAX_NODE_OUTPUT_ITEMS}"
            ),
            Self::OutputTooLarge(length) => write!(
                f,
                "node output is {length} bytes, maximum is {MAX_NODE_OUTPUT_BYTES}"
            ),
            Self::ResponseRequestMismatch { expected, actual } => write!(
                f,
                "response request id mismatch: expected {expected}, got {actual}"
            ),
            Self::StateConflict => f.write_str("node state changed before the conditional write"),
            Self::Runtime(error) => write!(f, "runtime operation failed: {error}"),
            Self::TransitionRejected(reason) => write!(f, "node transition rejected: {reason}"),
        }
    }
}

impl Error for NodeCoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CanonicalEncoding(error) => Some(error),
            Self::CanonicalDecoding(error) => Some(error),
            Self::InvalidChainId(error) => Some(error),
            Self::Runtime(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CanonicalEncodingError> for NodeCoreError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(value)
    }
}

impl From<CanonicalDecodingError> for NodeCoreError {
    fn from(value: CanonicalDecodingError) -> Self {
        Self::CanonicalDecoding(value)
    }
}

impl From<RuntimeError> for NodeCoreError {
    fn from(value: RuntimeError) -> Self {
        Self::Runtime(value)
    }
}

/// Stable, caller-supplied idempotency identifier for one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId([u8; 32]);

impl RequestId {
    /// Creates a non-zero request identifier.
    pub fn new(bytes: [u8; 32]) -> Result<Self, NodeCoreError> {
        if bytes == [0; 32] {
            return Err(NodeCoreError::ZeroRequestId);
        }
        Ok(Self(bytes))
    }

    /// Returns the identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Closed node event families routed to application-specific schema decoders.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NodeEventKind {
    /// Client transaction submission.
    SubmitTransaction = 0x0001,
    /// Validator vote delivery.
    ReceiveVote = 0x0002,
    /// Certificate delivery.
    ReceiveCertificate = 0x0003,
    /// Shared-object consensus message delivery.
    ReceiveConsensusMessage = 0x0004,
    /// Governance certificate application.
    ApplyGovernanceCertificate = 0x0005,
    /// Protocol-upgrade certificate application.
    ApplyProtocolUpgrade = 0x0006,
    /// Validator-set change certificate application.
    ApplyValidatorSetChange = 0x0007,
    /// Untrusted liveness tick delivery.
    Tick = 0x0008,
}

impl NodeEventKind {
    /// Returns the stable wire identifier.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

impl TryFrom<u16> for NodeEventKind {
    type Error = NodeCoreError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(Self::SubmitTransaction),
            0x0002 => Ok(Self::ReceiveVote),
            0x0003 => Ok(Self::ReceiveCertificate),
            0x0004 => Ok(Self::ReceiveConsensusMessage),
            0x0005 => Ok(Self::ApplyGovernanceCertificate),
            0x0006 => Ok(Self::ApplyProtocolUpgrade),
            0x0007 => Ok(Self::ApplyValidatorSetChange),
            0x0008 => Ok(Self::Tick),
            other => Err(NodeCoreError::UnknownEventKind(other)),
        }
    }
}

/// One replay-bounded, canonical input to the node state machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeEvent {
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    request_id: RequestId,
    kind: NodeEventKind,
    payload: Vec<u8>,
}

impl NodeEvent {
    /// Creates a validated event around one canonical application payload.
    pub fn new(
        chain_id: ChainId,
        protocol_version: ProtocolVersion,
        epoch: Epoch,
        request_id: RequestId,
        kind: NodeEventKind,
        payload: Vec<u8>,
    ) -> Result<Self, NodeCoreError> {
        validate_chain_id(&chain_id)?;
        validate_payload(&payload)?;
        Ok(Self {
            chain_id,
            protocol_version,
            epoch,
            request_id,
            kind,
            payload,
        })
    }

    /// Returns the replay-protected chain identifier.
    #[must_use]
    pub fn chain_id(&self) -> &ChainId {
        &self.chain_id
    }

    /// Returns the replay-protected protocol version.
    #[must_use]
    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Returns the replay-protected epoch.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the request identifier.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Returns the event family.
    #[must_use]
    pub const fn kind(&self) -> NodeEventKind {
        self.kind
    }

    /// Returns the canonical application payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Encodes the event into its stable canonical wire form.
    pub fn encode(&self) -> Result<Vec<u8>, NodeCoreError> {
        let mut frame = CanonicalStruct::new(NODE_EVENT_TYPE_ID, ENCODING_VERSION);
        frame.field_str(1, self.chain_id.as_str())?;
        frame.field_u32(2, self.protocol_version.get())?;
        frame.field_u64(3, self.epoch.get())?;
        frame.field_bytes(4, self.request_id.as_bytes().to_vec())?;
        frame.field_u16(5, self.kind.as_u16())?;
        frame.field_bytes(6, self.payload.clone())?;
        Ok(frame.finish()?)
    }

    /// Decodes and validates exactly one canonical event frame.
    pub fn decode(bytes: &[u8]) -> Result<Self, NodeCoreError> {
        let frame = decode_canonical_frame(bytes)?;
        frame.require_type(NODE_EVENT_TYPE_ID)?;
        frame.require_version(ENCODING_VERSION)?;
        frame.require_only_fields(&[1, 2, 3, 4, 5, 6])?;

        let chain_id = ChainId::new(frame.required_str(1)?.to_owned())
            .map_err(NodeCoreError::InvalidChainId)?;
        let request_bytes = frame.required_field(4)?;
        let request_array: [u8; 32] = request_bytes
            .try_into()
            .map_err(|_| NodeCoreError::InvalidRequestIdLength(request_bytes.len()))?;
        Self::new(
            chain_id,
            ProtocolVersion::new(frame.required_u32(2)?),
            Epoch::new(frame.required_u64(3)?),
            RequestId::new(request_array)?,
            NodeEventKind::try_from(frame.required_u16(5)?)?,
            frame.required_field(6)?.to_vec(),
        )
    }

    fn validate_context(&self, config: &NodeConfig) -> Result<(), NodeCoreError> {
        if self.chain_id != config.chain_id {
            return Err(NodeCoreError::ChainMismatch {
                expected: config.chain_id.clone(),
                actual: self.chain_id.clone(),
            });
        }
        if self.protocol_version != config.protocol_version {
            return Err(NodeCoreError::ProtocolVersionMismatch {
                expected: config.protocol_version,
                actual: self.protocol_version,
            });
        }
        if self.epoch != config.epoch {
            return Err(NodeCoreError::EpochMismatch {
                expected: config.epoch,
                actual: self.epoch,
            });
        }
        Ok(())
    }
}

/// Immutable invocation context supplied by the runtime adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeConfig {
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    state_key: Vec<u8>,
}

impl NodeConfig {
    /// Creates a node-core invocation configuration.
    pub fn new(
        chain_id: ChainId,
        protocol_version: ProtocolVersion,
        epoch: Epoch,
        state_key: Vec<u8>,
    ) -> Result<Self, NodeCoreError> {
        validate_chain_id(&chain_id)?;
        if state_key.is_empty() {
            return Err(NodeCoreError::EmptyStateKey);
        }
        Ok(Self {
            chain_id,
            protocol_version,
            epoch,
            state_key,
        })
    }

    /// Returns the configured chain identifier.
    #[must_use]
    pub fn chain_id(&self) -> &ChainId {
        &self.chain_id
    }

    /// Returns the configured protocol version.
    #[must_use]
    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Returns the configured epoch.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the explicit persistence key used by this state machine.
    #[must_use]
    pub fn state_key(&self) -> &[u8] {
        &self.state_key
    }
}

/// Stable status returned to the request adapter.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeResponseStatus {
    /// The event was accepted and persisted.
    Accepted = 0x0001,
    /// The authenticated event was deterministically rejected by application logic.
    Rejected = 0x0002,
}

impl NodeResponseStatus {
    /// Returns the stable wire identifier.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

impl TryFrom<u16> for NodeResponseStatus {
    type Error = NodeCoreError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(Self::Accepted),
            0x0002 => Ok(Self::Rejected),
            other => Err(NodeCoreError::UnknownResponseStatus(other)),
        }
    }
}

/// Adapter-neutral response produced by a successful state transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeResponse {
    request_id: RequestId,
    status: NodeResponseStatus,
    payload: Option<Vec<u8>>,
}

impl NodeResponse {
    /// Creates a bounded response. A present payload must be a canonical frame.
    pub fn new(
        request_id: RequestId,
        status: NodeResponseStatus,
        payload: Option<Vec<u8>>,
    ) -> Result<Self, NodeCoreError> {
        if let Some(bytes) = &payload {
            validate_payload(bytes)?;
        }
        Ok(Self {
            request_id,
            status,
            payload,
        })
    }

    /// Returns the matching request identifier.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Returns the response status.
    #[must_use]
    pub const fn status(&self) -> NodeResponseStatus {
        self.status
    }

    /// Returns the optional canonical response payload.
    #[must_use]
    pub fn payload(&self) -> Option<&[u8]> {
        self.payload.as_deref()
    }

    /// Encodes this response into its adapter-neutral canonical wire form.
    pub fn encode(&self) -> Result<Vec<u8>, NodeCoreError> {
        let mut frame = CanonicalStruct::new(NODE_RESPONSE_TYPE_ID, ENCODING_VERSION);
        frame.field_bytes(1, self.request_id.as_bytes().to_vec())?;
        frame.field_u16(2, self.status.as_u16())?;
        if let Some(payload) = &self.payload {
            frame.field_bytes(3, payload.clone())?;
        }
        Ok(frame.finish()?)
    }

    /// Decodes one adapter-neutral canonical response.
    pub fn decode(bytes: &[u8]) -> Result<Self, NodeCoreError> {
        let frame = decode_canonical_frame(bytes)?;
        frame.require_type(NODE_RESPONSE_TYPE_ID)?;
        frame.require_version(ENCODING_VERSION)?;
        frame.require_only_fields(&[1, 2, 3])?;

        let request_bytes = frame.required_field(1)?;
        let request_array: [u8; 32] = request_bytes
            .try_into()
            .map_err(|_| NodeCoreError::InvalidRequestIdLength(request_bytes.len()))?;
        Self::new(
            RequestId::new(request_array)?,
            NodeResponseStatus::try_from(frame.required_u16(2)?)?,
            frame.field(3).map(<[u8]>::to_vec),
        )
    }
}

/// Adapter-neutral outbound delivery request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboundMessage {
    event: NodeEvent,
}

impl OutboundMessage {
    /// Creates an outbound message around a fully framed node event.
    #[must_use]
    pub const fn new(event: NodeEvent) -> Self {
        Self { event }
    }

    /// Returns the event to deliver through an untrusted transport.
    #[must_use]
    pub const fn event(&self) -> &NodeEvent {
        &self.event
    }
}

/// Bounded side effects returned only after state persistence succeeds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeOutput {
    responses: Vec<NodeResponse>,
    outbound_messages: Vec<OutboundMessage>,
}

impl NodeOutput {
    /// Creates and validates one invocation's output.
    pub fn new(
        responses: Vec<NodeResponse>,
        outbound_messages: Vec<OutboundMessage>,
    ) -> Result<Self, NodeCoreError> {
        if responses.len() > MAX_NODE_OUTPUT_ITEMS {
            return Err(NodeCoreError::TooManyOutputItems {
                collection: "responses",
                count: responses.len(),
            });
        }
        if outbound_messages.len() > MAX_NODE_OUTPUT_ITEMS {
            return Err(NodeCoreError::TooManyOutputItems {
                collection: "outbound messages",
                count: outbound_messages.len(),
            });
        }

        let response_bytes = responses.iter().filter_map(|item| item.payload.as_ref());
        let outbound_bytes = outbound_messages.iter().map(|item| item.event.payload());
        let total = response_bytes
            .map(Vec::len)
            .chain(outbound_bytes.map(<[u8]>::len))
            .try_fold(0_usize, usize::checked_add)
            .ok_or(NodeCoreError::OutputTooLarge(usize::MAX))?;
        if total > MAX_NODE_OUTPUT_BYTES {
            return Err(NodeCoreError::OutputTooLarge(total));
        }

        Ok(Self {
            responses,
            outbound_messages,
        })
    }

    /// Returns adapter responses in deterministic application order.
    #[must_use]
    pub fn responses(&self) -> &[NodeResponse] {
        &self.responses
    }

    /// Returns outbound events in deterministic application order.
    #[must_use]
    pub fn outbound_messages(&self) -> &[OutboundMessage] {
        &self.outbound_messages
    }
}

/// One validated candidate state replacement and its deferred outputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeTransition {
    next_state: Vec<u8>,
    output: NodeOutput,
}

impl NodeTransition {
    /// Creates a transition around one bounded canonical state value.
    pub fn new(next_state: Vec<u8>, output: NodeOutput) -> Result<Self, NodeCoreError> {
        validate_state(&next_state)?;
        Ok(Self { next_state, output })
    }

    /// Returns the candidate persisted state.
    #[must_use]
    pub fn next_state(&self) -> &[u8] {
        &self.next_state
    }

    /// Returns output held until compare-and-swap succeeds.
    #[must_use]
    pub const fn output(&self) -> &NodeOutput {
        &self.output
    }
}

/// Application-specific deterministic transition over explicit persisted bytes.
pub trait NodeStateMachine {
    /// Computes one transition without performing I/O or retaining protocol state.
    fn transition(
        &self,
        current_state: Option<&[u8]>,
        event: &NodeEvent,
    ) -> Result<NodeTransition, NodeCoreError>;
}

/// Handles exactly one event and atomically persists its deterministic transition.
///
/// Outputs are returned only after compare-and-swap succeeds. The caller may then
/// sign or deliver them. A conflict is surfaced to the adapter; node-core never
/// retries because retry policy and invocation budgets belong to the adapter.
pub fn handle_event<R, M>(
    runtime: &R,
    config: &NodeConfig,
    event: NodeEvent,
    machine: &M,
) -> Result<NodeOutput, NodeCoreError>
where
    R: Runtime,
    M: NodeStateMachine,
{
    event.validate_context(config)?;
    let current = runtime.state_store().get(config.state_key())?;
    if let Some(bytes) = &current {
        validate_state(bytes)?;
    }

    let transition = machine.transition(current.as_deref(), &event)?;
    for response in transition.output.responses() {
        if response.request_id() != event.request_id() {
            return Err(NodeCoreError::ResponseRequestMismatch {
                expected: event.request_id(),
                actual: response.request_id(),
            });
        }
    }
    for message in transition.output.outbound_messages() {
        message.event().validate_context(config)?;
    }

    let result = runtime.state_store().compare_and_swap(
        config.state_key.clone(),
        current,
        transition.next_state,
    )?;
    if !result.swapped {
        return Err(NodeCoreError::StateConflict);
    }
    Ok(transition.output)
}

fn validate_chain_id(chain_id: &ChainId) -> Result<(), NodeCoreError> {
    let length = chain_id.as_str().len();
    if length > MAX_CHAIN_ID_BYTES {
        return Err(NodeCoreError::ChainIdTooLong(length));
    }
    Ok(())
}

fn validate_payload(payload: &[u8]) -> Result<(), NodeCoreError> {
    if payload.len() > MAX_NODE_PAYLOAD_BYTES {
        return Err(NodeCoreError::PayloadTooLarge(payload.len()));
    }
    decode_canonical_frame(payload)?;
    Ok(())
}

fn validate_state(state: &[u8]) -> Result<(), NodeCoreError> {
    if state.len() > MAX_NODE_STATE_BYTES {
        return Err(NodeCoreError::StateTooLarge(state.len()));
    }
    decode_canonical_frame(state)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtime::{MemoryRuntime, StateStore};

    const TEST_STATE_TYPE_ID: u16 = 0xEF01;
    const TEST_PAYLOAD_TYPE_ID: u16 = 0xEF02;

    fn canonical(type_id: u16, value: u64) -> Vec<u8> {
        let mut frame = CanonicalStruct::new(type_id, 1);
        frame.field_u64(1, value).unwrap();
        frame.finish().unwrap()
    }

    fn request(byte: u8) -> RequestId {
        RequestId::new([byte; 32]).unwrap()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn event(chain: &str, request_id: RequestId) -> NodeEvent {
        NodeEvent::new(
            ChainId::new(chain).unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(7),
            request_id,
            NodeEventKind::SubmitTransaction,
            canonical(TEST_PAYLOAD_TYPE_ID, 9),
        )
        .unwrap()
    }

    fn config(chain: &str) -> NodeConfig {
        NodeConfig::new(
            ChainId::new(chain).unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(7),
            b"node/state".to_vec(),
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
            let value = match current_state {
                Some(bytes) => decode_canonical_frame(bytes)?.required_u64(1)?,
                None => 0,
            };
            let next = value
                .checked_add(1)
                .ok_or(NodeCoreError::TransitionRejected("test counter overflow"))?;
            let response = NodeResponse::new(
                event.request_id(),
                NodeResponseStatus::Accepted,
                Some(canonical(TEST_PAYLOAD_TYPE_ID, next)),
            )?;
            NodeTransition::new(
                canonical(TEST_STATE_TYPE_ID, next),
                NodeOutput::new(vec![response], Vec::new())?,
            )
        }
    }

    #[test]
    fn event_round_trip_has_stable_encoding() {
        let event = event("sunrise-test", request(0x11));
        let encoded = event.encode().unwrap();
        let decoded = NodeEvent::decode(&encoded).unwrap();

        assert_eq!(decoded, event);
        assert_eq!(
            hex(&encoded),
            "534e524501e00100060001000c00000073756e726973652d7465737402000400000003000000\
             03000800000007000000000000000400200000001111111111111111111111111111111111111111\
             1111111111111111111111110500020000000100060018000000534e524502ef0100010001000800\
             00000900000000000000"
                .replace(' ', "")
        );
    }

    #[test]
    fn event_decode_rejects_unknown_kind_and_schema_fields() {
        let payload = canonical(TEST_PAYLOAD_TYPE_ID, 1);
        let mut unknown_kind = CanonicalStruct::new(NODE_EVENT_TYPE_ID, ENCODING_VERSION);
        unknown_kind.field_str(1, "sunrise-test").unwrap();
        unknown_kind.field_u32(2, 3).unwrap();
        unknown_kind.field_u64(3, 7).unwrap();
        unknown_kind.field_bytes(4, [0x22; 32]).unwrap();
        unknown_kind.field_u16(5, 0xFFFF).unwrap();
        unknown_kind.field_bytes(6, payload.clone()).unwrap();
        assert_eq!(
            NodeEvent::decode(&unknown_kind.finish().unwrap()).unwrap_err(),
            NodeCoreError::UnknownEventKind(0xFFFF)
        );

        let mut extra_field = CanonicalStruct::new(NODE_EVENT_TYPE_ID, ENCODING_VERSION);
        extra_field.field_str(1, "sunrise-test").unwrap();
        extra_field.field_u32(2, 3).unwrap();
        extra_field.field_u64(3, 7).unwrap();
        extra_field.field_bytes(4, [0x22; 32]).unwrap();
        extra_field.field_u16(5, 1).unwrap();
        extra_field.field_bytes(6, payload).unwrap();
        extra_field.field_u16(7, 0).unwrap();
        assert!(matches!(
            NodeEvent::decode(&extra_field.finish().unwrap()),
            Err(NodeCoreError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedField(7)
            ))
        ));
    }

    #[test]
    fn event_requires_non_zero_request_and_canonical_payload() {
        assert_eq!(RequestId::new([0; 32]), Err(NodeCoreError::ZeroRequestId));
        assert!(matches!(
            NodeEvent::new(
                ChainId::new("sunrise-test").unwrap(),
                ProtocolVersion::new(3),
                Epoch::new(7),
                request(1),
                NodeEventKind::Tick,
                vec![1, 2, 3],
            ),
            Err(NodeCoreError::CanonicalDecoding(_))
        ));
    }

    #[test]
    fn response_round_trip_preserves_optional_payload() {
        let response = NodeResponse::new(
            request(0x21),
            NodeResponseStatus::Accepted,
            Some(canonical(TEST_PAYLOAD_TYPE_ID, 42)),
        )
        .unwrap();
        let encoded = response.encode().unwrap();

        assert_eq!(NodeResponse::decode(&encoded).unwrap(), response);
        assert_eq!(
            hex(&encoded),
            "534e524502e001000300010020000000212121212121212121212121212121212121212121212121\
             21212121212121210200020000000100030018000000534e524502ef010001000100080000002a00\
             000000000000"
                .replace(' ', "")
        );

        let empty = NodeResponse::new(request(0x22), NodeResponseStatus::Rejected, None).unwrap();
        assert_eq!(
            NodeResponse::decode(&empty.encode().unwrap()).unwrap(),
            empty
        );
    }

    #[test]
    fn handle_event_persists_before_returning_output() {
        let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
        let config = config("sunrise-test");
        let event = event("sunrise-test", request(0x33));

        let output = handle_event(&runtime, &config, event, &IncrementMachine).unwrap();
        let persisted = runtime
            .state_store()
            .get(config.state_key())
            .unwrap()
            .unwrap();

        assert_eq!(
            decode_canonical_frame(&persisted).unwrap().required_u64(1),
            Ok(1)
        );
        assert_eq!(output.responses().len(), 1);
        assert!(output.outbound_messages().is_empty());
    }

    #[test]
    fn wrong_context_is_rejected_before_transition() {
        let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
        let error = handle_event(
            &runtime,
            &config("expected-chain"),
            event("other-chain", request(0x55)),
            &IncrementMachine,
        )
        .unwrap_err();

        assert!(matches!(error, NodeCoreError::ChainMismatch { .. }));
        assert_eq!(runtime.state_store().get(b"node/state").unwrap(), None);
    }

    struct ConflictingMachine<'a> {
        runtime: &'a MemoryRuntime,
        state_key: Vec<u8>,
    }

    impl NodeStateMachine for ConflictingMachine<'_> {
        fn transition(
            &self,
            _current_state: Option<&[u8]>,
            _event: &NodeEvent,
        ) -> Result<NodeTransition, NodeCoreError> {
            self.runtime
                .state_store()
                .put(self.state_key.clone(), canonical(TEST_STATE_TYPE_ID, 99))?;
            NodeTransition::new(canonical(TEST_STATE_TYPE_ID, 1), NodeOutput::default())
        }
    }

    #[test]
    fn compare_and_swap_conflict_discards_transition_output() {
        let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
        let config = config("sunrise-test");
        runtime
            .state_store()
            .put(
                config.state_key().to_vec(),
                canonical(TEST_STATE_TYPE_ID, 0),
            )
            .unwrap();
        let machine = ConflictingMachine {
            runtime: &runtime,
            state_key: config.state_key().to_vec(),
        };

        let error = handle_event(
            &runtime,
            &config,
            event("sunrise-test", request(0x66)),
            &machine,
        )
        .unwrap_err();
        let persisted = runtime
            .state_store()
            .get(config.state_key())
            .unwrap()
            .unwrap();

        assert_eq!(error, NodeCoreError::StateConflict);
        assert_eq!(
            decode_canonical_frame(&persisted).unwrap().required_u64(1),
            Ok(99)
        );
    }

    #[test]
    fn response_must_match_event_request() {
        struct WrongResponseMachine;

        impl NodeStateMachine for WrongResponseMachine {
            fn transition(
                &self,
                _current_state: Option<&[u8]>,
                _event: &NodeEvent,
            ) -> Result<NodeTransition, NodeCoreError> {
                let response =
                    NodeResponse::new(request(0x77), NodeResponseStatus::Accepted, None)?;
                NodeTransition::new(
                    canonical(TEST_STATE_TYPE_ID, 1),
                    NodeOutput::new(vec![response], Vec::new())?,
                )
            }
        }

        let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
        let error = handle_event(
            &runtime,
            &config("sunrise-test"),
            event("sunrise-test", request(0x78)),
            &WrongResponseMachine,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            NodeCoreError::ResponseRequestMismatch { .. }
        ));
        assert_eq!(runtime.state_store().get(b"node/state").unwrap(), None);
    }

    #[test]
    fn outbound_event_must_match_invocation_context() {
        struct CrossChainOutputMachine;

        impl NodeStateMachine for CrossChainOutputMachine {
            fn transition(
                &self,
                _current_state: Option<&[u8]>,
                _event: &NodeEvent,
            ) -> Result<NodeTransition, NodeCoreError> {
                let outbound = OutboundMessage::new(event("other-chain", request(0x79)));
                NodeTransition::new(
                    canonical(TEST_STATE_TYPE_ID, 1),
                    NodeOutput::new(Vec::new(), vec![outbound])?,
                )
            }
        }

        let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
        let error = handle_event(
            &runtime,
            &config("sunrise-test"),
            event("sunrise-test", request(0x7A)),
            &CrossChainOutputMachine,
        )
        .unwrap_err();

        assert!(matches!(error, NodeCoreError::ChainMismatch { .. }));
        assert_eq!(runtime.state_store().get(b"node/state").unwrap(), None);
    }
}
