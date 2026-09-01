//! The bounded Developer MVP client: submit, receipt wait, and the four
//! query operations, all over an injected [`Transport`].

use std::num::NonZeroU32;
use std::time::{Duration, Instant};

use node_core::{NodeEvent, NodeEventKind, RequestId};
use node_wire::{
    HttpContextQueryResult, HttpNextNonceQueryResult, HttpNodeResult, HttpObjectQueryResult,
    HttpReceiptQueryResult, NODE_EVENT_MEDIA_TYPE, NODE_EVENT_PATH, NODE_RESULT_MEDIA_TYPE,
    QUERY_CONTEXT_PATH, QUERY_NEXT_NONCE_PATH, QUERY_OBJECT_PATH, QUERY_RECEIPT_PATH,
    QUERY_RESULT_MEDIA_TYPE,
};
use objects::{Address, ObjectId};
use protocol_types::{ChainId, Epoch, ProtocolVersion};

use crate::context::ExpectedProtocolContext;
use crate::error::ClientError;
use crate::transport::{Method, Transport, WireRequest};

/// Explicit inputs for one `SubmitTransaction` event.
///
/// `request_id` is the caller's own bounded idempotency identifier: this
/// client never derives one with an ad hoc hash, and it verifies the
/// server's result is bound to exactly this id before returning it.
pub struct SubmitTransactionRequest {
    /// Chain replay-protection identifier, matching the trusted context.
    pub chain_id: ChainId,
    /// Protocol version, matching the committed `ProtocolConfig`.
    pub protocol_version: ProtocolVersion,
    /// Epoch, matching the trusted current epoch.
    pub epoch: Epoch,
    /// Caller-supplied, non-zero request identifier.
    pub request_id: RequestId,
    /// Exact canonical signed `Transaction` bytes, as produced by
    /// [`crate::transaction::build_signed_transaction`].
    pub signed_transaction_bytes: Vec<u8>,
}

/// Explicit, caller-visible bounds for [`Client::wait_for_receipt`].
///
/// Polling never runs unbounded and never spawns a background worker: every
/// attempt happens synchronously on the caller's own thread, and the loop
/// stops at whichever bound is reached first.
#[derive(Clone, Copy, Debug)]
pub struct ReceiptPollBounds {
    /// Maximum number of `query_receipt` attempts.
    pub max_attempts: NonZeroU32,
    /// Delay before the second attempt; doubles (capped by `max_backoff`)
    /// after each subsequent absent result.
    pub initial_backoff: Duration,
    /// Upper bound on the delay between attempts.
    pub max_backoff: Duration,
    /// Maximum total wall-clock time to keep polling.
    pub max_elapsed: Duration,
}

/// A bounded Developer MVP client over one injected [`Transport`].
pub struct Client<T> {
    transport: T,
}

impl<T> Client<T>
where
    T: Transport,
{
    /// Creates a client around an already-configured transport.
    #[must_use]
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Returns a reference to the underlying transport.
    #[must_use]
    pub const fn transport(&self) -> &T {
        &self.transport
    }

    /// Queries `GET /v1/context`: trusted chain/protocol/epoch/hash-suite/
    /// authentication/domain composition.
    pub fn query_context(&self) -> Result<HttpContextQueryResult, ClientError> {
        let body = self.get(QUERY_CONTEXT_PATH)?;
        Ok(HttpContextQueryResult::decode(&body)?)
    }

    /// Queries `GET /v1/context` and requires every field
    /// [`ExpectedProtocolContext`] covers to match before returning it (see
    /// `ARCHITECTURE.md` DR-0085 / `TODO.md` CLI-First Node Production Gate
    /// S1). This is the mandatory trusted-context check callers must perform
    /// before any nonce/object query or signing: a successful transport
    /// connection alone — TLS or otherwise — never establishes that the
    /// remote server actually speaks the caller's intended chain/protocol.
    pub fn query_verified_context(
        &self,
        expected: &ExpectedProtocolContext,
    ) -> Result<HttpContextQueryResult, ClientError> {
        let context = self.query_context()?;
        expected.verify(&context)?;
        Ok(context)
    }

    /// Queries `GET /v1/objects/{object_id}`.
    pub fn query_object(&self, object_id: ObjectId) -> Result<HttpObjectQueryResult, ClientError> {
        let path = substitute_selector(
            QUERY_OBJECT_PATH,
            "{object_id}",
            &hex64_lower(object_id.as_bytes()),
        );
        let body = self.get(&path)?;
        let result = HttpObjectQueryResult::decode(&body)?;
        if result.object_id() != object_id {
            return Err(ClientError::ObjectQuerySelectorMismatch {
                expected: object_id,
                actual: result.object_id(),
            });
        }
        Ok(result)
    }

    /// Queries `GET /v1/receipts/{request_id}`.
    pub fn query_receipt(
        &self,
        request_id: RequestId,
    ) -> Result<HttpReceiptQueryResult, ClientError> {
        self.query_receipt_with_deadline(request_id, None)
    }

    fn query_receipt_with_deadline(
        &self,
        request_id: RequestId,
        deadline: Option<Instant>,
    ) -> Result<HttpReceiptQueryResult, ClientError> {
        let path = substitute_selector(
            QUERY_RECEIPT_PATH,
            "{request_id}",
            &hex64_lower(request_id.as_bytes()),
        );
        let body = self.get_with_deadline(&path, deadline)?;
        let result = HttpReceiptQueryResult::decode(&body)?;
        if result.request_id() != request_id {
            return Err(ClientError::ReceiptQuerySelectorMismatch {
                expected: request_id,
                actual: result.request_id(),
            });
        }
        Ok(result)
    }

    /// Queries `GET /v1/senders/{sender}/next-nonce`.
    pub fn query_next_nonce(
        &self,
        sender: Address,
    ) -> Result<HttpNextNonceQueryResult, ClientError> {
        let path = substitute_selector(
            QUERY_NEXT_NONCE_PATH,
            "{sender}",
            &hex64_lower(sender.as_bytes()),
        );
        let body = self.get(&path)?;
        let result = HttpNextNonceQueryResult::decode(&body)?;
        if result.sender() != sender {
            return Err(ClientError::NextNonceQuerySelectorMismatch {
                expected: sender,
                actual: result.sender(),
            });
        }
        Ok(result)
    }

    /// Submits one canonical `SubmitTransaction` event and returns the
    /// server's bounded result, after independently verifying the result is
    /// bound to the exact request id the caller supplied.
    pub fn submit_transaction(
        &self,
        request: SubmitTransactionRequest,
    ) -> Result<HttpNodeResult, ClientError> {
        let event = NodeEvent::new(
            request.chain_id,
            request.protocol_version,
            request.epoch,
            request.request_id,
            NodeEventKind::SubmitTransaction,
            request.signed_transaction_bytes,
        )?;
        let body = event.encode()?;

        let wire_request = WireRequest {
            method: Method::Post,
            path: NODE_EVENT_PATH.to_string(),
            content_type: Some(NODE_EVENT_MEDIA_TYPE),
            body,
            deadline: None,
        };
        let response = self.transport.send(&wire_request)?;
        let body = expect_success(response, NODE_RESULT_MEDIA_TYPE)?;
        let result = HttpNodeResult::decode(&body)?;

        if result.request_id() != request.request_id {
            return Err(ClientError::SubmitResponseRequestIdMismatch {
                expected: request.request_id,
                actual: result.request_id(),
            });
        }
        Ok(result)
    }

    /// Polls `query_receipt` until a present receipt is observed or one of
    /// `bounds`'s explicit attempt/elapsed-time bounds is reached.
    ///
    /// Receipt absence is normal while a submitted transaction is still
    /// in flight; this method exists so a caller never has to hand-write an
    /// unbounded polling loop. It creates no background worker: every
    /// attempt and every sleep happens on the calling thread.
    pub fn wait_for_receipt(
        &self,
        request_id: RequestId,
        bounds: &ReceiptPollBounds,
    ) -> Result<HttpReceiptQueryResult, ClientError> {
        let start = Instant::now();
        let deadline = start
            .checked_add(bounds.max_elapsed)
            .ok_or(ClientError::ReceiptPollDeadlineOverflow)?;
        let mut backoff = bounds.initial_backoff;
        let mut attempt: u32 = 0;
        loop {
            if Instant::now() >= deadline {
                return Err(ClientError::ReceiptPollExhausted {
                    attempts: attempt,
                    elapsed: start.elapsed(),
                });
            }
            attempt += 1;
            let result = match self.query_receipt_with_deadline(request_id, Some(deadline)) {
                Ok(result) => result,
                Err(ClientError::Transport(
                    crate::transport::TransportError::RequestDeadlineExceeded,
                )) if Instant::now() >= deadline => {
                    return Err(ClientError::ReceiptPollExhausted {
                        attempts: attempt,
                        elapsed: start.elapsed(),
                    });
                }
                Err(error) => return Err(error),
            };
            if matches!(result, HttpReceiptQueryResult::Present { .. }) {
                return Ok(result);
            }
            if attempt >= bounds.max_attempts.get() || Instant::now() >= deadline {
                return Err(ClientError::ReceiptPollExhausted {
                    attempts: attempt,
                    elapsed: start.elapsed(),
                });
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            std::thread::sleep(backoff.min(bounds.max_backoff).min(remaining));
            backoff = backoff
                .checked_mul(2)
                .unwrap_or(bounds.max_backoff)
                .min(bounds.max_backoff);
        }
    }

    fn get(&self, path: &str) -> Result<Vec<u8>, ClientError> {
        self.get_with_deadline(path, None)
    }

    fn get_with_deadline(
        &self,
        path: &str,
        deadline: Option<Instant>,
    ) -> Result<Vec<u8>, ClientError> {
        let request = WireRequest {
            method: Method::Get,
            path: path.to_string(),
            content_type: None,
            body: Vec::new(),
            deadline,
        };
        let response = self.transport.send(&request)?;
        expect_success(response, QUERY_RESULT_MEDIA_TYPE)
    }
}

fn expect_success(
    response: crate::transport::WireResponse,
    expected_content_type: &'static str,
) -> Result<Vec<u8>, ClientError> {
    if response.status != 200 {
        return Err(ClientError::UnexpectedStatus {
            status: response.status,
            body: String::from_utf8_lossy(&response.body).into_owned(),
        });
    }
    let matches_expected = response
        .content_type
        .as_deref()
        .is_some_and(|value| value.eq_ignore_ascii_case(expected_content_type));
    if !matches_expected {
        return Err(ClientError::UnexpectedContentType {
            expected: expected_content_type,
            actual: response.content_type,
        });
    }
    Ok(response.body)
}

fn substitute_selector(template: &str, placeholder: &str, value: &str) -> String {
    template.replacen(placeholder, value, 1)
}

fn hex64_lower(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::LocalSigner;
    use crate::transaction::{TransactionRequest, build_signed_transaction};
    use crate::transport::{TransportError, WireResponse};
    use abi::AccessManifest;
    use objects::ObjectRef;
    use protocol_types::{Digest32, HashAlgorithmId, SignatureSchemeId};
    use std::cell::RefCell;

    struct FakeTransport {
        responses: RefCell<Vec<Result<WireResponse, TransportError>>>,
        requests: RefCell<Vec<WireRequest>>,
    }

    impl FakeTransport {
        fn new(responses: Vec<Result<WireResponse, TransportError>>) -> Self {
            Self {
                responses: RefCell::new(responses),
                requests: RefCell::new(Vec::new()),
            }
        }
    }

    impl Transport for FakeTransport {
        fn send(&self, request: &WireRequest) -> Result<WireResponse, TransportError> {
            self.requests.borrow_mut().push(request.clone());
            self.responses
                .borrow_mut()
                .pop()
                .expect("fake transport ran out of scripted responses")
        }
    }

    struct DeadlineTransport;

    impl Transport for DeadlineTransport {
        fn send(&self, request: &WireRequest) -> Result<WireResponse, TransportError> {
            assert!(request.deadline.is_some());
            std::thread::sleep(Duration::from_millis(150));
            Err(TransportError::RequestDeadlineExceeded)
        }
    }

    fn ok_response(content_type: &str, body: Vec<u8>) -> Result<WireResponse, TransportError> {
        Ok(WireResponse {
            status: 200,
            content_type: Some(content_type.to_string()),
            body,
        })
    }

    fn sample_signed_transaction_bytes() -> Vec<u8> {
        let signer = LocalSigner::from_seed([0xA5; 32]);
        let request = TransactionRequest {
            chain_id: ChainId::new("sunrise-devnet").unwrap(),
            protocol_version: ProtocolVersion::new(3),
            epoch: Epoch::new(5),
            nonce: 0,
            access_manifest: AccessManifest::new(),
            module_ref: ObjectRef {
                id: ObjectId::new([0x33; 32]),
                version: 1,
                digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x44; 32]),
            },
            entrypoint: "noop".to_string(),
            args: Vec::new(),
            gas_limit: 1,
            fee_payment: None,
        };
        build_signed_transaction(&signer, SignatureSchemeId::Ed25519, request).unwrap()
    }

    #[test]
    fn query_next_nonce_builds_the_exact_hex_selector_path() {
        let sender = Address::new([0xAB; 32]);
        let result = HttpNextNonceQueryResult::new(sender, Epoch::new(3), 7);
        let transport = FakeTransport::new(vec![ok_response(
            QUERY_RESULT_MEDIA_TYPE,
            result.encode().unwrap(),
        )]);
        let client = Client::new(transport);

        let decoded = client.query_next_nonce(sender).unwrap();
        assert_eq!(decoded, result);

        let requests = client.transport().requests.borrow();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].path,
            format!("/v1/senders/{}/next-nonce", "ab".repeat(32))
        );
        assert_eq!(requests[0].method, Method::Get);
    }

    #[test]
    fn query_methods_reject_results_for_another_selector() {
        let requested_object = ObjectId::new([0x10; 32]);
        let returned_object = ObjectId::new([0x11; 32]);
        let object_transport = FakeTransport::new(vec![ok_response(
            QUERY_RESULT_MEDIA_TYPE,
            HttpObjectQueryResult::Absent {
                object_id: returned_object,
            }
            .encode()
            .unwrap(),
        )]);
        let object_error = Client::new(object_transport)
            .query_object(requested_object)
            .unwrap_err();
        assert!(matches!(
            object_error,
            ClientError::ObjectQuerySelectorMismatch { expected, actual }
                if expected == requested_object && actual == returned_object
        ));

        let requested_receipt = RequestId::new([0x20; 32]).unwrap();
        let returned_receipt = RequestId::new([0x21; 32]).unwrap();
        let receipt_transport = FakeTransport::new(vec![ok_response(
            QUERY_RESULT_MEDIA_TYPE,
            HttpReceiptQueryResult::Absent {
                request_id: returned_receipt,
            }
            .encode()
            .unwrap(),
        )]);
        let receipt_error = Client::new(receipt_transport)
            .query_receipt(requested_receipt)
            .unwrap_err();
        assert!(matches!(
            receipt_error,
            ClientError::ReceiptQuerySelectorMismatch { expected, actual }
                if expected == requested_receipt && actual == returned_receipt
        ));

        let requested_sender = Address::new([0x30; 32]);
        let returned_sender = Address::new([0x31; 32]);
        let nonce_transport = FakeTransport::new(vec![ok_response(
            QUERY_RESULT_MEDIA_TYPE,
            HttpNextNonceQueryResult::new(returned_sender, Epoch::new(3), 0)
                .encode()
                .unwrap(),
        )]);
        let nonce_error = Client::new(nonce_transport)
            .query_next_nonce(requested_sender)
            .unwrap_err();
        assert!(matches!(
            nonce_error,
            ClientError::NextNonceQuerySelectorMismatch { expected, actual }
                if expected == requested_sender && actual == returned_sender
        ));
    }

    #[test]
    fn query_context_rejects_an_unexpected_status() {
        let transport = FakeTransport::new(vec![Ok(WireResponse {
            status: 503,
            content_type: Some("text/plain; charset=utf-8".to_string()),
            body: b"query-unavailable".to_vec(),
        })]);
        let client = Client::new(transport);

        let error = client.query_context().unwrap_err();
        assert!(matches!(
            error,
            ClientError::UnexpectedStatus { status: 503, .. }
        ));
    }

    #[test]
    fn query_context_rejects_an_unexpected_content_type() {
        let transport = FakeTransport::new(vec![Ok(WireResponse {
            status: 200,
            content_type: Some("application/octet-stream".to_string()),
            body: vec![],
        })]);
        let client = Client::new(transport);

        let error = client.query_context().unwrap_err();
        assert!(matches!(error, ClientError::UnexpectedContentType { .. }));
    }

    #[test]
    fn query_context_rejects_a_missing_content_type() {
        let transport = FakeTransport::new(vec![Ok(WireResponse {
            status: 200,
            content_type: None,
            body: vec![],
        })]);
        let client = Client::new(transport);

        let error = client.query_context().unwrap_err();
        assert!(matches!(error, ClientError::UnexpectedContentType { .. }));
    }

    fn sample_expected_context() -> crate::context::ExpectedProtocolContext {
        crate::context::ExpectedProtocolContext::new(
            ChainId::new("sunrise-devnet").unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(5),
            protocol_types::HashSuiteId::new(1),
            1,
            1,
            1,
            protocol_types::AtomicityDomainId::new([0x44; 32]).unwrap(),
        )
        .unwrap()
    }

    fn sample_matching_context_result() -> HttpContextQueryResult {
        HttpContextQueryResult::new(
            ChainId::new("sunrise-devnet").unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(5),
            protocol_types::HashSuiteId::new(1),
            1,
            1,
            1,
            protocol_types::AtomicityDomainId::new([0x44; 32]).unwrap(),
            vec![0xAA],
        )
        .unwrap()
    }

    #[test]
    fn query_verified_context_returns_the_context_on_an_exact_match() {
        let transport = FakeTransport::new(vec![ok_response(
            QUERY_RESULT_MEDIA_TYPE,
            sample_matching_context_result().encode().unwrap(),
        )]);
        let client = Client::new(transport);

        let result = client
            .query_verified_context(&sample_expected_context())
            .unwrap();
        assert_eq!(result, sample_matching_context_result());
    }

    #[test]
    fn query_verified_context_rejects_a_mismatched_chain_id() {
        let mismatched = HttpContextQueryResult::new(
            ChainId::new("some-other-chain").unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(5),
            protocol_types::HashSuiteId::new(1),
            1,
            1,
            1,
            protocol_types::AtomicityDomainId::new([0x44; 32]).unwrap(),
            vec![0xAA],
        )
        .unwrap();
        let transport = FakeTransport::new(vec![ok_response(
            QUERY_RESULT_MEDIA_TYPE,
            mismatched.encode().unwrap(),
        )]);
        let client = Client::new(transport);

        let error = client
            .query_verified_context(&sample_expected_context())
            .unwrap_err();
        assert!(matches!(
            error,
            ClientError::ProtocolContextMismatch(
                crate::context::ProtocolContextMismatch::ChainId { .. }
            )
        ));
    }

    #[test]
    fn submit_transaction_rejects_a_result_bound_to_another_request_id() {
        let submitted_id = RequestId::new([0x01; 32]).unwrap();
        let other_id = RequestId::new([0x02; 32]).unwrap();
        let mismatched_result = HttpNodeResult::new(other_id, vec![]).unwrap();
        let transport = FakeTransport::new(vec![ok_response(
            NODE_RESULT_MEDIA_TYPE,
            mismatched_result.encode().unwrap(),
        )]);
        let client = Client::new(transport);

        let error = client
            .submit_transaction(SubmitTransactionRequest {
                chain_id: ChainId::new("sunrise-devnet").unwrap(),
                protocol_version: ProtocolVersion::new(3),
                epoch: Epoch::new(5),
                request_id: submitted_id,
                signed_transaction_bytes: sample_signed_transaction_bytes(),
            })
            .unwrap_err();

        assert!(matches!(
            error,
            ClientError::SubmitResponseRequestIdMismatch { expected, actual }
                if expected == submitted_id && actual == other_id
        ));
    }

    #[test]
    fn submit_transaction_accepts_a_correctly_bound_result() {
        let request_id = RequestId::new([0x03; 32]).unwrap();
        let matching_result = HttpNodeResult::new(request_id, vec![]).unwrap();
        let transport = FakeTransport::new(vec![ok_response(
            NODE_RESULT_MEDIA_TYPE,
            matching_result.encode().unwrap(),
        )]);
        let client = Client::new(transport);

        let outcome = client
            .submit_transaction(SubmitTransactionRequest {
                chain_id: ChainId::new("sunrise-devnet").unwrap(),
                protocol_version: ProtocolVersion::new(3),
                epoch: Epoch::new(5),
                request_id,
                signed_transaction_bytes: sample_signed_transaction_bytes(),
            })
            .unwrap();

        assert_eq!(outcome.request_id(), request_id);
        let requests = client.transport().requests.borrow();
        assert_eq!(requests[0].method, Method::Post);
        assert_eq!(requests[0].path, NODE_EVENT_PATH);
        assert_eq!(requests[0].content_type, Some(NODE_EVENT_MEDIA_TYPE));
    }

    #[test]
    fn wait_for_receipt_returns_as_soon_as_present_is_observed() {
        let request_id = RequestId::new([0x04; 32]).unwrap();
        let absent = HttpReceiptQueryResult::Absent { request_id };
        let present = HttpReceiptQueryResult::Present {
            request_id,
            event_digest: protocol_types::Digest32::new(
                protocol_types::HashAlgorithmId::Sha2_256,
                [0x11; 32],
            ),
            dedup_record_bytes: sample_dedup_record_bytes(request_id),
        };
        // `FakeTransport::send` pops from the end, so push in reverse order.
        let transport = FakeTransport::new(vec![
            ok_response(QUERY_RESULT_MEDIA_TYPE, present.encode().unwrap()),
            ok_response(QUERY_RESULT_MEDIA_TYPE, absent.encode().unwrap()),
        ]);
        let client = Client::new(transport);

        let bounds = ReceiptPollBounds {
            max_attempts: NonZeroU32::new(5).unwrap(),
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(5),
            max_elapsed: Duration::from_secs(5),
        };
        let result = client.wait_for_receipt(request_id, &bounds).unwrap();
        assert_eq!(result, present);
        let requests = client.transport().requests.borrow();
        assert_eq!(requests.len(), 2);
        assert!(requests.iter().all(|request| request.deadline.is_some()));
    }

    #[test]
    fn wait_for_receipt_stops_at_the_attempt_bound() {
        let request_id = RequestId::new([0x05; 32]).unwrap();
        let absent = HttpReceiptQueryResult::Absent { request_id };
        let transport = FakeTransport::new(vec![
            ok_response(QUERY_RESULT_MEDIA_TYPE, absent.encode().unwrap()),
            ok_response(QUERY_RESULT_MEDIA_TYPE, absent.encode().unwrap()),
        ]);
        let client = Client::new(transport);

        let bounds = ReceiptPollBounds {
            max_attempts: NonZeroU32::new(2).unwrap(),
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(2),
            max_elapsed: Duration::from_secs(5),
        };
        let error = client.wait_for_receipt(request_id, &bounds).unwrap_err();
        assert!(matches!(
            error,
            ClientError::ReceiptPollExhausted { attempts: 2, .. }
        ));
    }

    #[test]
    fn wait_for_receipt_honors_a_zero_elapsed_bound_without_dispatch() {
        let request_id = RequestId::new([0x09; 32]).unwrap();
        let client = Client::new(FakeTransport::new(Vec::new()));
        let bounds = ReceiptPollBounds {
            max_attempts: NonZeroU32::new(1).unwrap(),
            initial_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
            max_elapsed: Duration::ZERO,
        };

        let error = client.wait_for_receipt(request_id, &bounds).unwrap_err();
        assert!(matches!(
            error,
            ClientError::ReceiptPollExhausted { attempts: 0, .. }
        ));
        assert!(client.transport().requests.borrow().is_empty());
    }

    #[test]
    fn wait_for_receipt_maps_its_expired_request_deadline_to_poll_exhaustion() {
        let request_id = RequestId::new([0x0A; 32]).unwrap();
        let client = Client::new(DeadlineTransport);
        let bounds = ReceiptPollBounds {
            max_attempts: NonZeroU32::new(2).unwrap(),
            initial_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
            max_elapsed: Duration::from_millis(100),
        };

        let error = client.wait_for_receipt(request_id, &bounds).unwrap_err();
        assert!(matches!(
            error,
            ClientError::ReceiptPollExhausted { attempts: 1, .. }
        ));
    }

    fn sample_dedup_record_bytes(request_id: RequestId) -> Vec<u8> {
        let record = node_core::NodeDedupRecord::new(
            request_id,
            protocol_types::Digest32::new(protocol_types::HashAlgorithmId::Sha2_256, [0x11; 32]),
            vec![],
        )
        .unwrap();
        record.encode().unwrap()
    }
}
