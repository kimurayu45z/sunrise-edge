//! Test-only fake [`Transport`] shared by command unit tests.

use std::cell::RefCell;

use sunrise_edge_client::{Transport, TransportError, WireRequest, WireResponse};

/// A deterministic fake transport that returns pre-scripted responses.
///
/// Responses are consumed in the order they are given (first pushed, first
/// returned), mirroring the order commands issue requests in.
pub struct FakeTransport {
    responses: RefCell<Vec<Result<WireResponse, TransportError>>>,
    requests: RefCell<Vec<WireRequest>>,
}

impl FakeTransport {
    /// Creates a fake transport that returns `responses` in order.
    pub fn new(responses: Vec<Result<WireResponse, TransportError>>) -> Self {
        let mut reversed = responses;
        reversed.reverse();
        Self {
            responses: RefCell::new(reversed),
            requests: RefCell::new(Vec::new()),
        }
    }

    /// Returns every request this transport observed, in order.
    pub fn requests(&self) -> Vec<WireRequest> {
        self.requests.borrow().clone()
    }
}

impl Transport for FakeTransport {
    fn send(&self, request: &WireRequest) -> Result<WireResponse, TransportError> {
        self.requests.borrow_mut().push(request.clone());
        self.responses
            .borrow_mut()
            .pop()
            .unwrap_or(Err(TransportError::RequestDeadlineExceeded))
    }
}

/// Builds a well-formed `200` response with the query-result media type.
pub fn query_ok(body: Vec<u8>) -> Result<WireResponse, TransportError> {
    Ok(WireResponse {
        status: 200,
        content_type: Some(sunrise_edge_client::QUERY_RESULT_MEDIA_TYPE.to_string()),
        body,
    })
}

/// Builds a well-formed `200` node-event-result response.
pub fn node_result_ok(body: Vec<u8>) -> Result<WireResponse, TransportError> {
    Ok(WireResponse {
        status: 200,
        content_type: Some(sunrise_edge_client::NODE_RESULT_MEDIA_TYPE.to_string()),
        body,
    })
}
