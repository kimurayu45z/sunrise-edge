//! `receipt`: query `GET /v1/receipts/{request_id}`.

use std::ffi::OsString;

use sunrise_edge_client::{Client, HttpReceiptQueryResult, RequestId, Transport};

use crate::args::{parse_flags, scalar};
use crate::error::CliError;
use crate::hex::decode_hex_32;
use crate::net::{connect, tls_flag_specs};
use crate::output::bounded_hex_field;

const ENDPOINT: &str = "--endpoint";
const REQUEST_ID: &str = "--request-id";

/// Runs `receipt --endpoint <host:port> --request-id <hex> [--tls-server-name
/// <dns-name> --tls-ca-cert-der-file <path>]`.
pub fn run<I>(args: I) -> Result<(), CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut specs = vec![scalar(ENDPOINT), scalar(REQUEST_ID)];
    specs.extend(tls_flag_specs());
    let parsed = parse_flags(args, &specs)?;
    let endpoint = parsed.require(ENDPOINT)?;
    let request_id_bytes = decode_hex_32(REQUEST_ID, parsed.require(REQUEST_ID)?)?;
    let request_id = RequestId::new(request_id_bytes)?;

    let client = connect(endpoint, &parsed)?;
    execute(&client, request_id)
}

fn execute<T>(client: &Client<T>, request_id: RequestId) -> Result<(), CliError>
where
    T: Transport,
{
    let result = client.query_receipt(request_id)?;

    println!("request_id={request_id}");
    match result {
        HttpReceiptQueryResult::Absent { .. } => {
            println!("status=absent");
        }
        HttpReceiptQueryResult::Present {
            event_digest,
            dedup_record_bytes,
            ..
        } => {
            println!("status=present");
            println!(
                "event_digest_algorithm={}",
                event_digest.algorithm().as_u16()
            );
            println!("event_digest={event_digest}");
            let (hex, truncated) = bounded_hex_field(&dedup_record_bytes);
            println!("dedup_record_bytes_len={}", dedup_record_bytes.len());
            println!("dedup_record_bytes_truncated={truncated}");
            println!("dedup_record_bytes={hex}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{FakeTransport, query_ok};
    use sunrise_edge_client::QUERY_RECEIPT_PATH;

    #[test]
    fn execute_queries_the_exact_hex_receipt_path() {
        let request_id = RequestId::new([0x08; 32]).unwrap();
        let result = HttpReceiptQueryResult::Absent { request_id };
        let transport = FakeTransport::new(vec![query_ok(result.encode().unwrap())]);
        let client = Client::new(transport);

        execute(&client, request_id).unwrap();

        let requests = client.transport().requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].path,
            QUERY_RECEIPT_PATH.replace("{request_id}", &"08".repeat(32))
        );
    }
}
