//! `object`: query `GET /v1/objects/{object_id}`.

use std::ffi::OsString;

use sunrise_edge_client::{Client, HttpObjectQueryResult, ObjectId, Transport};

use crate::args::{parse_flags, scalar};
use crate::error::CliError;
use crate::hex::decode_hex_32;
use crate::net::{connect, tls_flag_specs};
use crate::output::bounded_hex_field;

const ENDPOINT: &str = "--endpoint";
const OBJECT_ID: &str = "--object-id";

/// Runs `object --endpoint <host:port> --object-id <hex> [--tls-server-name
/// <dns-name> --tls-ca-cert-der-file <path>]`.
pub fn run<I>(args: I) -> Result<(), CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut specs = vec![scalar(ENDPOINT), scalar(OBJECT_ID)];
    specs.extend(tls_flag_specs());
    let parsed = parse_flags(args, &specs)?;
    let endpoint = parsed.require(ENDPOINT)?;
    let object_id = ObjectId::new(decode_hex_32(OBJECT_ID, parsed.require(OBJECT_ID)?)?);

    let client = connect(endpoint, &parsed)?;
    execute(&client, object_id)
}

fn execute<T>(client: &Client<T>, object_id: ObjectId) -> Result<(), CliError>
where
    T: Transport,
{
    let result = client.query_object(object_id)?;

    println!("object_id={object_id}");
    match result {
        HttpObjectQueryResult::Absent { .. } => {
            println!("status=absent");
        }
        HttpObjectQueryResult::Tombstoned {
            head_revision,
            last_object_version,
            ..
        } => {
            println!("status=tombstoned");
            println!("head_revision={}", head_revision.get());
            println!("last_object_version={}", last_object_version.get());
        }
        HttpObjectQueryResult::CurrentInline {
            head_revision,
            object_version,
            digest,
            canonical_object_bytes,
            ..
        } => {
            println!("status=current_inline");
            println!("head_revision={}", head_revision.get());
            println!("object_version={}", object_version.get());
            println!("digest_algorithm={}", digest.algorithm().as_u16());
            println!("digest={digest}");
            let (hex, truncated) = bounded_hex_field(&canonical_object_bytes);
            println!("object_bytes_len={}", canonical_object_bytes.len());
            println!("object_bytes_truncated={truncated}");
            println!("object_bytes={hex}");
        }
        HttpObjectQueryResult::HistoricalCurrentInline { .. } => {
            // `Client::query_object` rejects this before returning. Keep the
            // match exhaustive if another in-process caller supplies it.
            println!("status=historical_current_inline_unverified");
        }
        HttpObjectQueryResult::CurrentBlobReference {
            head_revision,
            object_version,
            digest,
            blob_digest,
            ..
        } => {
            println!("status=current_blob_reference");
            println!("head_revision={}", head_revision.get());
            println!("object_version={}", object_version.get());
            println!("digest_algorithm={}", digest.algorithm().as_u16());
            println!("digest={digest}");
            println!("blob_digest_algorithm={}", blob_digest.algorithm().as_u16());
            println!("blob_digest={blob_digest}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{FakeTransport, query_ok};
    use sunrise_edge_client::QUERY_OBJECT_PATH;

    #[test]
    fn execute_queries_the_exact_hex_object_path() {
        let object_id = ObjectId::new([0x07; 32]);
        let result = HttpObjectQueryResult::Absent { object_id };
        let transport = FakeTransport::new(vec![query_ok(result.encode().unwrap())]);
        let client = Client::new(transport);

        execute(&client, object_id).unwrap();

        let requests = client.transport().requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].path,
            QUERY_OBJECT_PATH.replace("{object_id}", &"07".repeat(32))
        );
    }
}
