//! `context`: query `GET /v1/context`.

use std::ffi::OsString;

use sunrise_edge_client::{Client, Transport};

use crate::args::{parse_flags, scalar};
use crate::error::CliError;
use crate::net::{connect, tls_flag_specs};
use crate::output::{bounded_hex_field, sanitize_line};

const ENDPOINT: &str = "--endpoint";

/// Runs `context --endpoint <host:port> [--tls-server-name <dns-name>
/// --tls-ca-cert-der-file <path>]`.
pub fn run<I>(args: I) -> Result<(), CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut specs = vec![scalar(ENDPOINT)];
    specs.extend(tls_flag_specs());
    let parsed = parse_flags(args, &specs)?;
    let endpoint = parsed.require(ENDPOINT)?;

    let client = connect(endpoint, &parsed)?;
    execute(&client)
}

fn execute<T>(client: &Client<T>) -> Result<(), CliError>
where
    T: Transport,
{
    let context = client.query_context()?;

    // `chain_id` is server-derived free-form text (unlike every other field
    // here, which is a fixed-size hex identifier): sanitize it so a
    // malicious or misconfigured server cannot inject extra terminal lines
    // into this deterministic `key=value` output.
    println!("{}", chain_id_line(context.chain_id().as_str()));
    println!("protocol_version={}", context.protocol_version().get());
    println!("epoch={}", context.epoch().get());
    println!("hash_suite_id={}", context.hash_suite_id().get());
    println!(
        "transaction_auth_profile_id={}",
        context.transaction_auth_profile_id()
    );
    println!("signature_scheme_id={}", context.signature_scheme_id());
    println!("address_binding_id={}", context.address_binding_id());
    println!("domain={}", context.domain());
    let (hex, truncated) = bounded_hex_field(context.protocol_config_bytes());
    println!(
        "protocol_config_bytes_len={}",
        context.protocol_config_bytes().len()
    );
    println!("protocol_config_bytes_truncated={truncated}");
    println!("protocol_config_bytes={hex}");
    Ok(())
}

fn chain_id_line(chain_id: &str) -> String {
    format!("chain_id={}", sanitize_line(chain_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{FakeTransport, query_ok};
    use sunrise_edge_client::{
        AtomicityDomainId, ChainId, Epoch, HashSuiteId, HttpContextQueryResult, ProtocolVersion,
        QUERY_CONTEXT_PATH,
    };

    #[test]
    fn execute_queries_the_context_path() {
        let result = HttpContextQueryResult::new(
            ChainId::new("test-chain").unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(5),
            HashSuiteId::new(1),
            1,
            1,
            1,
            AtomicityDomainId::new([0x22; 32]).unwrap(),
            vec![0xAA],
        )
        .unwrap();
        let transport = FakeTransport::new(vec![query_ok(result.encode().unwrap())]);
        let client = Client::new(transport);

        execute(&client).unwrap();
        let requests = client.transport().requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].path, QUERY_CONTEXT_PATH);
    }

    #[test]
    fn chain_id_line_sanitizes_embedded_control_characters() {
        // `ChainId::new` only rejects an empty/whitespace-only value, so a
        // misconfigured or malicious server can still return a chain id
        // containing control characters; the printed line must stay single-
        // line regardless.
        let line = chain_id_line("chain\nid\r\ninjected=line");

        assert!(line.starts_with("chain_id="));
        assert_eq!(line.lines().count(), 1);
        assert!(!line.contains('\n'));
        assert!(!line.contains('\r'));
    }

    #[test]
    fn execute_succeeds_with_a_chain_id_containing_control_characters() {
        let result = HttpContextQueryResult::new(
            ChainId::new("chain\nid\r\ninjected=line").unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(5),
            HashSuiteId::new(1),
            1,
            1,
            1,
            AtomicityDomainId::new([0x22; 32]).unwrap(),
            vec![0xAA],
        )
        .unwrap();
        let transport = FakeTransport::new(vec![query_ok(result.encode().unwrap())]);
        let client = Client::new(transport);

        assert!(execute(&client).is_ok());
    }
}
