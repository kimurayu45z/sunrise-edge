//! `next-nonce`: query `GET /v1/senders/{sender}/next-nonce`.

use std::ffi::OsString;

use sunrise_edge_client::{Address, Client, Transport};

use crate::args::{parse_flags, scalar};
use crate::error::CliError;
use crate::hex::decode_hex_32;
use crate::net::{connect, tls_flag_specs};

const ENDPOINT: &str = "--endpoint";
const SENDER: &str = "--sender";

/// Runs `next-nonce --endpoint <host:port> --sender <hex> [--tls-server-name
/// <dns-name> --tls-ca-cert-der-file <path>]`.
pub fn run<I>(args: I) -> Result<(), CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut specs = vec![scalar(ENDPOINT), scalar(SENDER)];
    specs.extend(tls_flag_specs());
    let parsed = parse_flags(args, &specs)?;
    let endpoint = parsed.require(ENDPOINT)?;
    let sender = Address::new(decode_hex_32(SENDER, parsed.require(SENDER)?)?);

    let client = connect(endpoint, &parsed)?;
    execute(&client, sender)
}

fn execute<T>(client: &Client<T>, sender: Address) -> Result<(), CliError>
where
    T: Transport,
{
    let result = client.query_next_nonce(sender)?;

    println!("sender={}", result.sender());
    println!("epoch={}", result.epoch().get());
    println!("next_nonce={}", result.next_nonce());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{FakeTransport, query_ok};
    use sunrise_edge_client::{Epoch, HttpNextNonceQueryResult, QUERY_NEXT_NONCE_PATH};

    #[test]
    fn execute_queries_the_exact_hex_sender_path() {
        let sender = Address::new([0x09; 32]);
        let result = HttpNextNonceQueryResult::new(sender, Epoch::new(3), 7);
        let transport = FakeTransport::new(vec![query_ok(result.encode().unwrap())]);
        let client = Client::new(transport);

        execute(&client, sender).unwrap();

        let requests = client.transport().requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].path,
            QUERY_NEXT_NONCE_PATH.replace("{sender}", &"09".repeat(32))
        );
    }
}
