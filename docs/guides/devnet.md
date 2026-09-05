# Local devnet and Rust CLI

This guide starts the local, non-production Sunrise Edge devnet and drives it
with the Rust CLI. The devnet binds loopback only, is single-validator, and
must never be used to custody real assets or exposed beyond your own machine.

The commands assume the workspace has already been built once:

```bash
cargo build --workspace
```

## 1. Create development keys

Choose explicit paths and create sender, recipient, and distinct fee-treasury
development seed files. These are private, non-keystore development secrets,
each containing exactly 64 hexadecimal characters. The CLI requires permission
`0600` and rejects symlinks.

```bash
SENDER_SEED_FILE=/tmp/sunrise-edge-sender-seed
RECIPIENT_SEED_FILE=/tmp/sunrise-edge-recipient-seed
TREASURY_SEED_FILE=/tmp/sunrise-edge-treasury-seed
DEVNET_DATA_DIR=/tmp/sunrise-edge-devnet
umask 077
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$SENDER_SEED_FILE"
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$RECIPIENT_SEED_FILE"
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$TREASURY_SEED_FILE"
chmod 600 "$SENDER_SEED_FILE" "$RECIPIENT_SEED_FILE" "$TREASURY_SEED_FILE"
```

## 2. Derive addresses

Each command prints one `address=<64-hex-character address>` line. The values
depend on the random seeds, so this guide does not hard-code them.

```bash
SENDER_ADDRESS_LINE="$(cargo run -p sunrise-edge-cli -- address --seed-file "$SENDER_SEED_FILE")"
RECIPIENT_ADDRESS_LINE="$(cargo run -p sunrise-edge-cli -- address --seed-file "$RECIPIENT_SEED_FILE")"
TREASURY_ADDRESS_LINE="$(cargo run -p sunrise-edge-cli -- address --seed-file "$TREASURY_SEED_FILE")"
SENDER_OWNER="${SENDER_ADDRESS_LINE#address=}"
RECIPIENT_OWNER="${RECIPIENT_ADDRESS_LINE#address=}"
TREASURY_OWNER="${TREASURY_ADDRESS_LINE#address=}"
printf 'SENDER_OWNER=%s\nRECIPIENT_OWNER=%s\nTREASURY_OWNER=%s\n' \
  "$SENDER_OWNER" "$RECIPIENT_OWNER" "$TREASURY_OWNER"
```

## 3. Start the devnet

Run this in terminal A:

```bash
cargo run -p sunrise-edge-devnet -- \
  --data-dir "$DEVNET_DATA_DIR" \
  --listen 127.0.0.1:7400 \
  --chain-id sunrise-local-devnet \
  --epoch 0 \
  --dev-owner "$SENDER_OWNER" \
  --dev-owner "$RECIPIENT_OWNER" \
  --fee-treasury-owner "$TREASURY_OWNER" \
  --max-concurrent 16
```

Startup prints one line per seeded owner, including the treasury:

```text
owner=<owner> role=<dev-owner|fee-treasury> seed_status=<created|verified-existing> source=<object id> destination=<object id>
```

It also prints the preinstalled module identity:

```text
asset_id=<...> asset_account_type=<...> module_id=<...> module_version=<...> module_digest=<algorithm-label>:<hex digest>
```

Copy the sender owner's `source`, recipient owner's `destination`, treasury
owner's `destination`, `asset_id`, `module_id`, `module_version`, and
`module_digest`. The digest currently prints as `sha2-256:<hex>`: pass `1` for
`--module-digest-algorithm` and only the hexadecimal portion after the colon
for `--module-digest`.

## 4. Configure and query the CLI

In terminal B, set the exact values printed above. Replace the contents of the
quoted uppercase placeholders; do not copy shell angle brackets.

```bash
SENDER_SEED_FILE=/tmp/sunrise-edge-sender-seed
SENDER_OWNER="PASTE_SENDER_ADDRESS_PRINTED_IN_STEP_2"
RECIPIENT_OWNER="PASTE_RECIPIENT_ADDRESS_PRINTED_IN_STEP_2"
TREASURY_OWNER="PASTE_TREASURY_ADDRESS_PRINTED_IN_STEP_2"
SOURCE_OBJECT_ID="PASTE_SENDER_SOURCE_OBJECT_ID_PRINTED_IN_STEP_3"
DESTINATION_OBJECT_ID="PASTE_RECIPIENT_DESTINATION_OBJECT_ID_PRINTED_IN_STEP_3"
TREASURY_OBJECT_ID="PASTE_TREASURY_DESTINATION_OBJECT_ID_PRINTED_IN_STEP_3"
FEE_ASSET_ID="PASTE_ASSET_ID_PRINTED_IN_STEP_3"
MODULE_ID="PASTE_MODULE_ID_PRINTED_IN_STEP_3"
MODULE_VERSION="PASTE_MODULE_VERSION_PRINTED_IN_STEP_3"
MODULE_DIGEST_HEX="PASTE_HEX_AFTER_THE_MODULE_DIGEST_COLON"
REQUEST_ID="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
```

The expected values below are the operator's own locally trusted expectation,
not values copied from the untrusted server response. They must equal the
devnet configuration used in step 3 and this profile's fixed protocol values.
See [DR-0085](../architecture/decisions/0081-0087-cli-first-roadmap.md) and
[`TODO.md`](../../TODO.md#cli-first-node-production-gate) S1.

```bash
EXPECTED_CHAIN_ID="sunrise-local-devnet"
EXPECTED_PROTOCOL_VERSION=3
EXPECTED_EPOCH=0
EXPECTED_HASH_SUITE_ID=1
EXPECTED_DOMAIN="4444444444444444444444444444444444444444444444444444444444444444"

cargo run -p sunrise-edge-cli -- context --endpoint 127.0.0.1:7400
cargo run -p sunrise-edge-cli -- next-nonce --endpoint 127.0.0.1:7400 \
  --sender "$SENDER_OWNER"
cargo run -p sunrise-edge-cli -- object --endpoint 127.0.0.1:7400 \
  --object-id "$SOURCE_OBJECT_ID"
```

These queries do not change state.

## 5. Submit an asset transfer

The sender signs a debit from its seeded source into the recipient's existing
seeded destination. The destination remains owned by `RECIPIENT_OWNER` before
and after the transfer. Amounts are in the asset's smallest unit.

```bash
cargo run -p sunrise-edge-cli -- transfer \
  --endpoint 127.0.0.1:7400 \
  --seed-file "$SENDER_SEED_FILE" \
  --module-id "$MODULE_ID" \
  --module-version "$MODULE_VERSION" \
  --module-digest-algorithm 1 \
  --module-digest "$MODULE_DIGEST_HEX" \
  --source-object "$SOURCE_OBJECT_ID" \
  --destination-object "$DESTINATION_OBJECT_ID" \
  --destination-owner "$RECIPIENT_OWNER" \
  --amount 250 \
  --gas-limit 1000000 \
  --fee-asset-id "$FEE_ASSET_ID" \
  --max-fee 1000001 \
  --fee-treasury-object "$TREASURY_OBJECT_ID" \
  --request-id "$REQUEST_ID" \
  --expected-chain-id "$EXPECTED_CHAIN_ID" \
  --expected-protocol-version "$EXPECTED_PROTOCOL_VERSION" \
  --expected-epoch "$EXPECTED_EPOCH" \
  --expected-hash-suite-id "$EXPECTED_HASH_SUITE_ID" \
  --expected-domain "$EXPECTED_DOMAIN" \
  --wait \
  --wait-max-attempts 20 \
  --wait-initial-backoff-ms 10 \
  --wait-max-backoff-ms 50 \
  --wait-max-elapsed-ms 5000
```

`transfer` requires `--destination-owner`, all five `--expected-*` flags, and,
for this non-zero-fee devnet, the complete fee configuration shown above. It
rejects partial fee flags, zero max fee, a treasury equal to source or
destination, an invalid destination owner, or an invalid expected context
before network dispatch. It then verifies `/v1/context`, the source owner, and
the destination owner before signing. A rejected or execution-failed
submission is a typed non-zero-exit error, including with `--wait`.

## 6. Capture post-transfer state

Capture the receipt, all three current objects, and next nonce. These are the
pre-restart observations used in the next step.

```bash
OBSERVATION_PREFIX="/tmp/sunrise-edge-$REQUEST_ID"
cargo run -p sunrise-edge-cli -- receipt --endpoint 127.0.0.1:7400 \
  --request-id "$REQUEST_ID" > "$OBSERVATION_PREFIX.receipt"
cargo run -p sunrise-edge-cli -- object --endpoint 127.0.0.1:7400 \
  --object-id "$SOURCE_OBJECT_ID" > "$OBSERVATION_PREFIX.source"
cargo run -p sunrise-edge-cli -- object --endpoint 127.0.0.1:7400 \
  --object-id "$DESTINATION_OBJECT_ID" > "$OBSERVATION_PREFIX.destination"
cargo run -p sunrise-edge-cli -- object --endpoint 127.0.0.1:7400 \
  --object-id "$TREASURY_OBJECT_ID" > "$OBSERVATION_PREFIX.treasury"
cargo run -p sunrise-edge-cli -- next-nonce --endpoint 127.0.0.1:7400 \
  --sender "$SENDER_OWNER" > "$OBSERVATION_PREFIX.nonce"
```

## 7. Restart and compare

Stop the devnet in terminal A with `Ctrl-C`. Rerun the exact command from step
3 with the same data directory, chain id, and owners. Wait until all three
owners report `seed_status=verified-existing`, then run:

```bash
diff -u "$OBSERVATION_PREFIX.receipt" <(
  cargo run -p sunrise-edge-cli -- receipt --endpoint 127.0.0.1:7400 \
    --request-id "$REQUEST_ID"
)
diff -u "$OBSERVATION_PREFIX.source" <(
  cargo run -p sunrise-edge-cli -- object --endpoint 127.0.0.1:7400 \
    --object-id "$SOURCE_OBJECT_ID"
)
diff -u "$OBSERVATION_PREFIX.destination" <(
  cargo run -p sunrise-edge-cli -- object --endpoint 127.0.0.1:7400 \
    --object-id "$DESTINATION_OBJECT_ID"
)
diff -u "$OBSERVATION_PREFIX.treasury" <(
  cargo run -p sunrise-edge-cli -- object --endpoint 127.0.0.1:7400 \
    --object-id "$TREASURY_OBJECT_ID"
)
diff -u "$OBSERVATION_PREFIX.nonce" <(
  cargo run -p sunrise-edge-cli -- next-nonce --endpoint 127.0.0.1:7400 \
    --sender "$SENDER_OWNER"
)
```

Every `diff` must exit successfully with no output. This proves orderly
stop/reopen persistence for the observed state. It does not prove `kill -9`,
power-loss, torn-write, load, concurrency, or production SQLite suitability.

The automated E2E additionally replays one byte-identical signed request before
and after restart. The CLI intentionally exposes no raw replay command because
`transfer` re-queries the current nonce and object references before signing.

## Optional remote TLS transport

Every network command (`context`, `object`, `receipt`, `next-nonce`, and
`transfer`) accepts a paired optional flag set:

```text
--tls-server-name <dns-name> --tls-ca-cert-der-file <path>
```

With neither flag, `--endpoint` must be loopback and the CLI uses plaintext.
With both flags, `--endpoint` is an already-resolved remote `SocketAddr`; the
CLI performs no DNS resolution. Supplying exactly one flag fails locally before
network dispatch.

```bash
cargo run -p sunrise-edge-cli -- context \
  --endpoint 203.0.113.10:7443 \
  --tls-server-name node.example.internal \
  --tls-ca-cert-der-file /etc/sunrise-edge/ca.der
```

The DNS name is used for both SNI and hostname validation and is never inferred
from the endpoint IP. The CA file must contain exactly one non-empty DER-encoded
X.509 certificate no larger than
`sunrise_edge_client::MAX_CA_CERTIFICATE_DER_BYTES` (16 KiB). The client does
not use the system trust store, accept PEM/bundles, or present an mTLS client
certificate.

TLS authenticates the endpoint, not the intended chain or protocol. Therefore
`transfer` still requires the independently configured `--expected-*` values
and validates `/v1/context` before nonce/object queries or signing. Certificate
revocation, rotation, lifecycle management, and operator CA distribution remain
part of later production work.
