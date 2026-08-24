# AWS Lambda HTTP API ingress adapter

This adapter maps Amazon API Gateway HTTP API payload format `2.0` events to the shared
Web ingress contract and converts Web responses back to explicit Lambda proxy results.
It has no AWS SDK dependency and performs no control-plane operation.

Canonical event requests must arrive as strict, canonical base64. The mapper checks
encoded length before decoding, accepts only the exact base64 alphabet and padding,
reconstructs only the three headers used by the shared contract, and rejects non-binary
event bodies. All Lambda responses are emitted as base64 so canonical result bytes are
not text-transcoded.

API Gateway currently permits 10 MB API payloads, while synchronous Lambda request and
buffered response payloads are limited to 6 MB and include the JSON event/result
envelope. This adapter therefore uses conservative 4 MiB request and response budgets.
That is below the shared protocol envelope and remains an explicit As-Is conformance
gap.

Required Lambda environment configuration:

- `SUNRISE_NODE_CORE_URL`: exact HTTPS node-core `/v1/events` endpoint.
- `SUNRISE_NODE_CORE_BEARER_TOKEN`: encrypted secret value supplied at runtime, never
  checked into source or deployment templates.
- `SUNRISE_NODE_CORE_TIMEOUT_MS`: optional integer from 1 through 30000; defaults to
  5000 and must remain below the Lambda timeout.

Run static checks and permission-free mapper tests with:

```bash
deno task check
```

No unauthenticated API Gateway deployment template is included. Production must define
JWT scopes, IAM, or a custom authorizer; private networking or mutually authenticated
node-core transport; Secrets Manager/KMS rotation; reserved concurrency, throttling,
WAF, logs/traces/metrics; durable deduplication/outbox; fault/load tests; and staged
deployment/rollback. The actual API integration must explicitly set payload format
version `2.0`.
