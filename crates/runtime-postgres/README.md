# PostgreSQL runtime schema

This crate applies and verifies Sunrise Edge's generation-one normalized
PostgreSQL schema, bootstraps an exact `(chain, validator, atomicity domain)`
metadata row, and implements `StructuredDurableDomainStateStore` over an
explicit bounded synchronous connection pool.

The structured store performs fenced state/receipt reads and serializable
state/receipt/outbox commits with complete read assertions, checked revisions,
per-statement remaining-deadline timeouts, bounded unchanged-envelope
serialization retry, and conservative commit-result classification.
It also implements `IndexedOutboxRepository` with exact-request and stable
indexed due claims, same-lease reconciliation, expired-lease replacement,
retained attempt history, and idempotent acknowledgement. It does not yet
implement cancellation after a started synchronous operation or production
fault/capacity certification.
Request handling must never call `apply_initial_schema` or
`bootstrap_namespace`; those remain operator-only actions.

The live integration test runs only against a dedicated database named
`sunrise_edge_test`:

```bash
SUNRISE_EDGE_TEST_POSTGRES_URL=postgresql://postgres:test@127.0.0.1:5432/sunrise_edge_test \
  cargo test -p runtime-postgres --all-targets
```

The test refuses to reset any database with a different name. CI supplies a
digest-pinned PostgreSQL 18 service and runs this test through the normal
workspace gate.
