# PostgreSQL runtime schema

This crate applies and verifies Sunrise Edge's generation-one normalized
PostgreSQL schema, bootstraps an exact `(chain, validator, atomicity domain)`
metadata row, and implements `StructuredDurableDomainStateStore` over an
explicit bounded synchronous connection pool.

The structured store performs fenced state/object/receipt reads and serializable
state/object/receipt/outbox commits with complete read assertions, checked revisions,
per-statement remaining-deadline timeouts, bounded unchanged-envelope
serialization retry, and conservative commit-result classification.
Object heads are body-free and lock in canonical object-ID order. Immutable
metadata is validated for head reads using presence/length fields without
selecting inline payload bytes. Separate immutable-version reads map the
generation-one inline/blob columns losslessly; inline payloads use the existing
canonical Object encoding and canonical Owner projection, while tombstones
retain history and reconstruct the last version. Head owner/routing projections
are routing data, not authorization: execution must separately match and decode
the linked inline version and compare its typed owner. Blob-backed execution
remains fail-closed until fetch and content verification are implemented.
It also implements `IndexedOutboxRepository` with exact-request and stable
indexed due claims, same-lease reconciliation, expired-lease replacement,
retained attempt history, and idempotent acknowledgement. It does not yet
implement cancellation after a started synchronous operation or production
fault/capacity certification.

The live test additionally implements the optional shared
`runtime::conformance::CommitLossFixture` capability through a bounded,
test-only `NoTls` TCP proxy that sits between the pool and the real database.
It can sever the connection either immediately before a dispatched `COMMIT`
reaches the backend, or immediately after the backend returns a successful
`CommandComplete("COMMIT")`/`ReadyForQuery`; both instants classify as
`Indeterminate(ConnectionLost)`. The shared conformance case injects the
before-dispatch instant once, for one plain state commit, and proves no state
was published, confirmed by an unfaulted retry of the same read assertion
committing successfully. It injects the after-acceptance instant three times:
for one structured invocation commit, proving the exact committed state
revision/value and exact receipt content were published and that replaying the
same invocation observes `RequestAlreadyCommitted`; for an outbox claim on
that invocation's message, first proving with a different, never-used lease
that the original lease is still active (`NoDueWork`) and then that a
same-lease replay reconciles to the identical claimed message; and for the
corresponding acknowledgement, first proving that reclaiming with the original
lease is rejected as lease-ID reuse and then that a same-identity replay
reconciles to `Acknowledged` with the acknowledgement persisted and no message
left due for this one-message batch. These discriminating probes matter
because a same-lease claim replay or same-identity acknowledgement replay
alone would succeed identically whether or not the prior transaction actually
persisted. A final unfaulted commit proves the connection pool recovers a
healthy connection. This is evidence that the backend returned a successful
commit acknowledgement over the plain transport before the driver lost it,
not proof of crash durability under abrupt process/power loss; it says
nothing about TLS-path connection loss, disk-full/WAL exhaustion,
backup/restore, capacity/load/soak, or real failover.
Request handling must never call `apply_initial_schema` or
`bootstrap_namespace`; those remain operator-only actions. Writer failover uses
the separate expected-generation `advance_writer_fence` operator seam and must
never be exposed to request input. Reads, writes, and fence advance reject a
namespace outside the active migration phase. Fence advance does not revoke an
unexpired delivery lease; the replacement writer waits for its bounded expiry.

The live integration test runs only against a dedicated database named
`sunrise_edge_test`:

```bash
SUNRISE_EDGE_TEST_POSTGRES_URL=postgresql://postgres:test@127.0.0.1:5432/sunrise_edge_test \
  cargo test -p runtime-postgres --all-targets
```

The test refuses to reset any database with a different name. It runs the same
feature-gated durable conformance cases as the in-memory fixture and adds live
pool/row-lock deadline exhaustion, commit-boundary deadline classification,
serialization exhaustion, schema-skew injection, and the commit-loss
connection-loss capability described above. CI supplies a digest-pinned
PostgreSQL 18 service and runs this test through the normal workspace gate.
