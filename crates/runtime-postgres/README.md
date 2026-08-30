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
nothing about TLS-path connection loss, WAL or commit-boundary exhaustion,
backup/restore, capacity/load/soak, or real failover. The separate bounded
data-tablespace ENOSPC scenario described below does not broaden those claims.
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
  cargo test -p runtime-postgres --test postgres_schema
```

The test refuses to reset any database with a different name. It runs the same
feature-gated durable conformance cases as the in-memory fixture and adds live
pool/row-lock deadline exhaustion, commit-boundary deadline classification,
serialization exhaustion, schema-skew injection, and the commit-loss
connection-loss capability described above. CI supplies a digest-pinned
PostgreSQL 18 service and runs this test through the normal workspace gate.

### Live SIGKILL crash-recovery test

`tests/postgres_crash_recovery.rs` is a separate test binary that kills and
restarts the whole database-service container, so it requires **both**
`SUNRISE_EDGE_TEST_POSTGRES_URL` **and** the exact full Docker container ID
of that same container, in `SUNRISE_EDGE_TEST_POSTGRES_CONTAINER_ID`. A safe
way to produce both against a disposable, named test container:

```bash
docker run -d --name sunrise-edge-pg-crash-test \
  -e POSTGRES_PASSWORD=test -e POSTGRES_DB=sunrise_edge_test \
  -p 55432:5432 postgres:18.6-alpine3.24@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2
CONTAINER_ID="$(docker inspect --format '{{.Id}}' sunrise-edge-pg-crash-test)"

SUNRISE_EDGE_TEST_POSTGRES_URL=postgresql://postgres:test@127.0.0.1:55432/sunrise_edge_test \
SUNRISE_EDGE_TEST_POSTGRES_CONTAINER_ID="$CONTAINER_ID" \
  cargo test -p runtime-postgres --test postgres_crash_recovery
```

`docker inspect --format '{{.Id}}'` prints the exact full ID Docker assigned
that specific container; never derive, guess, or match a container by name
or label at test time. Setting only `SUNRISE_EDGE_TEST_POSTGRES_URL` without
the container ID is **intentionally rejected**, not silently skipped: partial
crash-test configuration panics immediately (see
`resolve_crash_scenario` in `tests/support/mod.rs`) rather than risk running,
or quietly skipping, against the wrong assumption. Leave both variables unset
to skip the crash test while still running the rest of `--all-targets`.

This test also acquires a cross-process lock file before touching the
database, named `sunrise-edge-runtime-postgres-live-test.lock` inside
`std::env::temp_dir()` (i.e. `$TMPDIR` or the platform equivalent — commonly
scoped per user, not shared host-wide), so it never runs concurrently with
any other live test in this crate. The lock releases itself when the test
process exits normally or panics. If a test process is killed before it can
run its own cleanup, the lock file is abandoned and every future live test
run fails loudly, pointing at that exact path. Only delete it by hand, and
only after confirming no live test process for this crate
(e.g. `pgrep -fl postgres_crash_recovery` or `pgrep -fl postgres_schema`) is
still actually running — deleting it while a live test genuinely holds it
would let two destructive live tests run concurrently against the same
container.

### Live bounded data-tablespace ENOSPC test

`tests/postgres_disk_full.rs` starts and owns a digest-pinned disposable
PostgreSQL 18 container. Set both variables to make it required locally:

```bash
SUNRISE_EDGE_TEST_POSTGRES_DISK_FULL_IMAGE=postgres:18.6-alpine3.24@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2 \
SUNRISE_EDGE_TEST_POSTGRES_DISK_FULL_REQUIRED=1 \
  cargo test -p runtime-postgres --all-features --test postgres_disk_full -- --nocapture
```

The test keeps PGDATA/WAL on an unfilled 512 MiB tmpfs, fills only a distinct
64 MiB default tablespace, proves direct SQLSTATE `53100` and the adapter's
definite pre-commit `UnavailableBeforeCommit`, then frees space and reconciles
exact non-publication and recovery through the same pool/store. It force-removes
only its exact created container on normal return or panic. Leaving both
variables unset skips the test; setting the required flag without a valid
digest-pinned image fails instead of skipping. This does not cover WAL or
commit-boundary exhaustion, real storage media/cache/filesystem faults, or
production certification.
