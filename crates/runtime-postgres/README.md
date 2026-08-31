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
`runtime::conformance::CommitLossFixture` capability first through a bounded,
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
healthy connection. The exact same shared suite then runs through a second
bounded proxy whose client leg requires ordinary PostgreSQL `SSLRequest` and
`SslMode::Require`. It generates an ephemeral private CA and `localhost`-only
leaf, configures rustls with only that CA, rejects a live IP-host negative
connection, and asserts that an authenticated handshake completed before the
fault cases finish. The proxy terminates TLS and relays plaintext PostgreSQL
frames to the dedicated test database. This is evidence that the backend
returned a successful commit acknowledgement before the driver lost it and
that the client/driver-to-test-terminator TLS path preserves the same
classification and reconciliation. It is not proof of crash durability under
abrupt process/power loss, PostgreSQL-server TLS, provider trust-store or
certificate lifecycle behavior, mTLS, WAL or commit-boundary exhaustion,
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

### Live bounded WAL-exhaustion test

`tests/postgres_wal_full.rs` starts and owns a separate digest-pinned
disposable PostgreSQL 18 container that relocates `pg_wal` (via `initdb
--waldir`) onto its own small 64 MiB tmpfs, distinct from and much smaller
than the unfilled 512 MiB tmpfs holding PGDATA and the default tablespace.
Set both variables to make it required locally:

```bash
SUNRISE_EDGE_TEST_POSTGRES_WAL_FULL_IMAGE=postgres:18.6-alpine3.24@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2 \
SUNRISE_EDGE_TEST_POSTGRES_WAL_FULL_REQUIRED=1 \
  cargo test -p runtime-postgres --all-features --test postgres_wal_full -- --nocapture
```

Unlike the disk-full scenario's data-tablespace `ENOSPC`, a real write
failure on the WAL filesystem is fatal to the *entire* PostgreSQL server: a
direct client write that crosses a WAL segment boundary on the nearly-full
WAL tmpfs still returns SQLSTATE `53100` (`disk_full`), but at `PANIC`
severity rather than the disk-full scenario's plain `ERROR`, and the
connection then closes as the whole postmaster terminates every backend and
crash-restarts (its own automatic recovery attempt fails the same way, since
it also needs to write WAL, taking the server down a second time). After an
in-place recovery, the test independently refills the same mount and drives
a bounded incompressible state mutation through the adapter, making the
adapter's own structured invocation commit exhaust WAL and crash the server.
Its observed public outcome is `UnavailableBeforeCommit`; only the direct
first cycle claims the raw SQLSTATE and severity because the adapter API does
not expose them. Because the whole server (not just one
connection) goes down, this test overrides the container's entrypoint with a
small supervisor script that keeps the *container* itself alive across the
crash; recovery frees WAL space and restarts postgres **in place** with
`pg_ctl start` inside that same, still-running container — never `docker
start`, which would recreate every tmpfs mount empty and destroy the
evidence — then reconciles exact non-publication and recovery, including a
strictly-advanced `pg_postmaster_start_time()` after each of the two restarts,
through the same pool/store.
It force-removes only its exact created container on normal return or panic.
Leaving both variables unset skips the test; setting the required flag
without a valid digest-pinned image fails instead of skipping. This does not
cover literal-`COMMIT` WAL/data `ENOSPC`; that boundary remains untested and
this scenario makes no ENOSPC-specific classification claim for it. It also
does not cover real storage-device `ENOSPC`, block-device faults, or
production certification.

### Live bounded connection-exhaustion test

`tests/postgres_connection_exhaustion.rs` starts and owns a separate
digest-pinned disposable PostgreSQL 18 container configured with an exact
tiny `max_connections` (5), zero `superuser_reserved_connections`, and zero
PostgreSQL 16+ `reserved_connections` (a second, independent reserved pool
for the `pg_use_reserved_connections` role) — so no role gets a capacity
carve-out this test's exact accounting would need to special-case.
`autovacuum` is disabled too, but only as optional quiescence against
unrelated background activity: autovacuum workers and the autovacuum
launcher are accounted from their own separate budget, never carved out of
`max_connections`, so this test's `backend_type = 'client backend'`-filtered
counts already exclude them regardless. Set both variables to make it
required locally:

```bash
SUNRISE_EDGE_TEST_POSTGRES_CONNECTION_EXHAUSTION_IMAGE=postgres:18.6-alpine3.24@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2 \
SUNRISE_EDGE_TEST_POSTGRES_CONNECTION_EXHAUSTION_REQUIRED=1 \
  cargo test -p runtime-postgres --all-features --test postgres_connection_exhaustion -- --nocapture
```

An already-open operator connection bootstraps the disposable namespace and
stays open for the whole scenario. Immediately after the short-lived admin
client that created the disposable database is dropped, the test boundedly
polls through the operator connection until exactly one active client
backend (its own) is visible, since dropping a connection only requests
asynchronous teardown; this poll is safe because no connection pool exists
yet and nothing else in the scenario can independently change the count at
that point (unlike a later point in this same scenario, where such a poll
would not be safe — see below). A small, exactly bounded number of direct
blocker connections then saturate every remaining server slot; one further
direct connection attempt is live evidence that the server is genuinely out
of capacity: SQLSTATE `53300` (`too_many_connections`) at `FATAL` severity.
With capacity still fully exhausted, a freshly built, max-size-one adapter
pool — proven to hold zero physical connections before its first checkout —
drives one bounded structured invocation commit. Live evidence, not the
naively assumed `UnavailableBeforeCommit`: `r2d2`'s `Pool::get_timeout` only
ever returns once it either succeeds or its entire requested wait elapses, so
by the time this crate's connection-acquisition helper re-checks the
caller's operation deadline to classify the failure, that deadline has, by
construction, also just elapsed. Pool exhaustion and deadline exhaustion
therefore collapse into the same observable outcome here: the definite
pre-commit `Rejected(DeadlineExceededBeforeCommit)`, not
`UnavailableBeforeCommit` (which this adapter reserves for a fault surfacing
after a connection and transaction are already open, as in the
disk-full/WAL-full scenarios above). Non-publication of state, receipt,
commit sequence, and outbox rows is proven through the still-open operator
connection while capacity remains exhausted, since the adapter pool itself
cannot open a new connection to check this. The rejected attempt's own
internal connection attempt keeps retrying independently in the background
after `commit_invocation` returns, so the slot freed by releasing exactly one
blocker connection can be reclaimed by that background retry at any time —
this test does not poll for a transient count (which would race that
independent retry) and instead proves recovery deterministically: the next
`commit_invocation` call must succeed, and the post-recovery, steady-state
active client-backend count and the single backend carrying the adapter
pool's own `application_name`, both read through the same operator
connection, confirm specifically that the adapter pool reclaimed it. The
identical invocation then commits through the same pool and store; the test
also proves the exact `RequestAlreadyCommitted` replay, one exact outbox
claim/acknowledgement followed by `NoDueWork`, and pool usability afterward.
It force-removes only its exact created container on normal return or panic.
Leaving both variables unset skips the test; setting the required flag
without a valid digest-pinned image fails instead of skipping. This does not
cover real-device resource exhaustion, load/soak capacity, connection-pool
behavior under a provider-managed pooler (e.g. PgBouncer), PostgreSQL-server
or provider TLS beyond the bounded client-to-terminator evidence above, real
writer failover, or production certification.

### Live bounded database-snapshot restore rehearsal test

`tests/postgres_backup_restore.rs` starts and owns **two** separate
digest-pinned disposable PostgreSQL 18 containers (a source and a fully
isolated target — different container processes, different generated
passwords, different published host ports). Set both variables to make it
required locally:

```bash
SUNRISE_EDGE_TEST_POSTGRES_BACKUP_RESTORE_IMAGE=postgres:18.6-alpine3.24@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2 \
SUNRISE_EDGE_TEST_POSTGRES_BACKUP_RESTORE_REQUIRED=1 \
  cargo test -p runtime-postgres --all-features --test postgres_backup_restore -- --nocapture
```

The test commits one structured invocation (state, receipt, one pending
outbox message) on the source, then runs `pg_dump -d <db> --no-owner
--no-privileges --inserts` inside the source container via bounded `docker
exec` output capture. `--inserts` avoids `COPY ... FROM stdin` embedded data
blocks — the convention that the data literally follows the `COPY` statement
in the same script is implemented by `psql` itself, not the wire protocol —
so the captured plain-`INSERT` snapshot is a self-contained SQL script after
the marker removal below. The test applies it through
`postgres::Client::batch_execute` over its
own bounded connection to the target, with no intermediate file, `docker cp`,
or `psql` subprocess. It strips PostgreSQL 18 `pg_dump`'s bracketing
`\restrict`/`\unrestrict` lines first: these are a `psql`-only safety
meta-command pair, not SQL, and the server rejects them as a syntax error if
sent verbatim over the wire, which is exactly what happens when bypassing
`psql` this way.

Before advancing the copied namespace fence, the test verifies exact schema
identity (`verify_initial_schema`) and reads the exact restored namespace
metadata, state, and receipt back through the normal adapter read path (never
by inferring row contents from raw SQL). It then advances the restored
namespace's writer fence through the operator-only `advance_writer_fence`
seam, proves a stale context still carrying the pre-backup fence is rejected
as `Rejected(WriterFenced { .. })` against the restored target with no
publication, and proves a fresh context carrying the new fence reconciles the
exact restored receipt/state, observes `RequestAlreadyCommitted` for the
identical invocation, and claims and acknowledges the exact restored
pending outbox payload through `NoDueWork`, and then commits genuinely new
work. A deterministic negative pair uses two more empty databases on the same
target container. A dump cut inside the required `storage_metadata` table
definition must fail its one simple-query batch atomically and leave no schema
marker. A syntactically valid dump with only the fixture's `state_records`
insert removed must restore schema, namespace metadata, and receipt cleanly,
yet fail the deeper rehearsal verification gate on the missing state row.

It force-removes both of its exact created containers on normal return or
panic. Leaving both variables unset skips the test; setting the required flag
without a valid digest-pinned image fails instead of skipping. This is a
bounded database-snapshot restore rehearsal only, not a production
backup/restore capability: it does not cover point-in-time recovery,
continuous WAL archiving/shipping, a hot/consistent backup taken under
concurrent write load, `pg_basebackup`/replication-based backup, backup
encryption or off-host storage, retention/rotation policy, restore
automation, checkpoint publication (the schema has no implemented
checkpoint-publication path; `sunrise_edge.checkpoints` is not written or
read by anything in this crate), blob-manifest verification, state-root
verification, encryption-key verification, multi-database/whole-cluster
backup, backup under concurrent adapter write traffic, real storage-device or
off-host transfer faults, capacity/load/soak, TLS-path connection loss, real
writer failover beyond the one bounded fence advance proven here (the copied
target fence does not fence or stop the still-isolated source database), or
production certification.

### Live bounded PgBouncer transaction-pooling rehearsal test

`tests/postgres_pgbouncer.rs` starts and owns **two** separate digest-pinned
disposable containers — a PostgreSQL 18.6 backend and a `ghcr.io/icoretech/
pgbouncer-docker` 1.25.2 proxy — on one isolated, freshly generated Docker
bridge network. Set all three variables to make it required locally:

```bash
SUNRISE_EDGE_TEST_POSTGRES_PGBOUNCER_POSTGRES_IMAGE=postgres:18.6-alpine3.24@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2 \
SUNRISE_EDGE_TEST_POSTGRES_PGBOUNCER_IMAGE=ghcr.io/icoretech/pgbouncer-docker:1.25.2@sha256:53dc42879de6b87efed6ad239558cfa6fef6f08c5fa4acc109da5f5af1868b89 \
SUNRISE_EDGE_TEST_POSTGRES_PGBOUNCER_REQUIRED=1 \
  cargo test -p runtime-postgres --all-features --test postgres_pgbouncer -- --nocapture
```

Leaving all three unset skips the test; configuring only one of the two
pinned images (with or without the required flag) always fails rather than
skipping, since a scenario needing two images can't safely infer intent from
half a configuration. PgBouncer resolves PostgreSQL only by its Docker
network alias, never a host-published address; this test's own direct
verification connections bypass the proxy entirely and talk straight to
PostgreSQL's own separately published port, so they stay usable even while
the proxy's single backend is deliberately held busy.

The proxy's `pgbouncer.ini`/`userlist.txt` are written into the already-running
container over stdin via `docker exec -i ... dd of=<path> status=none` — one
direct-argv call per file, no shell, no host bind mount, and (unlike `tee`)
no echo of the written content into the captured command output: BusyBox
`dd` writes only to the target file and, with `status=none`, produces no
stdout/stderr at all, so the generated credential hash is never copied into
a bounded-output temp file this scenario would otherwise have to create just
to discard. The pool credential is a freshly generated password; with
`password_encryption=md5` pinned on the PostgreSQL container,
`pg_authid.rolpassword` is read back after setting it and used directly as
the userlist's MD5 credential hash, never invented or hashed by the test
itself. The rendered configuration sets `pool_mode = transaction`,
`pool_size`/`default_pool_size`/`max_db_connections`/`max_user_connections =
1` for the one tested database/user pool, a nonzero
`max_prepared_statements`, and a bounded `query_wait_timeout` — every one of
these is asserted through PgBouncer's own admin console (`SHOW CONFIG`/`SHOW
POOLS`/`SHOW DATABASES`/`SHOW SERVERS`/`SHOW CLIENTS`, queried over the
simple query protocol, the only protocol PgBouncer's admin console answers),
never inferred from client-side behavior. `SHOW CONFIG`'s
`default_pool_size`/`max_db_connections`/`max_user_connections` and the
tested database's own `SHOW DATABASES` `pool_size` are each independently
read back and asserted exactly one, since `pool_size` in the rendered ini is
not the only setting that could cap or override the backend count.

Two distinct client connections, open simultaneously, each run one
sequential transaction; `SHOW SERVERS`' `remote_pid` is identical after
both, proving transaction pooling actually reused one physical PostgreSQL
backend rather than opening a second. The real adapter (a genuine `r2d2`
pool plus `PostgresDurableStore`, distinguished by its own
`application_name`) is then pointed at the proxy, not PostgreSQL directly.
While a separate direct proxied client holds the pool's only backend inside
an open transaction (left open by simply withholding `COMMIT`/`ROLLBACK`,
never a timed sleep) — proven not merely present but genuinely occupied, by
asserting the sole `SHOW SERVERS` row for that database reports PgBouncer's
own `active` state — one adapter structured invocation is driven with a
context deadline well longer than PgBouncer's own `query_wait_timeout`.
Live evidence, not an assumed classification: PgBouncer's queue timeout
surfaces as PostgreSQL protocol SQLSTATE `08P01` (`query_wait_timeout`) on
the adapter's first statement (its transaction-opening `BEGIN`); this
crate's `PreCommitFailure::from_sqlstate` has no dedicated arm for
connection-exception class `08` and so falls through to its default
`Unavailable` bucket — the definite pre-commit
`Rejected(UnavailableBeforeCommit)`, never `Indeterminate`. The observed
elapsed time is bounded from both directions around PgBouncer's own
`query_wait_timeout` specifically (not this probe's own much larger context
budget), proving the rejection's timing tracks the proxy's queue timeout.
No state/receipt/outbox row is published, checked through the direct,
proxy-bypassing verification connection, which the proxy's contention
cannot affect.

After the blocking transaction is released, the identical invocation is
retried through the same adapter pool/store. A bounded, explicitly
documented retry tolerates one specific, live-verified transient, distinct
from a genuine proxy rejection by its timing alone: `r2d2` can occasionally
recycle, rather than evict, the blocked probe's connection if its local
closed-state check has not yet caught up with PgBouncer's asynchronous
socket close, so the very next checkout can be handed that already-dead
connection and fail near-instantly with a local, unclassified I/O error —
also `Rejected(UnavailableBeforeCommit)` by the same default classification,
but resolved in sub-millisecond time rather than tracking
`query_wait_timeout`. The retry only tolerates that exact narrow shape (a
sub-second `UnavailableBeforeCommit`); the loop's final outcome must still
be `Committed`, and any other outcome fails the test immediately (the loop's
accumulator is seeded with a rejection, never `Committed`, so a future edit
that shrank the retry bound to zero attempts would fail loudly instead of
vacuously passing). Recovery proves `Committed`; `SHOW SERVERS`' `remote_pid`,
read again, proves the recovered commit was served by the exact same sole
backend the two synthetic clients observed earlier, not a different backend
process; `SHOW CLIENTS` filtered by the adapter pool's own
`application_name` proves specifically that the adapter pool's own proxy
connection reclaimed the freed backend; a replay of the identical invocation
returns exact `RequestAlreadyCommitted`; the exact outbox message claims and
acknowledges through `NoDueWork`; and the pool remains usable for a further
read.

It force-removes both of its exact created containers, and the generated
Docker network, on normal return or panic (containers before the network,
since Docker refuses to remove a network with live attachments). This is
explicitly a bounded local PgBouncer transaction-pooling rehearsal only, not
provider-managed pooler service certification: it does not cover load/soak
capacity, PgBouncer high availability or connection draining, TLS on either
the client or backend leg, real writer failover, or production readiness.
