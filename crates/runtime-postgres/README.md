# PostgreSQL runtime schema

This crate is the explicit schema-lifecycle foundation for Sunrise Edge's
normalized PostgreSQL durable adapter. It currently applies and verifies the
generation-one schema and bootstraps an exact
`(chain, validator, atomicity domain)` metadata row.

It does not yet implement `StructuredDurableDomainStateStore` or
`IndexedOutboxRepository`, and applying the migration is not production
certification. Request handling must never call `apply_initial_schema` or
`bootstrap_namespace`; those are operator-only actions.

The live integration test runs only against a dedicated database named
`sunrise_edge_test`:

```bash
SUNRISE_EDGE_TEST_POSTGRES_URL=postgresql://postgres:test@127.0.0.1:5432/sunrise_edge_test \
  cargo test -p runtime-postgres --all-targets
```

The test refuses to reset any database with a different name. CI supplies a
digest-pinned PostgreSQL 18 service and runs this test through the normal
workspace gate.
