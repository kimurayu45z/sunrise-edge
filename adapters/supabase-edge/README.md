# Supabase Edge ingress adapter

This adapter exposes the shared Web ingress contract as a Supabase Edge Function named
`sunrise-edge`. Supabase routes function requests under a path prefixed by the function
name, so the wrapper removes that prefix only for the exact `/v1/events` and
`/health/live` contract paths before delegating.

`supabase/config.toml` explicitly retains gateway JWT verification. As a result, both
routes currently require a valid caller JWT; splitting public liveness from
authenticated event submission is a production deployment decision, not an implicit
authentication bypass in this adapter.

Required project secrets:

- `SUNRISE_NODE_CORE_URL`: exact HTTPS node-core `/v1/events` endpoint.
- `SUNRISE_NODE_CORE_BEARER_TOKEN`: project secret for the outbound node-core
  capability, never a checked-in plain-text value.
- `SUNRISE_NODE_CORE_TIMEOUT_MS`: optional integer from 1 through 30000; defaults
  to 5000.

Run local static checks and permission-free adapter tests with:

```bash
deno task check
```

The hosted platform currently documents 256 MB memory, two seconds of CPU per request,
and a 150-second request idle timeout, but does not publish a request payload ceiling on
the same limits page. The As-Is adapter therefore keeps the shared bound and makes no
unsupported platform-capacity claim.

This remains an authenticated relay, not production equivalence. Real gateway and
hosted-runtime tests, caller authorization policy, separate health access, private or
mutually authenticated node-core transport, secret rotation, durable
deduplication/outbox, resource and abuse testing, observability, and rollout/rollback
rehearsal remain Phase 17 To-Be requirements.
