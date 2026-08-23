# Vercel ingress adapter

This adapter exposes the shared Web ingress contract as a Vercel Node.js Function using
the recommended Web `fetch` export. `vercel.json` rewrites the canonical `/v1/events`
and `/health/live` routes to the single function and caps the invocation at ten seconds.

Vercel documents a 4.5 MB request/response payload ceiling. The adapter uses a
conservative 4 MiB request budget so the shared handler can reject declared or streamed
oversize input before forwarding it. This is lower than the protocol transport limit and
is therefore an explicit As-Is conformance gap.

Required project configuration:

- `SUNRISE_NODE_CORE_URL`: exact HTTPS node-core `/v1/events` endpoint.
- `SUNRISE_NODE_CORE_BEARER_TOKEN`: Sensitive Environment Variable for production and
  preview, never a checked-in plain-text value.
- `SUNRISE_NODE_CORE_TIMEOUT_MS`: optional integer from 1 through 30000; defaults to
  5000 and should remain below the ten-second Function duration.

Run local static checks and permission-free adapter tests with:

```bash
deno task check
```

This is an As-Is authenticated relay, not production equivalence. A deployment that
accepts every protocol-valid event requires a platform/path architecture that does not
truncate the larger shared envelope. Private connectivity or mutually authenticated
requests, secret rotation, durable deduplication and outbox delivery, real
preview/production tests, abuse controls, observability, and rollout/rollback rehearsal
remain Phase 17 To-Be requirements.
