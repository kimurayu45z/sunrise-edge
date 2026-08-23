# Deno ingress adapter

This adapter exposes the shared Web ingress contract through Deno's default `fetch`
export. It targets the current Deno 2 and Deno Deploy platform, not Deno Deploy Classic.

The adapter accepts only an exact HTTPS `/v1/events` node-core endpoint. It adds a
bounded Bearer capability from a secret environment variable, rejects redirects so
credentials cannot cross origins, applies a fixed downstream timeout, and delegates all
public request validation and response sanitization to `adapters/shared/web-ingress.ts`.

Required deployment configuration:

- `SUNRISE_NODE_CORE_URL`: exact HTTPS node-core `/v1/events` endpoint.
- `SUNRISE_NODE_CORE_BEARER_TOKEN`: Deno Deploy secret, never a checked-in plain-text
  variable.
- `SUNRISE_NODE_CORE_TIMEOUT_MS`: optional integer from 1 through 30000; defaults
  to 5000.

For local serving, grant only the named environment variables and the exact node-core
host, for example:

```bash
deno serve \
  --allow-env=SUNRISE_NODE_CORE_URL,SUNRISE_NODE_CORE_BEARER_TOKEN,SUNRISE_NODE_CORE_TIMEOUT_MS \
  --allow-net=node.internal.example:443 \
  src/main.ts
```

Run static checks and permission-free adapter tests with:

```bash
deno task check
```

This is an As-Is authenticated relay, not the production trust architecture. Private
connectivity or mTLS/signed service requests, key rotation, durable deduplication and
outbox delivery, platform policy, load/fault testing, and a real Deno Deploy rehearsal
remain Phase 17 To-Be requirements.
