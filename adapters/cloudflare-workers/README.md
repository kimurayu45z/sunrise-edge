# Cloudflare Workers ingress adapter

This package is the Phase 16 As-Is Cloudflare ingress for Sunrise Edge. It
enforces the shared HTTP envelope and forwards accepted requests through the
private `NODE_CORE` Service Binding. It does not implement node state,
authentication, deduplication, or a transactional outbox by itself.

The configured target service name is `sunrise-edge-node-core`. Deploy and test
that service first, keep it inaccessible from the public Internet, and update
the binding through reviewed Wrangler configuration if the deployment name
changes. Do not replace the binding with a public URL or embed Cloudflare API
credentials.

## Validate locally

```bash
npm ci
npm run check
npx wrangler deploy --dry-run
```

`npm run check` verifies generated binding types, runs strict TypeScript and
the no-floating-promises lint rule, and executes integration tests inside
workerd with a mock Service Binding. No deployment is performed by these
commands.

Project typechecking intentionally invokes the `typescript-7` package alias,
currently TypeScript 7.0.2. The separately pinned `typescript` 6.x package is
only the compiler API used by `typescript-eslint` until its peer range supports
TypeScript 7. Do not bypass that peer range with forced installation or replace
ESLint as a dependency-upgrade shortcut.

Production gaps and exit criteria are tracked under Phase 16 in the repository
[`TODO.md`](../../TODO.md).
