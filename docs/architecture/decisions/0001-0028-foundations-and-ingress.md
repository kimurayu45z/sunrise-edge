# Architecture decisions DR-0001–DR-0028

Foundational protocol, consensus, execution, node-boundary, ingress, and
repository-validation decisions.

- DR-0001: Use a single canonical framed binary format for hashes, signatures, and protocol-critical payloads.
- DR-0002: Keep `HashAlgorithmId` broader than the currently enabled built-ins so future support can be added without changing digest shape.
- DR-0003: Treat hash-suite scheduling as configuration resolution, not as a bulk migration job.
- DR-0011: Introduce a governance-managed `SystemModuleRegistry` with versioned
  module commitments (`code`, `semantics`, `manifest`) and optional native/ZK
  acceleration hints while preserving canonical execution equivalence.
- DR-0012: Store complete hash-suite and protocol-upgrade schedules in canonical
  configuration, enforce future activation at enactment, and use per-object
  hash-identified lazy migrations instead of global state rewrites.
- DR-0013: Use event-driven three-chain HotStuff for shared-object ordering.
  Keep the protocol state explicit and persistable, accept untrusted relay and
  Tick delivery, and require authenticated quorum certificates for safety.
- DR-0014: Keep state commitments and execution proofs independently agile.
  Use versioned leaf/node framing, ship Poseidon2/BN254 only as an experimental
  inactive alternative to genesis SHA-256, reserve unsupported schemes without
  fallback, and dispatch bounded proof envelopes only to an exact-ID verifier.
- DR-0015: Put one bounded canonical event and one explicit conditional state
  transition behind a runtime-neutral node-core boundary. Publish no output
  before persistence succeeds, keep retries and delivery in adapters, and treat
  single-key CAS as an interim seam that must evolve into a crash-safe atomic
  write-set and outbox contract for production.
- DR-0016: Use an exact, versioned canonical binary HTTP contract for the native
  adapter, enforce independent transport and protocol bounds, and keep HTTP
  status mapping outside node-core. Dispatch outbound events only after state
  commit while treating the remaining commit/send window as deferred production
  work requiring a transactional outbox.
- DR-0017: Implement Cloudflare public ingress as a bounded ES-module Worker and
  call the private node service through a generated, awaited Service Binding.
  Treat the binding as routing/capability isolation rather than event
  authentication, and keep the ingress independently testable in workerd.
- DR-0018: Share one Web Fetch API ingress implementation across edge providers
  and inject only a minimal node-core fetch capability. Provider wrappers may
  add authentication and deployment wiring but must not fork canonical paths,
  media types, bounds, status rules, or response sanitization.
- DR-0019: Implement Deno ingress as a thin default-fetch wrapper over the
  shared contract. Require an exact HTTPS node-core endpoint, inject only a
  secret Bearer capability, reject redirects, and treat stronger private or
  mutually authenticated transport as a production Phase 17 requirement.
- DR-0020: Allow provider adapters to narrow the shared request-body capacity
  when the hosting platform has a smaller hard limit, but reject zero,
  non-integer, or larger values and record the resulting conformance gap.
- DR-0021: Share the interim exact-HTTPS, Bearer-authenticated node-core fetch
  capability across Web providers without moving environment lookup or secret
  lifecycle into the shared layer. Keep private or mutually authenticated
  transport as a production exit requirement.
- DR-0022: Model Vercel's smaller payload ceiling as an explicit 4 MiB adapter
  request budget rather than pretending it accepts the full protocol envelope.
  Reuse shared Web semantics and authenticated transport, and keep real Vercel
  deployment behavior as an unfulfilled production gate.
- DR-0023: Normalize only the exact Supabase function-prefixed contract paths
  and keep gateway JWT verification enabled for the combined function. Do not
  invent an undocumented hosted payload limit or equate local wrapper tests with
  production gateway conformance.
- DR-0024: Map only API Gateway HTTP API payload version 2.0, require canonical
  base64 for binary events, and cap decoded request and raw buffered response at
  4 MiB to stay conservatively below Lambda's 6 MB JSON-envelope limits. Ship no
  unauthenticated production API configuration.
- DR-0025: Define provider-neutral pre-dispatch ingress fixtures once and run
  them through every local provider consumer. Treat this as drift detection,
  not a substitute for real gateway and runtime conformance testing.
- DR-0026: Use one pinned repository validation entrypoint locally and in CI so
  Rust and every adapter gate run together. Treat green CI as regression
  evidence only, not production provenance or real-provider certification.
- DR-0027: Resolve CI actions from verified upstream tags and commit their full
  immutable revisions. Keep the human-readable release tag as a comment and
  require reviewed updates rather than following a mutable major tag.
- DR-0028: Ask Dependabot for bounded weekly Cargo, npm, and GitHub Actions
  update PRs, but never auto-merge them. Require human compatibility review and
  the complete repository gate for every proposed supply-chain change.
