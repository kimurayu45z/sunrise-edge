# Architecture

The architecture is split by responsibility so contributors can read the
smallest relevant document. Implemented canonical bytes, stable vectors, and
accepted decision records remain compatibility constraints even when the
roadmap describes a later target state.

- [Core protocol](core-protocol.md): sections 1–27, from canonical encoding and
  cryptography through consensus, execution, governance, and security.
- [Runtime and ingress](runtime-and-ingress.md): sections 28–40, including the
  node invocation boundary and provider adapters.
- [Persistence](persistence.md): section 41 and the runtime-neutral durable
  state boundary.
- [Developer product surfaces](product-surfaces.md): sections 42–46, covering
  the devnet, query API, Rust client, CLI, and signing host boundary.
- [Decision records](decisions/README.md): accepted and compatibility-relevant
  decisions grouped into bounded ranges.

Production-oriented persistence requirements and the PostgreSQL mapping are
separate operational references under [`docs/operations`](../operations/).
Current work queues, gate summaries, and roadmap sequencing belong only in
[`TODO.md`](../../TODO.md). Architecture documents may describe implemented
behavior and preserve historical evidence inside accepted decision records.
