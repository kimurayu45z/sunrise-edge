# Shared Web ingress

`web-ingress.ts` implements the provider-neutral Fetch API contract used by
edge adapters. A provider wrapper supplies only a typed `NodeCoreFetcher`.

The shared layer owns request paths, exact media types, bounded stream reads,
status handling, and downstream response sanitization. It deliberately owns no
provider binding, secret lookup, durable state, retry policy, or mutable global
state. Provider wrappers must keep those concerns outside this module and must
not weaken its bounds or fail-closed behavior.

A provider whose request-body capacity is smaller than the protocol transport
limit may pass `maximumRequestBodyBytes`. The shared implementation accepts
only a positive integer no larger than its default bound, so an adapter can
narrow the capacity envelope but cannot silently raise the security limit.

`authenticated-node-core.ts` provides the reusable outbound capability for Web
providers that lack a private service binding. It requires an exact HTTPS
endpoint, injects an ASCII Bearer secret into an allow-listed request, rejects
redirects, and applies a bounded timeout. Provider entrypoints still own secret
lookup and must replace this incremental public transport with the stronger
private or mutually authenticated Phase 17 production design.
