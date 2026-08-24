# Shared Web ingress

`web-ingress.ts` implements the provider-neutral Fetch API contract used by
edge adapters. A provider wrapper supplies only a typed `NodeCoreFetcher`.

The shared layer owns request paths, exact media types, bounded stream reads,
status handling, and downstream response sanitization. It deliberately owns no
provider binding, secret lookup, durable state, retry policy, or mutable global
state. Provider wrappers must keep those concerns outside this module and must
not weaken its bounds or fail-closed behavior.
