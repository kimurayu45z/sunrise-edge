# Architecture decision DR-0099

Close every native public `POST /v1/events` surface to authenticated
`SubmitTransaction` only, satisfying criterion 1 of the
[Initial Code Security Audit Entry Gate](../../../TODO.md#initial-code-security-audit-entry-gate)
(DR-0097, see [DR-0094–DR-0098](0094-0098-blobs-audit-and-documentation.md)).

- DR-0099: Reject every known non-`SubmitTransaction` `NodeEventKind` at the
  native-http external boundary, before any identity allocation, clock read,
  storage I/O, machine `access_plan`/transition, outbox work, or transport
  send, on all four native router families.

  **External-boundary policy, not a node-core change.** Of the eight known
  `NodeEventKind` values, native-http authenticates and authorizes exactly
  one, `SubmitTransaction`, end to end today. `ReceiveVote`,
  `ReceiveCertificate`, `ReceiveConsensusMessage`,
  `ApplyGovernanceCertificate`, `ApplyProtocolUpgrade`,
  `ApplyValidatorSetChange`, and `Tick` each need their own family-specific
  authentication and authorization that no native route implements yet. A new
  crate-private `native-http` error, `InvocationError::EventFamilyRequiresAuthenticatedRoute`,
  is returned only after an exhaustive classification of every known
  `NodeEventKind`; the typed error itself carries no event-kind detail and maps
  every one of the seven rejected kinds to exactly the same opaque
  `501 event-family-requires-authenticated-route` response. This is deliberately
  not a new public `node_core::NodeCoreError` variant and does not touch
  node-core's generic `TransactionalNodeStateMachine` path or
  `validate_generic_event`: the fully implemented, reusable generic machinery
  is untouched, and this decision only narrows which event kinds native-http
  is currently willing to hand to it.

  **All four router families, both `with_executor` constructors.** `router`,
  `resolved_domain_router`, `structured_durable_router`, and
  `preinstalled_wasm_structured_durable_router` (and each corresponding
  `_with_executor` constructor) reject the seven kinds through the same
  `reject_unauthenticated_event_family` check immediately after bounded
  canonical `NodeEvent` decode. The two legacy routes, `router` and
  `resolved_domain_router`, authenticate no event at all, so they keep their
  pre-existing, unchanged behavior of also rejecting `SubmitTransaction`
  itself with the prior `501 submit-transaction-requires-authenticated-route`
  response; combined with this decision, both legacy routes are now closed for
  every known `NodeEventKind`. `structured_durable_router` and
  `preinstalled_wasm_structured_durable_router` still authenticate and accept
  a valid `SubmitTransaction` unchanged; their generic non-`SubmitTransaction`
  dispatch branch became unreachable from HTTP and was removed from
  native-http only, leaving node-core's generic entrypoint itself intact for
  any future per-family authenticated route.

  **Scope discipline.** Implementing authenticated ingress for the other seven
  event families is explicitly not required by this decision or by the audit
  entry gate; it remains open follow-on work, tracked per family with its own
  focused delta audit before that family is externally reachable again.

  **Compatibility.** This decision changes no canonical `NodeEvent`,
  `Transaction`, object, receipt, nonce, or submit bytes, no enum tag, no
  signature, and no protocol configuration. It changes no public Rust API
  outside native-http's own crate-private error type. Malformed or unknown
  `NodeEvent` bytes keep their existing decoder-failure response, and
  content-type/content-encoding/body-limit behavior is unchanged. Ledger code
  is untouched.
