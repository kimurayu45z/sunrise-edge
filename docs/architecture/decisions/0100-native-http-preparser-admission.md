# Architecture decision DR-0100

Bound native HTTP resources before request parsing so slow or incomplete
connections cannot bypass the existing synchronous-work admission boundary.

- DR-0100: The repository-owned native server accepts a connection only while
  a separate, bounded connection permit is available. That permit is acquired
  immediately after TCP `accept`, before Hyper parses any request bytes, and is
  held until the connection closes. Excess connections are closed without
  parsing or enqueueing application work.

  **Two independent admission domains.** Pre-parser connection admission does
  not replace `NativeBlockingExecutor`. The connection permit bounds sockets,
  HTTP parser state, and slow request reads. The existing blocking permit still
  bounds synchronous canonical decode, authentication, state-machine,
  persistence, and outbox work after the complete body is available. Scheduler
  recovery continues to share only the latter because it opens no HTTP
  connection.

  **Finite HTTP/1 lifecycle.** The server applies a total header-read deadline,
  an idle deadline between socket reads, a total deadline while collecting
  the one bounded request body, and an idle deadline while writing the
  response plus a total deadline from the first response write. HTTP/1
  keep-alive is disabled, limiting each
  accepted connection to exactly one request. Header count and parser-buffer
  size are also fixed. A body is collected before the Axum router is invoked,
  so a body timeout cannot abandon a state-machine or database operation that
  has already started. The existing 16 MiB plus 512-byte framing body ceiling
  remains unchanged.

  **Policy and compatibility.** `serve` retains its existing public signature
  and uses a conservative bounded default. `serve_with_policy` permits an
  embedding host or deterministic test to choose smaller values within hard
  ceilings; zero, excessive, or incoherent values fail at construction. Every
  router family receives the same controls because this server boundary wraps
  the completed `Router`, rather than modifying an individual route. Canonical
  protocol bytes, transaction behavior, error framing after routing, and
  `NativeBlockingExecutor` semantics are unchanged.

  **Evidence boundary.** Raw-TCP tests cover incomplete headers occupying the
  only connection permit, immediate excess-connection close and recovery,
  body-idle termination, total body-read timeout, stalled and slow-drip
  response-write termination, one-request connection closure, and a legitimate
  liveness request. This is deterministic local
  conformance, not a production load/soak, kernel-backlog, reverse-proxy, TLS
  terminator, or provider-ingress certification.
