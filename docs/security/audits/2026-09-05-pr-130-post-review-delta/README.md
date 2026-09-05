# PR #130 Post-Review Security Delta

This directory preserves the canonical completed focused-delta artifacts for:

- base revision: `4db26d470901cb7895e7c32444be072029932013`;
- audited executable revision: `b74c1ae1d12a2ce7d5c691b613457933c998defe`;
- pull request: `#130`;
- scan id: `68406e55-9a84-4cc3-ba28-c6908e10d992`;
- producer: `codex-security-plugin` version `0.1.23`;
- completed and sealed: `2026-09-05T15:05:22.521959Z`;
- coverage: complete for the exact two-file diff; and
- reportable findings: `0`.

The delta fixes a tech-lead review blocker by retrying transient native
listener accept errors with bounded, shutdown-responsive backoff. It also
closes the review's object-query compatibility finding by rejecting encoding
v2 for statuses whose canonical encoding remains v1. The audited files are
`crates/native-http/src/lib.rs` and `crates/node-wire/src/lib.rs`.

[`scan-manifest.json`](scan-manifest.json),
[`findings.json`](findings.json), and [`coverage.json`](coverage.json) are the
canonical machine-readable artifacts. [`report.md`](report.md) is their
human-readable projection. The generated files are preserved without altering
their contents.

The review was static and source-backed. The complete repository gate also
passed for the executable revision before this evidence-only documentation
delta. No OS-level injected `TcpListener::accept` failure test was performed;
the source-level shutdown race and deterministic backoff/status-version tests
were reviewed. This evidence does not establish production deployment,
kernel, proxy, TLS, HA, load/soak, physical-device, or mainnet behavior.
