# Security Audit Evidence

This index retains audit outputs against immutable revisions. Each entry is
scope-specific: it is not a production, deployment, mainnet, or future-change
certification. Changes covered by the delta-audit rule in
[`initial-code-audit-scope.md`](../initial-code-audit-scope.md) require a new
review.

- [2026-09-05 PR #130 Daybreak re-audit](2026-09-05-pr-130-daybreak/README.md):
  Standard single-pass static source re-audit of
  `cdf438c51b1609eb4886d8edcddc22af183f48c0`; complete coverage within the
  declared scope, zero reportable findings, and all four initial findings
  dispositioned as fixed.
- [2026-09-05 PR #130 post-review delta](2026-09-05-pr-130-post-review-delta/README.md):
  focused review of executable commit
  `b74c1ae1d12a2ce7d5c691b613457933c998defe` against
  `4db26d470901cb7895e7c32444be072029932013`; complete coverage of the two-file
  delta and zero reportable findings.
