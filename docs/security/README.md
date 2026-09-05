# Security

This directory contains the repository-owned security material for Sunrise
Edge. Scope-specific audit evidence is retained below; it does not claim that
the complete software is production-ready or mainnet-ready.

- [Security policy](../../SECURITY.md): private reporting route, supported
  security invariants, severity context, and durable exclusions.
- [Threat model](threat-model.md): reusable As-Is architecture, trust
  boundaries, attacker stories, assumptions, and severity calibration.
- [Initial code-audit scope](initial-code-audit-scope.md): exact source scope,
  exclusions, revision binding, validation commands, and delta-audit rule for
  the first independent engagement.
- [Audit evidence](audits/README.md): immutable target revisions, canonical
  scan artifacts, limitations, and finding dispositions.

The live implementation status and roadmap remain in [`TODO.md`](../../TODO.md).
An audit scope exclusion is not an accepted-risk decision and does not prevent
private vulnerability reporting.
