# PR #130 Daybreak Security Re-Audit

This directory preserves the canonical completed re-audit artifacts for:

- target revision: `cdf438c51b1609eb4886d8edcddc22af183f48c0`;
- pull request: `#130`;
- scan id: `034f9d08-2613-402d-868e-0fce48bb6bfc`;
- producer: `codex-security-plugin` version `0.1.23`;
- started: `2026-09-05T12:30:40.014562Z`;
- completed and sealed: `2026-09-05T12:31:14.663978Z`;
- status: `completed`;
- coverage: `complete` within the declared scope; and
- reportable findings: `0`.

The scan separately dispositioned every initial finding as fixed:

- `csf_e77c8313ca0a303cedfa981b`: forged `CurrentInline` body;
- `csf_f989f2782c1a74ecb3f1c63b`: non-exclusive Ed25519 funded owner;
- `csf_0def7e2c09e504c51dc13d81`: unsigned request-id relabeling; and
- `csf_6b9af57d0e0e5c5425e690db`: slow native HTTP connection exhaustion.

[`scan-manifest.json`](scan-manifest.json),
[`findings.json`](findings.json), and [`coverage.json`](coverage.json) are the
canonical machine-readable artifacts. [`report.md`](report.md) is their
human-readable projection. The files are preserved without altering their
generated contents.

An earlier workbench envelope against the same revision stopped with a false
partial ledger after retaining resolved checkpoint rows. Its report explicitly
marks itself superseded by this sealed scan id, so it is not retained as the
authoritative audit result.

The audit was static and source-only. Its exclusions and limitations include
dynamic execution, dependency advisory lookup, production proxy/kernel/TLS
behavior, PostgreSQL deployment and operations, HA, backup, load/soak,
physical hardware, and mainnet behavior. The repository validation and GitHub
CI evidence for the target revision are separate from these scan artifacts.
