# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |
| Earlier/unreleased snapshots | No |

## Report privately

Use GitHub's private vulnerability reporting for this repository. Do not open a public issue containing keys, usernames, hostnames, IP addresses, filesystem paths, receipts, or network topology.

Expected response targets are 72 hours for acknowledgement, five business days for initial triage, and coordinated disclosure within 90 days when a fix is required. These are response targets, not guarantees.

## Security boundary

CPU Router relies on:

- OpenSSH host-key verification and a dedicated task key;
- an `authorized_keys` forced command with `restrict`;
- an owner-only Unix socket;
- a closed JSON protocol with bounded frames;
- configured SHA-256 matching for the installed `worker.py` module file;
- deterministic source manifests and archive/member digests;
- pinned Rust toolchains, `--locked`, and offline Cargo execution;
- systemd and process resource limits.

It does not provide a separate cryptographic application protocol, multi-tenant isolation, protection from a compromised owner host, or a general-purpose sandbox. The wire protocol accepts no arbitrary shell command, but admitted trusted repository source can execute build scripts, procedural macros, tests, compilers, and linkers on the owner. Repository-local `.cargo` configuration is excluded. Route only source you trust to hosts you administer.

## In scope

- command or path injection across the closed request boundary;
- bypass of source, worker, host, architecture, or artifact verification;
- secret-file inclusion despite the declared selection policy;
- symlink/traversal escape;
- idempotency collisions or duplicate execution;
- silent fallback after admitted remote failure.

## Out of scope

- vulnerabilities in OpenSSH, Git, Cargo, Rust, Python, or systemd themselves;
- physical access or compromised administrator/root accounts;
- denial of service beyond documented ceilings;
- unsafe behavior in third-party Rust build scripts submitted by the operator.
