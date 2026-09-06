# CPU Router / Cargo Automation

<!-- last-verified: 2026-09-06 -->

Fail-closed, architecture-owned Cargo jobs over restricted SSH. A client creates a deterministic, digest-bound snapshot of a Git worktree; the configured native owner runs an allowlisted Cargo action in an isolated directory and returns a typed result or verified ELF binary.

> **Alpha and Linux-only.** This is not transparent process migration, a generic remote shell, or a claim that remote compilation is always faster. Review the threat model and configuration before enabling the optional `cargo` wrapper.

## Why

Rust work can be assigned to machines that own the target architecture without copying an uncontrolled working directory or exposing a generic remote-shell interface:

- `x86_64-unknown-linux-gnu` → configured x86-64 owner
- `aarch64-unknown-linux-gnu` → configured AArch64 owner
- missing owner, source tamper, unknown action, toolchain drift, or artifact mismatch → fail closed

Admitted Cargo jobs still execute repository-controlled build scripts,
procedural macros, tests, and compiler inputs on the owner host. Route only
trusted source from trusted submitters.

There are no calls to OpenAI, Anthropic, Pinecone, Weaviate, Supabase, or any hosted AI service. Runtime traffic is ordinary OpenSSH plus a local Unix socket. Cargo dependency access is disabled inside admitted jobs; dependencies must already exist in the owner's Cargo cache.

## Verified surface

| Capability | State |
|---|---|
| Deterministic tar+gzip source envelope | Tested |
| Manifest/archive/member SHA-256 verification | Tested |
| Secret-name, traversal, symlink, and undeclared-member rejection | Tested |
| Strict Cargo `check`, `test`, and constrained release `build` grammar | Tested |
| Durable same-request replay and changed-request collision rejection | Tested |
| Configured `worker.py` module-file digest, host identity, target architecture, and ELF-machine checks | Tested |
| Live deployment on arbitrary hardware | Operator responsibility |
| General remote shell | Deliberately unsupported |
| Windows/macOS owners | Unsupported in v0.1.0 |
| Security audit or production certification | Not claimed |

## How it works

```text
cargo/cpu-cargo
  └─ snapshot tracked + unignored Git files
      └─ manifest + archive digests
          └─ OpenSSH key restricted to cpu-router-submit
              └─ owner-only Unix socket
                  └─ bounded admission agent
                      └─ isolated Cargo worker
                          ├─ pinned native toolchain
                          ├─ forced --locked + offline mode
                          └─ verified result / ELF artifact
```

The worker accepts a closed JSON request. It never accepts a shell string, caller-controlled remote path, target directory, manifest path, or arbitrary environment map.

## Prerequisites

- Linux client and owner hosts
- Python 3.11+
- OpenSSH client/server
- Git
- `uv` for the documented installation path
- Rust toolchains installed under `~/.rustup/toolchains/<pinned-toolchain>` on each owner
- Required locked Cargo dependencies already cached on each owner

## Install

Install the same release on the client and every owner:

```bash
uv tool install .
```

Verify the entry points:

```bash
cpu-router --help
cpu-router --version
cpu-router-worker-sha256
```

Copy and edit the configuration:

```bash
mkdir -p ~/.config/cpu-router
cp config.example.json ~/.config/cpu-router/config.json
chmod 600 ~/.config/cpu-router/config.json
```

`config.json` must name both architecture owners, pinned toolchains, dedicated task-key path, dedicated known-hosts file, and the expected SHA-256 of the installed `worker.py` module file on that owner. This is a narrow installation-drift check, not whole-package integrity. Obtain it without printing source:

```bash
cpu-router-worker-sha256
```

### Owner agent

Copy `systemd/cpu-router-agent.service` to `~/.config/systemd/user/`, replace the three `REPLACE_...` values, then:

```bash
systemctl --user daemon-reload
systemctl --user enable --now cpu-router-agent.service
systemctl --user is-active cpu-router-agent.service
```

The service uses an owner-only socket under `%t/cpu-router/agent.sock`. Adjust CPU and memory ceilings to the actual host.

### Restricted SSH ingress

Create a dedicated key on each client. Do not reuse a login key:

```bash
ssh-keygen -t ed25519 -N '' -f ~/.ssh/cpu_router_tasks_ed25519
```

On each owner, add only that public key with a forced command and OpenSSH restrictions. Replace the executable path with the result of `command -v cpu-router-submit` on the owner:

```text
restrict,command="/ABSOLUTE/PATH/cpu-router-submit" ssh-ed25519 PUBLIC_KEY_MATERIAL cpu-router-task-client
```

Create `~/.ssh/cpu_router_known_hosts` from independently verified owner host keys. Do not disable strict host-key checking.

Then set `expected_worker_sha256` in the client config and test each owner:

```bash
cpu-router --arch x86_64 health
cpu-router --arch aarch64 health
```

Success is a client receipt whose status is `verified-transport-identity-and-worker-module`.

## Cargo usage

Explicit routing:

```bash
cpu-cargo check --workspace --all-targets
cpu-cargo test -p your-crate --all-targets
cpu-cargo build --release --bin your-binary
cpu-cargo test --target aarch64-unknown-linux-gnu --all-targets
```

Optional transparent command name:

```bash
ln -s "$(command -v cpu-cargo)" ~/.local/bin/cargo
```

Only admitted `check`, `test`, and single-binary release `build` shapes route remotely. Other commands execute the configured real Cargo and print the reason. Once a request is admitted remotely, failure never silently recompiles locally.

Force a local execution:

```bash
CPU_ROUTER_LOCAL=1 cargo check
```

## Snapshot contract

Included files are `git ls-files --cached --others --exclude-standard`, minus explicit control/derived trees. Each file is bounded, read once through a no-follow descriptor with metadata checked before and after the read, hashed, sorted, and archived with normalized tar/gzip metadata.

Rejected inputs include:

- absolute paths or `..`
- symlinks and non-regular files
- `.git`, `.ares`, `.cargo`, `.ssh`, `target`, `node_modules`, virtual environments, and receipt roots
- common secret filenames and key/container suffixes
- more than 5,000 files, files over 2 MiB, source over 32 MiB, or compressed envelopes over 8 MiB

Filename checks reduce accidental disclosure; they cannot prove arbitrary source text contains no secret. Review the selected source set before using a remote owner outside your trust boundary.

No arbitrary command string crosses the wire protocol. That is not a promise
that admitted jobs execute no programs: trusted repository source can run Cargo
build scripts, procedural macros, tests, compilers, and linkers under the
worker's offline, path, timeout, and systemd restrictions. Repository-local
`.cargo` configuration is excluded to prevent source-selected compiler wrappers
and Cargo aliases from widening that boundary.

## Failure and idempotency

The client retries `busy`/`in-progress` admission using one UUID. The agent stores one durable response per UUID:

- same UUID + same canonical request → replay with `agent_replayed=true`
- same UUID + different request → `idempotency key collision`
- owner unavailable or response invalid → failure, no local fallback

## Validation

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m compileall -q src tests
uv build
PYTHONPATH=src python3 scripts/smoke_installed.py
```

The unit suite is hermetic and does not contact remote hosts.

## Limits

- No scheduler fairness across users or hosts
- No encrypted application layer beyond SSH
- No sandbox stronger than systemd restrictions, resource limits, and isolated directories
- No online dependency fetch in admitted jobs
- No distributed `rustc`/sccache implementation
- Exact source snapshots trade incremental reuse for stronger provenance
- Network and filesystem trust still depend on your SSH and host administration

## Rollback

Remove the optional `~/.local/bin/cargo` symlink first; the real Cargo path in `config.json` remains unchanged. Then disable the owner agent:

```bash
systemctl --user disable --now cpu-router-agent.service
rm ~/.config/systemd/user/cpu-router-agent.service
systemctl --user daemon-reload
uv tool uninstall cpu-router-cargo-automation
```

After preserving any evidence you need, remove only CPU Router configuration,
receipts, caches, the dedicated `cpu_router_tasks_ed25519` keypair, and
`cpu_router_known_hosts`. On each owner, remove only the forced-command
`authorized_keys` line carrying the dedicated task-key comment. Do not remove
general SSH credentials or unrelated `authorized_keys` entries.

## Security

Read [SECURITY.md](SECURITY.md). Do not report vulnerabilities in public issues when they include hostnames, keys, usernames, paths, or network topology.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Changes that widen the request grammar, add shell execution, disable host-key checking, weaken worker-digest verification, or introduce silent fallback will not be accepted without a new protocol and threat-model review.

## License

[MIT](LICENSE)
