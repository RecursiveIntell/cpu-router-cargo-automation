# AGENTS.md

## Source ownership

- `src/cpu_router/protocol.py` owns schemas, architecture aliases, and canonical encoding.
- `src/cpu_router/snapshot.py` owns source selection, archive verification, and Cargo argument admission.
- `src/cpu_router/worker.py` owns bounded Cargo execution and ELF artifact production.
- `src/cpu_router/agent.py` owns concurrency and durable idempotency.
- `src/cpu_router/client.py` owns SSH transport verification and client receipts.
- `src/cpu_router/cargo_wrapper.py` owns local-versus-remote Cargo routing and artifact promotion.

Do not duplicate these semantics in installers or documentation.

## Required checks

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests
python3 -m build
```

## Hard boundaries

- Never accept a shell command, remote path, target directory, environment map, or arbitrary Cargo flag from the wire protocol.
- Never disable strict SSH host-key checking or worker digest verification.
- Never fall back locally after a request has been admitted remotely.
- Never include credentials, hostnames, IP addresses, usernames, or live receipts in tracked fixtures.
- Preserve exact idempotency: same key/same request replays; same key/different request rejects.
- New files and public docs must remain MIT-compatible.

## Publication

Stage named files only, run the required checks, inspect the full diff for topology or secrets, sign off commits, and use a PR to `main`.
