"""Persistent Unix-socket admission agent with durable idempotency receipts."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import signal
import socketserver
import subprocess
import sys
import threading
import time
from pathlib import Path

from .protocol import AGENT_RECEIPT_SCHEMA, UUID_RE

MAX_FRAME = 12_000_000
MAX_RESPONSE = 24_000_000
WORKER_TIMEOUT = 1_200


def error(status: str, message: str) -> dict:
    return {"status": status, "error": message}


class Agent:
    def __init__(self, state: Path, max_jobs: int):
        self.jobs = state / "jobs"
        self.jobs.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.slots = threading.BoundedSemaphore(max_jobs)

    def execute(self, raw: bytes) -> dict:
        request_hash = hashlib.sha256(raw).hexdigest()
        try:
            request = json.loads(raw)
            key = request["idempotency_key"]
            if not isinstance(key, str) or not UUID_RE.fullmatch(key):
                raise ValueError("invalid idempotency key")
        except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            return error("rejected", str(exc))
        receipt_path = self.jobs / f"{key}.json"
        lock_path = self.jobs / f"{key}.lock"
        if receipt_path.exists():
            record = json.loads(receipt_path.read_text())
            if record.get("request_sha256") != request_hash:
                return error("rejected", "idempotency key collision")
            response = dict(record["response"])
            response["agent_replayed"] = True
            return response
        try:
            lock_fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            return error("in-progress", "same idempotency key is active")
        response = error("failed", "worker returned no valid response")
        exit_code = None
        started = time.time()
        try:
            os.write(lock_fd, request_hash.encode())
            os.close(lock_fd)
            proc = subprocess.Popen(
                [sys.executable, "-I", "-m", "cpu_router.worker"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            try:
                stdout, stderr = proc.communicate(raw, timeout=WORKER_TIMEOUT)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=10)
                response = error("failed", "worker timeout; process group killed")
            else:
                exit_code = proc.returncode
                if len(stdout) > MAX_RESPONSE:
                    response = error("failed", "worker response too large")
                else:
                    try:
                        response = json.loads(stdout)
                    except json.JSONDecodeError:
                        response = error(
                            "failed",
                            "invalid worker response: "
                            + stderr.decode(errors="replace")[-2048:],
                        )
            record = {
                "schema": AGENT_RECEIPT_SCHEMA,
                "request_sha256": request_hash,
                "idempotency_key": key,
                "started_unix": started,
                "ended_unix": time.time(),
                "worker_exit_code": exit_code,
                "response": response,
            }
            temporary = receipt_path.with_suffix(".tmp")
            with temporary.open("x") as handle:
                json.dump(record, handle, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            temporary.replace(receipt_path)
        finally:
            lock_path.unlink(missing_ok=True)
        return response


class Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = self.request.recv(min(65_536, MAX_FRAME + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > MAX_FRAME:
                self.request.sendall(
                    json.dumps(error("rejected", "request too large")).encode()
                )
                return
        server = self.server
        if not isinstance(server, Server):
            self.request.sendall(json.dumps(error("failed", "invalid server")).encode())
            return
        if not server.agent.slots.acquire(blocking=False):
            response = error("busy", "host concurrency limit reached")
        else:
            try:
                response = server.agent.execute(b"".join(chunks))
            finally:
                server.agent.slots.release()
        self.request.sendall(json.dumps(response, separators=(",", ":")).encode())


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = False
    block_on_close = True

    def __init__(self, socket_path: str, agent: Agent):
        self.agent = agent
        super().__init__(socket_path, Handler)


def main() -> int:
    runtime = Path(
        os.environ.get("RUNTIME_DIRECTORY", f"/run/user/{os.getuid()}/cpu-router")
    )
    state = Path(
        os.environ.get("STATE_DIRECTORY", Path.home() / ".local/state/cpu-router")
    )
    runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock_handle = (runtime / "agent.lock").open("w")
    try:
        fcntl.flock(lock_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("CPU Router agent already running", file=sys.stderr)
        return 73
    socket_path = runtime / "agent.sock"
    socket_path.unlink(missing_ok=True)
    max_jobs = int(os.environ.get("CPU_ROUTER_MAX_JOBS", "1"))
    if not 1 <= max_jobs <= 16:
        print("CPU_ROUTER_MAX_JOBS must be 1..16", file=sys.stderr)
        return 64
    with Server(str(socket_path), Agent(state, max_jobs)) as server:
        os.chmod(socket_path, 0o600)
        server.serve_forever(poll_interval=0.25)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
