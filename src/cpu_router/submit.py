"""Restricted-SSH forced command: relay stdin to the owner-only Unix socket."""

from __future__ import annotations

import json
import os
import socket
import sys
from pathlib import Path

MAX_FRAME = 12_000_000
MAX_RESPONSE = 24_000_000
EXIT_BY_STATUS = {"ok": 0, "rejected": 2, "failed": 3, "busy": 75, "in-progress": 75}


def main() -> int:
    raw = sys.stdin.buffer.read(MAX_FRAME + 1)
    if len(raw) > MAX_FRAME:
        print(json.dumps({"status": "rejected", "error": "request too large"}))
        return 2
    runtime = (
        Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}"))
        / "cpu-router"
    )
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(1_210)
            client.connect(str(runtime / "agent.sock"))
            client.sendall(raw)
            client.shutdown(socket.SHUT_WR)
            chunks: list[bytes] = []
            size = 0
            while True:
                chunk = client.recv(min(65_536, MAX_RESPONSE + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > MAX_RESPONSE:
                    raise ValueError("agent response too large")
        response = b"".join(chunks)
        parsed = json.loads(response)
        sys.stdout.buffer.write(response)
        return EXIT_BY_STATUS.get(parsed.get("status"), 1)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(
            json.dumps({"status": "failed", "error": str(exc)}, separators=(",", ":"))
        )
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
