"""Container-local health and boundary checks. No third-party dependencies."""

import argparse
import json
import os
import socket
from pathlib import Path


def health():
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(2)
        conn.connect("/run/archive/http.sock")
        conn.sendall(b"GET /healthz HTTP/1.1\r\nHost: archive\r\nConnection: close\r\n\r\n")
        assert conn.recv(1024).startswith(b"HTTP/1.1 200"), "archive health failed"


def boundary():
    assert os.getuid() == 10001, "unexpected service user"
    assert set(os.listdir("/sys/class/net")) == {"lo"}, "container has a network interface"
    status = Path("/proc/self/status").read_text()
    assert "CapEff:\t0000000000000000" in status and "NoNewPrivs:\t1" in status, "privilege boundary missing"
    for path in ("/app/backend", "/var/run/docker.sock", "/root/.ssh", "/var/lib/caddy"):
        assert not os.path.exists(path), "unexpected production mount: " + path
    try:
        Path("/opt/archive/write-probe").write_text("probe")
    except OSError:
        pass
    else:
        raise AssertionError("root filesystem is writable")
    # Literal addresses avoid relying on DNS behavior; no payload is sent.
    for host, port in (("169.254.169.254", 80), ("172.17.0.1", 80), ("10.0.0.1", 443), ("1.1.1.1", 443), ("2606:4700:4700::1111", 443)):
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as conn:
            conn.settimeout(0.3)
            try:
                conn.connect((host, port))
            except OSError:
                continue
            raise AssertionError("unexpected outbound connectivity")
    health()
    print(
        json.dumps(
            {
                "network": "loopback only",
                "outboundProbes": "blocked",
                "user": 10001,
                "capabilities": "none",
                "rootFilesystem": "read-only",
                "unixHealth": "ready",
            }
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("health", "boundary"))
    args = parser.parse_args()
    health() if args.command == "health" else boundary()
