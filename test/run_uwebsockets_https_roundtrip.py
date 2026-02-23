#!/usr/bin/env python3
import argparse
import subprocess
import sys
import time
from pathlib import Path


def exe_path(path: Path) -> Path:
    if sys.platform.startswith("win") and path.suffix.lower() != ".exe":
        return path.with_suffix(path.suffix + ".exe")
    return path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", required=True)
    parser.add_argument("--port", type=int, default=9560)
    parser.add_argument("--server-bin", required=True)
    parser.add_argument("--client-bin", required=True)
    args = parser.parse_args()

    source_dir = Path(args.source_dir)
    server_bin = exe_path(Path(args.server_bin))
    client_bin = exe_path(Path(args.client_bin))

    cert = source_dir / "test" / "fixtures" / "trusted-server-crt.pem"
    key = source_dir / "test" / "fixtures" / "trusted-server-key.pem"
    ca = source_dir / "test" / "fixtures" / "trusted-ca-crt.pem"

    if not server_bin.exists():
        raise FileNotFoundError(f"Server binary not found: {server_bin}")
    if not client_bin.exists():
        raise FileNotFoundError(f"Client binary not found: {client_bin}")

    server_cmd = [
        str(server_bin),
        "--port",
        str(args.port),
        "--cert",
        str(cert),
        "--key",
        str(key),
    ]

    server_proc = subprocess.Popen(server_cmd)
    try:
        time.sleep(0.4)
        if server_proc.poll() is not None:
            raise RuntimeError("uWebSockets HTTPS server exited before client started")

        client_cmd = [
            str(client_bin),
            "--port",
            str(args.port),
            "--host",
            "127.0.0.1",
            "--ca",
            str(ca),
        ]
        try:
            result = subprocess.run(client_cmd, timeout=20)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("uWebSockets HTTPS client timed out") from exc
        if result.returncode != 0:
            raise RuntimeError("uWebSockets HTTPS client failed")

    finally:
        if server_proc.poll() is None:
            server_proc.terminate()
            try:
                server_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server_proc.kill()
                server_proc.wait()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
