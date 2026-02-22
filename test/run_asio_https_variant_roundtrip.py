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
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--server-bin", required=True)
    parser.add_argument("--client-bin", required=True)

    parser.add_argument("--server-cert")
    parser.add_argument("--server-key")
    parser.add_argument("--server-cert-der")
    parser.add_argument("--server-key-der")
    parser.add_argument("--server-chain-pem")

    parser.add_argument("--client-ca", required=True)
    parser.add_argument("--client-host", default="127.0.0.1")

    args = parser.parse_args()

    source_dir = Path(args.source_dir)
    if not source_dir.exists():
        raise FileNotFoundError(f"Source directory not found: {source_dir}")

    server_bin = exe_path(Path(args.server_bin))
    client_bin = exe_path(Path(args.client_bin))

    if not server_bin.exists():
        raise FileNotFoundError(f"Server binary not found: {server_bin}")
    if not client_bin.exists():
        raise FileNotFoundError(f"Client binary not found: {client_bin}")

    server_cmd = [str(server_bin), "--port", str(args.port)]
    if args.server_cert:
        server_cmd += ["--cert", args.server_cert]
    if args.server_key:
        server_cmd += ["--key", args.server_key]
    if args.server_cert_der:
        server_cmd += ["--cert-der", args.server_cert_der]
    if args.server_key_der:
        server_cmd += ["--key-der", args.server_key_der]
    if args.server_chain_pem:
        server_cmd += ["--chain-pem", args.server_chain_pem]

    server_proc = subprocess.Popen(server_cmd)
    try:
        time.sleep(0.3)
        if server_proc.poll() is not None:
            raise RuntimeError("Asio HTTPS server exited before client started")

        client_cmd = [
            str(client_bin),
            "--port",
            str(args.port),
            "--host",
            args.client_host,
            "--ca",
            args.client_ca,
        ]
        try:
            result = subprocess.run(client_cmd, timeout=20)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("Asio HTTPS client timed out") from exc
        if result.returncode != 0:
            raise RuntimeError("Asio HTTPS client failed")

        server_rc = server_proc.wait(timeout=5)
        if server_rc != 0:
            raise RuntimeError(f"Asio HTTPS server exited with code {server_rc}")

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
