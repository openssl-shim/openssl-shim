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


def run() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", required=True)
    parser.add_argument("--server-bin", required=True)
    parser.add_argument("--client-bin", required=True)
    parser.add_argument("--port", type=int, default=9465)
    parser.add_argument("--startup-timeout", type=float, default=1.0)
    parser.add_argument("--client-timeout", type=float, default=30.0)
    parser.add_argument("--server-timeout", type=float, default=30.0)
    args = parser.parse_args()

    source_dir = Path(args.source_dir)
    server_bin = exe_path(Path(args.server_bin))
    client_bin = exe_path(Path(args.client_bin))

    if not server_bin.exists():
        raise FileNotFoundError(f"server binary not found: {server_bin}")
    if not client_bin.exists():
        raise FileNotFoundError(f"client binary not found: {client_bin}")

    cert = source_dir / "test" / "fixtures" / "trusted-server-crt.pem"
    key = source_dir / "test" / "fixtures" / "trusted-server-key.pem"

    server_cmd = [
        str(server_bin),
        "--port", str(args.port),
        "--cert", str(cert),
        "--key", str(key),
    ]

    server_proc = subprocess.Popen(
        server_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    server_output = ""
    try:
        # Avoid probing the port here: this server accepts exactly one client.
        time.sleep(args.startup_timeout)
        if server_proc.poll() is not None:
            out, _ = server_proc.communicate(timeout=1.0)
            server_output += out
            raise RuntimeError(f"renegotiation server exited early\n{server_output}")

        client_cmd = [str(client_bin), str(args.port)]
        try:
            client_res = subprocess.run(
                client_cmd,
                capture_output=True,
                text=True,
                timeout=args.client_timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("renegotiation client timed out") from exc

        try:
            out, _ = server_proc.communicate(timeout=args.server_timeout)
            server_output += out
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("renegotiation server did not exit in time") from exc

        if client_res.returncode != 0:
            raise RuntimeError(
                "renegotiation client failed\n"
                f"stdout:\n{client_res.stdout}\n"
                f"stderr:\n{client_res.stderr}\n"
                f"server output:\n{server_output}"
            )

        if server_proc.returncode != 0:
            raise RuntimeError(
                "renegotiation server failed\n"
                f"output:\n{server_output}"
            )

        if "Renegotiation complete" not in server_output:
            raise RuntimeError(
                "renegotiation server did not report completion\n"
                f"output:\n{server_output}"
            )

        return 0

    finally:
        if server_proc.poll() is None:
            server_proc.terminate()
            try:
                out, _ = server_proc.communicate(timeout=3.0)
                server_output += out
            except subprocess.TimeoutExpired:
                server_proc.kill()
                out, _ = server_proc.communicate(timeout=3.0)
                server_output += out


if __name__ == "__main__":
    raise SystemExit(run())
