#!/usr/bin/env python3
import argparse
import subprocess
from pathlib import Path


def run() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", default="build")
    parser.add_argument("--config", default="Debug")
    parser.add_argument("--target", action="append", default=[])
    parser.add_argument("--regex", default="")
    parser.add_argument("--timeout", type=float, default=600.0)
    args = parser.parse_args()

    build_dir = Path(args.build_dir)

    for target in args.target:
        cmd = ["cmake", "--build", str(build_dir), "--parallel", "--config", args.config, "--target", target]
        print("[run_selected_ctest]", " ".join(cmd))
        subprocess.check_call(cmd, timeout=args.timeout)

    ctest_cmd = ["ctest", "--test-dir", str(build_dir), "-C", args.config, "--output-on-failure"]
    if args.regex:
        ctest_cmd += ["-R", args.regex]
    print("[run_selected_ctest]", " ".join(ctest_cmd))
    subprocess.check_call(ctest_cmd, timeout=args.timeout)
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
