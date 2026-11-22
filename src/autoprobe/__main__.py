#!/usr/bin/env python3
"""
autoprobe - discover the dependencies a git project needs to build on a
RHEL 8 (UBI 8) image, then emit a reproducible Containerfile.

How it works
------------
1. Starts ONE long-lived container from the base image (no image rebuild per loop).
2. Copies the repo in, runs probe commands + build command, STREAMING output live.
3. On failure, parses the log, maps the error to a package (static tables first,
   then `dnf provides` for headers / libs / commands / pkg-config / cmake modules,
   then pip for Python modules), installs it inside the SAME container, retries.
4. When the build passes, writes Containerfile + updates config.yaml.
   Optional --verify does a clean `podman build` + `podman run` of the result.

Works for: autotools, CMake, Meson, plain Makefile, and Python projects
(pyproject / setup.py / requirements.txt, built in a venv at /opt/venv).

RHEL/UBI repos only (no third-party repos).  UBI 8 does NOT ship gsl-devel,
hdf5-devel, etc.  We enable the UBI CodeReady Builder repo (extra -devel packages),
and when a package is still missing we fall back to source recipes (GSL, HDF5 built
into /usr/local) or your own `source_builds:` entries in config.yaml.
"""
from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

import yaml

from . import io_utils
from .io_utils import LOG_FILE
from .prober import Prober


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("-c", "--config", default="config.yaml")
    ap.add_argument("-n", "--max-loops", type=int, default=0, help="override max_loops")
    ap.add_argument("--verify", action="store_true", help="clean podman build+run at the end")
    ap.add_argument("--keep", action="store_true", help="keep probe container after success")
    args = ap.parse_args()

    if not shutil.which("podman"):
        print("podman not found in PATH", file=sys.stderr)
        return 1
    cfg_path = Path(args.config)
    if not cfg_path.exists():
        print(f"Missing {cfg_path}", file=sys.stderr)
        return 1
    cfg = yaml.safe_load(cfg_path.read_text()) or {}
    if not cfg.get("repo_name") or not Path(cfg["repo_name"]).is_dir():
        print(f"repo_name directory not found: {cfg.get('repo_name')}", file=sys.stderr)
        return 1

    with LOG_FILE.open("w") as f:
        io_utils.LOGF = f
        try:
            return Prober(cfg, cfg_path, args).run()
        except KeyboardInterrupt:
            print("\nInterrupted. Probe container left running for inspection.", file=sys.stderr)
            return 130


if __name__ == "__main__":
    sys.exit(main())
