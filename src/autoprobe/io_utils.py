"""
io_utils.py - console/log output and subprocess streaming helpers used
throughout autoprobe.

LOGF is a module-level file handle that, when set, mirrors everything
say()/stream() print to a log file. __main__.py sets io_utils.LOGF
(replacing the old `global LOGF` pattern in the monolithic script).
"""
from __future__ import annotations

import shlex
import subprocess
import sys
from pathlib import Path

LOG_FILE = Path("autoprobe.log")

# Set by __main__.py before running the Prober (io_utils.LOGF = <open file>).
LOGF = None


def say(msg: str) -> None:
    line = f"\n>>> {msg}"
    print(line, flush=True)
    if LOGF:
        LOGF.write(line + "\n")


def stream(cmd: list[str], echo: bool = True) -> tuple[int, str]:
    """Run cmd, stream its output live, return (rc, full output)."""
    header = "$ " + " ".join(shlex.quote(c) for c in cmd[:6]) + (" ..." if len(cmd) > 6 else "")
    if echo:
        print(header, flush=True)
    if LOGF:
        LOGF.write(header + "\n")
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, bufsize=1, errors="replace")
    except FileNotFoundError as exc:
        return 127, str(exc)
    buf = []
    assert p.stdout
    for line in p.stdout:
        if echo:
            sys.stdout.write(line)
            sys.stdout.flush()
        if LOGF:
            LOGF.write(line)
        buf.append(line)
    p.wait()
    return p.returncode, "".join(buf)
