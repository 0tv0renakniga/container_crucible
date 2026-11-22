"""
diagnose.py - pure failure-diagnosis logic: maps build-log error text to a
list of (kind, arg) remediation actions. kinds: dnf | provides | pip | python | pyver.
"""
from __future__ import annotations

import os
import re

from .config_loader import COMMAND_TO_PKG, LIB_KEYWORDS, MACRO_TO_PKG, MODULE_TO_PIP, PIP_TOOLS

ERR_LINE = re.compile(
    r"error|not found|could not|could not find|cannot find|no such file|undefined|"
    r"missing|required|unable|failed|no package|no module", re.I)


def command_action(tool: str):
    tool = os.path.basename(tool)
    if tool in PIP_TOOLS:
        return ("pip", tool)
    if tool in ("python", "python3", "pip", "pip3") or re.fullmatch(r"python3\.\d+", tool):
        return ("python", "")
    if tool in COMMAND_TO_PKG:
        return ("dnf", COMMAND_TO_PKG[tool])
    return ("provides", f"*/bin/{tool}")


def diagnose(text: str, pyver: str = "3.11") -> list[tuple[str, str]]:
    """Return an ordered, de-duplicated list of (kind, arg) fixes.
    kinds: dnf | provides | pip | python | pyver"""
    acts: list[tuple[str, str]] = []

    def add(kind: str, arg: str) -> None:
        if (kind, arg) not in acts:
            acts.append((kind, arg))

    lines = text.splitlines()
    tail = lines[-120:]
    blob = "\n".join(lines[-4000:])

    # 1. Explicit toolchain failures from ./configure
    for m in re.finditer(r"configure: error: (.+)", blob):
        msg = m.group(1).lower()
        if "c++ compiler" in msg:
            add("dnf", "gcc-c++")
        elif "c compiler" in msg:
            add("dnf", "gcc")
        elif "fortran" in msg:
            add("dnf", "gcc-gfortran")

    # 2. Library keywords on the error lines near the end of the log
    err_lines = [l for l in tail if ERR_LINE.search(l)]
    err_lines += [m.group(0) for m in re.finditer(r"configure: error:.*", blob)]
    for line in err_lines:
        for rx, pkg in LIB_KEYWORDS:
            if re.search(rx, line, re.I):
                add("dnf", pkg)

    # 3. Missing commands
    for m in re.finditer(r"([\w.+/-]+): (?:command )?not found", blob):
        add(*command_action(m.group(1)))
    for m in re.finditer(r"""Can't exec ["']([^"']+)["']""", blob):
        add(*command_action(m.group(1)))
    for m in re.finditer(r"""env: ['"]?([\w.+-]+)['"]?: No such file""", blob):
        add(*command_action(m.group(1)))
    for m in re.finditer(r"Unknown compiler\(s\): \[?['\"]?(\w+)", blob):
        add(*command_action(m.group(1)))
    if re.search(r"unable to find a build program corresponding to \"?Ninja", blob, re.I):
        add("pip", "ninja")

    # 4. Missing headers
    for m in re.finditer(r"([\w./+-]+\.(?:h|hpp|hh|H)):\s*No such file or directory", blob):
        hdr = m.group(1)
        if os.path.basename(hdr) == "Python.h":
            add("dnf", f"python{pyver}-devel")
        else:
            add("provides", f"*/{hdr}")

    # 5. Missing link libs
    for m in re.finditer(r"cannot find -l([\w+.-]+)", blob):
        add("provides", f"*/lib{m.group(1)}.so")

    # 6. pkg-config / meson dependencies
    for rx in (r"No package '([^']+)' found", r"Package '([^']+)', required by", r"Package '?([\w.+-]+)'? (?:was )?not found",
               r"Dependency \"([\w.+-]+)\" not found", r"Run-time dependency ([\w.+-]+) found: NO"):
        for m in re.finditer(rx, blob):
            add("provides", f"pkgconfig({m.group(1)})")

    # 7. CMake
    for m in re.finditer(r'Could not find a package configuration file provided by "([\w.+-]+)"', blob):
        add("provides", f"cmake({m.group(1)})")
    for m in re.finditer(r"CMake Error[^\n]*\n(?:[^\n]*\n){0,3}?[^\n]*Could NOT find (\w+)", blob):
        name = m.group(1).lower()
        hit = False
        for rx, pkg in LIB_KEYWORDS:
            if re.search(rx, name):
                add("dnf", pkg)
                hit = True
        if not hit:
            add("provides", f"*/lib{name}.so")

    # 8. Autoconf macros
    for m in re.finditer(r"possibly undefined macro:\s*(\w+)", blob):
        for rx, pkg in MACRO_TO_PKG:
            if re.match(rx, m.group(1)):
                add("dnf", pkg)
                break

    # 9. Python
    for m in re.finditer(r"No module named ['\"]([\w.]+)['\"]", blob):
        top = m.group(1).split(".")[0]
        add("pip", MODULE_TO_PIP.get(top, top))
    m = re.search(r"requires a different Python: [\d.]+ not in '([^']+)'", blob)
    if m:
        need = re.search(r">=\s*(\d+)\.(\d+)", m.group(1))
        if need:
            want = (int(need.group(1)), int(need.group(2)))
            for v in ("3.9", "3.11", "3.12"):
                if tuple(map(int, v.split("."))) >= want:
                    if tuple(map(int, v.split("."))) > tuple(map(int, pyver.split("."))):
                        add("pyver", v)
                    break
    if re.search(r"can't find Rust compiler|rustc.*not found|cargo.*not found", blob, re.I):
        add("dnf", "rust")
        add("dnf", "cargo")

    return acts
