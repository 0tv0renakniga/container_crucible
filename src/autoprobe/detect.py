"""
detect.py - project-type detection and static Python import scanning.
"""
from __future__ import annotations

import ast
import os
import re
import warnings
from pathlib import Path

# --------------------------------------------------------------------------
# Project detection
# --------------------------------------------------------------------------
def detect_project(repo: Path) -> dict:
    has = lambda *names: any((repo / n).exists() for n in names)  # noqa: E731
    python = has("pyproject.toml", "setup.py", "setup.cfg", "requirements.txt")
    info = {"python": python, "pkgs": [], "pips": [], "label": "unknown",
            "build": "cd /app/repo && ls -la"}
    nproc = '"$(nproc)"'
    if has("autogen.sh", "bootstrap", "bootstrap.sh") and not has("configure"):
        script = next(n for n in ("autogen.sh", "bootstrap", "bootstrap.sh") if has(n))
        info.update(label="autotools (bootstrap script)",
                    build=f"cd /app/repo && bash ./{script} && ./configure && make -j{nproc}")
    elif has("configure.ac", "configure.in"):
        info.update(label="autotools",
                    build=f"cd /app/repo && autoreconf -fi && ./configure && make -j{nproc}")
    elif has("configure"):
        info.update(label="configure script",
                    build=f"cd /app/repo && ./configure && make -j{nproc}")
    elif has("CMakeLists.txt"):
        info.update(label="cmake", pkgs=["cmake"],
                    build=("cd /app/repo && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release "
                           f"&& cmake --build build -j{nproc}"))
    elif has("meson.build"):
        info.update(label="meson", pips=["meson", "ninja"], python=True,
                    build="cd /app/repo && meson setup build && ninja -C build")
    elif python:
        info.update(label="python",
                    build=("cd /app/repo && { [ ! -f requirements.txt ] || "
                           "pip install -r requirements.txt; } && pip install ."))
    elif has("Makefile", "makefile", "GNUmakefile"):
        info.update(label="make", build=f"cd /app/repo && make -j{nproc}")
    return info


# --------------------------------------------------------------------------
# Python import scanner (works with or without pyproject.toml)
# --------------------------------------------------------------------------
SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "build", "dist", "__pycache__",
             ".tox", "venv", ".venv", "env", ".eggs"}
# Python-2 stdlib modules: NOT pip packages, so never try to pip install them.
PY2_ONLY = {"urllib2", "urlparse", "ConfigParser", "Tkinter", "cPickle", "StringIO",
            "cStringIO", "Queue", "httplib", "commands", "__builtin__", "SocketServer",
            "HTMLParser", "tkMessageBox", "copy_reg", "xmlrpclib", "Cookie"}
IMPORT_RX = re.compile(
    r"^\s*(?:from\s+([A-Za-z_][\w.]*)\s+import\s|import\s+([A-Za-z_][\w.,\t ]*))", re.M)


def scan_python(repo: Path, max_files: int = 5000) -> dict:
    """Statically collect imports from *.py files AND extension-less scripts whose
    shebang mentions python (e.g. Examples/TimeExample/Plot).  Uses ast; files that
    don't parse (Python 2 code) fall back to a regex."""
    files: list[Path] = []
    local: set[str] = set()
    pkg_parent: dict[str, str] = {}
    for root, dirs, names in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        rootp = Path(root)
        has_py = False
        for n in names:
            fp = rootp / n
            if n.endswith(".py"):
                files.append(fp)
                local.add(n[:-3])
                has_py = True
                if n == "__init__.py" and rootp != repo:
                    pkg_parent[rootp.name] = str(rootp.relative_to(repo).parent)
            elif "." not in n and len(files) < max_files:
                try:
                    with fp.open("rb") as f:
                        head = f.readline(200)
                except OSError:
                    continue
                if head.startswith(b"#!") and b"python" in head:
                    files.append(fp)
                    has_py = True
        if has_py and rootp != repo:
            local.add(rootp.name)
        if len(files) >= max_files:
            break

    imports: set[str] = set()
    py2_files = 0
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        for fp in files:
            try:
                src = fp.read_text(encoding="utf-8", errors="replace")[:2_000_000]
            except OSError:
                continue
            try:
                for node in ast.walk(ast.parse(src)):
                    if isinstance(node, ast.Import):
                        imports.update(a.name.split(".")[0] for a in node.names)
                    elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                        imports.add(node.module.split(".")[0])
            except (SyntaxError, ValueError):
                py2_files += 1
                for m in IMPORT_RX.finditer(src):
                    if m.group(1):
                        imports.add(m.group(1).split(".")[0])
                    else:
                        for part in m.group(2).split(","):
                            tok = part.strip().split(" ")[0].split(".")[0]
                            if tok:
                                imports.add(tok)
    imports.discard("__future__")
    third = sorted(i for i in imports if i and i not in local)
    pypath = sorted({os.path.normpath(os.path.join("/app/repo", par))
                     for name, par in pkg_parent.items() if name in imports})
    return {"files": len(files), "third_party": third, "python_path": pypath,
            "py2_files": py2_files}
