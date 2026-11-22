"""
prober.py - the Prober class: drives a long-lived podman container through
repeated probe/build/fix/retry cycles, and emits the final Containerfile and
config.yaml on success.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import sys
from pathlib import Path

import yaml

from .config_loader import BASELINE, BLOCKED, ENV_SCRIPT, SOURCE_RECIPES
from .detect import detect_project, scan_python
from .diagnose import command_action, diagnose
from .io_utils import LOG_FILE, say, stream

DEFAULT_BASE = "registry.access.redhat.com/ubi8/ubi:latest"
CONTAINERFILE = Path("Containerfile")
ENV_FILE = Path("autoprobe-env.sh")

# UBI ships a CodeReady Builder repo (disabled by default) with extra -devel packages.
ENABLE_CRB = ("sed -i '/^\\[ubi-8-codeready-builder\\]/,/^\\[/ s/^enabled *= *0/enabled = 1/' "
              "/etc/yum.repos.d/ubi.repo || true")

NEVRA = re.compile(
    r"^(?P<n>\S+?)-(?:\d+:)?\d[^\s]*?\.(?:x86_64|aarch64|noarch|i686|ppc64le|s390x)\s+:")


class Prober:
    def __init__(self, cfg: dict, cfg_path: Path, args: argparse.Namespace):
        self.cfg, self.cfg_path, self.args = cfg, cfg_path, args
        self.base = cfg.get("base_image", DEFAULT_BASE)
        self.image = cfg.get("image_name", "rhel8-auto-probe")
        self.repo = cfg["repo_name"]
        self.cname = f"{self.image}-probe"
        self.max_loops = args.max_loops or int(cfg.get("max_loops", 10))
        self.enable_crb = bool(cfg.get("enable_ubi_crb", True))
        self.probes = list(cfg.get("probe_commands") or [])
        self.test_cmd = cfg.get("test_cmd")
        self.user_env = cfg.get("env") or {}

        proj = detect_project(Path(self.repo))
        self.project = proj
        self.build_cmd = cfg.get("build_cmd") or proj["build"]
        self.pyscan = scan_python(Path(self.repo))
        self.python = bool(cfg.get("python", proj["python"] or self.pyscan["files"] > 0))
        self.pypath = list(cfg.get("python_path") or self.pyscan["python_path"])
        self.last_out = ""
        native = proj["label"] not in ("python", "unknown", "meson")
        default_install = ""
        if self.pyscan["files"] and native:
            default_install = ("cd /app/repo && cmake --install build && ldconfig"
                               if proj["label"] == "cmake"
                               else "cd /app/repo && make install && ldconfig")
        self.install_cmd = cfg.get("install_cmd", default_install) or ""
        self.pyver = str(cfg.get("python_version", "3.11"))

        pk = BASELINE + proj["pkgs"] + list(cfg.get("packages") or [])
        self.pkgs: list[str] = []
        for p in pk:
            if p not in BLOCKED and p not in self.pkgs:
                self.pkgs.append(p)
        self.pips: list[str] = list(dict.fromkeys(proj["pips"] + list(cfg.get("pip_packages") or [])))
        self.sources: list[dict] = list(cfg.get("source_builds") or [])
        self.tried: set[tuple[str, str]] = set()

    # ---- container plumbing -------------------------------------------------
    def sh(self, script: str, echo: bool = True) -> tuple[int, str]:
        return stream(["podman", "exec", self.cname, "bash", "-lc", script], echo=echo)

    def env_text(self) -> str:
        extra = "".join(f"export {k}={shlex.quote(str(v))}\n" for k, v in self.user_env.items())
        if self.py_paths():
            extra = (f"export PYTHONPATH={':'.join(self.py_paths())}${{PYTHONPATH:+:$PYTHONPATH}}\n"
                     + extra)
        return ENV_SCRIPT + extra

    def write_support_files(self) -> None:
        ENV_FILE.write_text(self.env_text())

    def script_python(self) -> str:
        v = self.pyver
        return (f"set -eux; rm -rf /opt/venv; dnf install -y python{v} python{v}-devel python{v}-pip "
                f"&& dnf clean all && python{v} -m venv /opt/venv "
                f"&& /opt/venv/bin/pip install -U pip setuptools wheel")

    @staticmethod
    def pip_cmd(pkgs: list[str]) -> str:
        # one at a time and in order: some sdists (spacepy...) need numpy present first
        return " && ".join(f"pip install {shlex.quote(p)}" for p in pkgs)

    def script_build(self) -> str:
        cmds = [*self.probes, self.build_cmd] + ([self.install_cmd] if self.install_cmd else [])
        return "set -eo pipefail\n" + "\n".join(cmds)

    def py_paths(self) -> list[str]:
        """Installed copy first (it contains generated files like Lgm_Wrap.py), then repo dirs.
        `make install` puts modules under /usr/local, which the venv python does NOT search."""
        paths: list[str] = []
        if self.python and self.install_cmd:
            paths += [f"/usr/local/lib/python{self.pyver}/site-packages",
                      f"/usr/local/lib64/python{self.pyver}/site-packages"]
        return paths + self.pypath

    def script_run(self) -> str:
        cmds = ([*self.probes, self.build_cmd] + ([self.install_cmd] if self.install_cmd else [])
                + ([self.test_cmd] if self.test_cmd else []))
        return "set -eo pipefail\n" + "\n".join(cmds)

    def start(self) -> bool:
        stream(["podman", "rm", "-f", self.cname], echo=False)
        say(f"Starting probe container from {self.base}")
        rc, _ = stream(["podman", "run", "-d", "--name", self.cname, self.base, "sleep", "infinity"])
        if rc:
            return False
        self.write_support_files()
        stream(["podman", "exec", self.cname, "mkdir", "-p", "/app/repo"], echo=False)
        say("Copying repository into the container")
        stream(["podman", "cp", f"{self.repo}/.", f"{self.cname}:/app/repo"], echo=False)
        stream(["podman", "cp", str(ENV_FILE), f"{self.cname}:/etc/profile.d/autoprobe.sh"], echo=False)
        if self.enable_crb:
            self.sh(ENABLE_CRB, echo=False)

        say(f"Installing {len(self.pkgs)} baseline/saved packages")
        self.dnf_bulk(self.pkgs)
        if self.python:
            say(f"Setting up Python {self.pyver} venv")
            if self.sh(self.script_python())[0]:
                print("!! python setup failed; continuing without it", file=sys.stderr)
            else:
                if self.pips:
                    self.sh(self.pip_cmd(self.pips))
                self.python_prepare()
        for s in self.sources:
            say(f"Re-running saved source build: {s['name']}")
            self.sh(s["script"])
        return True

    def dnf_bulk(self, pkgs: list[str]) -> None:
        self.sh("dnf install -y --setopt=strict=0 " + " ".join(pkgs))
        _, out = self.sh("rpm -q " + " ".join(pkgs), echo=False)
        for m in re.finditer(r"package (\S+) is not installed", out):
            print(f"!! '{m.group(1)}' unavailable in enabled repos; dropping it", file=sys.stderr)
            self.pkgs.remove(m.group(1))

    # ---- fixes --------------------------------------------------------------
    def resolve(self, pattern: str) -> str | None:
        _, out = self.sh(f"dnf -q provides {shlex.quote(pattern)}", echo=False)
        names = list(dict.fromkeys(m.group("n") for l in out.splitlines()
                                   if (m := NEVRA.match(l))))
        pref = [n for n in names if n.endswith("-devel")
                and not re.search(r"mpich|openmpi|static|doc", n)]
        pool = pref or names
        return sorted(pool, key=len)[0] if pool else None

    def add_dnf(self, name: str) -> bool:
        if name in BLOCKED or name in self.pkgs:
            return False
        rc, _ = self.sh(f"dnf install -y {shlex.quote(name)}")
        if rc == 0:
            self.pkgs.append(name)
            return True
        recipe = SOURCE_RECIPES.get(name)
        if recipe and not any(s["name"] == recipe["name"] for s in self.sources):
            say(f"'{name}' not in any repo -> building {recipe['name']} from source")
            if self.sh(recipe["script"])[0] == 0:
                self.sources.append(dict(recipe))
                return True
        return False

    def add_pip(self, name: str) -> bool:
        if name in self.pips:
            return False
        if not self.python:
            self.python = True
            if self.sh(self.script_python())[0]:
                return False
        rc, self.last_out = self.sh(f"pip install {shlex.quote(name)}")
        if rc == 0:
            self.pips.append(name)
            return True
        return False

    def python_prepare(self) -> None:
        """Install third-party modules found by the static import scan."""
        from .config_loader import MODULE_TO_PIP
        from .detect import PY2_ONLY

        sc = self.pyscan
        say(f"Python scan: {sc['files']} files, candidate third-party imports: "
            f"{', '.join(sc['third_party']) or 'none'}")
        if sc["py2_files"]:
            print(f"!! {sc['py2_files']} file(s) don't parse as Python 3 (Python 2 code?)",
                  file=sys.stderr)
        if not sc["third_party"]:
            return
        code = ("import importlib.util, sys\n"
                "for m in sys.argv[1:]:\n"
                "    try:\n"
                "        ok = importlib.util.find_spec(m) is not None\n"
                "    except Exception:\n"
                "        ok = False\n"
                "    if not ok: print('MISSING', m)\n")
        _, out = self.sh("python -c " + shlex.quote(code) + " "
                         + " ".join(map(shlex.quote, sc["third_party"])), echo=False)
        missing = [l.split()[1] for l in out.splitlines() if l.startswith("MISSING ")]
        self.unresolved: list[str] = []
        for m in missing:
            if m in PY2_ONLY:
                print(f"!! '{m}' is a Python 2 stdlib module (code needs porting)", file=sys.stderr)
                self.unresolved.append(m)
                continue
            name = MODULE_TO_PIP.get(m, m)
            say(f"Python module '{m}' -> pip '{name}'")
            if self.add_pip(name):
                continue
            for kind, arg in diagnose(self.last_out, self.pyver):
                if (kind, arg) not in self.tried:
                    self.tried.add((kind, arg))
                    say(f"Fix -> {kind}: {arg}")
                    self.apply(kind, arg)
            if not self.add_pip(name):
                self.unresolved.append(m)
        if self.unresolved:
            print("!! could not resolve modules (local-only, py2-only or wrong PyPI name?): "
                  + ", ".join(self.unresolved), file=sys.stderr)

    def apply(self, kind: str, arg: str) -> bool:
        if kind == "dnf":
            return self.add_dnf(arg)
        if kind == "provides":
            pkg = self.resolve(arg)
            if not pkg:
                print(f"   (no package provides {arg})")
                return False
            return self.add_dnf(pkg)
        if kind == "pip":
            return self.add_pip(arg)
        if kind == "python":
            if self.python:
                return False
            self.python = True
            return self.sh(self.script_python())[0] == 0
        if kind == "pyver":
            self.pyver = arg
            if self.sh(self.script_python())[0]:
                return False
            if self.pips:
                self.sh(self.pip_cmd(self.pips))
            return True
        return False

    # ---- outputs ------------------------------------------------------------
    def save_config(self) -> None:
        c = self.cfg
        c.pop("extra_repos", None)
        c.update(packages=self.pkgs, build_cmd=self.build_cmd)
        if self.python:
            c.update(python=True, python_version=self.pyver, pip_packages=self.pips)
            if self.pypath:
                c["python_path"] = self.pypath
        c["install_cmd"] = self.install_cmd
        if self.sources:
            c["source_builds"] = self.sources
        self.cfg_path.write_text(yaml.safe_dump(c, sort_keys=False, width=1000))

    def write_containerfile(self) -> None:
        def run(script: str) -> str:
            return "RUN " + json.dumps(["/bin/bash", "-lc", script])
        L = [f"FROM {self.base}", "WORKDIR /app", "",
             "ENV LD_LIBRARY_PATH=/usr/local/lib:/usr/local/lib64", "ENV MPLBACKEND=Agg"]
        if self.python:
            L += ["ENV VIRTUAL_ENV=/opt/venv", "ENV PATH=/opt/venv/bin:/usr/local/bin:$PATH"]
        if self.py_paths():
            L.append(f"ENV PYTHONPATH={':'.join(self.py_paths())}")
        L += [
              "COPY autoprobe-env.sh /etc/profile.d/autoprobe.sh"]
        if self.enable_crb:
            L.append(run(ENABLE_CRB))
        L.append(run(f"dnf install -y {' '.join(self.pkgs)} && dnf clean all"))
        if self.python:
            L.append(run(self.script_python()))
            if self.pips:
                L.append(run(self.pip_cmd(self.pips)))
        for s in self.sources:
            L.append(run(s["script"]))
        # The build + install are baked into the image, so `podman run -it IMAGE` gives
        # a shell with everything already built.  A failing build fails `podman build`.
        L += ["", f"COPY {self.repo} /app/repo", run(self.script_build())]
        if self.test_cmd:
            L.append("CMD " + json.dumps(["/bin/bash", "-lc", self.test_cmd]))
        else:
            L.append('CMD ["/bin/bash", "-l"]')
        L.append("")
        CONTAINERFILE.write_text("\n".join(L))
        say(f"Wrote {CONTAINERFILE}")

    # ---- main loop ----------------------------------------------------------
    def run(self) -> int:
        say(f"Detected project type: {self.project['label']}")
        say(f"Build command: {self.build_cmd}")
        if not self.start():
            print("Could not start container (is podman working?)", file=sys.stderr)
            return 1

        ok = False
        for attempt in range(1, self.max_loops + 1):
            say(f"Build attempt {attempt}/{self.max_loops}")
            rc, out = self.sh(self.script_run())
            if rc == 0:
                ok = True
                break
            fixes = [f for f in diagnose(out, self.pyver) if f not in self.tried]
            if not fixes:
                say("Build failed and no new fix could be inferred.")
                break
            progress = False
            for kind, arg in fixes:
                self.tried.add((kind, arg))
                say(f"Fix -> {kind}: {arg}")
                progress |= self.apply(kind, arg)
            self.save_config()
            if not progress:
                say("None of the proposed fixes could be applied.")
                break
        else:
            say(f"Reached max_loops ({self.max_loops}).")

        self.save_config()
        if not ok:
            print(f"\nFAILED. Full log: {LOG_FILE}\nInspect the container with:\n"
                  f"  podman exec -it {self.cname} bash -l\n"
                  f"Add anything you find to config.yaml (packages / pip_packages / env / "
                  f"source_builds / build_cmd) and re-run.", file=sys.stderr)
            return 1

        self.write_containerfile()
        if not self.args.keep:
            stream(["podman", "rm", "-f", self.cname], echo=False)
        if self.args.verify:
            say("Verifying with a clean podman build + run")
            if stream(["podman", "build", "-t", self.image, "."])[0]:
                return 1
            if stream(["podman", "run", "--rm", self.image])[0]:
                return 1
        else:
            print(f"\nSUCCESS. The build is baked into the image. Tinker with:\n"
                  f"  podman build -t {self.image} . && podman run --rm -it {self.image}")
        return 0
