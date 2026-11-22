"""
prober.py - the Prober class: drives a long-lived podman container through
repeated probe/build/fix/retry cycles, and emits the final Containerfile and
config.yaml on success.

Phase 2A.2 adds opt-in C/C++ submodule build stages (`submodule_builds:` in
config.yaml). Each stage is built once per autoprobe run, before build_cmd, and
its install tree is exported into PATH / LD_LIBRARY_PATH / PKG_CONFIG_PATH /
CPPFLAGS / LDFLAGS / CMAKE_PREFIX_PATH for later stages and the main build.
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
SUBMODULE_MARKER_DIR = "/opt/autoprobe/submodules"
EXECUTABLE_MARKER_DIR = "/opt/autoprobe/executables"

# UBI ships a CodeReady Builder repo (disabled by default) with extra -devel packages.
ENABLE_CRB = ("sed -i '/^\\[ubi-8-codeready-builder\\]/,/^\\[/ s/^enabled *= *0/enabled = 1/' "
              "/etc/yum.repos.d/ubi.repo || true")

NEVRA = re.compile(
    r"^(?P<n>\S+?)-(?:\d+:)?\d[^\s]*?\.(?:x86_64|aarch64|noarch|i686|ppc64le|s390x)\s+:")


def _dedupe(items: list[str]) -> list[str]:
    """Order-preserving de-duplication (used for generated export paths)."""
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


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

        # --- venv lifecycle control (new in 2A.1) ---
        # Default False preserves the original always-recreate behavior of
        # script_python(); set `venv: {reuse: true}` in config.yaml to opt in
        # to reusing an existing /opt/venv that already matches python_version.
        self.venv_reuse = bool((cfg.get("venv") or {}).get("reuse", False))

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

        # --- C/C++ submodule build stages (new in 2A.2) ---
        # Absent/empty submodule_builds preserves original behavior exactly.
        self.submodule_builds: list[dict] = self._parse_submodule_builds(
            cfg.get("submodule_builds"))

        # --- second executable builds (new in 2A.3) ---
        # Absent/empty executable_builds preserves original behavior exactly.
        self.executable_builds: list[dict] = self._parse_executable_builds(
            cfg.get("executable_builds"))

    # ---- submodule_builds / executable_builds (new in 2A.2 / 2A.3) ---------
    def _parse_stage_common(self, item, where: str, repo: Path) -> dict:
        """Validate fields shared by submodule_builds and executable_builds."""
        if not isinstance(item, dict):
            raise ValueError(f"{where} must be a mapping")

        name = str(item.get("name") or "").strip()
        path = str(item.get("path") or "").strip()
        script = item.get("script")

        if not name:
            raise ValueError(f"{where}: missing 'name'")
        if name in (".", "..") or not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
            raise ValueError(
                f"{where}: 'name' must match [A-Za-z0-9_.-]+ and not be '.' or '..'")

        if not path:
            raise ValueError(f"{where}: missing 'path'")
        rel = Path(path)
        if rel.is_absolute() or ".." in rel.parts:
            raise ValueError(
                f"{where}: 'path' must be relative to repo_name and stay inside it")
        if not (repo / rel).is_dir():
            raise ValueError(f"{where}: path not found: {repo / rel}")

        if not isinstance(script, str) or not script.strip():
            raise ValueError(f"{where}: 'script' must be a non-empty string")

        env_raw = item.get("env") or {}
        if not isinstance(env_raw, dict):
            raise ValueError(f"{where}: 'env' must be a mapping")
        env: dict[str, str] = {}
        for key, val in env_raw.items():
            key = str(key)
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
                raise ValueError(f"{where}: invalid env var name {key!r}")
            env[key] = str(val)

        required = item.get("required", True)
        if isinstance(required, str):
            required = required.strip().lower() not in {"", "0", "false", "no", "off"}
        else:
            required = bool(required)

        return {
            "name": name,
            "path": rel.as_posix(),
            "script": script.rstrip("\n") + "\n",
            "env": env,
            "required": required,
        }

    def _parse_submodule_builds(self, raw) -> list[dict]:
        """Validate/normalize config.yaml's optional `submodule_builds:` list.

        Absent/empty means no stages (original behavior). Each returned stage
        has concrete defaults so the rest of Prober never re-checks YAML.
        """
        if raw is None:
            return []
        if not isinstance(raw, list):
            raise ValueError("submodule_builds must be a list of mappings")

        stages: list[dict] = []
        seen: set[str] = set()
        repo = Path(self.repo)

        for idx, item in enumerate(raw, 1):
            where = f"submodule_builds[{idx}]"
            stage = self._parse_stage_common(item, where, repo)
            if stage["name"] in seen:
                raise ValueError(f"{where}: duplicate name {stage['name']!r}")
            seen.add(stage["name"])

            prefix = str(item.get("prefix") or "/usr/local").strip()
            if not prefix.startswith("/"):
                raise ValueError(f"{where}: 'prefix' must be an absolute path")
            if prefix != "/":
                prefix = prefix.rstrip("/") or "/"
            base = "" if prefix == "/" else prefix

            def dirs(key: str, defaults: list[str]) -> list[str]:
                val = item.get(key)
                if val is None:
                    return defaults
                if not isinstance(val, list):
                    raise ValueError(f"{where}: '{key}' must be a list")
                out: list[str] = []
                for entry in val:
                    entry = str(entry).rstrip("/") or "/"
                    if not entry.startswith("/"):
                        raise ValueError(
                            f"{where}: '{key}' entries must be absolute paths")
                    out.append(entry)
                return out

            stage.update({
                "prefix": prefix,
                "bin_dirs": dirs("bin_dirs", [f"{base}/bin"]),
                "lib_dirs": dirs("lib_dirs", [f"{base}/lib", f"{base}/lib64"]),
                "include_dirs": dirs("include_dirs", [f"{base}/include"]),
                "pkgconfig_dirs": dirs("pkgconfig_dirs", [
                    f"{base}/lib/pkgconfig",
                    f"{base}/lib64/pkgconfig",
                    f"{base}/share/pkgconfig",
                ]),
            })
            stages.append(stage)
        return stages

    def _parse_executable_builds(self, raw) -> list[dict]:
        """Validate/normalize config.yaml's optional `executable_builds:` list.

        Each entry builds a separate executable after the 2A.2 submodule stages
        (`after: submodules`, default) or after the main build+install
        (`after: build`). Absent/empty preserves original behavior.
        """
        if raw is None:
            return []
        if not isinstance(raw, list):
            raise ValueError("executable_builds must be a list of mappings")

        stages: list[dict] = []
        seen: set[str] = set()
        repo = Path(self.repo)

        for idx, item in enumerate(raw, 1):
            where = f"executable_builds[{idx}]"
            stage = self._parse_stage_common(item, where, repo)
            if stage["name"] in seen:
                raise ValueError(f"{where}: duplicate name {stage['name']!r}")
            seen.add(stage["name"])

            install_script = item.get("install_script") or ""
            if not isinstance(install_script, str):
                raise ValueError(f"{where}: 'install_script' must be a string")

            after = str(item.get("after") or "submodules").strip().lower()
            if after not in ("submodules", "build"):
                raise ValueError(
                    f"{where}: 'after' must be 'submodules' or 'build' (got {after!r})")

            stage.update({
                "install_script": (install_script.rstrip("\n") + "\n")
                                  if install_script.strip() else "",
                "after": after,
            })
            stages.append(stage)
        return stages

    def submodule_export_dirs(self) -> dict[str, list[str]]:
        """All export directories contributed by submodule_builds, deduped."""
        bins: list[str] = []
        libs: list[str] = []
        incs: list[str] = []
        pcs: list[str] = []
        prefixes: list[str] = []
        for s in self.submodule_builds:
            bins.extend(s["bin_dirs"])
            libs.extend(s["lib_dirs"])
            incs.extend(s["include_dirs"])
            pcs.extend(s["pkgconfig_dirs"])
            prefixes.append(s["prefix"])
        return {
            "bin": _dedupe(bins),
            "lib": _dedupe(libs),
            "include": _dedupe(incs),
            "pkgconfig": _dedupe(pcs),
            "prefix": _dedupe(prefixes),
        }

    def submodule_env_block(self) -> str:
        """Shell exports appended after ENV_SCRIPT (empty when unused)."""
        d = self.submodule_export_dirs()
        lines: list[str] = []

        if d["bin"]:
            dirs = ":".join(shlex.quote(p) for p in d["bin"])
            lines.append(f"export PATH={dirs}${{PATH:+:$PATH}}")
        if d["lib"]:
            dirs = ":".join(shlex.quote(p) for p in d["lib"])
            lines.append(
                f"export LD_LIBRARY_PATH={dirs}${{LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}}")
        if d["pkgconfig"]:
            dirs = ":".join(shlex.quote(p) for p in d["pkgconfig"])
            lines.append(
                f"export PKG_CONFIG_PATH={dirs}${{PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}}")
        if d["include"]:
            flags = " ".join(f"-I{p}" for p in d["include"])
            lines.append(f'export CPPFLAGS="{flags} ${{CPPFLAGS:-}}"')
        if d["lib"]:
            flags = " ".join(f"-L{p}" for p in d["lib"])
            lines.append(f'export LDFLAGS="{flags} ${{LDFLAGS:-}}"')
        if d["prefix"]:
            dirs = ":".join(shlex.quote(p) for p in d["prefix"])
            lines.append(
                f"export CMAKE_PREFIX_PATH={dirs}${{CMAKE_PREFIX_PATH:+:$CMAKE_PREFIX_PATH}}")

        if not lines:
            return ""
        return ("# --- submodule_builds exports (generated by autoprobe) ---\n"
                + "\n".join(lines) + "\n")

    def _guarded_stage_script(self, marker_dir: str, name: str, cwd: str,
                              env_lines: list[str], script: str,
                              install_script: str = "", required: bool = True,
                              label: str = "Stage", detail: str = "") -> str:
        """Idempotent, diagnose-friendly shell block shared by both stage types."""
        marker = f"{marker_dir}/{name}"
        done_q = shlex.quote(marker + ".done")
        skipped_q = shlex.quote(marker + ".skipped")
        cwd_q = shlex.quote(cwd)

        body = ""
        if env_lines:
            body += "\n".join(env_lines) + "\n"
        body += script
        if install_script:
            body += install_script

        required_flag = "1" if required else "0"
        skip_msg = f">>> {label} [{name}] already handled; skipping"
        build_msg = (f">>> Building {label.lower()} [{name}]"
                     + (f" ({detail})" if detail else ""))
        fail_msg = f"!! {label} [{name}] failed"

        return (
            f"if [ -f {done_q} ] || [ -f {skipped_q} ]; then\n"
            f"  echo {shlex.quote(skip_msg)}\n"
            f"else\n"
            f"  echo {shlex.quote(build_msg)}\n"
            f"  mkdir -p {shlex.quote(marker_dir)}\n"
            f"  if (\n"
            f"    cd {cwd_q}\n"
            f"{body}"
            f"  ); then\n"
            f"    touch {done_q}\n"
            f"  else\n"
            f"    echo {shlex.quote(fail_msg)} >&2\n"
            f"    if [ {required_flag} -eq 1 ]; then exit 1; else touch {skipped_q}; fi\n"
            f"  fi\n"
            f"fi"
        )

    def submodule_stage_script(self, stage: dict) -> str:
        env_lines = [f"export AP_PREFIX={shlex.quote(stage['prefix'])}"]
        env_lines += [f"export {k}={shlex.quote(v)}" for k, v in stage["env"].items()]
        return self._guarded_stage_script(
            SUBMODULE_MARKER_DIR, stage["name"], f"/app/repo/{stage['path']}",
            env_lines, stage["script"], required=stage["required"],
            label="Submodule", detail=stage["path"])

    def submodule_stage_scripts(self) -> list[str]:
        return [self.submodule_stage_script(s) for s in self.submodule_builds]

    def executable_stage_script(self, stage: dict) -> str:
        env_lines = [f"export {k}={shlex.quote(v)}" for k, v in stage["env"].items()]
        return self._guarded_stage_script(
            EXECUTABLE_MARKER_DIR, stage["name"], f"/app/repo/{stage['path']}",
            env_lines, stage["script"], install_script=stage["install_script"],
            required=stage["required"], label="Executable", detail=stage["path"])

    def executable_stage_scripts(self, after: str) -> list[str]:
        return [self.executable_stage_script(s) for s in self.executable_builds
                if s["after"] == after]

    # ---- container plumbing -------------------------------------------------
    def sh(self, script: str, echo: bool = True) -> tuple[int, str]:
        return stream(["podman", "exec", self.cname, "bash", "-lc", script], echo=echo)

    def env_text(self) -> str:
        extra = "".join(f"export {k}={shlex.quote(str(v))}\n" for k, v in self.user_env.items())
        if self.py_paths():
            extra = (f"export PYTHONPATH={':'.join(self.py_paths())}${{PYTHONPATH:+:$PYTHONPATH}}\n"
                     + extra)
        parts = [ENV_SCRIPT]
        if not ENV_SCRIPT.endswith("\n"):
            parts.append("\n")
        parts.append(self.submodule_env_block())
        parts.append(extra)
        return "".join(parts)

    def write_support_files(self) -> None:
        ENV_FILE.write_text(self.env_text())

    def script_python(self) -> str:
        v = self.pyver
        return (f"set -eux; rm -rf /opt/venv; dnf install -y python{v} python{v}-devel python{v}-pip "
                f"&& dnf clean all && python{v} -m venv /opt/venv "
                f"&& /opt/venv/bin/pip install -U pip setuptools wheel")

    def venv_check_script(self) -> str:
        """Exit 0 iff a venv already exists at /opt/venv for the currently
        requested Python version (self.pyver). Used only when venv.reuse is
        enabled; a version change naturally fails this check, so switching
        python_version still forces a rebuild even with reuse enabled."""
        v = self.pyver
        return f"test -x /opt/venv/bin/python{v}"

    def setup_venv(self) -> tuple[int, str]:
        """Create the /opt/venv virtualenv, or - if venv.reuse is enabled in
        config.yaml and a venv already exists for the current python_version -
        skip recreation and reuse it. Default (venv.reuse: false) always
        recreates, identical to calling script_python() directly as the
        original code did at every call site."""
        if self.venv_reuse:
            rc, _ = self.sh(self.venv_check_script(), echo=False)
            if rc == 0:
                say(f"Reusing existing /opt/venv (python{self.pyver})")
                return 0, ""
            say(f"No reusable /opt/venv (python{self.pyver}) found; creating it")
        return self.sh(self.script_python())

    @staticmethod
    def pip_cmd(pkgs: list[str]) -> str:
        # one at a time and in order: some sdists (spacepy...) need numpy present first
        return " && ".join(f"pip install {shlex.quote(p)}" for p in pkgs)

    def py_paths(self) -> list[str]:
        """Installed copy first (it contains generated files like Lgm_Wrap.py), then repo dirs.
        `make install` puts modules under /usr/local, which the venv python does NOT search."""
        paths: list[str] = []
        if self.python and self.install_cmd:
            paths += [f"/usr/local/lib/python{self.pyver}/site-packages",
                      f"/usr/local/lib64/python{self.pyver}/site-packages"]
        return paths + self.pypath

    def build_steps(self) -> list[str]:
        cmds = [*self.probes, *self.submodule_stage_scripts(),
                *self.executable_stage_scripts("submodules"), self.build_cmd]
        if self.install_cmd:
            cmds.append(self.install_cmd)
        cmds.extend(self.executable_stage_scripts("build"))
        return cmds

    def script_build(self) -> str:
        return "set -eo pipefail\n" + "\n".join(self.build_steps())

    def script_run(self) -> str:
        cmds = self.build_steps()
        if self.test_cmd:
            cmds.append(self.test_cmd)
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
            if self.setup_venv()[0]:
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
            if self.setup_venv()[0]:
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
            return self.setup_venv()[0] == 0
        if kind == "pyver":
            self.pyver = arg
            if self.setup_venv()[0]:
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

        sub = self.submodule_export_dirs()
        ld_dirs = _dedupe([*sub["lib"], "/usr/local/lib", "/usr/local/lib64"])
        L = [f"FROM {self.base}", "WORKDIR /app", "",
             f"ENV LD_LIBRARY_PATH={':'.join(ld_dirs)}", "ENV MPLBACKEND=Agg"]
        if self.python:
            L.append("ENV VIRTUAL_ENV=/opt/venv")
        path_dirs = _dedupe([*sub["bin"],
                             *(["/opt/venv/bin", "/usr/local/bin"] if self.python else [])])
        if path_dirs:
            L.append(f"ENV PATH={':'.join(path_dirs)}:$PATH")
        if sub["pkgconfig"]:
            pkg_dirs = _dedupe([*sub["pkgconfig"], "/usr/local/lib/pkgconfig",
                                "/usr/local/lib64/pkgconfig", "/usr/lib64/pkgconfig"])
            L.append(f"ENV PKG_CONFIG_PATH={':'.join(pkg_dirs)}")
        if sub["prefix"]:
            cmake_dirs = _dedupe([*sub["prefix"], "/usr/local", "/usr"])
            L.append(f"ENV CMAKE_PREFIX_PATH={':'.join(cmake_dirs)}")
        if self.py_paths():
            L.append(f"ENV PYTHONPATH={':'.join(self.py_paths())}")
        L += [
              "COPY autoprobe-env.sh /etc/profile.d/autoprobe.sh"]
        if self.enable_crb:
            L.append(run(ENABLE_CRB))
        L.append(run(f"dnf install -y {' '.join(self.pkgs)} && dnf clean all"))
        if self.python:
            # A fresh `podman build` always starts from clean image layers, so there
            # is never an existing venv to reuse here - venv.reuse only applies to
            # the long-lived probe container during `autoprobe`'s own run() loop.
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
                  f"source_builds / submodule_builds / executable_builds / "
                  f"build_cmd) and re-run.", file=sys.stderr)
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
