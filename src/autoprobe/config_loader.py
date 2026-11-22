"""
config_loader.py - loads autoprobe's static configuration data (package tables,
source-build recipes, and the shell env template) from the configs/ directory
and exposes them as drop-in replacements for the constants that used to be
hardcoded in autoprobe.py.

Resolution order for the configs/ directory:
  1. $AUTOPROBE_CONFIG_DIR environment variable, if set.
  2. A `configs/` directory found by walking up from this file's location
     (handles running from a source checkout or an editable install, where
     configs/ sits alongside src/ at the project root).
  3. `importlib.resources` lookup inside the installed `autoprobe` package,
     in case a packaging step later vendors configs/ under autoprobe/configs/.

All exposed names match the original autoprobe.py constants exactly:
    BASELINE        : list[str]
    BLOCKED         : set[str]
    COMMAND_TO_PKG  : dict[str, str]
    LIB_KEYWORDS    : list[tuple[str, str]]
    MACRO_TO_PKG    : list[tuple[str, str]]
    MODULE_TO_PIP   : dict[str, str]
    PIP_TOOLS       : set[str]
    SOURCE_RECIPES  : dict[str, dict]
    ENV_SCRIPT      : str
"""
from __future__ import annotations

import os
from pathlib import Path

import yaml

try:  # Python 3.9+
    import importlib.resources as ilr
except ImportError:  # pragma: no cover
    ilr = None  # type: ignore


class ConfigLoadError(RuntimeError):
    pass


def _candidate_config_dirs() -> list[Path]:
    """Ordered list of directories to try for configs/."""
    candidates: list[Path] = []

    env_dir = os.environ.get("AUTOPROBE_CONFIG_DIR")
    if env_dir:
        candidates.append(Path(env_dir))

    # Walk up from this file looking for a sibling/ancestor "configs" dir.
    # Typical source-tree layout: <root>/src/autoprobe/config_loader.py
    #                             <root>/configs/packages.yaml
    here = Path(__file__).resolve()
    for parent in here.parents:
        maybe = parent / "configs"
        if maybe.is_dir():
            candidates.append(maybe)

    return candidates


def _find_config_dir() -> Path:
    for c in _candidate_config_dirs():
        if (c / "packages.yaml").exists():
            return c

    # Fallback: packaged resources inside the autoprobe package itself
    # (only relevant if a future packaging step vendors configs/ there).
    if ilr is not None:
        try:
            pkg_files = ilr.files("autoprobe").joinpath("configs")
            if pkg_files.joinpath("packages.yaml").is_file():
                return Path(str(pkg_files))
        except (ModuleNotFoundError, FileNotFoundError):
            pass

    raise ConfigLoadError(
        "Could not locate the autoprobe configs/ directory. "
        "Set AUTOPROBE_CONFIG_DIR to its path, or run from a source tree "
        "that has a configs/ directory alongside src/."
    )


def _load_yaml(path: Path) -> dict:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigLoadError(f"Could not read {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigLoadError(f"Invalid YAML in {path}: {exc}") from exc
    if data is None:
        raise ConfigLoadError(f"{path} is empty")
    return data


def _pairs(raw: list) -> list[tuple[str, str]]:
    """Convert a YAML list of 2-item lists into a list of (str, str) tuples,
    preserving original ordering exactly (order matters for first-match wins)."""
    return [(str(a), str(b)) for a, b in raw]


def _load_all() -> dict:
    cfg_dir = _find_config_dir()

    pkg_path = cfg_dir / "packages.yaml"
    recipes_path = cfg_dir / "source_recipes.yaml"
    env_path = cfg_dir / "env_template.sh"

    for p in (pkg_path, recipes_path, env_path):
        if not p.exists():
            raise ConfigLoadError(f"Missing required config file: {p}")

    pkg_data = _load_yaml(pkg_path)
    recipes_data = _load_yaml(recipes_path)

    required_pkg_keys = (
        "BASELINE", "BLOCKED", "COMMAND_TO_PKG", "LIB_KEYWORDS",
        "MACRO_TO_PKG", "MODULE_TO_PIP", "PIP_TOOLS",
    )
    missing = [k for k in required_pkg_keys if k not in pkg_data]
    if missing:
        raise ConfigLoadError(f"{pkg_path} is missing keys: {missing}")
    if "SOURCE_RECIPES" not in recipes_data:
        raise ConfigLoadError(f"{recipes_path} is missing key: SOURCE_RECIPES")

    try:
        env_script = env_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigLoadError(f"Could not read {env_path}: {exc}") from exc

    return {
        "BASELINE": list(pkg_data["BASELINE"]),
        "BLOCKED": set(pkg_data["BLOCKED"]),
        "COMMAND_TO_PKG": dict(pkg_data["COMMAND_TO_PKG"]),
        "LIB_KEYWORDS": _pairs(pkg_data["LIB_KEYWORDS"]),
        "MACRO_TO_PKG": _pairs(pkg_data["MACRO_TO_PKG"]),
        "MODULE_TO_PIP": dict(pkg_data["MODULE_TO_PIP"]),
        "PIP_TOOLS": set(pkg_data["PIP_TOOLS"]),
        "SOURCE_RECIPES": dict(recipes_data["SOURCE_RECIPES"]),
        "ENV_SCRIPT": env_script,
        "_config_dir": cfg_dir,
    }


# --------------------------------------------------------------------------
# Module-level, drop-in-compatible names (loaded once at import time).
# --------------------------------------------------------------------------
_loaded = _load_all()

BASELINE: list[str] = _loaded["BASELINE"]
BLOCKED: set[str] = _loaded["BLOCKED"]
COMMAND_TO_PKG: dict[str, str] = _loaded["COMMAND_TO_PKG"]
LIB_KEYWORDS: list[tuple[str, str]] = _loaded["LIB_KEYWORDS"]
MACRO_TO_PKG: list[tuple[str, str]] = _loaded["MACRO_TO_PKG"]
MODULE_TO_PIP: dict[str, str] = _loaded["MODULE_TO_PIP"]
PIP_TOOLS: set[str] = _loaded["PIP_TOOLS"]
SOURCE_RECIPES: dict[str, dict] = _loaded["SOURCE_RECIPES"]
ENV_SCRIPT: str = _loaded["ENV_SCRIPT"]

CONFIG_DIR: Path = _loaded["_config_dir"]  # new, informational only; not in original


def reload() -> None:
    """Re-read config files from disk and refresh the module-level names in place.
    Not used by the original autoprobe.py behavior, but handy for tests/tinkering
    without re-importing the module."""
    global BASELINE, BLOCKED, COMMAND_TO_PKG, LIB_KEYWORDS, MACRO_TO_PKG
    global MODULE_TO_PIP, PIP_TOOLS, SOURCE_RECIPES, ENV_SCRIPT, CONFIG_DIR
    data = _load_all()
    BASELINE = data["BASELINE"]
    BLOCKED = data["BLOCKED"]
    COMMAND_TO_PKG = data["COMMAND_TO_PKG"]
    LIB_KEYWORDS = data["LIB_KEYWORDS"]
    MACRO_TO_PKG = data["MACRO_TO_PKG"]
    MODULE_TO_PIP = data["MODULE_TO_PIP"]
    PIP_TOOLS = data["PIP_TOOLS"]
    SOURCE_RECIPES = data["SOURCE_RECIPES"]
    ENV_SCRIPT = data["ENV_SCRIPT"]
    CONFIG_DIR = data["_config_dir"]
