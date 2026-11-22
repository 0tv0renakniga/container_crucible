"""
autoprobe - probes a git repository inside a throwaway RHEL8/UBI8 container,
auto-resolves missing build dependencies, and emits a reproducible Containerfile.

Public API re-exported here for convenience, e.g.:
    from autoprobe import Prober, detect_project, diagnose
"""
from .detect import detect_project, scan_python
from .diagnose import command_action, diagnose
from .io_utils import say, stream
from .prober import Prober
from .__main__ import main

__all__ = [
    "say", "stream",
    "detect_project", "scan_python",
    "diagnose", "command_action",
    "Prober",
    "main",
]

__version__ = "1.3.0"
