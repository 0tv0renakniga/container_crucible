# Install Instructions

```bash
# Development / editable install (recommended while iterating on autoprobe itself)
cd autoprobe/
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Run it
autoprobe --config config.yaml
# or equivalently:
python -m autoprobe --config config.yaml
```

```bash
# Regular (non-editable) install — configs/ is placed under <venv>/share/autoprobe/configs
pip install .
autoprobe --config config.yaml
```

## Note
Both paths are resolved automatically by config_loader.py's candidate search — no environment variable needed in either case. AUTOPROBE_CONFIG_DIR remains available as an explicit override (e.g., for containerized runs where configs are mounted at a custom path).

# Migration/Integration Notes
- Entry point: autoprobe = "autoprobe.__main__:main" reproduces running python autoprobe.py ... directly — same argparse flags (-c/--config, -n/--max-loops, --verify, --keep), same main() return-code semantics (sys.exit(main()) still happens in __main__.py's if __name__ == "__main__": guard for direct-script execution).
- Only non-structural change touching behavior-adjacent code: config_loader.py gained one new candidate path (sys.prefix/share/autoprobe/configs) for the installed, non-editable case. This is strictly additive — it's tried only if the dev-tree configs/ isn't found, so it doesn't alter behavior for your current workflow (running from the source tree with configs/ present).
- Dependency: PyYAML>=6.0 is declared explicitly in pyproject.toml (previously implicit via import yaml at the top of the monolithic script with no declared dependency anywhere).
containerfiles/ (templates) from the target layout isn't populated yet since the original autoprobe.py has no separate Containerfile template file — write_containerfile() builds the Containerfile programmatically in prober.py. No action needed in Phase 1; this stays empty/unused unless a later phase introduces templating.
- tests/ directory isn't populated in Phase 1 (no tests existed in the original script to port) — left as a placeholder for future work, not required for behavior parity.

# Phase2: Migration/Integration Notes
- No behavior change by default. venv.reuse defaults to false; every existing call site that used to call self.sh(self.script_python()) now calls self.setup_venv(), which — when venv.reuse is absent or false — immediately delegates to script_python(), identical to before.
- Scope limitation (flagged intentionally): only venv.reuse was added, not a configurable venv path. /opt/venv remains hardcoded because configs/env_template.sh (the ENV_SCRIPT sourced via /etc/profile.d/autoprobe.sh) also hardcodes /opt/venv/bin/activate. Making the path configurable would require templating that file too — out of scope for this narrowly-requested feature; flag if you want that as a follow-up.
- Where reuse actually matters in practice: within one autoprobe run, across repeated apply() calls (e.g., many failed pip installs triggering add_pip() → setup_venv() checks each time python isn't yet enabled) and if you later add a "keep container, re-run tool" workflow in Phase 2 that doesn't tear the container down between invocations. In the current architecture, start() always does podman rm -f then creates a brand-new container at the top of every run(), so within today's lifecycle, reuse has limited observable effect unless combined with future container-reuse logic — flagging this now so expectations are set correctly.
- write_containerfile() deliberately ignores venv.reuse since a fresh image build never has a pre-existing venv to reuse.
