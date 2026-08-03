# Sentinel Command Gate verification

Use the bounded verification entry point from this directory:

```bash
python3 -m venv /private/tmp/sentinel-command-gate-venv
/private/tmp/sentinel-command-gate-venv/bin/pip install -r requirements-dev.txt
/private/tmp/sentinel-command-gate-venv/bin/python tools/verify_release.py
```

The versioned candidate under `AIOM_SENTINEL_COMMAND_GATE_v1.2.1/` remains an
immutable transport basis. Its lower-level commands are internal/debug-only.
