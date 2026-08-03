#!/usr/bin/env python3
"""Clean, dependency-aware Command Gate verification entry point."""
from __future__ import annotations
import hashlib, os, shutil, subprocess, sys, tempfile
from pathlib import Path

_SURFACE = Path(__file__).resolve().parents[1]
_CANDIDATES = sorted(_SURFACE.glob('AIOM_SENTINEL_COMMAND_GATE_v1.2.1'))
ROOT = _CANDIDATES[0] if _CANDIDATES else _SURFACE

def digest_tree(root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(root.rglob('*')):
        if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc':
            h.update(p.relative_to(root).as_posix().encode()); h.update(p.read_bytes())
    return h.hexdigest()

def main() -> int:
    before = digest_tree(ROOT)
    try:
        import cryptography  # noqa: F401
    except Exception as exc:
        print('IMPLEMENTATION_RESULT: NOT_ESTABLISHED')
        print('ENVIRONMENTAL_EVIDENCE_COMPLETENESS: INCOMPLETE')
        print(f'OVERALL_STATE: BLOCKED_MISSING_DEPENDENCY ({exc})')
        return 2
    with tempfile.TemporaryDirectory(prefix='sentinel-release-') as tmp:
        copy = Path(tmp) / ROOT.name
        shutil.copytree(ROOT, copy, ignore=shutil.ignore_patterns('__pycache__','*.pyc','.DS_Store'))
        env = os.environ.copy(); env['PYTHONPYCACHEPREFIX'] = str(Path(tmp) / 'pycache'); env['PYTHONDONTWRITEBYTECODE'] = '0'
        commands = [
            [sys.executable, '-m', 'py_compile', 'verify_candidate.py', *map(str, sorted((copy/'tools').glob('*.py')))],
            [sys.executable, 'tools/run_full_verification.py'],
            [sys.executable, 'tools/run_regression_suite.py'],
        ]
        statuses=[]
        for cmd in commands:
            shown=[str(x).replace(str(copy), 'TREE') for x in cmd]
            r=subprocess.run(cmd, cwd=copy, env=env, text=True, capture_output=True)
            statuses.append((r.returncode, ' '.join(shown)))
            print(r.stdout, end=''); print(r.stderr, file=sys.stderr, end='')
            if r.returncode != 0:
                print('IMPLEMENTATION_RESULT: FAIL')
                print('ENVIRONMENTAL_EVIDENCE_COMPLETENESS: INCOMPLETE')
                print(f'OVERALL_STATE: FAIL ({"; ".join(c for rc,c in statuses if rc)})')
                return 1
    after = digest_tree(ROOT)
    if before != after:
        print('SOURCE_TREE_MUTATION: true')
        return 1
    print('SOURCE_TREE_PYCACHE: 0')
    print('SOURCE_MUTATION: false')
    print('IMPLEMENTATION_RESULT: PASS')
    print('ENVIRONMENTAL_EVIDENCE_COMPLETENESS: COMPLETE')
    print('OVERALL_STATE: PASS')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
