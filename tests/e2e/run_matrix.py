#!/usr/bin/env python3
"""Cargo-style integration driver: runs `run.py` five times to exercise
the e2e suite under different phase orderings + state policies.

The matrix:
  1. forward,  clean slate
  2. reverse,  preserved state (continues from #1's data dir + repos)
  3. reverse,  clean slate
  4. forward,  preserved state (continues from #3's data dir + repos)
  5. random,   clean slate

"Preserved state" means the same server data dir and bare git repos as the
prior run, but a fresh client work dir and fresh client-side caches — so
the test exercises whether persisted data survives ordering changes
without being polluted by leftover client state.

"Within-group" reordering applies: group order is fixed (independent
push-side → bigfile cluster → isolated), but the within-group order can
flip. `bigfile` is anchored as the head of its group since the other
group-2 phases consume the rev_state it builds.

Each inner run is a fresh `python3 tests/e2e/run.py` subprocess so a
failure in one run doesn't bleed into the next. The matrix aggregates
exit codes and prints a per-run pass/fail summary.

Invoke directly:

    python3 tests/e2e/run_matrix.py

This script never builds the container image — it assumes the image is
already cached. If not, run `python3 tests/e2e/run.py` once by hand
first.
"""

from __future__ import annotations

import argparse
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

HERE = Path(__file__).resolve().parent
RUN_PY = HERE / "run.py"


@dataclass
class RunResult:
    label: str
    cmd: list[str]
    exit_code: int
    elapsed_s: float
    output_file: Optional[Path] = None


def _info(msg: str) -> None:
    print(f"[matrix] {msg}", flush=True)


def _invoke(
    *,
    label: str,
    extra_args: list[str],
    extra_env: Optional[dict] = None,
    output_file: Optional[Path] = None,
    stream: bool = True,
    runner: Path = RUN_PY,
) -> RunResult:
    cmd = [sys.executable, str(runner), "--no-build", *extra_args]
    _info(f">>> {label}")
    _info(f"    $ {' '.join(cmd)}")
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    t0 = time.perf_counter()
    if stream:
        completed = subprocess.run(cmd, env=env)
    else:
        # Capture to a file so we can show it on failure but keep the
        # matrix output compact on success.
        assert output_file is not None
        with output_file.open("w") as fh:
            completed = subprocess.run(
                cmd,
                env=env,
                stdout=fh,
                stderr=subprocess.STDOUT,
            )
    elapsed = time.perf_counter() - t0
    status = (
        "OK" if completed.returncode == 0 else f"FAIL (exit {completed.returncode})"
    )
    _info(f"<<< {label}: {status}  [{elapsed:.1f}s]")
    if completed.returncode != 0 and output_file is not None:
        # Surface the failing run's tail so CI logs aren't a black box.
        _info(f"--- last 60 lines of {output_file.name} ---")
        with output_file.open() as fh:
            tail = fh.readlines()[-60:]
        for line in tail:
            print(line.rstrip(), flush=True)
        _info("--- end of tail ---")
    return RunResult(
        label=label,
        cmd=cmd,
        exit_code=completed.returncode,
        elapsed_s=elapsed,
        output_file=output_file,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--keep-tmpdir",
        action="store_true",
        help="Don't delete the matrix tempdir on exit (for inspecting "
        "the .e2e_state.json + data dirs of each preserved-state "
        "pair).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Seed for the run-5 random order. Default: a fresh random.",
    )
    parser.add_argument(
        "--stop-on-failure",
        action="store_true",
        help="Abort the matrix as soon as one run fails (default: keep "
        "going so you see every run's status).",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress each inner run's live output; capture to per-run "
        "log files and print only summaries. Failing runs still dump "
        "their tail.",
    )
    parser.add_argument(
        "--s3",
        action="store_true",
        help="Run the whole suite on the S3 backend (`run.py --backend s3`) "
        "instead of the fs suite. The S3 run tears its bucket down at the "
        "end, so the preserved-state permutations don't apply; the matrix "
        "collapses to a single forward, clean-slate invocation.",
    )
    parser.add_argument(
        "--postgres",
        action="store_true",
        help="Run the whole suite with the Postgres metadata store "
        "(`run.py --meta postgres`). Like --s3, the sidecar is torn down at "
        "end of run so preserved-state permutations don't apply; the matrix "
        "collapses to one invocation. Composes with --s3 (runs both flags).",
    )
    args = parser.parse_args()

    if args.s3 or args.postgres:
        # Neither sidecar survives the run (bucket + database are torn down),
        # so the ordering/preserved-state permutations collapse to one run.
        extra: list[str] = []
        labels: list[str] = []
        if args.s3:
            extra += ["--backend", "s3"]
            labels.append("s3 blob store")
        if args.postgres:
            extra += ["--meta", "postgres"]
            labels.append("postgres metadata")
        desc = " + ".join(labels)
        _info(f"{desc}: running `run.py {' '.join(extra)}` once (no permutations)")
        r = _invoke(
            label=f"{desc} suite (full)",
            extra_args=extra,
            runner=RUN_PY,
            stream=not args.quiet,
            output_file=None,
        )
        return r.exit_code

    matrix_root = Path(tempfile.mkdtemp(prefix="bale-e2e-matrix-"))
    _info(f"matrix work dir: {matrix_root}")

    state_dir_1 = matrix_root / "state-1"
    state_dir_3 = matrix_root / "state-3"
    logs_dir = matrix_root / "logs"
    if args.quiet:
        logs_dir.mkdir()

    random_seed = args.seed if args.seed is not None else secrets.randbits(32)
    _info(f"run 5 random seed: {random_seed}")

    matrix = [
        {
            "label": "1/5 forward, clean slate",
            "args": ["--order=forward", f"--state-dir={state_dir_1}"],
        },
        {
            "label": "2/5 reverse, preserved (from #1)",
            "args": ["--order=reverse", f"--reuse-from={state_dir_1}"],
        },
        {
            "label": "3/5 reverse, clean slate",
            "args": ["--order=reverse", f"--state-dir={state_dir_3}"],
        },
        {
            "label": "4/5 forward, preserved (from #3)",
            "args": ["--order=forward", f"--reuse-from={state_dir_3}"],
        },
        {
            "label": "5/5 random, clean slate",
            "args": ["--order=random", f"--seed={random_seed}"],
        },
    ]

    results: list[RunResult] = []
    try:
        for i, step in enumerate(matrix, start=1):
            output_file = logs_dir / f"run-{i}.log" if args.quiet else None
            r = _invoke(
                label=step["label"],
                extra_args=step["args"],
                output_file=output_file,
                stream=not args.quiet,
            )
            results.append(r)
            if r.exit_code != 0 and args.stop_on_failure:
                _info("stopping early per --stop-on-failure")
                break
    finally:
        print("", flush=True)
        _info("=" * 60)
        _info("matrix summary")
        _info("=" * 60)
        label_w = max((len(r.label) for r in results), default=0)
        total_s = 0.0
        worst_exit = 0
        for r in results:
            tag = "PASS" if r.exit_code == 0 else f"FAIL(exit {r.exit_code})"
            _info(f"  {r.label.ljust(label_w)}  {tag}  [{r.elapsed_s:.1f}s]")
            total_s += r.elapsed_s
            if r.exit_code != 0:
                worst_exit = r.exit_code if worst_exit == 0 else worst_exit
        _info(f"  total wallclock: {total_s:.1f}s")
        if args.keep_tmpdir:
            _info(f"keeping {matrix_root}")
        else:
            shutil.rmtree(matrix_root, ignore_errors=True)

    if any(r.exit_code != 0 for r in results) or len(results) < len(matrix):
        return worst_exit or 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
