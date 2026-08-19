"""One command that regenerates every artefact this submission depends on.

    python run_all.py                # full run
    python run_all.py --quick        # fast pass: fewer records, fewer sizes
    python run_all.py --skip-bench   # tests and demonstrations only

Stages, in order:

1. ``pytest``                     -- the automated test suite, TR-1..TR-7 on both
                                     AEAD configurations
2. ``demo.run_demo``              -- transcripts for TR-1..TR-7 into ``evidence/``
3. ``demo.run_network_demo``      -- the same subsystem over real TCP sockets
4. ``bench.nonce_analysis``       -- supporting analysis for TR-7
5. ``bench.perf``                 -- TR-8 measurements, tables and charts

Exits non-zero if any stage fails, so it doubles as a pre-submission check.
Every number quoted in the report comes from an ``evidence/`` file this script
produces; nothing in the report is written by hand from memory.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
EVIDENCE_DIR = ROOT / "evidence"


def member2_pending() -> bool:
    """Whether the receiver/replay/adversary modules are still stubs.

    Those three are Member 2's deliverable (see HANDOFF.md).  Until they exist,
    every stage that needs a receiver -- the demonstrations, the network demo,
    the TR-8 recover measurements -- cannot run, so we say so once and skip
    them rather than emitting five tracebacks.
    """
    sys.path.insert(0, str(ROOT))
    from srp import adversary, receiver, replay

    return any(
        getattr(module, "MEMBER2_STUB", False)
        for module in (receiver, replay, adversary)
    )


def run_stage(name: str, command: list[str], *, echo: bool = True) -> tuple[bool, float]:
    print()
    print("#" * 78)
    print(f"# {name}")
    print(f"# $ {' '.join(command[1:])}")
    print("#" * 78)
    started = time.perf_counter()
    completed = subprocess.run(command, cwd=str(ROOT))
    elapsed = time.perf_counter() - started
    ok = completed.returncode == 0
    print(f"# {name}: {'OK' if ok else 'FAILED'} in {elapsed:.1f}s")
    return ok, elapsed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--quick", action="store_true",
                        help="smaller record counts and only the required TR-8 sizes")
    parser.add_argument("--skip-bench", action="store_true",
                        help="skip the TR-8 performance evaluation")
    parser.add_argument("--skip-tests", action="store_true", help="skip pytest")
    args = parser.parse_args(argv)

    py = sys.executable
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

    pending = member2_pending()
    if pending:
        print("=" * 78)
        print(" INCOMPLETE BUILD: srp/receiver.py, srp/replay.py and srp/adversary.py")
        print(" are specification stubs awaiting Member 2 (see HANDOFF.md).")
        print()
        print(" Running only the stages that do not need a receiver.  The")
        print(" demonstrations, the network demo and the TR-8 measurements will")
        print(" run again as soon as those three modules are implemented; no")
        print(" change to this script is needed.")
        print("=" * 78)

    stages: list[tuple[str, list[str]]] = []
    if not args.skip_tests:
        stages.append(("Automated test suite (TR-1..TR-7, both configurations)",
                       [py, "-m", "pytest", "-q"]))
    if not pending:
        stages.append((
            "Demonstration transcripts (TR-1..TR-7)",
            [py, "-m", "demo.run_demo", "--quiet",
             "--records", "2000" if args.quick else "10000"],
        ))
        stages.append(("Network demonstration (sender / actor / receiver over TCP)",
                       [py, "-m", "demo.run_network_demo"]))
    stages.append(("Nonce management analysis (TR-7 supporting material)",
                   [py, "-m", "bench.nonce_analysis"]))
    if not args.skip_bench and not pending:
        perf = [py, "-m", "bench.perf"]
        if args.quick:
            perf.append("--quick")
        stages.append(("Performance evaluation (TR-8)", perf))

    results = []
    total_started = time.perf_counter()
    for name, command in stages:
        ok, elapsed = run_stage(name, command)
        results.append((name, ok, elapsed))
        if not ok and "test suite" in name:
            print("\nStopping: the test suite must pass before evidence is regenerated.")
            break

    print()
    print("=" * 78)
    print(" RUN SUMMARY")
    print("=" * 78)
    for name, ok, elapsed in results:
        print(f"  [{'PASS' if ok else 'FAIL'}]  {name[:56]:<56} {elapsed:>7.1f}s")
    print("-" * 78)
    print(f"  total {time.perf_counter() - total_started:.1f}s")

    artefacts = sorted(EVIDENCE_DIR.glob("*")) if EVIDENCE_DIR.exists() else []
    if artefacts:
        print("-" * 78)
        print("  Evidence written:")
        for path in artefacts:
            print(f"    evidence/{path.name:<28} {path.stat().st_size:>10,} bytes")
    print("=" * 78)

    return 0 if all(ok for _, ok, _ in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
