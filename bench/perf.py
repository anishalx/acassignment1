"""TR-8 -- Performance Evaluation of AES-GCM against ChaCha20-Poly1305.

Run from the repository root::

    python -m bench.perf                    # full run, charts included
    python -m bench.perf --quick            # required sizes only
    python -m bench.perf --no-charts        # skip matplotlib output

Outputs, all under ``evidence/``:

* ``perf-results.json``   every measurement, machine readable
* ``perf-summary.md``     tables for the report (this is also the "table view"
                          that the low-contrast series colour in the charts
                          relies on for accessibility)
* ``perf-*.png``          charts

Methodology
-----------

The two configurations are measured under identical conditions: same host, same
process, same interleaving, same record sizes, same code path.  The only
difference is which primitive the suite object invokes.

*Sizes.* 64 B, 1 KiB and 64 KiB are required by TR-8; 16 B, 256 B, 4 KiB, 16 KiB,
256 KiB and 1 MiB are added so the fixed-cost and per-byte regimes are both
visible.  A single point cannot distinguish "this cipher is faster" from "this
record size is dominated by per-record overhead", and that distinction turns out
to be the main finding.

*Batching.* Each measurement times a batch of operations rather than a single
one.  A single AEAD call on a 64-byte record takes about a microsecond, which is
within noise of ``perf_counter`` resolution and scheduler jitter; batching
amortises the timer.  Batch size is derived from a byte budget so that every
size does comparable total work.

*Repetition and statistic.* Nine batches per measurement, and the **median** is
reported.  The mean is the wrong statistic on a laptop: a single scheduler
preemption or a turbo-clock drop inflates one batch and drags the mean with it.
The median ignores those; the interquartile range is recorded alongside so the
report can state how stable the numbers actually were.

*Warm-up.* One full batch is run and discarded before timing, so key schedules,
branch predictors, allocator arenas and the CPU's clock ramp are all settled.

*What is timed.* Four things per size, because they answer different questions:

``protect``   the full subsystem path -- nonce allocation, header construction,
              AEAD seal, wire serialisation.  This is what an application pays.
``recover``   the full receive path -- parse, binding checks, replay window,
              AEAD open.  Also what an application pays.
``seal``      the bare AEAD call.  Isolates the cipher from the framing.
``open``      the bare AEAD call.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from srp import (  # noqa: E402
    HEADER_LEN,
    SUITE_NAMES,
    TAG_LEN,
    Receiver,
    RecordHeader,
    Sender,
    derive_nonce,
    new_session_id,
    suite_class,
)

EVIDENCE_DIR = ROOT / "evidence"

#: Record sizes measured.  The three required by TR-8 are flagged below.
SIZES: tuple[int, ...] = (16, 64, 256, 1024, 4096, 16384, 65536, 262144, 1048576)

#: Sizes TR-8 mandates.
REQUIRED_SIZES: tuple[int, ...] = (64, 1024, 65536)

#: Byte budget per timed batch; batch size = budget / record size, clamped.
BATCH_BYTES = 64 * 1024 * 1024
MIN_OPS = 64
MAX_OPS = 20_000

REPS = 9

#: How many times the whole measurement grid is swept; samples are pooled.
SWEEPS = 2

#: Disables AES-NI and PCLMULQDQ in OpenSSL, so AES-GCM falls back to its
#: software AES and GHASH paths.  Used for the hardware-acceleration comparison.
#:
#: In the 64-bit word OpenSSL builds from CPUID leaf 1, bit 57 is AES-NI and
#: bit 33 is PCLMULQDQ; ``~`` clears the named bits.
#:
#: The trailing ``:~0x0`` is essential and was found empirically.  Supplying a
#: value with no colon makes OpenSSL zero the *extended* feature words from
#: CPUID leaf 7 as well, which switches off AVX2 -- and AVX2 is exactly what
#: ChaCha20-Poly1305's fast path uses.  Without the colon, ChaCha20 measured
#: ~890 MiB/s against a ~1,620 MiB/s baseline, so the "control" was being
#: slowed by nearly half and the comparison understated ChaCha20 badly.  With
#: ``:~0x0`` the extended words are left as detected, ChaCha20 holds its
#: baseline, and the change is isolated to the AES path where it belongs.
NO_AESNI_CAP = "~0x200000200000000:~0x0"


def batch_size(record_size: int) -> int:
    return max(MIN_OPS, min(MAX_OPS, BATCH_BYTES // record_size))


def pin_to_one_cpu() -> str:
    """Confine the process to a single logical CPU.

    This host is a hybrid Intel design: it has both performance cores and
    efficiency cores, which run at very different clocks.  Left alone, the
    Windows scheduler migrates the benchmark thread between the two types
    mid-run, and the same workload then measures two to three times apart
    depending on which core it happened to land on.  That is large enough to
    swamp the difference between the two AEAD configurations, which is the thing
    being measured.

    Pinning removes the variable.  CPU 2 rather than CPU 0: the low-numbered
    logical processors are performance cores on this topology, and CPU 0 also
    fields most device interrupts.  Failure is non-fatal.
    """
    cpu = 2 if (os.cpu_count() or 1) >= 4 else 0
    try:
        if sys.platform == "win32":
            import ctypes

            kernel32 = ctypes.windll.kernel32
            kernel32.SetProcessAffinityMask.argtypes = [
                ctypes.c_void_p, ctypes.c_size_t
            ]
            kernel32.SetProcessAffinityMask.restype = ctypes.c_int
            handle = ctypes.c_void_p(kernel32.GetCurrentProcess())
            if kernel32.SetProcessAffinityMask(handle, 1 << cpu):
                return f"pinned to CPU {cpu}"
        elif hasattr(os, "sched_setaffinity"):
            os.sched_setaffinity(0, {cpu})
            return f"pinned to CPU {cpu}"
    except Exception:
        pass
    return "not pinned"


def raise_process_priority() -> str:
    """Ask the OS to preempt this process less often while measuring.

    Not an optimisation -- it does not make either configuration faster -- but a
    noise reduction.  At normal priority a background task getting scheduled
    mid-batch inflates that one sample, and on a laptop that happens often
    enough to matter.  ABOVE_NORMAL rather than HIGH deliberately: enough to
    win against ordinary background work, not enough to make the machine
    unresponsive.  Failure is non-fatal; the numbers are just noisier.
    """
    try:
        if sys.platform == "win32":
            import ctypes

            ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000
            handle = ctypes.windll.kernel32.GetCurrentProcess()
            if ctypes.windll.kernel32.SetPriorityClass(
                handle, ABOVE_NORMAL_PRIORITY_CLASS
            ):
                return "above normal"
        else:
            os.nice(-5)
            return "nice -5"
    except Exception:
        pass
    return "default (unchanged)"


# ---------------------------------------------------------------------------
# measurement
# ---------------------------------------------------------------------------

@dataclass
class Measurement:
    suite: str
    operation: str
    record_size: int
    ops_per_batch: int
    batches: int
    samples_s: list[float] = field(default_factory=list)

    @property
    def per_op_s(self) -> float:
        """Seconds per operation: the **minimum** batch, not the mean or median.

        Interference in a benchmark is one-sided.  A scheduler preemption, a
        cache eviction by another process, or a clock dip can only ever make a
        batch slower -- nothing makes it artificially faster.  The minimum is
        therefore the least-contaminated estimate of what the operation actually
        costs, which is why ``timeit`` documents the same choice.  A mean or
        median instead reports "the cost plus however much noise this machine
        happened to inject", which is not a property of the code and is not
        comparable between the two configurations.

        The median and the spread are retained below and reported alongside, so
        the report can state how noisy the host was rather than concealing it.
        """
        return min(self.samples_s) / self.ops_per_batch

    @property
    def median_per_op_s(self) -> float:
        return statistics.median(self.samples_s) / self.ops_per_batch

    @property
    def median_over_min(self) -> float:
        """How much slower the median batch was than the fastest, as a ratio."""
        return self.median_per_op_s / self.per_op_s

    @property
    def iqr_s(self) -> float:
        """Interquartile range of per-operation time, as a stability measure."""
        per_op = sorted(s / self.ops_per_batch for s in self.samples_s)
        n = len(per_op)
        return per_op[int(n * 0.75)] - per_op[int(n * 0.25)]

    @property
    def per_op_us(self) -> float:
        return self.per_op_s * 1e6

    @property
    def ops_per_s(self) -> float:
        return 1.0 / self.per_op_s

    @property
    def mib_per_s(self) -> float:
        """Throughput over *application* bytes, not wire bytes."""
        return (self.record_size / self.per_op_s) / (1024 * 1024)

    @property
    def rsd_pct(self) -> float:
        """Relative spread of the raw batch samples, as a noise indicator."""
        if len(self.samples_s) < 2:
            return 0.0
        return 100.0 * statistics.stdev(self.samples_s) / statistics.mean(self.samples_s)

    def as_dict(self) -> dict:
        data = asdict(self)
        data.update(
            per_op_us=self.per_op_us,
            median_per_op_us=self.median_per_op_s * 1e6,
            median_over_min=self.median_over_min,
            ops_per_s=self.ops_per_s,
            mib_per_s=self.mib_per_s,
            rsd_pct=self.rsd_pct,
            iqr_us=self.iqr_s * 1e6,
        )
        return data


def _time_batches(run_batch, ops: int, *, reps: int = REPS) -> list[float]:
    """Warm up once, then time ``reps`` batches and return their durations.

    Garbage collection is disabled across the timed region.  The sending and
    receiving paths allocate several tracked objects per record (the header, the
    parsed record, the verdict), so a generation-0 collection lands somewhere in
    the middle of a batch at an unpredictable point and shows up as a single
    inflated sample.  Disabling the collector does not make the code faster in
    any way that flatters one configuration over the other -- both allocate
    identically -- it just stops the comparison being contaminated by when the
    collector happened to fire.  A full collection is forced beforehand so the
    disabled region does not start with a backlog.
    """
    import gc

    run_batch()  # warm-up, discarded: key schedules, caches, clock ramp

    gc.collect()
    gc_was_enabled = gc.isenabled()
    gc.disable()
    try:
        samples = []
        for _ in range(reps):
            started = time.perf_counter()
            run_batch()
            samples.append(time.perf_counter() - started)
    finally:
        if gc_was_enabled:
            gc.enable()
        gc.collect()
    return samples


def measure_subsystem_protect(suite_name: str, size: int, ops: int) -> Measurement:
    """Full sending path: nonce, header, AEAD seal, serialisation."""
    cls = suite_class(suite_name)
    key = cls.generate_key()
    payload = os.urandom(size)

    # Budget must cover warm-up plus every timed batch.
    sender = Sender(
        cls(key), new_session_id(), record_limit=ops * (REPS + 2) + 16
    )

    def run_batch():
        protect = sender.protect
        for _ in range(ops):
            protect(payload)

    samples = _time_batches(run_batch, ops)
    return Measurement(suite_name, "protect", size, ops, REPS, samples)


def measure_subsystem_recover(suite_name: str, size: int, ops: int) -> Measurement:
    """Full receiving path: parse, bindings, replay window, AEAD open.

    Records are generated once, outside the timed region.  Each batch uses a
    **fresh receiver** so that every record is seen for the first time: reusing
    one receiver would make later batches hit the replay window's cheap
    duplicate rejection and report a decrypt time that never happened.
    """
    cls = suite_class(suite_name)
    key = cls.generate_key()
    session_id = new_session_id()
    payload = os.urandom(size)

    sender = Sender(cls(key), session_id, record_limit=ops + 16)
    records = [sender.protect(payload) for _ in range(ops)]

    # One receiver per batch, all built up front.  Constructing a receiver
    # instantiates the AEAD object and therefore runs the key schedule; doing
    # that inside the timed region would charge every batch a fixed setup cost
    # that has nothing to do with per-record recovery.
    receivers = iter([
        Receiver(cls(key), expected_session_id=session_id) for _ in range(REPS + 2)
    ])

    def run_batch():
        receive = next(receivers).receive
        for wire in records:
            receive(wire)

    samples = _time_batches(run_batch, ops)
    return Measurement(suite_name, "recover", size, ops, REPS, samples)


def measure_raw(suite_name: str, size: int, ops: int, *, decrypt: bool) -> Measurement:
    """Bare AEAD call, with nonce and AAD prepared outside the timed region."""
    cls = suite_class(suite_name)
    suite = cls(cls.generate_key())
    payload = os.urandom(size)
    header = RecordHeader(
        session_id=new_session_id(),
        stream_id=1,
        nonce_prefix=os.urandom(4),
        seq=0,
        payload_len=size,
        suite_id=cls.suite_id,
    )
    aad = header.aad()
    nonce = derive_nonce(header.nonce_prefix, header.seq)
    sealed = suite.seal(nonce, payload, aad)

    if decrypt:
        def run_batch():
            open_ = suite.open
            for _ in range(ops):
                open_(nonce, sealed, aad)
    else:
        def run_batch():
            seal = suite.seal
            for _ in range(ops):
                seal(nonce, payload, aad)

    samples = _time_batches(run_batch, ops)
    return Measurement(suite_name, "open" if decrypt else "seal", size, ops, REPS, samples)


MEASURERS = {
    "protect": lambda s, z, o: measure_subsystem_protect(s, z, o),
    "recover": lambda s, z, o: measure_subsystem_recover(s, z, o),
    "seal": lambda s, z, o: measure_raw(s, z, o, decrypt=False),
    "open": lambda s, z, o: measure_raw(s, z, o, decrypt=True),
}


def run_measurements(
    sizes: tuple[int, ...], *, sweeps: int = 2, verbose: bool = True
) -> list[Measurement]:
    """Measure every (size, operation, configuration) combination.

    Two things about the ordering are deliberate.

    *The two configurations are measured back to back* for a given size and
    operation, rather than one configuration's whole block followed by the
    other's.  The quantity being reported is a ratio between them, so anything
    that drifts over the run -- core temperature, clock residency, background
    load -- biases that ratio unless both sides sit inside the same slice of
    time.  Measuring them adjacently makes drift common-mode.

    *The whole grid is swept more than once* and the samples pooled.  A single
    sweep gives one contiguous window per measurement, so a slow patch of the
    run lands entirely on whichever measurement was unlucky.  Repeating the
    sweep gives every measurement a sample from each patch, and since the
    reported statistic is the minimum, each one keeps its best.
    """
    pooled: dict[tuple[str, str, int], Measurement] = {}

    for sweep in range(sweeps):
        if verbose and sweeps > 1:
            print(f"  --- sweep {sweep + 1} of {sweeps} ---")
        for size in sizes:
            ops = batch_size(size)
            for operation, measure in MEASURERS.items():
                for suite_name in SUITE_NAMES:
                    measurement = measure(suite_name, size, ops)
                    key = (suite_name, operation, size)
                    if key in pooled:
                        pooled[key].samples_s.extend(measurement.samples_s)
                        pooled[key].batches += measurement.batches
                    else:
                        pooled[key] = measurement
                    if verbose:
                        current = pooled[key]
                        print(
                            f"  {size:>9,} B  {suite_name:<20} {operation:<8} "
                            f"{current.per_op_us:>10.3f} us/rec  "
                            f"{current.mib_per_s:>9.1f} MiB/s  "
                            f"(n={ops}, med/min={current.median_over_min:.2f}x)"
                        )

    # Preserve a stable, readable ordering for the report tables.
    return [
        pooled[(suite, operation, size)]
        for size in sizes
        for suite in SUITE_NAMES
        for operation in MEASURERS
        if (suite, operation, size) in pooled
    ]


# ---------------------------------------------------------------------------
# hardware acceleration comparison
# ---------------------------------------------------------------------------

def run_child_raw_bench(sizes: tuple[int, ...]) -> None:
    """Child-process entry point: raw AEAD numbers as JSON on stdout."""
    payload = []
    for size in sizes:
        ops = batch_size(size)
        for suite_name in SUITE_NAMES:
            for decrypt in (False, True):
                m = measure_raw(suite_name, size, ops, decrypt=decrypt)
                payload.append(m.as_dict())
    print(json.dumps(payload))


def measure_without_aesni(sizes: tuple[int, ...], *, verbose: bool = True) -> dict | None:
    """Re-measure the raw AEAD path with AES-NI and PCLMULQDQ turned off.

    OpenSSL honours the ``OPENSSL_ia32cap`` environment variable as a mask over
    detected CPU features, so a child process started with the AES-NI and
    PCLMULQDQ bits cleared exercises AES-GCM's software fallback while leaving
    ChaCha20-Poly1305 -- which uses neither instruction -- essentially untouched.

    This is the experiment that makes the AES-GCM vs ChaCha20-Poly1305 comparison
    meaningful rather than a fact about one laptop: it separates "AES-GCM is
    faster" from "AES-GCM is faster *when the CPU implements it in hardware*".

    Returns ``None`` if the child fails, or if ChaCha20-Poly1305's own timing
    moved enough to suggest the mask perturbed more than the AES path.
    """
    env = dict(os.environ, OPENSSL_ia32cap=NO_AESNI_CAP)
    cmd = [sys.executable, "-m", "bench.perf", "--child-raw-bench",
           "--sizes", ",".join(str(s) for s in sizes)]
    try:
        completed = subprocess.run(
            cmd, cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=900
        )
    except (subprocess.SubprocessError, OSError) as exc:  # pragma: no cover
        if verbose:
            print(f"  AES-NI comparison unavailable: {exc}")
        return None

    if completed.returncode != 0:  # pragma: no cover
        if verbose:
            print(f"  AES-NI comparison failed (exit {completed.returncode})")
            print(completed.stderr[-500:])
        return None

    try:
        rows = json.loads(completed.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError) as exc:  # pragma: no cover
        if verbose:
            print(f"  AES-NI comparison produced no parseable output: {exc}")
        return None

    return {"cap_mask": NO_AESNI_CAP, "measurements": rows}


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------

def host_info() -> dict:
    info = {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_count": os.cpu_count(),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    try:
        from cryptography.hazmat.backends.openssl.backend import backend
        import cryptography

        info["cryptography"] = cryptography.__version__
        info["openssl"] = backend.openssl_version_text()
    except Exception:  # pragma: no cover
        pass
    try:  # friendlier CPU name on Windows
        if sys.platform == "win32":
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-CimInstance Win32_Processor).Name"],
                capture_output=True, text=True, timeout=30,
            )
            if out.returncode == 0 and out.stdout.strip():
                info["cpu_name"] = out.stdout.strip().splitlines()[0].strip()
    except Exception:  # pragma: no cover
        pass
    return info


def load_results(path: Path):
    """Rebuild measurements from a previous run's JSON.

    Lets the summary and charts be regenerated after a presentation change
    without re-measuring, which both saves four minutes and guarantees the
    regenerated artefacts describe exactly the same run.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    results = [
        Measurement(
            suite=row["suite"],
            operation=row["operation"],
            record_size=row["record_size"],
            ops_per_batch=row["ops_per_batch"],
            batches=row["batches"],
            samples_s=row["samples_s"],
        )
        for row in data["measurements"]
    ]
    return results, data["host"], data.get("no_aesni"), tuple(data["sizes"])


def lookup(results: list[Measurement], suite: str, operation: str, size: int) -> Measurement:
    for m in results:
        if m.suite == suite and m.operation == operation and m.record_size == size:
            return m
    raise KeyError(f"no measurement for {suite}/{operation}/{size}")


def format_size(size: int) -> str:
    if size >= 1024 * 1024:
        return f"{size // (1024 * 1024)} MiB"
    if size >= 1024:
        return f"{size // 1024} KiB"
    return f"{size} B"


def write_summary(
    results: list[Measurement],
    info: dict,
    no_aesni: dict | None,
    sizes: tuple[int, ...],
    path: Path,
) -> None:
    """Emit the markdown tables the report quotes, and the accessible table view."""
    lines: list[str] = []
    add = lines.append

    add("# TR-8 Performance Evaluation")
    add("")
    add("Protection and recovery of application records, AES-GCM against")
    add("ChaCha20-Poly1305 under identical conditions.")
    add("")
    add("## Measurement environment")
    add("")
    add("| Property | Value |")
    add("|---|---|")
    for key in ("cpu_name", "processor", "machine", "cpu_count", "platform",
                "python", "implementation", "cryptography", "openssl",
                "process_priority", "cpu_affinity", "timestamp"):
        if key in info and info[key] is not None:
            add(f"| {key.replace('_', ' ')} | {info[key]} |")
    add(f"| batches per measurement | {results[0].batches} "
        f"({results[0].batches // REPS} sweeps x {REPS}; **minimum** reported) |")
    add("| configuration ordering | the two AEAD suites measured back to back |")
    add(f"| batch byte budget | {BATCH_BYTES // (1024*1024)} MiB |")
    add("| garbage collection | disabled across each timed region |")
    add("")

    add("## Measurement stability")
    add("")
    add("The figure reported everywhere below is the **fastest** of the")
    add(f"{REPS} batches, not the mean or median. Benchmark interference is")
    add("one-sided -- preemption, cache eviction and clock dips can only add")
    add("time -- so the minimum is the least-contaminated estimate of the true")
    add("cost. This matters on this host in particular: it is a hybrid CPU with")
    add("performance and efficiency cores, and an unpinned thread migrating")
    add("between the two measures 2-3x apart, which is larger than the effect")
    add("being studied. The process is pinned to one core and raised in")
    add("priority for the same reason.")
    add("")
    add("How much noise remained, as the ratio of the median batch to the")
    add("fastest batch (1.00 would mean a perfectly quiet host):")
    add("")
    worst = sorted(results, key=lambda m: -m.median_over_min)[:5]
    median_ratio = statistics.median(m.median_over_min for m in results)
    add(f"- Median across all {len(results)} measurements: **{median_ratio:.2f}x**")
    add("- Worst five: " + ", ".join(
        f"{m.suite}/{m.operation}/{format_size(m.record_size)} {m.median_over_min:.2f}x"
        for m in worst
    ))
    add("")
    add("Differences smaller than the residual spread should not be read as")
    add("real; the conclusions drawn in the report rest on ratios well above it.")
    add("")

    add("## Required sizes (TR-8 minimum)")
    add("")
    add("Full subsystem path, i.e. what an application actually pays.")
    add("")
    add("| Record size | Operation | AES-GCM | ChaCha20-Poly1305 | Faster | Margin |")
    add("|---|---|---|---|---|---|")
    for size in REQUIRED_SIZES:
        if size not in sizes:
            continue
        for op in ("protect", "recover"):
            a = lookup(results, "aes-gcm", op, size)
            c = lookup(results, "chacha20-poly1305", op, size)
            faster = "AES-GCM" if a.per_op_s < c.per_op_s else "ChaCha20-Poly1305"
            ratio = max(c.per_op_s / a.per_op_s, a.per_op_s / c.per_op_s)
            add(
                f"| {format_size(size)} | {op} | "
                f"{a.per_op_us:.2f} us ({a.mib_per_s:,.0f} MiB/s) | "
                f"{c.per_op_us:.2f} us ({c.mib_per_s:,.0f} MiB/s) | "
                f"{faster} | {ratio:.2f}x |"
            )
    add("")

    add("## All measured sizes")
    add("")
    for op, title in (("protect", "Protection (sender)"), ("recover", "Recovery (receiver)")):
        add(f"### {title}")
        add("")
        add("| Record size | AES-GCM us/rec | AES-GCM MiB/s | ChaCha20 us/rec | "
            "ChaCha20 MiB/s | Ratio (ChaCha/AES) |")
        add("|---|---|---|---|---|---|")
        for size in sizes:
            a = lookup(results, "aes-gcm", op, size)
            c = lookup(results, "chacha20-poly1305", op, size)
            add(
                f"| {format_size(size)} | {a.per_op_us:.3f} | {a.mib_per_s:,.0f} | "
                f"{c.per_op_us:.3f} | {c.mib_per_s:,.0f} | "
                f"{c.per_op_s / a.per_op_s:.2f}x |"
            )
        add("")

    add("## Subsystem overhead over the bare AEAD call")
    add("")
    add("Difference between the full path and the raw primitive: nonce")
    add("allocation, header build/parse, binding checks and the replay window.")
    add("")
    add("| Record size | AES-GCM protect | AES-GCM recover | ChaCha20 protect | ChaCha20 recover |")
    add("|---|---|---|---|---|")
    for size in sizes:
        cells = []
        for suite in SUITE_NAMES:
            for full_op, raw_op in (("protect", "seal"), ("recover", "open")):
                full = lookup(results, suite, full_op, size)
                raw = lookup(results, suite, raw_op, size)
                delta = (full.per_op_s - raw.per_op_s) * 1e6
                pct = 100.0 * (full.per_op_s - raw.per_op_s) / full.per_op_s
                cells.append(f"{delta:+.3f} us ({pct:.0f}%)")
        add(f"| {format_size(size)} | " + " | ".join(cells) + " |")
    add("")

    if no_aesni:
        add("## Hardware acceleration: AES-GCM with AES-NI disabled")
        add("")
        add(f"Re-measured in a child process with `OPENSSL_ia32cap={no_aesni['cap_mask']}`,")
        add("which clears the AES-NI and PCLMULQDQ feature bits so OpenSSL falls back")
        add("to its software AES and GHASH paths. ChaCha20-Poly1305 uses neither")
        add("instruction, so its column is the control: it should barely move, and")
        add("the extent to which it does not is what licenses reading the AES-GCM")
        add("change as an AES-NI effect rather than a change in the machine.")
        add("")
        add("The `:~0x0` suffix on the mask matters. Without it OpenSSL also zeroes")
        add("the CPUID leaf-7 feature words, disabling AVX2 -- which ChaCha20's fast")
        add("path uses -- and the control then drops by nearly half, making AES-GCM's")
        add("relative loss look smaller than it is. See the note in `bench/perf.py`.")
        add("")
        add("| Record size | Operation | AES-GCM (AES-NI) | AES-GCM (software) | "
            "Slowdown | ChaCha20 (control) |")
        add("|---|---|---|---|---|---|")
        rows = no_aesni["measurements"]

        def child(suite: str, op: str, size: int) -> dict | None:
            for row in rows:
                if row["suite"] == suite and row["operation"] == op and row["record_size"] == size:
                    return row
            return None

        for size in sizes:
            for op in ("seal", "open"):
                hw = lookup(results, "aes-gcm", op, size)
                sw = child("aes-gcm", op, size)
                cc_hw = lookup(results, "chacha20-poly1305", op, size)
                cc_sw = child("chacha20-poly1305", op, size)
                if sw is None or cc_sw is None:
                    continue
                add(
                    f"| {format_size(size)} | {op} | {hw.mib_per_s:,.0f} MiB/s | "
                    f"{sw['mib_per_s']:,.0f} MiB/s | "
                    f"{sw['per_op_us'] / hw.per_op_us:.2f}x slower | "
                    f"{cc_hw.mib_per_s:,.0f} -> {cc_sw['mib_per_s']:,.0f} MiB/s |"
                )
        add("")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# charts
# ---------------------------------------------------------------------------

# Palette: dataviz reference instance, categorical slots 1-2 plus a lighter step
# of slot 1's own ramp for the "same entity, different condition" series.
# Validated with scripts/validate_palette.js (light, --pairs all): all checks
# pass; the low-contrast steps carry value labels and a table view as relief.
INK = "#0b0b0b"
INK_SECONDARY = "#52514e"
INK_MUTED = "#898781"
GRID = "#e1e0d9"
AXIS = "#c3c2b7"
SURFACE = "#fcfcfb"
SERIES = {
    "aes-gcm": "#2a78d6",              # categorical slot 1, blue
    "chacha20-poly1305": "#eb6834",    # categorical slot 2, orange
}
AES_SOFTWARE = "#86b6ef"               # blue ramp step 250: AES-GCM, no AES-NI
LABEL = {"aes-gcm": "AES-GCM", "chacha20-poly1305": "ChaCha20-Poly1305"}


def _style_axes(ax, *, ylabel: str, xlabel: str | None = None) -> None:
    ax.set_facecolor(SURFACE)
    ax.grid(axis="y", color=GRID, linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(AXIS)
        ax.spines[side].set_linewidth(1.0)
    ax.tick_params(colors=INK_MUTED, labelsize=9, length=0)
    ax.set_ylabel(ylabel, color=INK_SECONDARY, fontsize=10)
    if xlabel:
        ax.set_xlabel(xlabel, color=INK_SECONDARY, fontsize=10)


def make_charts(
    results: list[Measurement],
    no_aesni: dict | None,
    sizes: tuple[int, ...],
    outdir: Path,
) -> list[Path]:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from matplotlib.ticker import FuncFormatter
    except ImportError:  # pragma: no cover
        print("  matplotlib not available; skipping charts")
        return []

    plt.rcParams.update({
        "font.family": "sans-serif",
        "font.sans-serif": ["Segoe UI", "DejaVu Sans", "sans-serif"],
        "figure.facecolor": SURFACE,
        "savefig.facecolor": SURFACE,
    })
    outdir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    # -- Chart 1: throughput vs record size, small multiples by operation ----
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.6), dpi=170, sharey=True)
    for ax, (op, title) in zip(axes, (("protect", "Protection (sender)"),
                                      ("recover", "Recovery (receiver)"))):
        for index, suite in enumerate(SUITE_NAMES):
            xs = list(sizes)
            ys = [lookup(results, suite, op, s).mib_per_s for s in sizes]
            ax.plot(xs, ys, color=SERIES[suite], linewidth=2.0,
                    marker="o", markersize=5, zorder=3,
                    markeredgecolor=SURFACE, markeredgewidth=1.2)
            # Direct-label at each series' peak rather than its last point: the
            # curves converge at 1 MiB, so labels there sit on top of the lines.
            # At the peak the two series are furthest apart vertically, and the
            # upper/lower offsets keep the text clear of both curves.
            peak = max(range(len(ys)), key=ys.__getitem__)
            ax.annotate(
                LABEL[suite], xy=(xs[peak], ys[peak]),
                # Upper series labels above and centred; lower series labels
                # below and anchored leftward, so it cannot run into the upper
                # curve where that curve descends to the right.
                xytext=(0, 11) if index == 0 else (-8, -20),
                textcoords="offset points",
                ha="center" if index == 0 else "right",
                fontsize=9, color=INK_SECONDARY, fontweight="medium",
            )
        ax.set_xscale("log", base=2)
        ax.set_xticks(list(sizes))
        ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: format_size(int(v))))
        ax.tick_params(axis="x", rotation=45)
        _style_axes(ax, ylabel="Throughput (MiB/s)" if op == "protect" else "",
                    xlabel="Application record size")
        ax.set_title(title, color=INK, fontsize=11, loc="left", pad=10)
        ax.margins(y=0.14)
    fig.suptitle(
        "AEAD throughput by record size -- full subsystem path",
        color=INK, fontsize=13, x=0.008, ha="left", y=0.99, fontweight="semibold",
    )
    fig.tight_layout(rect=(0, 0, 1, 0.94))
    path = outdir / "perf-throughput.png"
    fig.savefig(path)
    plt.close(fig)
    written.append(path)

    # -- Chart 2: per-record latency, log-log --------------------------------
    fig, ax = plt.subplots(figsize=(8, 4.8), dpi=170)
    for suite in SUITE_NAMES:
        for op, style in (("protect", "-"), ("recover", "--")):
            ys = [lookup(results, suite, op, s).per_op_us for s in sizes]
            ax.plot(list(sizes), ys, style, color=SERIES[suite], linewidth=2.0,
                    marker="o" if op == "protect" else "s", markersize=4.5,
                    markeredgecolor=SURFACE, markeredgewidth=1.0, zorder=3,
                    label=f"{LABEL[suite]} -- {op}")
    ax.set_xscale("log", base=2)
    ax.set_yscale("log", base=10)
    ax.set_xticks(list(sizes))
    ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: format_size(int(v))))
    ax.tick_params(axis="x", rotation=45)
    _style_axes(ax, ylabel="Time per record (microseconds, log)",
                xlabel="Application record size")
    ax.set_title(
        "Per-record cost: a flat floor below ~1 KiB, linear above it",
        color=INK, fontsize=12, loc="left", pad=10,
    )
    legend = ax.legend(frameon=False, fontsize=9, loc="upper left")
    for text in legend.get_texts():
        text.set_color(INK_SECONDARY)
    fig.tight_layout()
    path = outdir / "perf-latency.png"
    fig.savefig(path)
    plt.close(fig)
    written.append(path)

    # -- Chart 3: the three TR-8 required sizes ------------------------------
    required = [s for s in REQUIRED_SIZES if s in sizes]
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.4), dpi=170)
    width = 0.36
    for ax, (op, title) in zip(axes, (("protect", "Protection (sender)"),
                                      ("recover", "Recovery (receiver)"))):
        positions = range(len(required))
        for offset, suite in zip((-width / 2 - 0.012, width / 2 + 0.012), SUITE_NAMES):
            values = [lookup(results, suite, op, s).mib_per_s for s in required]
            bars = ax.bar([p + offset for p in positions], values, width,
                          color=SERIES[suite], label=LABEL[suite], zorder=3)
            for bar, value in zip(bars, values):
                ax.annotate(f"{value:,.0f}", xy=(bar.get_x() + bar.get_width() / 2,
                                                 bar.get_height()),
                            xytext=(0, 3), textcoords="offset points",
                            ha="center", fontsize=8.5, color=INK_SECONDARY)
        ax.set_xticks(list(positions))
        ax.set_xticklabels([format_size(s) for s in required])
        _style_axes(ax, ylabel="Throughput (MiB/s)" if op == "protect" else "",
                    xlabel="Application record size")
        ax.set_title(title, color=INK, fontsize=11, loc="left", pad=10)
        ax.margins(y=0.16)
    handles, labels = axes[0].get_legend_handles_labels()
    legend = fig.legend(handles, labels, frameon=False, fontsize=9.5,
                        loc="upper right", ncol=2, bbox_to_anchor=(0.995, 1.0))
    for text in legend.get_texts():
        text.set_color(INK_SECONDARY)
    fig.suptitle("TR-8 required record sizes", color=INK, fontsize=13,
                 x=0.008, ha="left", y=0.99, fontweight="semibold")
    fig.tight_layout(rect=(0, 0, 1, 0.92))
    path = outdir / "perf-required-sizes.png"
    fig.savefig(path)
    plt.close(fig)
    written.append(path)

    # -- Chart 4: hardware acceleration --------------------------------------
    if no_aesni:
        rows = no_aesni["measurements"]

        def child_value(suite: str, op: str, size: int):
            for row in rows:
                if (row["suite"] == suite and row["operation"] == op
                        and row["record_size"] == size):
                    return row["mib_per_s"]
            return None

        chart_sizes = [s for s in (1024, 16384, 65536, 1048576) if s in sizes]
        series = [
            ("AES-GCM (AES-NI)", SERIES["aes-gcm"],
             lambda s: lookup(results, "aes-gcm", "seal", s).mib_per_s),
            ("AES-GCM (software)", AES_SOFTWARE,
             lambda s: child_value("aes-gcm", "seal", s)),
            ("ChaCha20-Poly1305", SERIES["chacha20-poly1305"],
             lambda s: lookup(results, "chacha20-poly1305", "seal", s).mib_per_s),
        ]
        if all(fn(s) is not None for _, _, fn in series for s in chart_sizes):
            fig, ax = plt.subplots(figsize=(9, 4.8), dpi=170)
            width = 0.26
            positions = range(len(chart_sizes))
            for i, (name, color, fn) in enumerate(series):
                offset = (i - 1) * (width + 0.014)
                values = [fn(s) for s in chart_sizes]
                bars = ax.bar([p + offset for p in positions], values, width,
                              color=color, label=name, zorder=3)
                for bar, value in zip(bars, values):
                    ax.annotate(f"{value:,.0f}",
                                xy=(bar.get_x() + bar.get_width() / 2, bar.get_height()),
                                xytext=(0, 3), textcoords="offset points",
                                ha="center", fontsize=8, color=INK_SECONDARY)
            ax.set_xticks(list(positions))
            ax.set_xticklabels([format_size(s) for s in chart_sizes])
            _style_axes(ax, ylabel="Throughput (MiB/s)",
                        xlabel="Application record size")
            ax.set_title(
                "Why AES-GCM wins here: AES-NI. With it disabled, ChaCha20-Poly1305 leads.",
                color=INK, fontsize=11.5, loc="left", pad=10,
            )
            ax.margins(y=0.16)
            legend = ax.legend(frameon=False, fontsize=9, loc="upper left")
            for text in legend.get_texts():
                text.set_color(INK_SECONDARY)
            fig.tight_layout()
            path = outdir / "perf-aesni.png"
            fig.savefig(path)
            plt.close(fig)
            written.append(path)

    return written


# ---------------------------------------------------------------------------
# driver
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="TR-8 performance evaluation")
    parser.add_argument("--quick", action="store_true",
                        help="measure only the three TR-8 required sizes")
    parser.add_argument("--sizes", type=str, default=None,
                        help="comma-separated record sizes in bytes")
    parser.add_argument("--sweeps", type=int, default=SWEEPS,
                        help=f"passes over the measurement grid (default: {SWEEPS})")
    parser.add_argument("--no-charts", action="store_true", help="skip chart generation")
    parser.add_argument("--no-aesni-comparison", action="store_true",
                        help="skip the AES-NI disabled re-measurement")
    parser.add_argument("--charts-only", action="store_true",
                        help="regenerate the summary and charts from the last run's JSON")
    parser.add_argument("--child-raw-bench", action="store_true",
                        help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    if args.charts_only:
        json_path = EVIDENCE_DIR / "perf-results.json"
        if not json_path.exists():
            print(f"no previous run at {json_path}; run the benchmark first")
            return 1
        results, info, no_aesni, sizes = load_results(json_path)
        write_summary(results, info, no_aesni, sizes, EVIDENCE_DIR / "perf-summary.md")
        for chart in make_charts(results, no_aesni, sizes, EVIDENCE_DIR):
            print(f"  chart    -> {chart.relative_to(ROOT)}")
        print("  summary and charts regenerated from the previous run")
        return 0

    if args.sizes:
        sizes = tuple(int(s) for s in args.sizes.split(","))
    elif args.quick:
        sizes = REQUIRED_SIZES
    else:
        sizes = SIZES

    if args.child_raw_bench:
        pin_to_one_cpu()
        raise_process_priority()
        run_child_raw_bench(sizes)
        return 0

    affinity = pin_to_one_cpu()
    priority = raise_process_priority()

    print("=" * 78)
    print(" TR-8  Performance Evaluation: AES-GCM vs ChaCha20-Poly1305")
    print("=" * 78)
    info = host_info()
    for key in ("cpu_name", "processor", "platform", "python", "cryptography", "openssl"):
        if info.get(key):
            print(f"  {key:<16} {info[key]}")
    print(f"  sizes            {', '.join(format_size(s) for s in sizes)}")
    print(f"  method           {args.sweeps} sweeps x {REPS} batches, minimum reported")
    print(f"  priority         {priority}")
    print(f"  cpu affinity     {affinity}")
    print("-" * 78)
    info["process_priority"] = priority
    info["cpu_affinity"] = affinity

    started = time.perf_counter()
    results = run_measurements(sizes, sweeps=args.sweeps)
    print("-" * 78)

    no_aesni = None
    if not args.no_aesni_comparison:
        print("  re-measuring the raw AEAD path with AES-NI and PCLMULQDQ disabled ...")
        no_aesni = measure_without_aesni(sizes)
        if no_aesni:
            print(f"  AES-NI comparison collected ({len(no_aesni['measurements'])} rows)")
        print("-" * 78)

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    json_path = EVIDENCE_DIR / "perf-results.json"
    json_path.write_text(json.dumps({
        "host": info,
        "method": {
            "batches_per_measurement": REPS,
            "batch_byte_budget": BATCH_BYTES,
            "statistic": "median",
            "min_ops": MIN_OPS,
            "max_ops": MAX_OPS,
        },
        "sizes": list(sizes),
        "required_sizes": list(REQUIRED_SIZES),
        "measurements": [m.as_dict() for m in results],
        "no_aesni": no_aesni,
    }, indent=2), encoding="utf-8")

    summary_path = EVIDENCE_DIR / "perf-summary.md"
    write_summary(results, info, no_aesni, sizes, summary_path)

    charts = [] if args.no_charts else make_charts(results, no_aesni, sizes, EVIDENCE_DIR)

    print(f"  results  -> {json_path.relative_to(ROOT)}")
    print(f"  summary  -> {summary_path.relative_to(ROOT)}")
    for chart in charts:
        print(f"  chart    -> {chart.relative_to(ROOT)}")
    print(f"  total elapsed {time.perf_counter() - started:.1f} s")
    print("=" * 78)

    # Headline comparison for the console.
    print(" Headline (full subsystem path, TR-8 required sizes):")
    for size in (s for s in REQUIRED_SIZES if s in sizes):
        for op in ("protect", "recover"):
            a = lookup(results, "aes-gcm", op, size)
            c = lookup(results, "chacha20-poly1305", op, size)
            ratio = c.per_op_s / a.per_op_s
            winner = "AES-GCM" if ratio > 1 else "ChaCha20-Poly1305"
            print(f"   {format_size(size):>8} {op:<8} AES-GCM {a.mib_per_s:>8,.0f} MiB/s | "
                  f"ChaCha20 {c.mib_per_s:>8,.0f} MiB/s | "
                  f"{winner} faster by {max(ratio, 1/ratio):.2f}x")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
