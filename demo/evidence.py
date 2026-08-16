"""A small reporter that emits test evidence in the format Section 6 requires.

Every Testing Requirement in the Assignment 1 Report needs Objective, Procedure,
Test Input, Expected Behaviour, Observed Behaviour, Outcome and Supporting
Evidence.  Rather than write those by hand and hope they still match the code,
the demo declares them here and the transcript is generated from the run -- so
the "Observed Behaviour" in the report is literally what the program did.

Output is ASCII-only so that it renders identically in a Windows console, a
POSIX terminal, and a pasted report appendix.
"""

from __future__ import annotations

import io
import sys
from dataclasses import dataclass, field
from pathlib import Path

WIDTH = 78


@dataclass
class TestOutcome:
    """Result of one Testing Requirement under one AEAD configuration."""

    tr: str
    title: str
    suite: str
    passed: bool
    observed: list[str] = field(default_factory=list)

    @property
    def status(self) -> str:
        return "PASS" if self.passed else "FAIL"


class Evidence:
    """Tees a formatted transcript to stdout and to a log file."""

    def __init__(self, log_path: Path | None = None, *, echo: bool = True) -> None:
        self._buffer = io.StringIO()
        self._log_path = log_path
        self._echo = echo
        self.outcomes: list[TestOutcome] = []
        self._current: TestOutcome | None = None

    # -- raw output --------------------------------------------------------

    def write(self, text: str = "") -> None:
        self._buffer.write(text + "\n")
        if self._echo:
            print(text)

    def rule(self, char: str = "-") -> None:
        self.write(char * WIDTH)

    def banner(self, text: str) -> None:
        self.rule("=")
        self.write(text)
        self.rule("=")

    # -- structured test documentation ------------------------------------

    def begin(
        self,
        tr: str,
        title: str,
        suite: str,
        *,
        objective: str,
        procedure: list[str],
        test_input: str,
        expected: str,
    ) -> None:
        self._current = TestOutcome(tr=tr, title=title, suite=suite, passed=True)
        self.write()
        self.rule("=")
        self.write(f" {tr}  {title}".ljust(WIDTH - len(suite) - 4) + f"[{suite}]")
        self.rule("=")
        self.write(f"  Objective : {objective}")
        self.write("  Procedure :")
        for i, step in enumerate(procedure, 1):
            self.write(f"              {i}. {step}")
        self.write(f"  Input     : {test_input}")
        self.write(f"  Expected  : {expected}")
        self.rule()

    def step(self, text: str) -> None:
        self.write(f"  > {text}")

    def detail(self, text: str) -> None:
        self.write(f"      {text}")

    def field(self, name: str, value) -> None:
        self.write(f"      {name:<22} {value}")

    def observe(self, text: str) -> None:
        """Record a line of Observed Behaviour for the report."""
        assert self._current is not None
        self._current.observed.append(text)
        self.write(f"  = {text}")

    def check(self, condition: bool, description: str) -> bool:
        """Assert a property, log it, and fold the result into the outcome."""
        assert self._current is not None
        mark = "ok  " if condition else "FAIL"
        self.write(f"  [{mark}] {description}")
        if not condition:
            self._current.passed = False
        return condition

    def end(self) -> TestOutcome:
        assert self._current is not None
        outcome = self._current
        self.rule()
        self.write(f"  OUTCOME   : {outcome.status}")
        self.outcomes.append(outcome)
        self._current = None
        return outcome

    # -- record rendering --------------------------------------------------

    def hexdump(self, label: str, data: bytes, *, limit: int = 64) -> None:
        from srp.util import hexdump

        self.write(f"      {label} ({len(data)} bytes)")
        self.write(hexdump(data, limit=limit, indent="        "))

    def show_record(self, label: str, wire: bytes, *, limit: int = 48) -> None:
        """Header breakdown plus a hex dump of the protected record."""
        from srp import HEADER_LEN, TAG_LEN, parse_record

        self.write(f"      {label} ({len(wire)} bytes"
                   f" = {HEADER_LEN} header + {len(wire) - HEADER_LEN - TAG_LEN}"
                   f" ciphertext + {TAG_LEN} tag)")
        try:
            record = parse_record(wire)
        except Exception as exc:  # unparseable frames still get a dump
            self.write(f"        <unparseable: {exc}>")
            self.hexdump("bytes", wire, limit=limit)
            return
        self.write(f"        header : {record.header.summary()}")
        self.write(f"        aad    : {record.header.aad().hex()}")
        self.write(f"        ct     : {record.ciphertext[:24].hex()}"
                   f"{'...' if len(record.ciphertext) > 24 else ''}")
        self.write(f"        tag    : {record.tag.hex()}")

    def show_diff(self, original: bytes, modified: bytes) -> None:
        from srp.util import describe_diff

        self.write(f"      modification : {describe_diff(original, modified)}")

    def show_verdict(self, label: str, verdict) -> None:
        self.write(f"      {label:<22} {verdict.describe()}")

    # -- summary -----------------------------------------------------------

    def summary_table(self) -> None:
        self.write()
        self.banner(" SUMMARY ")
        self.write(f"  {'TR':<6} {'Title':<34} {'Configuration':<20} Outcome")
        self.rule()
        for outcome in self.outcomes:
            self.write(
                f"  {outcome.tr:<6} {outcome.title[:34]:<34} "
                f"{outcome.suite:<20} {outcome.status}"
            )
        self.rule()
        passed = sum(1 for o in self.outcomes if o.passed)
        self.write(f"  {passed}/{len(self.outcomes)} demonstrations passed")
        self.rule("=")

    @property
    def all_passed(self) -> bool:
        return all(o.passed for o in self.outcomes)

    def save(self) -> Path | None:
        if self._log_path is None:
            return None
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        self._log_path.write_text(self._buffer.getvalue(), encoding="utf-8")
        return self._log_path


__all__ = ["Evidence", "TestOutcome", "WIDTH"]
