"""Small formatting helpers used by the demo, the tests and the report.

Nothing here is security-relevant; it exists so that test evidence is legible
in a report rather than a wall of hex.
"""

from __future__ import annotations


def hexdump(data: bytes, *, limit: int = 64, indent: str = "    ") -> str:
    """Classic offset / hex / ASCII dump, truncated to ``limit`` bytes."""
    shown = data[:limit]
    lines = []
    for offset in range(0, len(shown), 16):
        chunk = shown[offset : offset + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{indent}{offset:04x}  {hex_part:<47}  |{ascii_part}|")
    if len(data) > limit:
        lines.append(f"{indent}....  ({len(data) - limit} more bytes)")
    return "\n".join(lines) if lines else f"{indent}(empty)"


def first_difference(a: bytes, b: bytes) -> int | None:
    """Index of the first differing byte, or ``None`` if the prefixes match."""
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return i
    if len(a) != len(b):
        return min(len(a), len(b))
    return None


def describe_diff(original: bytes, modified: bytes, *, context: int = 4) -> str:
    """Human-readable summary of what an adversary changed."""
    index = first_difference(original, modified)
    if index is None:
        return "no byte-level difference"
    if index >= len(original) or index >= len(modified):
        return (
            f"length changed: {len(original)} -> {len(modified)} bytes "
            f"(first divergence at offset {index})"
        )
    lo = max(0, index - context)
    hi = index + context + 1
    return (
        f"offset {index}: 0x{original[index]:02x} -> 0x{modified[index]:02x} "
        f"(was {original[lo:hi].hex()}, now {modified[lo:hi].hex()})"
    )


def human_bytes(count: float) -> str:
    """Format a byte count with binary units."""
    for unit in ("B", "KiB", "MiB", "GiB"):
        if abs(count) < 1024.0 or unit == "GiB":
            return f"{count:.0f} {unit}" if unit == "B" else f"{count:.2f} {unit}"
        count /= 1024.0
    return f"{count:.2f} GiB"  # pragma: no cover - unreachable


__all__ = ["hexdump", "first_difference", "describe_diff", "human_bytes"]
