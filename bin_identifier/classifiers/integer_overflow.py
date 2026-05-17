"""
integer_overflow.py — Detect integer overflow / underflow patterns.

Signals:
  • Arithmetic / size-conversion functions
  • Small-type casts (atoi, strtoul) feeding allocation or bounds checks
  • malloc with user-controlled size
"""

from __future__ import annotations

from ..models import VulnerabilityMatch, Difficulty


# Functions where the result is often used in size calculations
SIZE_FUNCS = {
    "atoi", "atol", "atoll", "strtol", "strtoul", "strtoll", "strtoull",
    "sscanf", "__isoc99_sscanf",
}

ALLOC_FUNCS = {
    "malloc", "calloc", "realloc", "mmap",
}

INPUT_FUNCS = {
    "read", "recv", "fgets", "scanf", "__isoc99_scanf", "gets", "fread",
}


def classify_integer_overflow(ctx: dict) -> list[VulnerabilityMatch]:
    """Detect potential integer overflow / underflow scenarios."""
    imports = set(ctx["imported_functions"])
    evidence: list[str] = []
    confidence = 0.0

    size_found = imports & SIZE_FUNCS
    alloc_found = imports & ALLOC_FUNCS
    input_found = imports & INPUT_FUNCS

    if not size_found and not alloc_found:
        return []

    if size_found:
        evidence.append(
            f"Integer-conversion functions imported: {', '.join(sorted(size_found))} — "
            "return values may be used unchecked in size calculations"
        )
        confidence += 0.25

    if alloc_found:
        evidence.append(
            f"Dynamic allocation functions: {', '.join(sorted(alloc_found))} — "
            "size argument may originate from user input via integer conversion"
        )
        confidence += 0.15

    if input_found:
        evidence.append(f"User-input functions present: {', '.join(sorted(input_found))}")
        confidence += 0.10

    # 32-bit binaries are more prone to wrap-around
    if ctx["protections"].bits == 32:
        evidence.append("32-bit binary — smaller integer range increases wrap-around risk")
        confidence += 0.10

    if confidence < 0.25:
        return []

    confidence = min(confidence, 1.0)

    return [VulnerabilityMatch(
        id=4,
        name="Integer Overflow / Underflow",
        category="Arithmetic",
        difficulty=Difficulty.BEGINNER_INTERMEDIATE,
        confidence=confidence,
        description=(
            "Arithmetic wrapping causes a value to silently exceed its bounds — "
            "turning a size check into a bypass or allocating a too-small buffer. "
            "Often the root cause feeding a downstream memory corruption."
        ),
        tags=["integer", "wrap-around", "size check"],
        evidence=evidence,
        recommendations=[
            "Trace the flow from input → integer conversion → allocation/memcpy size.",
            "Supply boundary values: 0, -1, INT_MAX, INT_MAX+1, UINT_MAX.",
            "Look for signed/unsigned comparison mismatches in disassembly.",
            "Check if a negative size passes a signed check but becomes huge when unsigned.",
        ],
        exploit_steps=[
            "Step 1 — Identify the integer input: Find where the binary reads a numeric value from the user (e.g. via scanf('%d'), atoi(), strtoul()) that is later used as a size or index.",
            "Step 2 — Trace the data flow: In Ghidra or IDA, follow the integer from input to where it's used. Key patterns:\n    - Used as malloc(size) → controls allocation size\n    - Used as memcpy(dst, src, size) → controls copy length\n    - Used in an if(size < MAX) check → possible bypass",
            "Step 3 — Find the signed/unsigned mismatch: Look for comparisons where a signed int is compared (e.g. if(n < 256)) but later cast to unsigned for malloc/memcpy. Supplying -1 passes the signed check but becomes 0xFFFFFFFF unsigned.",
            "Step 4 — Test boundary values:\n    - Send 0 → may cause zero-size allocation (malloc(0) returns valid pointer)\n    - Send -1 → wraps to UINT_MAX\n    - Send INT_MAX+1 (2147483648) → wraps to INT_MIN\n    - Send 0xFFFFFFFF → wraps to 0 after +1",
            "Step 5 — Trigger the underallocation: If the integer controls malloc size, cause a too-small allocation by wrapping the size down, then overflow it:\n    # Example: size check allows n < 1024, then malloc(n + header_size)\n    # Send n = 0xFFFFFFFC → n + 4 = 0 → malloc(0) → tiny buffer\n    # Then write 1024 bytes → heap overflow",
            "Step 6 — Chain into memory corruption: The integer overflow is usually just the entry point. After creating an undersized buffer or bypassing a check, exploit the resulting:\n    - Heap overflow → corrupt adjacent metadata\n    - Stack overflow → overwrite return address\n    - Out-of-bounds array access → arbitrary read/write",
        ],
    )]
