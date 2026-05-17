"""
format_string.py — Detect format string vulnerabilities (basic + arbitrary write).

Signals:
  • printf/fprintf/sprintf imported AND user input flows to them
  • Presence of %n in strings (arbitrary write variant)
  • GOT is writable (Partial RELRO) — enables GOT overwrite
"""

from __future__ import annotations

from ..models import VulnerabilityMatch, Difficulty


PRINTF_FAMILY = {
    "printf", "fprintf", "sprintf", "snprintf",
    "vprintf", "vfprintf", "vsprintf", "vsnprintf",
    "dprintf", "syslog",
}

INPUT_FUNCS = {
    "gets", "fgets", "scanf", "__isoc99_scanf", "read",
    "recv", "recvfrom", "fread", "getline",
}


def classify_format_string_basic(ctx: dict) -> list[VulnerabilityMatch]:
    """Detect *basic* format string info-leak potential."""
    imports = set(ctx["imported_functions"])
    prot = ctx["protections"]
    evidence: list[str] = []
    confidence = 0.0

    printf_found = imports & PRINTF_FAMILY
    input_found = imports & INPUT_FUNCS

    if not printf_found:
        return []

    evidence.append(f"printf-family functions imported: {', '.join(sorted(printf_found))}")
    confidence += 0.25

    if input_found:
        evidence.append(
            f"User-input functions imported: {', '.join(sorted(input_found))} — "
            "input may flow directly to printf"
        )
        confidence += 0.25

    # No FORTIFY → no %n checks at runtime
    if prot.fortify.value == "Disabled":
        evidence.append("FORTIFY_SOURCE is DISABLED — printf not hardened")
        confidence += 0.15

    if prot.canary.value == "Disabled":
        evidence.append("No stack canary — leaked values can be used directly")
        confidence += 0.05

    if confidence < 0.25:
        return []

    confidence = min(confidence, 1.0)

    return [VulnerabilityMatch(
        id=2,
        name="Format String (Basic Info Leak)",
        category="Format String",
        difficulty=Difficulty.EASY,
        confidence=confidence,
        description=(
            "Pass format specifiers like %x or %s to printf-style functions "
            "the binary calls with user input directly. Leaks stack memory "
            "values with no binary modification needed."
        ),
        tags=["format string", "info leak"],
        evidence=evidence,
        recommendations=[
            "Send a payload of '%p.' * 20 and inspect leaked addresses.",
            "Map leaked values to stack layout, libc base, or canary.",
            "Use pwntools' FmtStr class for automated offset discovery.",
        ],
        exploit_steps=[
            "Step 1 — Confirm the vulnerability: Send '%p.%p.%p.%p.%p.%p' as input. If the binary prints hex addresses instead of the literal string, it's vulnerable.",
            "Step 2 — Map the stack: Send increasing numbers of %p to dump stack values. Note which positions contain interesting data:\n    for i in range(1, 30):\n        p.sendline(f'%{i}$p')  # Direct parameter access",
            "Step 3 — Identify leaked values: Match leaked addresses to known regions:\n    - 0x7f... → libc address (compute libc base = leaked - known_offset)\n    - 0x5... or 0x08... → binary .text address (PIE base)\n    - Stack canary (often has \\x00 as lowest byte)",
            "Step 4 — Leak specific targets: Use %s to read strings at addresses on the stack:\n    payload = p64(target_addr) + b'%7$s'  # Read string at target_addr",
            "Step 5 — Calculate bases: With a leaked libc address:\n    libc_base = leaked_addr - libc.symbols['<known_func>']\n    system = libc_base + libc.symbols['system']\n    bin_sh = libc_base + next(libc.search(b'/bin/sh'))",
            "Step 6 — Chain with another exploit: Use the leaked information to defeat ASLR/canary and chain into a stack overflow, ROP, or GOT overwrite.",
        ],
    )]


def classify_format_string_write(ctx: dict) -> list[VulnerabilityMatch]:
    """Detect *arbitrary write* via format string (%n)."""
    imports = set(ctx["imported_functions"])
    prot = ctx["protections"]
    evidence: list[str] = []
    confidence = 0.0

    printf_found = imports & PRINTF_FAMILY
    if not printf_found:
        return []

    input_found = imports & INPUT_FUNCS

    evidence.append(f"printf-family functions imported: {', '.join(sorted(printf_found))}")
    confidence += 0.20

    if input_found:
        evidence.append(f"User-input functions: {', '.join(sorted(input_found))}")
        confidence += 0.15

    # GOT writable → overwrite target
    if prot.relro.value in ("Disabled", "Partial"):
        evidence.append(
            f"RELRO is {prot.relro.value} — GOT is writable, enabling GOT overwrite via %n"
        )
        confidence += 0.20

    if prot.fortify.value == "Disabled":
        evidence.append("FORTIFY_SOURCE disabled — %n not blocked at runtime")
        confidence += 0.10

    # Check strings for %n hints
    strings = ctx["strings"]
    if any("%n" in s for s in strings):
        evidence.append("String containing '%n' found in binary")
        confidence += 0.15

    if confidence < 0.35:
        return []

    confidence = min(confidence, 1.0)

    return [VulnerabilityMatch(
        id=7,
        name="Format String (Arbitrary Write)",
        category="Format String",
        difficulty=Difficulty.INTERMEDIATE,
        confidence=confidence,
        description=(
            "Use %n to write controlled values to arbitrary memory addresses. "
            "Requires careful calculation of argument positions and byte widths. "
            "Can overwrite GOT entries or return addresses."
        ),
        tags=["format string", "arbitrary write", "GOT"],
        evidence=evidence,
        recommendations=[
            "Determine the format string argument offset (e.g. AAAA%p%p%p…).",
            "Use pwntools fmtstr_payload() to generate the write primitive.",
            "Target: overwrite GOT entry of a later-called function (e.g. exit → system).",
            "Or overwrite a return address / function pointer.",
        ],
        exploit_steps=[
            "Step 1 — Find your offset: Send 'AAAA' + '%p.' * 20 and look for '0x41414141' in the output. Its position is your format string offset (e.g. offset 6).",
            "Step 2 — Verify write primitive: Test with a controlled %n write. If printf(user_input) is called directly, %n will write the number of bytes printed so far to an address you supply.",
            "Step 3 — Identify the GOT target: Pick a function called AFTER the format string (e.g. exit, puts). Find its GOT entry:\n    objdump -R <binary> | grep exit\n    # or: pwntools ELF('<binary>').got['exit']",
            "Step 4 — Determine the overwrite value: Find the address of system() or a one_gadget in libc (may need an info leak first):\n    one_gadget libc.so.6",
            "Step 5 — Build the payload with pwntools:\n    from pwn import *\n    elf = ELF('./<binary>')\n    # offset = <your_offset>\n    payload = fmtstr_payload(offset, {elf.got['exit']: system_addr})\n    p.sendline(payload)",
            "Step 6 — Trigger the overwritten function: After the format string write completes, the binary calls exit() → which now jumps to system(). If system gets '/bin/sh' as argument, you have a shell.",
            "Step 7 — For partial overwrites (PIE/ASLR): Write only the last 2 bytes using %hn to avoid needing the full address. Combine with a prior info leak to compute the target.",
        ],
    )]
