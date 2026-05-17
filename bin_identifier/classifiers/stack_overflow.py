"""
stack_overflow.py — Detect stack buffer overflow / ret2win potential.

Signals:
  • Dangerous input functions (gets, scanf, strcpy, …) without canary
  • Interesting "win" / "flag" / "shell" functions already in the binary
  • No canary + No PIE → classic ret2win
"""

from __future__ import annotations

from ..models import VulnerabilityMatch, Difficulty


# Functions that can cause stack buffer overflows
DANGEROUS_INPUT_FUNCS = {
    "gets", "scanf", "__isoc99_scanf", "vscanf",
    "strcpy", "strcat", "sprintf", "vsprintf",
    "read",  # only dangerous with unchecked size
}

# Safer but still interesting
RISKY_INPUT_FUNCS = {
    "fgets", "recv", "recvfrom", "fread", "memcpy", "memmove",
    "strncpy", "snprintf",
}

# Function names that suggest a "win" target
WIN_PATTERNS = {
    "win", "flag", "shell", "secret", "get_flag", "print_flag",
    "give_shell", "backdoor", "system_call", "admin", "ret2win",
    "cat_flag", "read_flag", "open_flag",
}


def classify_stack_overflow(ctx: dict) -> list[VulnerabilityMatch]:
    """Analyse context for stack-based buffer overflow / ret2win."""
    imports = set(ctx["imported_functions"])
    exports = set(ctx["exported_functions"])
    all_syms = set(ctx["all_symbols"])
    prot = ctx["protections"]
    strings = ctx["strings"]

    evidence: list[str] = []
    confidence = 0.0

    # ── dangerous input functions ─────────────────────────────────
    dangerous_found = imports & DANGEROUS_INPUT_FUNCS
    risky_found = imports & RISKY_INPUT_FUNCS

    if dangerous_found:
        evidence.append(
            f"Dangerous input functions imported: {', '.join(sorted(dangerous_found))}"
        )
        confidence += 0.35

    if risky_found:
        evidence.append(
            f"Risky input functions imported: {', '.join(sorted(risky_found))}"
        )
        confidence += 0.10

    # ── stack canary absent ───────────────────────────────────────
    if prot.canary.value == "Disabled":
        evidence.append("Stack canary is DISABLED — no stack smashing protection")
        confidence += 0.20
    else:
        confidence -= 0.15

    # ── look for "win" functions ──────────────────────────────────
    combined = exports | all_syms
    win_funcs = {s for s in combined if s.lower() in WIN_PATTERNS}
    if win_funcs:
        evidence.append(
            f"Potential 'win' / target functions found: {', '.join(sorted(win_funcs))}"
        )
        confidence += 0.25

    # ── interesting strings (flag paths, /bin/sh) ─────────────────
    flag_strings = [s for s in strings
                    if any(k in s.lower() for k in ("flag", "/bin/sh", "/bin/bash", "cat flag"))]
    if flag_strings:
        evidence.append(
            f"Interesting strings: {', '.join(flag_strings[:5])}"
        )
        confidence += 0.10

    # ── PIE disabled makes ret2win trivial ────────────────────────
    if prot.pie.value == "Disabled":
        evidence.append("PIE is DISABLED — static addresses, ret2win is straightforward")
        confidence += 0.10

    # ── bail if no real signal ────────────────────────────────────
    if confidence <= 0.15:
        return []

    confidence = min(confidence, 1.0)

    recommendations = [
        "Find the offset to the return address (e.g. cyclic pattern in pwntools).",
        "Identify the target function address (objdump -d or pwntools ELF).",
        "Craft payload: padding + packed return address.",
    ]
    if win_funcs:
        recommendations.insert(0, f"Target function candidates: {', '.join(sorted(win_funcs))}")

    return [VulnerabilityMatch(
        id=1,
        name="Stack Buffer Overflow (ret2win)",
        category="Memory Corruption",
        difficulty=Difficulty.EASY,
        confidence=confidence,
        description=(
            "Overwrite the return address on the stack to redirect execution "
            "to a target function already in the binary. Straightforward once "
            "you find the offset — no shellcode needed, no ASLR bypass."
        ),
        tags=["stack", "overflow", "ret2win"],
        evidence=evidence,
        recommendations=recommendations,
        exploit_steps=[
            "Step 1 — Recon: Run checksec on the binary to confirm protections (no canary, no PIE expected). Use 'file' to identify architecture.",
            "Step 2 — Find the vulnerability: Disassemble the binary (objdump -d or Ghidra). Locate the function that reads user input into a stack buffer without bounds checking.",
            "Step 3 — Identify the target: Look for a 'win' function (e.g. win, flag, shell, backdoor) that prints the flag or spawns a shell. Note its address with: objdump -d <binary> | grep win",
            "Step 4 — Determine the offset: Use a cyclic pattern to find how many bytes it takes to overwrite the return address.\n    from pwn import *\n    p = process('./<binary>')\n    p.sendline(cyclic(200))\n    p.wait()\n    # Check core dump: cyclic_find(fault_addr)",
            "Step 5 — Handle alignment (x86_64): On 64-bit, the stack must be 16-byte aligned before a call. If the exploit segfaults in movaps, add a single 'ret' gadget before the win address:\n    ret_gadget = elf.search(asm('ret')).__next__()",
            "Step 6 — Craft the payload:\n    from pwn import *\n    elf = ELF('./<binary>')\n    offset = <found_offset>\n    payload = b'A' * offset\n    payload += p64(ret_gadget)   # alignment fix (64-bit only)\n    payload += p64(elf.symbols['win'])",
            "Step 7 — Exploit locally:\n    p = process('./<binary>')\n    p.sendline(payload)\n    p.interactive()  # should print the flag or give a shell",
            "Step 8 — Exploit remotely: Replace process() with remote():\n    p = remote('<host>', <port>)\n    p.sendline(payload)\n    print(p.recvall())",
        ],
    )]
