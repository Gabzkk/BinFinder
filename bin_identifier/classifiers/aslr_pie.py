"""
aslr_pie.py — Detect ASLR + PIE bypass (info leak chaining) potential.
"""

from __future__ import annotations
from ..models import VulnerabilityMatch, Difficulty

PRINTF_FAMILY = {"printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf", "puts", "write"}
INPUT_FUNCS = {"read", "recv", "fgets", "scanf", "__isoc99_scanf", "gets", "fread"}


def classify_aslr_pie_bypass(ctx: dict) -> list[VulnerabilityMatch]:
    imports = set(ctx["imported_functions"])
    prot = ctx["protections"]
    evidence, confidence = [], 0.0

    if prot.pie.value != "Enabled":
        return []

    evidence.append("PIE is ENABLED — addresses are randomised, info leak required")
    confidence += 0.15

    output_funcs = imports & PRINTF_FAMILY
    inp = imports & INPUT_FUNCS

    if output_funcs:
        evidence.append(f"Output functions: {', '.join(sorted(output_funcs))} — potential leak vector")
        confidence += 0.20
    if inp:
        evidence.append(f"Input functions: {', '.join(sorted(inp))}")
        confidence += 0.10

    libs = ctx.get("dynamic_libs", [])
    if any("libc" in lib for lib in libs):
        evidence.append("libc linked — leaked libc address → compute base via known offsets")
        confidence += 0.15

    if prot.canary.value == "Enabled":
        evidence.append("Canary ENABLED — may need to leak canary as well")
        confidence += 0.05

    if prot.relro.value in ("Disabled", "Partial"):
        evidence.append(f"RELRO is {prot.relro.value} — GOT overwrite still possible after leak")
        confidence += 0.10

    if confidence < 0.30:
        return []

    return [VulnerabilityMatch(
        id=10, name="ASLR + PIE Bypass (Info Leak Chaining)", category="Bypass",
        difficulty=Difficulty.HARD, confidence=min(confidence, 1.0),
        description="Leak a runtime address to defeat randomisation, then build a full exploit chain.",
        tags=["ASLR", "PIE", "info leak", "chaining"], evidence=evidence,
        recommendations=[
            "Leak an address from .text, libc, or stack (format string, partial overwrite, etc.).",
            "Compute base addresses: leaked_addr - known_offset = base.",
            "Chain with ROP or GOT overwrite using the computed addresses.",
            "Tools: pwntools ELF().address, libc-database, one_gadget.",
        ],
        exploit_steps=[
            "Step 1 — Identify the leak vector: Look for ways to read memory without crashing:\n    - Format string: %p leaks stack values (may contain .text or libc pointers)\n    - Uninitialised buffer: the binary prints a buffer without zeroing it first\n    - Partial overwrite: overflow only the lowest byte(s) of a pointer\n    - Heap leak: freed chunks contain fd/bk pointers to libc's main_arena",
            "Step 2 — Leak a .text address (defeats PIE): Any pointer into the binary's code/data section reveals the PIE base:\n    pie_base = leaked_text_addr - known_offset\n    # known_offset = address in the un-randomised binary (from objdump/pwntools)",
            "Step 3 — Leak a libc address (defeats ASLR): Leak a GOT entry or stack-stored return address pointing into libc:\n    libc_base = leaked_libc_addr - libc.symbols['<function>']\n    # Use libc-database to identify the exact libc version from the leak",
            "Step 4 — Leak the stack canary (if needed): The canary is typically at a fixed offset from %rsp. Use format string to read it:\n    canary = int(p.recv(...), 16)\n    # Canaries usually have \\x00 as the lowest byte",
            "Step 5 — Compute all needed addresses:\n    elf.address = pie_base\n    libc.address = libc_base\n    system = libc.symbols['system']\n    bin_sh = next(libc.search(b'/bin/sh'))\n    pop_rdi = pie_base + <pop_rdi_offset>",
            "Step 6 — Build the exploit chain: With all addresses known, construct the final payload (typically ROP or GOT overwrite):\n    payload = b'A' * offset\n    payload += p64(canary)    # if canary exists\n    payload += b'B' * 8      # saved RBP\n    payload += rop_chain      # ROP to system('/bin/sh')",
            "Step 7 — Execute: Send the payload in the second interaction (the first was used for leaking):\n    p.sendline(payload)\n    p.interactive()",
        ],
    )]
